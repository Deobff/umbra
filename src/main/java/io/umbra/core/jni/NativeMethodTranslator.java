package io.umbra.core.jni;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Translates one Java method body into C statements that execute the same
 * semantics through JNI.
 *
 * <p>The generated function is a stack machine: {@code st[]} is the operand
 * stack in JVM <em>slot</em> units (so a {@code long}/{@code double} occupies two
 * slots, exactly like the JVM), {@code lc[]} holds the local variables and
 * {@code sp} is the operand stack pointer. ASM's {@link Analyzer} supplies the
 * stack depth and local-variable kinds at every instruction; the emitted code
 * re-synchronises {@code sp} at every instruction, which keeps branches simple
 * and self-checking. Branches become {@code goto} labels, switches become C
 * {@code switch} statements, JNI calls are followed by exception checks that
 * jump to the matching translated catch handler (with runtime
 * {@code IsInstanceOf} dispatch) or return with the exception still pending.</p>
 *
 * <p>Methods whose bytecode uses features outside the supported set are
 * rejected with {@link UnsupportedException} and are left as Java methods by the
 * caller.</p>
 */
public final class NativeMethodTranslator implements Opcodes {

    /** Thrown when a method cannot be translated faithfully; the method stays Java. */
    public static final class UnsupportedException extends Exception {
        private static final long serialVersionUID = 1L;

        public UnsupportedException(String message) {
            super(message);
        }
    }

    private final String owner;
    private final MethodNode method;
    private final CGenerator generator;
    private final boolean staticMethod;
    private final List<String> argumentTypes;
    private final String returnDescriptor;
    private String cReturn;
    private final List<String> cArguments = new ArrayList<String>();

    private final StringBuilder out = new StringBuilder(1 << 12);
    private int tempCounter;
    private AbstractInsnNode[] instructions;
    private Frame<BasicValue>[] frames;
    private final Map<LabelNode, Integer> labelIndices = new HashMap<LabelNode, Integer>();
    private final Set<Integer> targetLabels = new LinkedHashSet<Integer>();
    private final Set<Integer> handlerStarts = new LinkedHashSet<Integer>();
    private final Map<Integer, Integer> dispatchByInstruction = new HashMap<Integer, Integer>();
    private final Map<Integer, ExcSet> dispatchSets = new LinkedHashMap<Integer, ExcSet>();
    private final Map<String, Integer> dispatchKeys = new HashMap<String, Integer>();
    private int maxStackSlots;
    private int instructionCount;

    public NativeMethodTranslator(String owner, MethodNode method, CGenerator generator) {
        this.owner = owner;
        this.method = method;
        this.generator = generator;
        this.staticMethod = (method.access & ACC_STATIC) != 0;
        this.argumentTypes = JniNames.argumentTypes(method.desc);
        this.returnDescriptor = JniNames.returnType(method.desc);
    }

    public int instructionCount() {
        return instructionCount;
    }

    public CGenerator.MethodC translate() throws UnsupportedException {
        if ((method.access & (ACC_NATIVE | ACC_ABSTRACT)) != 0) {
            throw new UnsupportedException("method is already native or abstract");
        }
        if (method.name.startsWith("<")) {
            throw new UnsupportedException("constructors and class initializers are not translated");
        }
        if (method.instructions == null || method.instructions.size() == 0) {
            throw new UnsupportedException("method has no code");
        }
        cReturn = cType(returnDescriptor);
        for (String type : argumentTypes) {
            cArguments.add(cType(type));
        }
        instructions = method.instructions.toArray();
        instructionCount = instructions.length;
        analyze();
        indexLabels();
        collectTargets();
        emitBody();
        CGenerator.MethodC result = new CGenerator.MethodC();
        result.functionName = "umbra_m" + generator.methodCount();
        result.owner = owner;
        result.name = method.name;
        result.descriptor = method.desc;
        result.staticMethod = staticMethod;
        result.cReturn = cReturn;
        result.cArguments = cArguments;
        result.body = out.toString();
        result.stackSlots = maxStackSlots + 2;
        result.localSlots = Math.max(1, method.maxLocals);        return result;
    }

    private void analyze() throws UnsupportedException {
        for (int i = 0; i < instructions.length; i++) {
            AbstractInsnNode insn = instructions[i];
            int opcode = insn.getOpcode();
            if (opcode < 0) {
                continue;
            }
            if (insn instanceof InvokeDynamicInsnNode) {
                throw new UnsupportedException("invokedynamic is not supported");
            }
            if (opcode == JSR || opcode == RET) {
                throw new UnsupportedException("subroutines (jsr/ret) are not supported");
            }
            if (opcode == MONITORENTER || opcode == MONITOREXIT) {
                throw new UnsupportedException("monitor instructions are not supported");
            }
            if (insn instanceof MethodInsnNode && opcode == INVOKESPECIAL
                    && ((MethodInsnNode) insn).itf) {
                throw new UnsupportedException("invokespecial on an interface is not supported");
            }
            if (insn instanceof LdcInsnNode) {
                Object constant = ((LdcInsnNode) insn).cst;
                if (!(constant instanceof Integer) && !(constant instanceof Long)
                        && !(constant instanceof Float) && !(constant instanceof Double)
                        && !(constant instanceof String) && !(constant instanceof Type)) {
                    throw new UnsupportedException("unsupported constant: "
                            + (constant == null ? "null" : constant.getClass().getName()));
                }
            }
        }
        try {
            frames = new Analyzer<BasicValue>(new BasicInterpreter()).analyze(owner, method);
        } catch (AnalyzerException e) {
            throw new UnsupportedException("bytecode analysis failed: " + e.getMessage());
        }
    }

    private void indexLabels() {
        for (int i = 0; i < instructions.length; i++) {
            if (instructions[i] instanceof LabelNode) {
                labelIndices.put((LabelNode) instructions[i], Integer.valueOf(i));
            }
        }
    }

    private void collectTargets() {
        for (int i = 0; i < instructions.length; i++) {
            AbstractInsnNode insn = instructions[i];
            if (insn instanceof JumpInsnNode) {
                addTarget(((JumpInsnNode) insn).label);
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode node = (TableSwitchInsnNode) insn;
                addTarget(node.dflt);
                for (LabelNode label : node.labels) {
                    addTarget(label);
                }
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode node = (LookupSwitchInsnNode) insn;
                addTarget(node.dflt);
                for (LabelNode label : node.labels) {
                    addTarget(label);
                }
            }
            if (insn instanceof LabelNode && isHandlerLabel((LabelNode) insn)) {
                addTarget((LabelNode) insn);
                handlerStarts.add(labelIndices.get(insn));
            }
        }
    }

    private boolean isHandlerLabel(LabelNode label) {
        if (method.tryCatchBlocks == null) {
            return false;
        }
        for (TryCatchBlockNode block : method.tryCatchBlocks) {
            if (block.handler == label) {
                return true;
            }
        }
        return false;
    }

    private void addTarget(LabelNode label) {
        Integer index = labelIndices.get(label);
        if (index != null) {
            targetLabels.add(index);
        }
    }

    private void emitBody() throws UnsupportedException {
        out.append("    /* translated from ").append(owner).append('#').append(method.name)
                .append(method.desc).append(" */\n");
        // Copy incoming arguments into the local variable slots.
        int slot = 0;
        if (!staticMethod) {
            out.append("    lc[0].l = (jobject)_self;\n");
            slot = 1;
        }
        for (int i = 0; i < argumentTypes.size(); i++) {
            String type = argumentTypes.get(i);
            out.append("    lc[").append(slot).append("].").append(slotMember(type))
                    .append(" = _a").append(i).append(";\n");
            slot += type.equals("J") || type.equals("D") ? 2 : 1;
        }
        for (int i = 0; i < instructions.length; i++) {
            Frame<BasicValue> frame = frames[i];
            if (frame != null && stackSlots(frame) > maxStackSlots) {
                maxStackSlots = stackSlots(frame);
            }
            boolean reachable = frame != null;
            if (targetLabels.contains(Integer.valueOf(i))) {
                out.append("L").append(i).append(": ;\n");
                if (handlerStarts.contains(Integer.valueOf(i))) {
                    out.append("    { st[0].l = umbra_ex; umbra_ex = NULL; }\n");
                }
            }
            if (!reachable || instructions[i].getOpcode() < 0) {
                continue;
            }
            out.append("    {\n");
            out.append("        sp = ").append(stackSlots(frame)).append(";\n");
            emitInstruction(instructions[i], frame, i);
            out.append("    }\n");
        }
        emitDispatchBlocks();
    }

    /**
     * Operand stack depth in JVM <em>slots</em>. ASM's frames count values
     * (long/double are a single value there) while the generated C stack mirrors
     * the JVM slot layout, so the two-slot values have to be expanded here.
     */
    private static int stackSlots(Frame<BasicValue> frame) {
        int slots = 0;
        for (int i = 0; i < frame.getStackSize(); i++) {
            BasicValue value = frame.getStack(i);
            Type type = value == null ? null : value.getType();
            slots += type != null && (type.getSort() == Type.LONG || type.getSort() == Type.DOUBLE)
                    ? 2 : 1;
        }
        return slots;
    }

    private void emitDispatchBlocks() {
        String ret = CGenerator.defaultReturn(cReturn);
        for (ExcSet set : dispatchSets.values()) {
            out.append("UMBRA_EXC_").append(set.id).append(": {\n");
            out.append("    jthrowable _e = (*env)->ExceptionOccurred(env);\n");
            out.append("    if (_e == NULL) { ").append(ret).append(" }\n");
            out.append("    (*env)->ExceptionClear(env);\n");
            for (HandlerEntry entry : set.entries) {
                if (entry.catchType == null) {
                    out.append("    umbra_ex = _e; goto L").append(entry.handlerIndex).append(";\n");
                } else {
                    out.append("    {\n");
                    out.append("        jclass _c = umbra_class(env, ").append(entry.classIndex).append(");\n");
                    out.append("        if (_c == NULL) { ").append(ret).append(" }\n");
                    out.append("        if ((*env)->IsInstanceOf(env, _e, _c)) { umbra_ex = _e; goto L")
                            .append(entry.handlerIndex).append("; }\n");
                    out.append("        if ((*env)->ExceptionCheck(env)) { ").append(ret).append(" }\n");
                    out.append("    }\n");
                }
            }
            out.append("    (*env)->Throw(env, _e);\n");
            out.append("    ").append(ret).append("\n");
            out.append("}\n");
        }
    }

    // ------------------------------------------------------------------
    // Instruction emission
    // ------------------------------------------------------------------

    private void emitInstruction(AbstractInsnNode node, Frame<BasicValue> frame, int index)
            throws UnsupportedException {
        if (node instanceof InsnNode) {
            emitSimple((InsnNode) node, index);
        } else if (node instanceof IntInsnNode) {
            emitIntInsn((IntInsnNode) node, index);
        } else if (node instanceof VarInsnNode) {
            emitVarInsn((VarInsnNode) node, frame);
        } else if (node instanceof TypeInsnNode) {
            emitTypeInsn((TypeInsnNode) node, index);
        } else if (node instanceof FieldInsnNode) {
            emitFieldInsn((FieldInsnNode) node, index);
        } else if (node instanceof MethodInsnNode) {
            emitMethodInsn((MethodInsnNode) node, index);
        } else if (node instanceof JumpInsnNode) {
            emitJumpInsn((JumpInsnNode) node);
        } else if (node instanceof LdcInsnNode) {
            emitLdcInsn((LdcInsnNode) node, index);
        } else if (node instanceof IincInsnNode) {
            IincInsnNode iinc = (IincInsnNode) node;
            line("lc[" + iinc.var + "].i = (jint)((umbra_u32)lc[" + iinc.var + "].i + (umbra_u32)"
                    + iinc.incr + "u);");
        } else if (node instanceof TableSwitchInsnNode) {
            emitTableSwitch((TableSwitchInsnNode) node);
        } else if (node instanceof LookupSwitchInsnNode) {
            emitLookupSwitch((LookupSwitchInsnNode) node);
        } else if (node instanceof MultiANewArrayInsnNode) {
            emitMultiArray((MultiANewArrayInsnNode) node, index);
        } else {
            throw new UnsupportedException("unsupported instruction "
                    + node.getClass().getSimpleName() + " (opcode " + node.getOpcode() + ")");
        }
    }

    private void emitSimple(InsnNode insn, int index) throws UnsupportedException {
        int opcode = insn.getOpcode();
        switch (opcode) {
            case NOP:
                return;
            case ACONST_NULL:
                pushRef("NULL");
                return;
            case ICONST_M1:
            case ICONST_0:
            case ICONST_1:
            case ICONST_2:
            case ICONST_3:
            case ICONST_4:
            case ICONST_5:
                pushInt(String.valueOf(opcode - ICONST_0));
                return;
            case LCONST_0:
            case LCONST_1:
                pushLong(String.valueOf(opcode - LCONST_0));
                return;
            case FCONST_0:
            case FCONST_1:
            case FCONST_2:
                pushFloat((opcode - FCONST_0) + ".0f");
                return;
            case DCONST_0:
            case DCONST_1:
                pushDouble((opcode - DCONST_0) + ".0");
                return;
            case IALOAD:
            case LALOAD:
            case FALOAD:
            case DALOAD:
            case AALOAD:
            case BALOAD:
            case CALOAD:
            case SALOAD:
                emitArrayLoad(opcode, index);
                return;
            case IASTORE:
            case LASTORE:
            case FASTORE:
            case DASTORE:
            case AASTORE:
            case BASTORE:
            case CASTORE:
            case SASTORE:
                emitArrayStore(opcode, index);
                return;
            case POP:
                line("sp -= 1;");
                return;
            case POP2:
                line("sp -= 2;");
                return;
            case DUP:
                line("st[sp] = st[sp - 1]; sp += 1;");
                return;
            case DUP_X1:
                line("st[sp] = st[sp - 1]; st[sp - 1] = st[sp - 2]; st[sp - 2] = st[sp]; sp += 1;");
                return;
            case DUP_X2:
                line("st[sp] = st[sp - 1]; st[sp - 1] = st[sp - 2]; st[sp - 2] = st[sp - 3];"
                        + " st[sp - 3] = st[sp]; sp += 1;");
                return;
            case DUP2:
                line("st[sp] = st[sp - 2]; st[sp + 1] = st[sp - 1]; sp += 2;");
                return;
            case DUP2_X1:
                line("jvalue _a = st[sp - 2]; jvalue _b = st[sp - 1]; jvalue _c = st[sp - 3];");
                line("st[sp - 3] = _a; st[sp - 2] = _b; st[sp - 1] = _c;"
                        + " st[sp] = _a; st[sp + 1] = _b; sp += 2;");
                return;
            case DUP2_X2:
                line("jvalue _a = st[sp - 2]; jvalue _b = st[sp - 1];");
                line("jvalue _c = st[sp - 3]; jvalue _d = st[sp - 4];");
                line("st[sp - 4] = _a; st[sp - 3] = _b; st[sp - 2] = _c; st[sp - 1] = _d;"
                        + " st[sp] = _a; st[sp + 1] = _b; sp += 2;");
                return;
            case SWAP:
                line("jvalue _a = st[sp - 1]; st[sp - 1] = st[sp - 2]; st[sp - 2] = _a;");
                return;
            case IADD:
                binInt("+");
                return;
            case ISUB:
                binInt("-");
                return;
            case IMUL:
                binInt("*");
                return;
            case IDIV:
                binDiv(true, index);
                return;
            case IREM:
                binDiv(false, index);
                return;
            case INEG:
                unaryInt("0u - (umbra_u32)");
                return;
            case ISHL:
                binShiftInt("<<");
                return;
            case ISHR:
                binShiftInt(">>");
                return;
            case IUSHR:
                binShiftIntUnsigned();
                return;
            case IAND:
                binInt("&");
                return;
            case IOR:
                binInt("|");
                return;
            case IXOR:
                binInt("^");
                return;
            case LADD:
                binLong("+");
                return;
            case LSUB:
                binLong("-");
                return;
            case LMUL:
                binLong("*");
                return;
            case LDIV:
                binLongDiv(true, index);
                return;
            case LREM:
                binLongDiv(false, index);
                return;
            case LNEG:
                unaryLong("0ull - (umbra_u64)");
                return;
            case LSHL:
                binShiftLong("<<");
                return;
            case LSHR:
                binShiftLong(">>");
                return;
            case LUSHR:
                binShiftLongUnsigned();
                return;
            case LAND:
                binLong("&");
                return;
            case LOR:
                binLong("|");
                return;
            case LXOR:
                binLong("^");
                return;
            case FADD:
                binFloat("+");
                return;
            case FSUB:
                binFloat("-");
                return;
            case FMUL:
                binFloat("*");
                return;
            case FDIV:
                binFloat("/");
                return;
            case FREM:
                binFloat("%");
                return;
            case FNEG:
                unaryFloat("-");
                return;
            case DADD:
                binDouble("+");
                return;
            case DSUB:
                binDouble("-");
                return;
            case DMUL:
                binDouble("*");
                return;
            case DDIV:
                binDouble("/");
                return;
            case DREM:
                binDouble("%");
                return;
            case DNEG:
                unaryDouble("-");
                return;
            case I2L:
                pushLong("(jlong)" + popInt());
                return;
            case I2F:
                pushFloat("(jfloat)" + popInt());
                return;
            case I2D:
                pushDouble("(jdouble)" + popInt());
                return;
            case L2I:
                pushInt("(jint)" + popLong());
                return;
            case L2F:
                pushFloat("(jfloat)" + popLong());
                return;
            case L2D:
                pushDouble("(jdouble)" + popLong());
                return;
            case F2I:
                pushInt("umbra_f2i(" + popFloat() + ")");
                return;
            case F2L:
                pushLong("umbra_f2l(" + popFloat() + ")");
                return;
            case F2D:
                pushDouble("(jdouble)" + popFloat());
                return;
            case D2I:
                pushInt("umbra_d2i(" + popDouble() + ")");
                return;
            case D2L:
                pushLong("umbra_d2l(" + popDouble() + ")");
                return;
            case D2F:
                pushFloat("(jfloat)" + popDouble());
                return;
            case I2B:
                pushInt("(jint)(jbyte)" + popInt());
                return;
            case I2C:
                pushInt("(jint)(jchar)" + popInt());
                return;
            case I2S:
                pushInt("(jint)(jshort)" + popInt());
                return;
            case LCMP:
                emitCompare("umbra_lcmp", true);
                return;
            case FCMPL:
                emitCompare("umbra_fcmpl", false);
                return;
            case FCMPG:
                emitCompare("umbra_fcmpg", false);
                return;
            case DCMPL:
                emitCompare("umbra_dcmpl", false);
                return;
            case DCMPG:
                emitCompare("umbra_dcmpg", false);
                return;
            case IRETURN:
            case LRETURN:
            case FRETURN:
            case DRETURN:
            case ARETURN:
            case RETURN:
                emitReturn(opcode);
                return;
            case ARRAYLENGTH:
                emitArrayLength(index);
                return;
            case ATHROW:
                emitThrow(index);
                return;
            case MONITORENTER:
            case MONITOREXIT:
                throw new UnsupportedException("monitor instructions are not supported");
            default:
                throw new UnsupportedException("unsupported instruction opcode " + opcode);
        }
    }

    private void emitIntInsn(IntInsnNode insn, int index) throws UnsupportedException {
        if (insn.getOpcode() == BIPUSH || insn.getOpcode() == SIPUSH) {
            pushInt(String.valueOf(insn.operand));
            return;
        }
        if (insn.getOpcode() == NEWARRAY) {
            emitNewPrimitiveArray(insn.operand, index);
            return;
        }
        throw new UnsupportedException("unsupported int instruction " + insn.getOpcode());
    }

    private void emitNewPrimitiveArray(int operand, int index) throws UnsupportedException {
        String type;
        String jni;
        switch (operand) {
            case T_BOOLEAN:
                type = "jbooleanArray";
                jni = "Boolean";
                break;
            case T_CHAR:
                type = "jcharArray";
                jni = "Char";
                break;
            case T_FLOAT:
                type = "jfloatArray";
                jni = "Float";
                break;
            case T_DOUBLE:
                type = "jdoubleArray";
                jni = "Double";
                break;
            case T_BYTE:
                type = "jbyteArray";
                jni = "Byte";
                break;
            case T_SHORT:
                type = "jshortArray";
                jni = "Short";
                break;
            case T_INT:
                type = "jintArray";
                jni = "Int";
                break;
            case T_LONG:
                type = "jlongArray";
                jni = "Long";
                break;
            default:
                throw new UnsupportedException("bad newarray type " + operand);
        }
        String count = popInt();
        String branch = exceptionBranch(index);
        String array = "_n" + tempCounter++;
        line(type + " " + array + " = (*env)->New" + jni + "Array(env, (jsize)" + count + ");");
        line("if (" + array + " == NULL) " + branch);
        pushRef(array);
    }

    private void emitVarInsn(VarInsnNode insn, Frame<BasicValue> frame) throws UnsupportedException {
        int opcode = insn.getOpcode();
        int variable = insn.var;
        switch (opcode) {
            case ILOAD:
                line("st[sp].i = lc[" + variable + "].i; sp += 1;");
                return;
            case LLOAD:
                line("st[sp].j = lc[" + variable + "].j; sp += 2;");
                return;
            case FLOAD:
                line("st[sp].f = lc[" + variable + "].f; sp += 1;");
                return;
            case DLOAD:
                line("st[sp].d = lc[" + variable + "].d; sp += 2;");
                return;
            case ALOAD:
                line("st[sp].l = lc[" + variable + "].l; sp += 1;");
                return;
            case ISTORE:
                line("lc[" + variable + "].i = st[sp - 1].i; sp -= 1;");
                return;
            case LSTORE:
                line("lc[" + variable + "].j = st[sp - 2].j; sp -= 2;");
                return;
            case FSTORE:
                line("lc[" + variable + "].f = st[sp - 1].f; sp -= 1;");
                return;
            case DSTORE:
                line("lc[" + variable + "].d = st[sp - 2].d; sp -= 2;");
                return;
            case ASTORE:
                line("lc[" + variable + "].l = st[sp - 1].l; sp -= 1;");
                return;
            case RET:
                throw new UnsupportedException("ret is not supported");
            default:
                throw new UnsupportedException("unsupported variable instruction " + opcode);
        }
    }

    private void emitTypeInsn(TypeInsnNode insn, int index) throws UnsupportedException {
        switch (insn.getOpcode()) {
            case NEW:
                emitNew(insn.desc, index);
                return;
            case ANEWARRAY:
                emitANewArray(insn.desc, index);
                return;
            case CHECKCAST:
                emitCheckCast(insn.desc, index);
                return;
            case INSTANCEOF:
                emitInstanceOf(insn.desc, index);
                return;
            default:
                throw new UnsupportedException("unsupported type instruction " + insn.getOpcode());
        }
    }

    private void emitNew(String internalName, int index) throws UnsupportedException {
        int classIndex = generator.classRef(internalName);
        String branch = exceptionBranch(index);
        String clazz = "_c" + tempCounter++;
        String object = "_o" + tempCounter++;
        line("jclass " + clazz + " = umbra_class(env, " + classIndex + ");");
        line("if (" + clazz + " == NULL) " + branch);
        // Force class initialization exactly like `new` does (GetMethodID triggers
        // class initialization per the JNI specification). "toString" is inherited
        // by every instantiable class, so it always resolves.
        String init = "_i" + tempCounter++;
        line("jmethodID " + init + " = (*env)->GetMethodID(env, " + clazz
                + ", \"toString\", \"()Ljava/lang/String;\");");
        line("if (" + init + " == NULL) " + branch);
        line("jobject " + object + " = (*env)->AllocObject(env, " + clazz + ");");
        line("if (" + object + " == NULL) " + branch);
        pushRef(object);
    }

    private void emitANewArray(String component, int index) throws UnsupportedException {
        int classIndex = generator.classRef(component);
        String branch = exceptionBranch(index);
        String count = popInt();
        line("{");
        line("    jclass _c = umbra_class(env, " + classIndex + ");");
        line("    if (_c == NULL) " + branch);
        String array = "_a" + tempCounter++;
        line("    jobject " + array + " = (*env)->NewObjectArray(env, (jsize)" + count + ", _c, NULL);");
        line("    if (" + array + " == NULL) " + branch);
        line("    st[sp].l = " + array + "; sp += 1;");
        line("}");
    }

    private void emitCheckCast(String type, int index) throws UnsupportedException {
        int classIndex = generator.classRef(type);
        String branch = exceptionBranch(index);
        line("{");
        line("    jclass _c = umbra_class(env, " + classIndex + ");");
        line("    if (_c == NULL) " + branch);
        line("    if (!umbra_checkcast(env, st[sp - 1].l, _c)) " + branch);
        line("}");
    }

    private void emitInstanceOf(String type, int index) throws UnsupportedException {
        int classIndex = generator.classRef(type);
        String branch = exceptionBranch(index);
        line("{");
        line("    jobject _o = st[sp - 1].l;");
        line("    sp -= 1;");
        line("    jclass _c = umbra_class(env, " + classIndex + ");");
        line("    if (_c == NULL) " + branch);
        line("    {");
        line("        jint _r = 0;");
        line("        if (_o != NULL) {");
        line("            _r = (*env)->IsInstanceOf(env, _o, _c) ? 1 : 0;");
        line("            if ((*env)->ExceptionCheck(env)) " + branch);
        line("        }");
        line("        st[sp].i = _r; sp += 1;");
        line("    }");
        line("}");
    }

    private void emitLdcInsn(LdcInsnNode insn, int index) throws UnsupportedException {
        Object constant = insn.cst;
        if (constant instanceof Integer) {
            pushInt("(jint)0x" + Integer.toHexString(((Integer) constant).intValue()) + "u");
            return;
        }
        if (constant instanceof Long) {
            pushLong("(jlong)0x" + Long.toHexString(((Long) constant).longValue()) + "ull");
            return;
        }
        if (constant instanceof Float) {
            int bits = Float.floatToRawIntBits(((Float) constant).floatValue());
            pushFloat("umbra_make_f((umbra_u32)0x" + Integer.toHexString(bits) + "u)");
            return;
        }
        if (constant instanceof Double) {
            long bits = Double.doubleToRawLongBits(((Double) constant).doubleValue());
            pushDouble("umbra_make_d((umbra_u64)0x" + Long.toHexString(bits) + "ull)");
            return;
        }
        if (constant instanceof String) {
            int stringIndex = generator.stringRef((String) constant);
            String branch = exceptionBranch(index);
            String string = "_s" + tempCounter++;
            line("jstring " + string + " = (*env)->NewStringUTF(env, umbra_str_" + stringIndex + ");");
            line("if (" + string + " == NULL) " + branch);
            pushRef(string);
            return;
        }
        if (constant instanceof Type) {
            Type type = (Type) constant;
            String branch = exceptionBranch(index);
            String clazz = "_c" + tempCounter++;
            switch (type.getSort()) {
                case Type.OBJECT:
                    line("jclass " + clazz + " = umbra_class(env, "
                            + generator.classRef(type.getInternalName()) + ");");
                    break;
                case Type.ARRAY:
                    line("jclass " + clazz + " = umbra_class(env, "
                            + generator.classRef(type.getDescriptor()) + ");");
                    break;
                case Type.BOOLEAN:
                case Type.BYTE:
                case Type.CHAR:
                case Type.SHORT:
                case Type.INT:
                case Type.LONG:
                case Type.FLOAT:
                case Type.DOUBLE:
                    line("jclass " + clazz + " = umbra_prim_class(env, '" + type.getDescriptor() + "');");
                    break;
                default:
                    throw new UnsupportedException("unsupported class constant " + type);
            }
            line("if (" + clazz + " == NULL) " + branch);
            pushRef(clazz);
            return;
        }
        throw new UnsupportedException("unsupported constant " + constant);
    }

    private void emitFieldInsn(FieldInsnNode insn, int index) throws UnsupportedException {
        boolean isStatic = insn.getOpcode() == GETSTATIC || insn.getOpcode() == PUTSTATIC;
        boolean isLoad = insn.getOpcode() == GETSTATIC || insn.getOpcode() == GETFIELD;
        int classIndex = generator.classRef(insn.owner);
        int id = generator.newIdSite();
        String branch = exceptionBranch(index);
        String kind = jniTypeName(insn.desc);
        String getPrefix = isStatic ? "GetStatic" : "Get";
        String setPrefix = isStatic ? "SetStatic" : "Set";
        if (isLoad) {
            if (!isStatic) {
                String object = popRef();
                line("{");
                emitFieldResolution(id, classIndex, false, insn, branch);
                String value = "_f" + tempCounter++;
                line("    " + cType(insn.desc) + " " + value + " = (*env)->" + getPrefix + kind
                        + "Field(env, " + object + ", umbra_ids[" + id + "].fid);");
                line("    if ((*env)->ExceptionCheck(env)) " + branch);
                pushFromDescriptor(insn.desc, value);
                line("}");
            } else {
                line("{");
                emitFieldResolution(id, classIndex, true, insn, branch);
                line("    jclass _c = umbra_class(env, " + classIndex + ");");
                line("    if (_c == NULL) " + branch);
                String value = "_f" + tempCounter++;
                line("    " + cType(insn.desc) + " " + value + " = (*env)->" + getPrefix + kind
                        + "Field(env, _c, umbra_ids[" + id + "].fid);");
                line("    if ((*env)->ExceptionCheck(env)) " + branch);
                pushFromDescriptor(insn.desc, value);
                line("}");
            }
        } else {
            String value = popByDescriptor(insn.desc);
            String object = isStatic ? null : popRef();
            line("{");
            emitFieldResolution(id, classIndex, isStatic, insn, branch);
            if (isStatic) {
                line("    jclass _c = umbra_class(env, " + classIndex + ");");
                line("    if (_c == NULL) " + branch);
                line("    (*env)->" + setPrefix + kind + "Field(env, _c, umbra_ids[" + id
                        + "].fid, (" + cType(insn.desc) + ")" + value + ");");
            } else {
                line("    (*env)->" + setPrefix + kind + "Field(env, " + object + ", umbra_ids[" + id
                        + "].fid, (" + cType(insn.desc) + ")" + value + ");");
            }
            line("    if ((*env)->ExceptionCheck(env)) " + branch);
            line("}");
        }
    }

    private void emitFieldResolution(int id, int classIndex, boolean isStatic,
                                     FieldInsnNode insn, String branch) {
        line("    if (!umbra_ids[" + id + "].ready) {");
        line("        jclass _c = umbra_class(env, " + classIndex + ");");
        line("        char _n[UMBRA_LIT_MAX];");
        line("        char _d[UMBRA_LIT_MAX];");
        line("        if (_c == NULL) " + branch);
        line("        umbra_lit_copy(" + generator.literalRef(insn.name) + ", _n);");
        line("        umbra_lit_copy(" + generator.literalRef(insn.desc) + ", _d);");
        line("        umbra_ids[" + id + "].fid = (*env)->Get"
                + (isStatic ? "Static" : "") + "FieldID(env, _c, _n, _d);");
        line("        if (umbra_ids[" + id + "].fid == NULL) " + branch);
        line("        umbra_ids[" + id + "].ready = 1;");
        line("    }");
    }

    private void emitMethodInsn(MethodInsnNode insn, int index) throws UnsupportedException {
        if (insn.getOpcode() == INVOKESPECIAL && insn.itf) {
            throw new UnsupportedException("invokespecial on an interface is not supported");
        }
        int opcode = insn.getOpcode();
        boolean isStatic = opcode == INVOKESTATIC;
        int classIndex = generator.classRef(insn.owner);
        int id = generator.newIdSite();
        String branch = exceptionBranch(index);
        List<String> args = JniNames.argumentTypes(insn.desc);
        String returnType = JniNames.returnType(insn.desc);
        String suffix = jniTypeName(returnType);
        line("    if (!umbra_ids[" + id + "].ready) {");
        line("        jclass _c = umbra_class(env, " + classIndex + ");");
        line("        char _n[UMBRA_LIT_MAX];");
        line("        char _d[UMBRA_LIT_MAX];");
        line("        if (_c == NULL) " + branch);
        line("        umbra_lit_copy(" + generator.literalRef(insn.name) + ", _n);");
        line("        umbra_lit_copy(" + generator.literalRef(insn.desc) + ", _d);");
        line("        umbra_ids[" + id + "].mid = (*env)->Get"
                + (isStatic ? "Static" : "") + "MethodID(env, _c, _n, _d);");
        line("        if (umbra_ids[" + id + "].mid == NULL) " + branch);
        line("        umbra_ids[" + id + "].ready = 1;");
        line("    }");
        line("{");
        if (!args.isEmpty()) {
            line("    jvalue _args[" + args.size() + "];");
            for (int i = args.size() - 1; i >= 0; i--) {
                String type = args.get(i);
                String value = popByDescriptor(type);
                line("    _args[" + i + "]." + jvalueMember(type) + " = (" + cType(type) + ")" + value + ";");
            }
        }
        String arguments = args.isEmpty() ? "NULL" : "_args";
        String receiver = null;
        if (!isStatic) {
            receiver = popRef();
        }
        String call;
        if (isStatic) {
            call = "(*env)->CallStatic" + suffix + "MethodA(env, umbra_class(env, " + classIndex
                    + "), umbra_ids[" + id + "].mid, " + arguments + ")";
        } else if (opcode == INVOKESPECIAL) {
            call = "(*env)->CallNonvirtual" + suffix + "MethodA(env, " + receiver
                    + ", umbra_class(env, " + classIndex + "), umbra_ids[" + id + "].mid, "
                    + arguments + ")";
        } else {
            call = "(*env)->Call" + suffix + "MethodA(env, " + receiver
                    + ", umbra_ids[" + id + "].mid, " + arguments + ")";
        }
        if ("V".equals(returnType)) {
            line("    " + call + ";");
            line("    if ((*env)->ExceptionCheck(env)) " + branch);
        } else {
            String value = "_r" + tempCounter++;
            line("    " + cType(returnType) + " " + value + " = " + call + ";");
            line("    if ((*env)->ExceptionCheck(env)) " + branch);
            pushFromDescriptor(returnType, value);
        }
        line("}");
    }

    private void emitJumpInsn(JumpInsnNode insn) throws UnsupportedException {
        int target = labelOf(insn.label);
        switch (insn.getOpcode()) {
            case GOTO:
                line("goto L" + target + ";");
                return;
            case IFEQ:
                line("if (" + popInt() + " == 0) goto L" + target + ";");
                return;
            case IFNE:
                line("if (" + popInt() + " != 0) goto L" + target + ";");
                return;
            case IFLT:
                line("if (" + popInt() + " < 0) goto L" + target + ";");
                return;
            case IFGE:
                line("if (" + popInt() + " >= 0) goto L" + target + ";");
                return;
            case IFGT:
                line("if (" + popInt() + " > 0) goto L" + target + ";");
                return;
            case IFLE:
                line("if (" + popInt() + " <= 0) goto L" + target + ";");
                return;
            case IF_ICMPEQ:
            case IF_ICMPNE:
            case IF_ICMPLT:
            case IF_ICMPGE:
            case IF_ICMPGT:
            case IF_ICMPLE:
                emitIntCompareJump(insn.getOpcode(), target);
                return;
            case IF_ACMPEQ:
                emitRefCompareJump("==", target);
                return;
            case IF_ACMPNE:
                emitRefCompareJump("!=", target);
                return;
            case IFNULL:
                line("if (" + popRef() + " == NULL) goto L" + target + ";");
                return;
            case IFNONNULL:
                line("if (" + popRef() + " != NULL) goto L" + target + ";");
                return;
            default:
                throw new UnsupportedException("unsupported jump " + insn.getOpcode());
        }
    }

    private void emitIntCompareJump(int opcode, int target) {
        String b = popInt();
        String a = popInt();
        String condition;
        switch (opcode) {
            case IF_ICMPEQ:
                condition = a + " == " + b;
                break;
            case IF_ICMPNE:
                condition = a + " != " + b;
                break;
            case IF_ICMPLT:
                condition = a + " < " + b;
                break;
            case IF_ICMPGE:
                condition = a + " >= " + b;
                break;
            case IF_ICMPGT:
                condition = a + " > " + b;
                break;
            default:
                condition = a + " <= " + b;
                break;
        }
        line("if (" + condition + ") goto L" + target + ";");
    }

    private void emitRefCompareJump(String operator, int target) {
        String b = popRef();
        String a = popRef();
        line("if ((*env)->IsSameObject(env, " + a + ", " + b + ") " + operator + " JNI_TRUE) goto L"
                + target + ";");
    }

    private void emitTableSwitch(TableSwitchInsnNode insn) throws UnsupportedException {
        String value = popInt();
        int target = labelOf(insn.dflt);
        line("switch (" + value + ") {");
        int key = insn.min;
        for (LabelNode label : insn.labels) {
            line("    case " + key + ": goto L" + labelOf(label) + ";");
            key++;
        }
        line("    default: goto L" + target + ";");
        line("}");
    }

    private void emitLookupSwitch(LookupSwitchInsnNode insn) throws UnsupportedException {
        String value = popInt();
        line("switch (" + value + ") {");
        for (int i = 0; i < insn.keys.size(); i++) {
            line("    case " + insn.keys.get(i).intValue() + ": goto L"
                    + labelOf(insn.labels.get(i)) + ";");
        }
        line("    default: goto L" + labelOf(insn.dflt) + ";");
        line("}");
    }

    private void emitMultiArray(MultiANewArrayInsnNode insn, int index) throws UnsupportedException {
        String descriptor = insn.desc;
        int dims = insn.dims;
        if (dims <= 0) {
            throw new UnsupportedException("bad multianewarray dimensions");
        }
        String branch = exceptionBranch(index);
        for (int k = dims - 1; k >= 0; k--) {
            String value = popInt();
            line("int _dim" + k + " = " + value + ";");
        }
        line("{");
        line("    jint _dims[" + dims + "];");
        for (int k = 0; k < dims; k++) {
            line("    _dims[" + k + "] = _dim" + k + ";");
        }
        line("    jclass _comps[" + dims + "];");
        for (int k = 0; k < dims; k++) {
            String component;
            try {
                component = descriptor.substring(k + 1);
            } catch (IndexOutOfBoundsException e) {
                throw new UnsupportedException("bad multianewarray descriptor " + descriptor);
            }
            char first = component.charAt(0);
            if (first == '[') {
                line("    _comps[" + k + "] = umbra_class(env, "
                        + generator.classRef(component) + ");");
            } else if (first == 'L') {
                line("    _comps[" + k + "] = umbra_class(env, "
                        + generator.classRef(component.substring(1, component.length() - 1)) + ");");
            } else {
                line("    _comps[" + k + "] = umbra_prim_class(env, '" + first + "');");
            }
            line("    if (_comps[" + k + "] == NULL) " + branch);
        }
        String array = "_m" + tempCounter++;
        line("    jobject " + array + " = umbra_multi(env, _comps, _dims, " + dims + ", 0);");
        line("    if (" + array + " == NULL) " + branch);
        line("    st[sp].l = " + array + "; sp += 1;");
        line("}");
    }

    private void emitArrayLoad(int opcode, int index) throws UnsupportedException {
        String position = popInt();
        String array = popRef();
        String branch = exceptionBranch(index);
        String value = "_e" + tempCounter++;
        switch (opcode) {
            case IALOAD:
                line("jint " + value + " = 0;");
                line("(*env)->GetIntArrayRegion(env, (jintArray)" + array + ", " + position
                        + ", 1, &" + value + ");");
                line("if ((*env)->ExceptionCheck(env)) " + branch);
                pushInt(value);
                return;
            case LALOAD:
                line("jlong " + value + " = 0;");
                line("(*env)->GetLongArrayRegion(env, (jlongArray)" + array + ", " + position
                        + ", 1, &" + value + ");");
                line("if ((*env)->ExceptionCheck(env)) " + branch);
                pushLong(value);
                return;
            case FALOAD:
                line("jfloat " + value + " = 0;");
                line("(*env)->GetFloatArrayRegion(env, (jfloatArray)" + array + ", " + position
                        + ", 1, &" + value + ");");
                line("if ((*env)->ExceptionCheck(env)) " + branch);
                pushFloat(value);
                return;
            case DALOAD:
                line("jdouble " + value + " = 0;");
                line("(*env)->GetDoubleArrayRegion(env, (jdoubleArray)" + array + ", " + position
                        + ", 1, &" + value + ");");
                line("if ((*env)->ExceptionCheck(env)) " + branch);
                pushDouble(value);
                return;
            case AALOAD:
                line("jobject " + value + " = (*env)->GetObjectArrayElement(env, (jobjectArray)"
                        + array + ", " + position + ");");
                line("if ((*env)->ExceptionCheck(env)) " + branch);
                pushRef(value);
                return;
            case BALOAD:
                line("jbyte " + value + " = 0;");
                line("(*env)->GetByteArrayRegion(env, (jbyteArray)" + array + ", " + position
                        + ", 1, &" + value + ");");
                line("if ((*env)->ExceptionCheck(env)) " + branch);
                pushInt("(jint)" + value);
                return;
            case CALOAD:
                line("jchar " + value + " = 0;");
                line("(*env)->GetCharArrayRegion(env, (jcharArray)" + array + ", " + position
                        + ", 1, &" + value + ");");
                line("if ((*env)->ExceptionCheck(env)) " + branch);
                pushInt("(jint)" + value);
                return;
            case SALOAD:
                line("jshort " + value + " = 0;");
                line("(*env)->GetShortArrayRegion(env, (jshortArray)" + array + ", " + position
                        + ", 1, &" + value + ");");
                line("if ((*env)->ExceptionCheck(env)) " + branch);
                pushInt("(jint)" + value);
                return;
            default:
                throw new UnsupportedException("unsupported array load " + opcode);
        }
    }

    private void emitArrayStore(int opcode, int index) throws UnsupportedException {
        String value = popStackValue(opcode);
        String position = popInt();
        String array = popRef();
        String branch = exceptionBranch(index);
        switch (opcode) {
            case IASTORE:
                line("(*env)->SetIntArrayRegion(env, (jintArray)" + array + ", " + position
                        + ", 1, &" + value + ");");
                break;
            case LASTORE:
                line("(*env)->SetLongArrayRegion(env, (jlongArray)" + array + ", " + position
                        + ", 1, &" + value + ");");
                break;
            case FASTORE:
                line("(*env)->SetFloatArrayRegion(env, (jfloatArray)" + array + ", " + position
                        + ", 1, &" + value + ");");
                break;
            case DASTORE:
                line("(*env)->SetDoubleArrayRegion(env, (jdoubleArray)" + array + ", " + position
                        + ", 1, &" + value + ");");
                break;
            case AASTORE:
                line("(*env)->SetObjectArrayElement(env, (jobjectArray)" + array + ", "
                        + position + ", " + value + ");");
                break;
            case BASTORE:
                line("jbyte _b = (jbyte)" + value + ";");
                line("(*env)->SetByteArrayRegion(env, (jbyteArray)" + array + ", " + position
                        + ", 1, &_b);");
                break;
            case CASTORE:
                line("jchar _c2 = (jchar)" + value + ";");
                line("(*env)->SetCharArrayRegion(env, (jcharArray)" + array + ", " + position
                        + ", 1, &_c2);");
                break;
            case SASTORE:
                line("jshort _s = (jshort)" + value + ";");
                line("(*env)->SetShortArrayRegion(env, (jshortArray)" + array + ", " + position
                        + ", 1, &_s);");
                break;
            default:
                throw new UnsupportedException("unsupported array store " + opcode);
        }
        line("if ((*env)->ExceptionCheck(env)) " + branch);
    }

    /** Pops one operand stack value of the kind required by an array store opcode. */
    private String popStackValue(int opcode) throws UnsupportedException {
        switch (opcode) {
            case IASTORE:
            case BASTORE:
            case CASTORE:
            case SASTORE:
                return popInt();
            case LASTORE:
                return popLong();
            case FASTORE:
                return popFloat();
            case DASTORE:
                return popDouble();
            case AASTORE:
                return popRef();
            default:
                throw new UnsupportedException("unsupported array store " + opcode);
        }
    }

    private void emitArrayLength(int index) {
        String array = popRef();
        line("jint _len = (*env)->GetArrayLength(env, (jarray)" + array + ");");
        line("if ((*env)->ExceptionCheck(env)) " + exceptionBranch(index));
        pushInt("_len");
    }

    private void emitThrow(int index) {
        String object = popRef();
        line("if (" + object + " == NULL) {");
        line("    (*env)->ThrowNew(env, umbra_class(env, UMBRA_C_NPE), \"null\");");
        line("} else {");
        line("    (*env)->Throw(env, " + object + ");");
        line("}");
        String branch = exceptionBranch(index);
        line(branch);
    }

    private void emitReturn(int opcode) throws UnsupportedException {
        switch (opcode) {
            case RETURN:
                line("return;");
                return;
            case IRETURN:
                line("return (" + cReturn + ")st[sp - 1].i;");
                return;
            case LRETURN:
                line("return (" + cReturn + ")st[sp - 2].j;");
                return;
            case FRETURN:
                line("return (" + cReturn + ")st[sp - 1].f;");
                return;
            case DRETURN:
                line("return (" + cReturn + ")st[sp - 2].d;");
                return;
            case ARETURN:
                line("return (" + cReturn + ")st[sp - 1].l;");
                return;
            default:
                throw new UnsupportedException("unsupported return " + opcode);
        }
    }

    private void emitCompare(String helper, boolean wide) {
        if (wide) {
            String b = popLong();
            String a = popLong();
            pushInt(helper + "(" + a + ", " + b + ")");
        } else {
            boolean single = helper.startsWith("umbra_f");
            String b = single ? popFloat() : popDouble();
            String a = single ? popFloat() : popDouble();
            pushInt(helper + "(" + a + ", " + b + ")");
        }
    }

    // ------------------------------------------------------------------
    // Arithmetic helpers
    // ------------------------------------------------------------------

    private void binInt(String operator) {
        String b = popInt();
        String a = popInt();
        pushInt("(jint)((umbra_u32)(" + a + ") " + operator + " (umbra_u32)(" + b + "))");
    }

    private void binDiv(boolean divide, int index) {
        String b = popInt();
        String a = popInt();
        String helper = divide ? "umbra_idiv" : "umbra_irem";
        pushInt(helper + "(env, " + a + ", " + b + ")");
        line("if ((*env)->ExceptionCheck(env)) " + exceptionBranch(index));
    }

    private void binLongDiv(boolean divide, int index) {
        String b = popLong();
        String a = popLong();
        String helper = divide ? "umbra_ldiv" : "umbra_lrem";
        pushLong(helper + "(env, " + a + ", " + b + ")");
        line("if ((*env)->ExceptionCheck(env)) " + exceptionBranch(index));
    }

    private void binLong(String operator) {
        String b = popLong();
        String a = popLong();
        pushLong("(jlong)((umbra_u64)(" + a + ") " + operator + " (umbra_u64)(" + b + "))");
    }

    private void binShiftInt(String operator) {
        String b = popInt();
        String a = popInt();
        if ("<<".equals(operator)) {
            pushInt("(jint)((umbra_u32)(" + a + ") << (" + b + " & 31))");
        } else {
            pushInt("(jint)((" + a + ") " + operator + " (" + b + " & 31))");
        }
    }

    private void binShiftIntUnsigned() {
        String b = popInt();
        String a = popInt();
        pushInt("(jint)((umbra_u32)(" + a + ") >> (" + b + " & 31))");
    }

    private void binShiftLong(String operator) {
        String b = popInt();
        String a = popLong();
        if ("<<".equals(operator)) {
            pushLong("(jlong)((umbra_u64)(" + a + ") << (" + b + " & 63))");
        } else {
            pushLong("(jlong)((" + a + ") " + operator + " (" + b + " & 63))");
        }
    }

    private void binShiftLongUnsigned() {
        String b = popInt();
        String a = popLong();
        pushLong("(jlong)((umbra_u64)(" + a + ") >> (" + b + " & 63))");
    }

    private void binFloat(String operator) {
        String b = popFloat();
        String a = popFloat();
        pushFloat("(" + a + " " + operator + " " + b + ")");
    }

    private void binDouble(String operator) {
        String b = popDouble();
        String a = popDouble();
        pushDouble("(" + a + " " + operator + " " + b + ")");
    }

    private void unaryInt(String prefix) {
        pushInt("(jint)(" + prefix + "(" + popInt() + "))");
    }

    private void unaryLong(String prefix) {
        pushLong("(jlong)(" + prefix + "(" + popLong() + "))");
    }

    private void unaryFloat(String prefix) {
        pushFloat("(" + prefix + "(" + popFloat() + "))");
    }

    private void unaryDouble(String prefix) {
        pushDouble("(" + prefix + "(" + popDouble() + "))");
    }

    // ------------------------------------------------------------------
    // Stack / exception plumbing
    // ------------------------------------------------------------------

    private void line(String text) {
        out.append("        ").append(text).append('\n');
    }

    private String exceptionBranch(int index) {
        Integer setId = dispatchFor(index);
        if (setId == null) {
            return CGenerator.defaultReturn(cReturn);
        }
        return "goto UMBRA_EXC_" + setId.intValue() + ";";
    }

    private Integer dispatchFor(int index) {
        Integer key = Integer.valueOf(index);
        if (dispatchByInstruction.containsKey(key)) {
            return dispatchByInstruction.get(key);
        }
        List<HandlerEntry> entries = new ArrayList<HandlerEntry>();
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode block : method.tryCatchBlocks) {
                Integer start = labelIndices.get(block.start);
                Integer end = labelIndices.get(block.end);
                Integer handler = labelIndices.get(block.handler);
                if (start == null || end == null || handler == null) {
                    continue;
                }
                if (index < start.intValue() || index >= end.intValue()) {
                    continue;
                }
                HandlerEntry entry = new HandlerEntry();
                entry.handlerIndex = handler.intValue();
                entry.catchType = block.type;
                entries.add(entry);
            }
        }
        // Drop duplicate handler/type pairs while keeping the original order.
        Set<String> seen = new LinkedHashSet<String>();
        List<HandlerEntry> unique = new ArrayList<HandlerEntry>();
        for (HandlerEntry entry : entries) {
            String keyText = entry.handlerIndex + ":" + entry.catchType;
            if (seen.add(keyText)) {
                unique.add(entry);
            }
        }
        if (unique.isEmpty()) {
            dispatchByInstruction.put(key, null);
            return null;
        }
        StringBuilder keyText = new StringBuilder();
        for (HandlerEntry entry : unique) {
            keyText.append(entry.handlerIndex).append(':').append(entry.catchType).append(';');
        }
        Integer existing = dispatchKeys.get(keyText.toString());
        int setId;
        if (existing != null) {
            setId = existing.intValue();
        } else {
            setId = dispatchSets.size();
            ExcSet set = new ExcSet();
            set.id = setId;
            set.entries = unique;
            for (HandlerEntry entry : unique) {
                if (entry.catchType != null) {
                    entry.classIndex = Integer.valueOf(generator.classRef(entry.catchType));
                }
                targetLabels.add(Integer.valueOf(entry.handlerIndex));
                handlerStarts.add(Integer.valueOf(entry.handlerIndex));
            }
            dispatchSets.put(Integer.valueOf(setId), set);
            dispatchKeys.put(keyText.toString(), Integer.valueOf(setId));
        }
        dispatchByInstruction.put(key, Integer.valueOf(setId));
        return Integer.valueOf(setId);
    }

    private int labelOf(LabelNode label) throws UnsupportedException {
        Integer index = labelIndices.get(label);
        if (index == null) {
            throw new UnsupportedException("unmapped label");
        }
        return index.intValue();
    }

    private void pushInt(String expression) {
        out.append("        st[sp].i = (jint)(").append(expression).append("); sp += 1;\n");
    }

    private void pushLong(String expression) {
        out.append("        st[sp].j = (jlong)(").append(expression).append("); sp += 2;\n");
    }

    private void pushFloat(String expression) {
        out.append("        st[sp].f = (jfloat)(").append(expression).append("); sp += 1;\n");
    }

    private void pushDouble(String expression) {
        out.append("        st[sp].d = (jdouble)(").append(expression).append("); sp += 2;\n");
    }

    private void pushRef(String expression) {
        out.append("        st[sp].l = (jobject)(").append(expression).append("); sp += 1;\n");
    }

    private String popInt() {
        String name = "_t" + tempCounter++;
        line("jint " + name + " = st[sp - 1].i; sp -= 1;");
        return name;
    }

    private String popLong() {
        String name = "_t" + tempCounter++;
        line("jlong " + name + " = st[sp - 2].j; sp -= 2;");
        return name;
    }

    private String popFloat() {
        String name = "_t" + tempCounter++;
        line("jfloat " + name + " = st[sp - 1].f; sp -= 1;");
        return name;
    }

    private String popDouble() {
        String name = "_t" + tempCounter++;
        line("jdouble " + name + " = st[sp - 2].d; sp -= 2;");
        return name;
    }

    private String popRef() {
        String name = "_t" + tempCounter++;
        line("jobject " + name + " = st[sp - 1].l; sp -= 1;");
        return name;
    }

    /** Pops a value of the given descriptor type (returns the C variable name). */
    private String popByDescriptor(String descriptor) throws UnsupportedException {
        switch (descriptor.charAt(0)) {
            case 'Z':
            case 'B':
            case 'C':
            case 'S':
            case 'I':
                return popInt();
            case 'J':
                return popLong();
            case 'F':
                return popFloat();
            case 'D':
                return popDouble();
            case 'L':
            case '[':
                return popRef();
            default:
                throw new UnsupportedException("bad type descriptor " + descriptor);
        }
    }

    private void pushFromDescriptor(String descriptor, String value) throws UnsupportedException {
        switch (descriptor.charAt(0)) {
            case 'Z':
            case 'B':
            case 'C':
            case 'S':
            case 'I':
                pushInt("(jint)(" + value + ")");
                return;
            case 'J':
                pushLong("(jlong)(" + value + ")");
                return;
            case 'F':
                pushFloat("(jfloat)(" + value + ")");
                return;
            case 'D':
                pushDouble("(jdouble)(" + value + ")");
                return;
            case 'L':
            case '[':
                pushRef(value);
                return;
            default:
                throw new UnsupportedException("bad type descriptor " + descriptor);
        }
    }

    // ------------------------------------------------------------------
    // Type mapping
    // ------------------------------------------------------------------

    static String cType(String descriptor) throws UnsupportedException {
        if (descriptor == null || descriptor.isEmpty()) {
            throw new UnsupportedException("empty type descriptor");
        }
        switch (descriptor.charAt(0)) {
            case 'V':
                return "void";
            case 'Z':
                return "jboolean";
            case 'B':
                return "jbyte";
            case 'C':
                return "jchar";
            case 'S':
                return "jshort";
            case 'I':
                return "jint";
            case 'J':
                return "jlong";
            case 'F':
                return "jfloat";
            case 'D':
                return "jdouble";
            case 'L':
            case '[':
                return "jobject";
            default:
                throw new UnsupportedException("bad type descriptor " + descriptor);
        }
    }

    static String jniTypeName(String descriptor) throws UnsupportedException {
        if (descriptor == null || descriptor.isEmpty()) {
            throw new UnsupportedException("empty type descriptor");
        }
        switch (descriptor.charAt(0)) {
            case 'V':
                return "Void";
            case 'Z':
                return "Boolean";
            case 'B':
                return "Byte";
            case 'C':
                return "Char";
            case 'S':
                return "Short";
            case 'I':
                return "Int";
            case 'J':
                return "Long";
            case 'F':
                return "Float";
            case 'D':
                return "Double";
            case 'L':
            case '[':
                return "Object";
            default:
                throw new UnsupportedException("bad type descriptor " + descriptor);
        }
    }

    private static String jvalueMember(String descriptor) throws UnsupportedException {
        switch (descriptor.charAt(0)) {
            case 'Z':
                return "z";
            case 'B':
                return "b";
            case 'C':
                return "c";
            case 'S':
                return "s";
            case 'I':
                return "i";
            case 'J':
                return "j";
            case 'F':
                return "f";
            case 'D':
                return "d";
            case 'L':
            case '[':
                return "l";
            default:
                throw new UnsupportedException("bad type descriptor " + descriptor);
        }
    }

    private static String slotMember(String descriptor) throws UnsupportedException {
        switch (descriptor.charAt(0)) {
            case 'Z':
            case 'B':
            case 'C':
            case 'S':
            case 'I':
                return "i";
            case 'J':
                return "j";
            case 'F':
                return "f";
            case 'D':
                return "d";
            case 'L':
            case '[':
                return "l";
            default:
                throw new UnsupportedException("bad type descriptor " + descriptor);
        }
    }

    private static final class HandlerEntry {
        int handlerIndex;
        Integer classIndex;
        String catchType;
    }

    private static final class ExcSet {
        int id;
        List<HandlerEntry> entries;
    }
}
