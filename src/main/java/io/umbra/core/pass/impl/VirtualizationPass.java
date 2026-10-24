package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.runtime.TemplateInjector;
import io.umbra.core.runtime.UmbraCantrip;
import io.umbra.core.runtime.vm2.UmbraVM2;
import io.umbra.core.runtime.vm2.Vm2Format;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.Cipher;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
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
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Method virtualization.
 *
 * <p>Two engines share this pass and are selected per run:</p>
 *
 * <ul>
 *   <li><b>classic</b> ({@code vm2.enabled=false}, default): the original safe
 *       subset. Method bodies are translated into a reduced instruction stream
 *       executed by {@code UmbraVM}; constructors, exception handlers,
 *       {@code NEW}, monitors and {@code invokedynamic} are rejected and the
 *       payload is stored as plain (optionally XOR-shielded) int arrays.</li>
 *   <li><b>VM2</b> ({@code vm2.enabled=true}): the hardened engine. It accepts
 *       try/catch tables (translated into an interpreter-side handler table),
 *       multi-dimensional arrays, interface/virtual/static calls and field
 *       access; skips constructors, monitors, jsr/ret and invokedynamic.
 *       Payloads are serialized into an encrypted, integrity-checked,
 *       optionally nested two-stage stream split across synthetic holder
 *       classes, with per-program opcode permutation and position-masked
 *       operands. The decoder and stack machine live in
 *       {@code UmbraVM2}.</li>
 * </ul>
 *
 * <p>Both engines are deterministic for a given seed (all randomness comes from
 * {@code ctx.random()}), never abort a run for one exotic method, and honour
 * generated/frozen classes and keep rules.</p>
 */
public final class VirtualizationPass implements Pass {

    private static final String ANNOTATION = "Lio/umbra/annotations/MethodVirtualization;";
    private static final int MAX_LOCALS = 4096;
    private static final int MAX_PAYLOAD_SLOTS = 4000;
    /** Prefix of synthetic invokedynamic bridges created per owner class. */
    private static final String INDY_BRIDGE_PREFIX = "umbra$i";
    /** Prefix of synthetic constructor-body helpers created per owner class. */
    private static final String CONSTRUCTOR_BODY_PREFIX = "umbra$c";
    private static final String VM_DESC =
            "([I[Ljava/lang/Object;[Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;";
    private static final String VM2_DESC =
            "([I[I[[I[Ljava/lang/Object;)Ljava/lang/Object;";

    private String decryptor;
    private String virtualMachine;
    private String vm2Engine;
    private Vm2Chunk vm2MapHolder;
    private boolean cantripEnabled;
    private int cantripLevel;
    private String cantripInterpreter;
    private int cantripPrograms;
    private long cantripValues;
    private long cantripChunks;

    @Override
    public String name() {
        return "method-virtualization";
    }

    @Override
    public int order() {
        // Runs after every pass that rewrites member descriptors or call sites
        // (reference obfuscation at 65, type confusion at 67): a payload keeps
        // reflective field/method references, so the names and descriptors it
        // stores must be final before a method is translated. Type confusion
        // re-types non-final fields to Object; translating first would leave the
        // payload looking for the pre-retyping descriptor and the interpreter
        // could not resolve the field at runtime. Native code generation (105)
        // and Nocturne (106) still run after this pass.
        return 68;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().methodVirtualization().enabled();
    }

    @Override
    public void run(PassContext context) {
        cantripEnabled = false;
        cantripLevel = 1;
        cantripInterpreter = null;
        cantripPrograms = 0;
        cantripValues = 0L;
        cantripChunks = 0L;
        boolean cantripRequested = context.config().optionBool("cantrip.enabled", false);
        if (cantripRequested) {
            if (!context.config().optionBool("vm2.enabled", false)) {
                context.log().warn("cantrip: requires vm2.enabled=true; ignoring");
            } else {
                cantripEnabled = true;
                cantripLevel = Math.max(1, Math.min(2,
                        context.config().optionInt("cantrip.level", 1)));
                context.log().info("cantrip: enabled (level %d) - VM2 payload chunks are "
                        + "reconstructed by a Cantrip dialect interpreter",
                        Integer.valueOf(cantripLevel));
            }
        }
        if (context.config().optionBool("vm2.enabled", false)) {
            runVm2(context);
        } else {
            runClassic(context);
        }
        if (cantripEnabled) {
            context.stats().add("cantrip.programs", cantripPrograms);
            context.stats().add("cantrip.chunks", (int) cantripChunks);
            context.stats().add("cantrip.values", (int) Math.min(Integer.MAX_VALUE, cantripValues));
            context.stats().add("cantrip.level", cantripLevel);
            context.log().info("cantrip: %d values reconstructed from %d chunks "
                    + "by %d Cantrip dialect programs",
                    Long.valueOf(cantripValues), Long.valueOf(cantripChunks),
                    Integer.valueOf(cantripPrograms));
        }
    }

    /** The original, deliberately conservative engine. */
    private void runClassic(PassContext context) {
        int maxInstructions = context.config().methodVirtualization().maxInstructions();
        int maxMethods = context.config().methodVirtualization().maxMethods();
        int methods = 0;
        int instructions = 0;
        int skipped = 0;

        List<ClassNode> snapshot = new ArrayList<ClassNode>(context.classes().classes().values());
        for (ClassNode node : snapshot) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
                if (context.rules().skipBodyTransform(node.name)) {
                    continue;
                }
            if ("module-info".equals(node.name)) {
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) {
                // Interfaces have unusual invocation shapes (default/super calls);
                // keep them out of the safe subset.
                continue;
            }
            if (!context.rules().transformClass(node)) {
                continue;
            }
            Boolean classEnabled = AsmUtil.annotationBoolean(node.invisibleAnnotations, ANNOTATION, "enabled");
            if (classEnabled == null) {
                classEnabled = AsmUtil.annotationBoolean(node.visibleAnnotations, ANNOTATION, "enabled");
            }
            if (Boolean.FALSE.equals(classEnabled)) {
                continue;
            }

            int perClass = 0;
            for (MethodNode method : node.methods) {
                if (maxMethods > 0 && perClass >= maxMethods) {
                    break;
                }
                if (!eligible(context, node, method, maxInstructions)) {
                    continue;
                }
                try {
                    Payload payload = translate(node, method);
                    if (payload == null) {
                        skipped++;
                        continue;
                    }
                    if (payload.slots() > MAX_PAYLOAD_SLOTS) {
                        skipped++;
                        context.log().debug("virtualization skipped %s.%s: payload too large",
                                node.name, method.name);
                        continue;
                    }
                    if (virtualMachine == null) {
                        virtualMachine = context.runtime().ensureVirtualMachine(
                                context.classes(), context.config().seed());
                    }
                    Holder holder = createHolder(context, payload);
                    rewrite(node, method, payload, holder);
                    methods++;
                    perClass++;
                    instructions += payload.code.size();
                } catch (SkipMethod e) {
                    skipped++;
                    context.log().debug("virtualization skipped %s.%s: %s",
                            node.name, method.name, e.getMessage());
                } catch (RuntimeException e) {
                    skipped++;
                    context.log().debug("virtualization failed %s.%s: %s",
                            node.name, method.name, e.getMessage());
                }
            }
        }

        context.stats().add("virtualization.methods", methods);
        context.stats().add("virtualization.instructions", instructions);
        context.stats().add("virtualization.skipped", skipped);
        context.log().info("method-virtualization: virtualized %d methods (%d instructions), %d skipped",
                methods, instructions, skipped);
    }

    private static boolean eligible(PassContext context, ClassNode owner, MethodNode method, int max) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        if (method.tryCatchBlocks != null && !method.tryCatchBlocks.isEmpty()) {
            return false;
        }
        if (method.instructions == null || method.instructions.size() < 3
                || method.instructions.size() > max) {
            return false;
        }
        if (method.maxLocals > MAX_LOCALS) {
            return false;
        }
        Boolean methodEnabled = AsmUtil.annotationBoolean(method.invisibleAnnotations, ANNOTATION, "enabled");
        if (methodEnabled == null) {
            methodEnabled = AsmUtil.annotationBoolean(method.visibleAnnotations, ANNOTATION, "enabled");
        }
        if (Boolean.FALSE.equals(methodEnabled)) {
            return false;
        }
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode < 0) {
                continue;
            }
            if (insn instanceof InvokeDynamicInsnNode) {
                return false;
            }
            if (opcode == Opcodes.NEW || opcode == Opcodes.JSR || opcode == Opcodes.RET
                    || opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT) {
                return false;
            }
            if (insn instanceof LdcInsnNode) {
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof Handle || constant instanceof ConstantDynamic) {
                    return false;
                }
            }
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;
                if (call.getOpcode() == Opcodes.INVOKESPECIAL
                        && !"<init>".equals(call.name)
                        && !owner.name.equals(call.owner)) {
                    // super.foo() would dispatch to the override through reflection.
                    return false;
                }
                // Reflection inside interpreted code sees the interpreter as its
                // caller, so caller-sensitive APIs must keep the real bytecode.
                if (isCallerSensitive(call.owner, call.name)) {
                    return false;
                }
            }
        }
        return true;
    }

    private Payload translate(ClassNode owner, MethodNode method) {
        Map<LabelNode, Integer> labels = new IdentityHashMap<LabelNode, Integer>();
        int pc = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode) {
                labels.put((LabelNode) insn, Integer.valueOf(pc));
                continue;
            }
            int opcode = insn.getOpcode();
            if (opcode < 0) {
                continue;
            }
            pc += length(insn);
        }

        Payload payload = new Payload();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode < 0) {
                continue;
            }
            if (insn instanceof LdcInsnNode) {
                payload.code.add(Opcodes.LDC);
                payload.code.add(payload.constant(((LdcInsnNode) insn).cst));
            } else if (insn instanceof IntInsnNode) {
                IntInsnNode value = (IntInsnNode) insn;
                if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
                    payload.code.add(Opcodes.LDC);
                    payload.code.add(payload.constant(Integer.valueOf(value.operand)));
                } else if (opcode == Opcodes.NEWARRAY) {
                    payload.code.add(opcode);
                    payload.code.add(value.operand);
                } else {
                    throw new SkipMethod("unsupported integer instruction " + opcode);
                }
            } else if (insn instanceof VarInsnNode) {
                payload.code.add(opcode);
                payload.code.add(((VarInsnNode) insn).var);
            } else if (insn instanceof IincInsnNode) {
                IincInsnNode iinc = (IincInsnNode) insn;
                payload.code.add(Opcodes.IINC);
                payload.code.add(iinc.var);
                payload.code.add(iinc.incr);
            } else if (insn instanceof FieldInsnNode) {
                FieldInsnNode field = (FieldInsnNode) insn;
                payload.code.add(opcode);
                payload.code.add(payload.ref("F|" + field.owner + "|" + field.name + "|" + field.desc));
            } else if (insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;
                payload.code.add(opcode);
                payload.code.add(payload.ref("M|" + call.owner + "|" + call.name + "|" + call.desc));
            } else if (insn instanceof TypeInsnNode) {
                if (opcode == Opcodes.NEW) {
                    throw new SkipMethod("NEW");
                }
                payload.code.add(opcode);
                payload.code.add(payload.ref("T|" + ((TypeInsnNode) insn).desc));
            } else if (insn instanceof JumpInsnNode) {
                payload.code.add(opcode);
                payload.code.add(label(labels, ((JumpInsnNode) insn).label));
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode table = (TableSwitchInsnNode) insn;
                payload.code.add(Opcodes.TABLESWITCH);
                payload.code.add(label(labels, table.dflt));
                payload.code.add(table.min);
                payload.code.add(table.max);
                for (LabelNode target : table.labels) {
                    payload.code.add(label(labels, target));
                }
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode lookup = (LookupSwitchInsnNode) insn;
                payload.code.add(Opcodes.LOOKUPSWITCH);
                payload.code.add(label(labels, lookup.dflt));
                payload.code.add(lookup.keys.size());
                for (int i = 0; i < lookup.keys.size(); i++) {
                    payload.code.add(((Integer) lookup.keys.get(i)).intValue());
                    payload.code.add(label(labels, lookup.labels.get(i)));
                }
            } else if (insn instanceof MultiANewArrayInsnNode) {
                MultiANewArrayInsnNode multi = (MultiANewArrayInsnNode) insn;
                payload.code.add(Opcodes.MULTIANEWARRAY);
                payload.code.add(payload.ref("T|" + multi.desc));
                payload.code.add(multi.dims);
            } else if (insn instanceof InsnNode) {
                if (opcode == Opcodes.NEW || opcode == Opcodes.MONITORENTER
                        || opcode == Opcodes.MONITOREXIT) {
                    throw new SkipMethod("unsupported instruction " + opcode);
                }
                payload.code.add(opcode);
            } else {
                throw new SkipMethod("unsupported instruction " + insn.getClass().getSimpleName());
            }
        }
        payload.finish();
        return payload;
    }

    private static int length(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (insn instanceof TableSwitchInsnNode) {
            TableSwitchInsnNode table = (TableSwitchInsnNode) insn;
            return 4 + table.labels.size();
        }
        if (insn instanceof LookupSwitchInsnNode) {
            return 3 + 2 * ((LookupSwitchInsnNode) insn).labels.size();
        }
        if (insn instanceof MultiANewArrayInsnNode) {
            return 3;
        }
        if (insn instanceof IincInsnNode) {
            return 3;
        }
        if (insn instanceof LdcInsnNode || insn instanceof IntInsnNode
                || insn instanceof VarInsnNode || insn instanceof JumpInsnNode
                || insn instanceof FieldInsnNode || insn instanceof MethodInsnNode
                || insn instanceof TypeInsnNode) {
            return 2;
        }
        if (insn instanceof LabelNode) {
            return 0;
        }
        if (opcode < 0) {
            return 0;
        }
        return 1;
    }

    private static int label(Map<LabelNode, Integer> labels, LabelNode label) {
        Integer pc = labels.get(label);
        if (pc == null) {
            throw new SkipMethod("unresolved label");
        }
        return pc.intValue();
    }

    private Holder createHolder(PassContext context, Payload payload) {
        String name;
        do {
            name = "umbra/runtime/V" + Long.toHexString(context.random().nextLong());
        } while (context.classes().getClass(name) != null);

        NameGenerator names = new NameGenerator(context.random(), "");
        Holder holder = new Holder(name, names.random(5), names.random(5), names.random(5));
        Shield shield = null;
        if (context.config().antiLlm().enabled()
                && context.config().antiLlm().shieldVirtualization()) {
            shield = createShield(context);
        }

        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC;
        node.name = name;
        node.superName = "java/lang/Object";
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL
                | Opcodes.ACC_SYNTHETIC, holder.codeField, "[I", null, null));
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL
                | Opcodes.ACC_SYNTHETIC, holder.constantField, "[Ljava/lang/Object;", null, null));
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL
                | Opcodes.ACC_SYNTHETIC, holder.refField, "[Ljava/lang/String;", null, null));

        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList code = clinit.instructions;
        AsmUtil.pushInt(code, payload.code.size());
        code.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        code.add(new FieldInsnNode(Opcodes.PUTSTATIC, name, holder.codeField, "[I"));
        AsmUtil.pushInt(code, payload.constants.size());
        code.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        code.add(new FieldInsnNode(Opcodes.PUTSTATIC, name, holder.constantField, "[Ljava/lang/Object;"));
        AsmUtil.pushInt(code, payload.refs.length);
        code.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"));
        code.add(new FieldInsnNode(Opcodes.PUTSTATIC, name, holder.refField, "[Ljava/lang/String;"));

        for (int i = 0; i < payload.code.size(); i++) {
            code.add(new FieldInsnNode(Opcodes.GETSTATIC, name, holder.codeField, "[I"));
            AsmUtil.pushInt(code, i);
            int value = payload.code.get(i);
            if (shield != null) {
                value ^= shield.keys[i & (shield.keys.length - 1)];
            }
            AsmUtil.pushInt(code, value);
            code.add(new InsnNode(Opcodes.IASTORE));
        }
        for (int i = 0; i < payload.constants.size(); i++) {
            code.add(new FieldInsnNode(Opcodes.GETSTATIC, name, holder.constantField, "[Ljava/lang/Object;"));
            AsmUtil.pushInt(code, i);
            emitConstant(context, code, payload.constants.get(i));
            code.add(new InsnNode(Opcodes.AASTORE));
        }
        for (int i = 0; i < payload.refs.length; i++) {
            code.add(new FieldInsnNode(Opcodes.GETSTATIC, name, holder.refField, "[Ljava/lang/String;"));
            AsmUtil.pushInt(code, i);
            emitString(context, code, payload.refs[i]);
            code.add(new InsnNode(Opcodes.AASTORE));
        }
        if (shield != null) {
            emitDecryptLoop(code, name, holder.codeField, shield);
            clinit.maxLocals = Math.max(clinit.maxLocals, 1);
            context.stats().add("antiLlm.shieldedPayloads", 1);
        }
        code.add(new InsnNode(Opcodes.RETURN));
        // Deepest path: decrypt loop (array, index, array, index, key, mask) = 6.
        clinit.maxStack = 6;
        node.methods.add(clinit);

        context.classes().addGenerated(node);
        context.stats().add("virtualization.holders", 1);
        return holder;
    }

    /**
     * Generates a separate key-holder class. The payload holder stores the
     * code array XORed with this key and decrypts it in its own {@code <clinit>}.
     * A static analyzer must locate and execute both initializers instead of
     * reading a literal instruction array.
     */
    private Shield createShield(PassContext context) {
        String holderName;
        do {
            holderName = "umbra/runtime/K" + Long.toHexString(context.random().nextLong());
        } while (context.classes().getClass(holderName) != null);
        NameGenerator names = new NameGenerator(context.random(), "");
        String keyField = names.random(5);
        int length = 8;
        int seed = context.random().nextInt();
        int[] keys = new int[length];
        int state = seed;
        for (int i = 0; i < length; i++) {
            state = state * 1103515245 + 12345;
            keys[i] = state ^ (i * 0x9E3779B9);
        }

        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC;
        node.name = holderName;
        node.superName = "java/lang/Object";
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL
                | Opcodes.ACC_SYNTHETIC, keyField, "[I", null, null));

        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList code = clinit.instructions;
        AsmUtil.pushInt(code, length);
        code.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        code.add(new FieldInsnNode(Opcodes.PUTSTATIC, holderName, keyField, "[I"));
        AsmUtil.pushInt(code, seed);
        code.add(new VarInsnNode(Opcodes.ISTORE, 0));
        AsmUtil.pushInt(code, 0);
        code.add(new VarInsnNode(Opcodes.ISTORE, 1));
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        code.add(loop);
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        AsmUtil.pushInt(code, length);
        code.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        AsmUtil.pushInt(code, 1103515245);
        code.add(new InsnNode(Opcodes.IMUL));
        AsmUtil.pushInt(code, 12345);
        code.add(new InsnNode(Opcodes.IADD));
        code.add(new VarInsnNode(Opcodes.ISTORE, 0));
        code.add(new FieldInsnNode(Opcodes.GETSTATIC, holderName, keyField, "[I"));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        AsmUtil.pushInt(code, 0x9E3779B9);
        code.add(new InsnNode(Opcodes.IMUL));
        code.add(new InsnNode(Opcodes.IXOR));
        code.add(new InsnNode(Opcodes.IASTORE));
        code.add(new IincInsnNode(1, 1));
        code.add(new JumpInsnNode(Opcodes.GOTO, loop));
        code.add(end);
        code.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 2;
        // Stack: key array + loop index + state + index + constant = 5.
        clinit.maxStack = 5;
        node.methods.add(clinit);

        context.classes().addGenerated(node);
        context.stats().add("antiLlm.keyHolders", 1);
        return new Shield(holderName, keyField, keys);
    }

    private static void emitDecryptLoop(InsnList code, String holderName, String codeField, Shield shield) {
        AsmUtil.pushInt(code, 0);
        code.add(new VarInsnNode(Opcodes.ISTORE, 0));
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        code.add(loop);
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        code.add(new FieldInsnNode(Opcodes.GETSTATIC, holderName, codeField, "[I"));
        code.add(new InsnNode(Opcodes.ARRAYLENGTH));
        code.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        code.add(new FieldInsnNode(Opcodes.GETSTATIC, holderName, codeField, "[I"));
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        code.add(new FieldInsnNode(Opcodes.GETSTATIC, holderName, codeField, "[I"));
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        code.add(new InsnNode(Opcodes.IALOAD));
        code.add(new FieldInsnNode(Opcodes.GETSTATIC, shield.holderName, shield.keyField, "[I"));
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        AsmUtil.pushInt(code, shield.keys.length - 1);
        code.add(new InsnNode(Opcodes.IAND));
        code.add(new InsnNode(Opcodes.IALOAD));
        code.add(new InsnNode(Opcodes.IXOR));
        code.add(new InsnNode(Opcodes.IASTORE));
        code.add(new IincInsnNode(0, 1));
        code.add(new JumpInsnNode(Opcodes.GOTO, loop));
        code.add(end);
    }

    private void emitConstant(PassContext context, InsnList code, Object value) {
        if (value instanceof String) {
            emitString(context, code, (String) value);
        } else if (value instanceof Integer) {
            AsmUtil.pushInt(code, ((Integer) value).intValue());
            code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf",
                    "(I)Ljava/lang/Integer;", false));
        } else if (value instanceof Long) {
            code.add(new LdcInsnNode(value));
            code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf",
                    "(J)Ljava/lang/Long;", false));
        } else if (value instanceof Float) {
            code.add(new LdcInsnNode(value));
            code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf",
                    "(F)Ljava/lang/Float;", false));
        } else if (value instanceof Double) {
            code.add(new LdcInsnNode(value));
            code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf",
                    "(D)Ljava/lang/Double;", false));
        } else if (value instanceof Type) {
            // Lazy class constant: the holder class is injected at the archive
            // ROOT, while program classes may live in a nested container
            // (BOOT-INF/classes, WEB-INF/classes). Emitting `ldc class <appClass>`
            // here would resolve it with the root class loader while the holder's
            // <clinit> runs and fail on such layouts. The interpreter therefore
            // receives a {tag, descriptor} marker and resolves the class on first
            // use through the context/helper/system class-loader chain.
            AsmUtil.pushInt(code, 2);
            code.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"));
            code.add(new InsnNode(Opcodes.DUP));
            AsmUtil.pushInt(code, 0);
            code.add(new LdcInsnNode("C"));
            code.add(new InsnNode(Opcodes.AASTORE));
            code.add(new InsnNode(Opcodes.DUP));
            AsmUtil.pushInt(code, 1);
            code.add(new LdcInsnNode(((Type) value).getDescriptor()));
            code.add(new InsnNode(Opcodes.AASTORE));
        } else {
            code.add(new LdcInsnNode(value));
        }
    }

    private void emitString(PassContext context, InsnList code, String value) {
        if (!context.config().stringEncryption().enabled()
                || value.length() < context.config().stringEncryption().minLength()) {
            code.add(new LdcInsnNode(value));
            return;
        }
        if (decryptor == null) {
            decryptor = context.runtime().ensureStringDecryptor(
                    context.classes(), context.config().seed());
        }
        long key = context.random().nextLong();
        if (key == 0L) {
            key = 0x5A17L;
        }
        code.add(new LdcInsnNode(Cipher.encrypt(value, key)));
        code.add(new LdcInsnNode(Long.valueOf(key)));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, decryptor, "d",
                "(Ljava/lang/String;J)Ljava/lang/String;", false));
    }

    private void rewrite(ClassNode owner, MethodNode method, Payload payload, Holder holder) {
        // Argument slots are part of the calling convention and must never be
        // reused: the interpreter array starts right after them.
        int localsSlot = Math.max(1, Math.max(method.maxLocals, argumentSlots(method)));
        int resultSlot = localsSlot + 1;
        InsnList out = new InsnList();
        AsmUtil.pushInt(out, localsSlot);
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        out.add(new VarInsnNode(Opcodes.ASTORE, localsSlot));

        boolean isStatic = (method.access & Opcodes.ACC_STATIC) != 0;
        if (!isStatic) {
            out.add(new VarInsnNode(Opcodes.ALOAD, localsSlot));
            AsmUtil.pushInt(out, 0);
            out.add(new VarInsnNode(Opcodes.ALOAD, 0));
            out.add(new InsnNode(Opcodes.AASTORE));
        }
        int slot = isStatic ? 0 : 1;
        for (Type argument : Type.getArgumentTypes(method.desc)) {
            out.add(new VarInsnNode(Opcodes.ALOAD, localsSlot));
            AsmUtil.pushInt(out, slot);
            out.add(new VarInsnNode(AsmUtil.loadOpcode(argument), slot));
            box(out, argument);
            out.add(new InsnNode(Opcodes.AASTORE));
            slot += argument.getSize();
        }

        out.add(new FieldInsnNode(Opcodes.GETSTATIC, holder.name, holder.codeField, "[I"));
        out.add(new FieldInsnNode(Opcodes.GETSTATIC, holder.name, holder.constantField, "[Ljava/lang/Object;"));
        out.add(new FieldInsnNode(Opcodes.GETSTATIC, holder.name, holder.refField, "[Ljava/lang/String;"));
        out.add(new VarInsnNode(Opcodes.ALOAD, localsSlot));
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, virtualMachine, "run", VM_DESC, false));
        out.add(new VarInsnNode(Opcodes.ASTORE, resultSlot));

        Type returns = Type.getReturnType(method.desc);
        if (returns.getSort() == Type.VOID) {
            out.add(new InsnNode(Opcodes.RETURN));
        } else {
            out.add(new VarInsnNode(Opcodes.ALOAD, resultSlot));
            switch (returns.getSort()) {
                case Type.BOOLEAN: {
                    // Accept both representations: Integer 0/1 (normalized VM)
                    // and java.lang.Boolean (older payloads / reflection).
                    LabelNode numberPath = new LabelNode();
                    out.add(new InsnNode(Opcodes.DUP));
                    out.add(new TypeInsnNode(Opcodes.INSTANCEOF, "java/lang/Boolean"));
                    out.add(new JumpInsnNode(Opcodes.IFEQ, numberPath));
                    out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Boolean"));
                    out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Boolean",
                            "booleanValue", "()Z", false));
                    out.add(new InsnNode(Opcodes.IRETURN));
                    out.add(numberPath);
                    out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
                    out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number",
                            "intValue", "()I", false));
                    out.add(new InsnNode(Opcodes.IRETURN));
                    break;
                }
                case Type.BYTE:
                case Type.CHAR:
                case Type.SHORT:
                case Type.INT:
                    out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
                    out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number",
                            "intValue", "()I", false));
                    out.add(new InsnNode(Opcodes.IRETURN));
                    break;
                case Type.LONG:
                    out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
                    out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number",
                            "longValue", "()J", false));
                    out.add(new InsnNode(Opcodes.LRETURN));
                    break;
                case Type.FLOAT:
                    out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
                    out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number",
                            "floatValue", "()F", false));
                    out.add(new InsnNode(Opcodes.FRETURN));
                    break;
                case Type.DOUBLE:
                    out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
                    out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number",
                            "doubleValue", "()D", false));
                    out.add(new InsnNode(Opcodes.DRETURN));
                    break;
                default:
                    out.add(new TypeInsnNode(Opcodes.CHECKCAST,
                            returns.getSort() == Type.ARRAY ? returns.getDescriptor() : returns.getInternalName()));
                    out.add(new InsnNode(Opcodes.ARETURN));
                    break;
            }
        }

        method.instructions = out;
        method.maxLocals = localsSlot + 2;
        // Deepest path builds one boxed argument: array + index + widest load
        // (2 slots) = 4; the dispatch call site peaks at four references too.
        method.maxStack = 4;
        method.tryCatchBlocks = new ArrayList<org.objectweb.asm.tree.TryCatchBlockNode>();
        method.localVariables = null;
        method.visibleLocalVariableAnnotations = null;
        method.invisibleLocalVariableAnnotations = null;
    }

    private static int argumentSlots(MethodNode method) {
        int slots = (method.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type argument : Type.getArgumentTypes(method.desc)) {
            slots += argument.getSize();
        }
        return slots;
    }

    private static void box(InsnList out, Type type) {
        switch (type.getSort()) {
                case Type.BOOLEAN:
                    // A JVM boolean operand is an int (0/1) on the stack. Store it
                    // as an Integer so the interpreter never has to unbox a
                    // java.lang.Boolean while executing virtualized bytecode
                    // (if/if_icmp/iand/... all use the int representation).
                    out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf",
                            "(I)Ljava/lang/Integer;", false));
                    break;
            case Type.BYTE:
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Byte", "valueOf",
                        "(B)Ljava/lang/Byte;", false));
                break;
            case Type.CHAR:
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Character", "valueOf",
                        "(C)Ljava/lang/Character;", false));
                break;
            case Type.SHORT:
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Short", "valueOf",
                        "(S)Ljava/lang/Short;", false));
                break;
            case Type.INT:
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf",
                        "(I)Ljava/lang/Integer;", false));
                break;
            case Type.LONG:
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf",
                        "(J)Ljava/lang/Long;", false));
                break;
            case Type.FLOAT:
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf",
                        "(F)Ljava/lang/Float;", false));
                break;
            case Type.DOUBLE:
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf",
                        "(D)Ljava/lang/Double;", false));
                break;
            default:
                break;
        }
    }

    /**
     * Hardened engine driver. Parses the vm2.* options, applies the optional
     * invokedynamic-bridge and constructor-body pre-transformations, translates
     * eligible methods into {@link Vm2Format.Program}s, encrypts and splits the
     * payload and rewrites each method body into a call to the injected
     * interpreter.
     */
    private void runVm2(PassContext context) {
        int maxMethods = context.config().methodVirtualization().maxMethods();
        int typedMax = context.config().methodVirtualization().maxInstructions();
        Vm2Counters counters = new Vm2Counters();
        counters.encrypt = context.config().optionBool("vm2.encryptPayload", true);
        counters.opcodeMap = context.config().optionBool("vm2.opcodeMap", true);
        counters.trys = context.config().optionBool("vm2.trys", true);
        counters.news = context.config().optionBool("vm2.news", false);
        counters.indy = context.config().optionBool("vm2.indy", true);
        counters.fusion = context.config().optionBool("vm2.fusion", true);
        counters.constructors = context.config().optionBool("vm2.constructors", false);
        counters.nested = counters.encrypt
                && context.config().optionBool("vm2.nested", true);
        counters.maxInstructions = Math.max(16,
                context.config().optionInt("vm2.maxInstructions", Math.max(4000, typedMax)));
        counters.holderCount = context.config().optionInt("vm2.holders", 2);
        if (counters.holderCount < 1) {
            counters.holderCount = 1;
        }
        if (counters.holderCount > 8) {
            counters.holderCount = 8;
        }
        counters.flags = 0;
        if (counters.encrypt) {
            counters.flags |= Vm2Format.FLAG_ENCRYPT;
        }
        if (counters.nested) {
            counters.flags |= Vm2Format.FLAG_NESTED;
        }
        if (counters.opcodeMap) {
            counters.flags |= Vm2Format.FLAG_OPCODES;
        }
        if (counters.trys) {
            counters.flags |= Vm2Format.FLAG_TRYS;
        }
        int[] encodedByReal = counters.opcodeMap
                ? Vm2Format.opcodePermutation(context.random()) : null;
        int[] mapValues = encodedByReal == null ? null : Vm2Format.decoderTable(encodedByReal);

        List<ClassNode> snapshot = new ArrayList<ClassNode>(context.classes().classes().values());
        for (ClassNode node : snapshot) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
            if (context.rules().skipBodyTransform(node.name)) {
                continue;
            }
            if ("module-info".equals(node.name)) {
                continue;
            }
            if ((node.access & Opcodes.ACC_ANNOTATION) != 0) {
                continue;
            }
            if (!context.rules().transformClass(node)) {
                continue;
            }
            Boolean classEnabled = AsmUtil.annotationBoolean(node.invisibleAnnotations, ANNOTATION, "enabled");
            if (classEnabled == null) {
                classEnabled = AsmUtil.annotationBoolean(node.visibleAnnotations, ANNOTATION, "enabled");
            }
            if (Boolean.FALSE.equals(classEnabled)) {
                continue;
            }
            List<MethodNode> snapshotMethods = new ArrayList<MethodNode>(node.methods);
            List<MethodNode> constructorBodies = new ArrayList<MethodNode>();
            int perClass = 0;
            for (MethodNode method : snapshotMethods) {
                if (maxMethods > 0 && perClass >= maxMethods) {
                    break;
                }
                if (isIndyBridge(method) || isConstructorBody(method)) {
                    continue;
                }
                if ("<init>".equals(method.name)) {
                    if (counters.constructors) {
                        try {
                            MethodNode body = extractConstructorBody(context, node, method);
                            if (body != null) {
                                counters.constructorsExtracted++;
                                constructorBodies.add(body);
                            }
                        } catch (RuntimeException e) {
                            context.log().debug("vm2 constructor extraction failed %s.%s: %s",
                                    node.name, method.name, e);
                        }
                    }
                    continue;
                }
                if (!eligibleVm2(context, node, method, counters)) {
                    continue;
                }
                if (virtualizeVm2(context, node, method, counters, encodedByReal, mapValues)) {
                    perClass++;
                }
            }
            for (MethodNode body : constructorBodies) {
                if (maxMethods > 0 && perClass >= maxMethods) {
                    break;
                }
                if (virtualizeVm2(context, node, body, counters, encodedByReal, mapValues)) {
                    perClass++;
                    counters.constructorBodies++;
                }
            }
        }

        context.stats().add("virtualization.methods", counters.methods);
        context.stats().add("virtualization.instructions", counters.instructions);
        context.stats().add("virtualization.skipped", counters.skipped);
        context.stats().add("virtualization.vm2.payloads", counters.methods);
        context.stats().add("virtualization.vm2.encryptedPayloads", counters.encrypt ? counters.methods : 0);
        context.stats().add("virtualization.vm2.nestedPayloads", counters.nestedPayloads);
        context.stats().add("virtualization.vm2.handlers", counters.handlers);
        context.stats().add("virtualization.vm2.blocks", counters.chunks);
        context.stats().add("virtualization.vm2.indyBridges", counters.indyBridges);
        context.stats().add("virtualization.vm2.constructorsExtracted", counters.constructorsExtracted);
        context.stats().add("virtualization.vm2.constructorBodies", counters.constructorBodies);
        context.stats().add("virtualization.vm2.fusion", counters.fusion ? 1 : 0);
        context.stats().add("virtualization.vm2.fused", counters.fused);
        context.stats().add("virtualization.vm2.format", Vm2Format.ROLLING_FORMAT);
        context.log().info("method-virtualization[vm2]: virtualized %d methods (%d instructions, "
                        + "%d handlers, %d indy bridges, %d constructor bodies, %d fused "
                        + "instructions), %d skipped",
                counters.methods, counters.instructions, counters.handlers, counters.indyBridges,
                counters.constructorBodies, counters.fused, counters.skipped);
    }

    /** Mutable statistics of one VM2 run (avoids long parameter lists). */
    private static final class Vm2Counters {
        boolean encrypt;
        boolean opcodeMap;
        boolean trys;
        boolean news;
        boolean indy;
        boolean fusion;
        boolean constructors;
        boolean nested;
        int flags;
        int maxInstructions;
        int holderCount;
        int methods;
        int instructions;
        int skipped;
        int handlers;
        int chunks;
        int nestedPayloads;
        int indyBridges;
        int constructorsExtracted;
        int constructorBodies;
        int fused;
    }

    /**
     * Translates, encodes and rewrites one method. Returns true when the method
     * (or constructor body helper) was virtualized.
     */
    private boolean virtualizeVm2(PassContext context, ClassNode node, MethodNode method,
                                  Vm2Counters counters, int[] encodedByReal, int[] mapValues) {
        try {
            Map<AbstractInsnNode, String> indyBridges = null;
            if (containsInvokeDynamic(method)) {
                if (!counters.indy) {
                    return false;
                }
                indyBridges = createIndyBridges(context, node, method, counters);
            }
            Vm2Format.Program program = translateVm2(context, node, method, counters,
                    encodedByReal, indyBridges);
            if (program.code.length > 200000) {
                counters.skipped++;
                context.log().debug("vm2 skipped %s.%s: payload too large", node.name, method.name);
                return false;
            }
            int payloadId = counters.methods + 1;
            context.log().debug("vm2 #%d %s.%s: %s", payloadId, node.name, method.name,
                    Vm2Format.describe(program));
            if (vm2Engine == null) {
                vm2Engine = TemplateInjector.inject(context.classes(), UmbraVM2.class,
                        "umbra/runtime/V", context.config().seed());
            }
            if (mapValues != null && vm2MapHolder == null) {
                vm2MapHolder = createVm2Chunk(context, mapValues, "umbra/runtime/M",
                        "virtualization.holders");
            }
            long key = context.random().nextLong();
            if (key == 0L) {
                key = 0x51ED270B1F2A3C4DL;
            }
            int salt = context.random().nextInt();
            int[] meta = new int[] {
                    Vm2Format.MAGIC, (int) key, (int) (key >>> 32), 0, 0, 0,
                    counters.flags | (payloadId << 16), salt
            };
            long stage1 = Vm2Format.metaKey(meta);
            Vm2Format.Encoded encoded = Vm2Format.serialize(program, stage1);
            int payloadBlockCount = Vm2Format.blockCount(encoded.payload.length,
                    counters.holderCount);
            List<int[]> blocks = new ArrayList<int[]>();
            if (counters.nested) {
                int[] outer = Vm2Format.generateOuterProgram(context.random());
                long stage2 = Vm2Format.runOuterProgram(outer, stage1, salt,
                        encoded.payload.length, payloadBlockCount);
                if (stage2 == 0L) {
                    stage2 = stage1 ^ 0x5DEECE66DL;
                }
                Vm2Format.crypt(encoded.payload, stage2);
                int[] outerEncrypted = new int[outer.length];
                System.arraycopy(outer, 0, outerEncrypted, 0, outer.length);
                Vm2Format.crypt(outerEncrypted, stage1);
                blocks.add(outerEncrypted);
                counters.nestedPayloads++;
            } else if (counters.encrypt) {
                Vm2Format.crypt(encoded.payload, stage1);
            }
            blocks.addAll(Vm2Format.split(encoded.payload, payloadBlockCount));
            meta[3] = encoded.payload.length;
            meta[4] = payloadBlockCount;
            meta[5] = encoded.integrity;
            Vm2Holder holder = createVm2Holders(context, meta, blocks);
            rewriteVm2(context, node, method, holder, mapValues != null);
            counters.methods++;
            counters.instructions += program.code.length;
            counters.handlers += program.handlers.length / 4;
            counters.chunks += blocks.size();
            return true;
        } catch (SkipMethod e) {
            counters.skipped++;
            context.log().debug("vm2 skipped %s.%s: %s", node.name, method.name, e.getMessage());
            return false;
        } catch (RuntimeException e) {
            counters.skipped++;
            context.log().debug("vm2 failed %s.%s: %s", node.name, method.name, e);
            if (context.log().verbose()) {
                e.printStackTrace();
            }
            return false;
        }
    }

    private static boolean containsInvokeDynamic(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof InvokeDynamicInsnNode) {
                return true;
            }
        }
        return false;
    }

    private static boolean isIndyBridge(MethodNode method) {
        return method.name.startsWith(INDY_BRIDGE_PREFIX);
    }

    private static boolean isConstructorBody(MethodNode method) {
        return method.name.startsWith(CONSTRUCTOR_BODY_PREFIX);
    }

    /**
     * Extracts every invokedynamic of a method into a synthetic bridge in the
     * same owner class. The bootstrap keeps its original lookup class and
     * package/private access (LambdaMetafactory semantics), and the payload
     * replaces the indy with a plain static call to the bridge.
     *
     * @return map from the original instruction to the bridge reference string
     */
    private Map<AbstractInsnNode, String> createIndyBridges(PassContext context, ClassNode owner,
                                                            MethodNode method, Vm2Counters counters) {
        Map<AbstractInsnNode, String> bridges = new IdentityHashMap<AbstractInsnNode, String>();
        List<MethodNode> pending = new ArrayList<MethodNode>();
        boolean interfaceOwner = (owner.access & Opcodes.ACC_INTERFACE) != 0;
        if (interfaceOwner && (owner.version & 0xFFFF) < Opcodes.V1_8) {
            throw new SkipMethod("invokedynamic in a pre-Java-8 interface cannot be bridged");
        }
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof InvokeDynamicInsnNode)) {
                continue;
            }
            InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) insn;
            String name = uniqueMethodName(context, owner, INDY_BRIDGE_PREFIX);
            int access = interfaceOwner
                    ? Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC
                    : Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
            MethodNode bridge = new MethodNode(access, name, indy.desc, null, null);
            InsnList code = bridge.instructions;
            int slot = 0;
            for (Type argument : Type.getArgumentTypes(indy.desc)) {
                code.add(new VarInsnNode(AsmUtil.loadOpcode(argument), slot));
                slot += argument.getSize();
            }
            code.add(new InvokeDynamicInsnNode(indy.name, indy.desc, indy.bsm, indy.bsmArgs));
            code.add(new InsnNode(AsmUtil.returnOpcode(Type.getReturnType(indy.desc))));
            bridge.maxLocals = slot;
            bridge.maxStack = Math.max(2, slot + 2);
            pending.add(bridge);
            bridges.put(insn, "M|" + owner.name + "|" + name + "|" + indy.desc);
            counters.indyBridges++;
        }
        if (!pending.isEmpty()) {
            owner.methods.addAll(pending);
        }
        return bridges;
    }

    /**
     * Moves the constructor body after the mandatory super()/this() call into a
     * private synthetic helper that can be virtualized. Conservative: skips
     * unusual prologues, constructors whose handlers cover the prologue, and
     * constructors writing final fields (the JVM only allows that in the
     * declaring {@code <init>}).
     *
     * @return the extracted helper, or {@code null} when the shape is unsafe
     */
    private MethodNode extractConstructorBody(PassContext context, ClassNode owner,
                                              MethodNode constructor) {
        if ((owner.access & Opcodes.ACC_INTERFACE) != 0) {
            return null;
        }
        if ((constructor.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE
                | Opcodes.ACC_SYNCHRONIZED)) != 0) {
            return null;
        }
        if (constructor.instructions == null) {
            return null;
        }
        MethodInsnNode initializer = null;
        int initializerIndex = -1;
        int index = 0;
        for (AbstractInsnNode insn = constructor.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;
                if (call.getOpcode() == Opcodes.INVOKESPECIAL && "<init>".equals(call.name)
                        && (call.owner.equals(owner.superName) || call.owner.equals(owner.name))) {
                    if (initializer != null) {
                        return null;
                    }
                    initializer = call;
                    initializerIndex = index;
                }
            }
            index++;
        }
        if (initializer == null || initializerIndex < 0) {
            return null;
        }
        // The prologue must stay straight line so nothing can branch across the
        // split point and the uninitialized-this rules stay untouched.
        index = 0;
        boolean sawInitializer = false;
        for (AbstractInsnNode insn = constructor.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode >= 0 && (insn instanceof JumpInsnNode
                    || insn instanceof TableSwitchInsnNode
                    || insn instanceof LookupSwitchInsnNode
                    || opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT)) {
                return null;
            }
            if (insn == initializer) {
                sawInitializer = true;
            }
            index++;
        }
        if (!sawInitializer) {
            return null;
        }
        // Body instructions and their labels must start after the initializer.
        Map<LabelNode, Integer> labelIndex = new IdentityHashMap<LabelNode, Integer>();
        index = 0;
        List<AbstractInsnNode> instructions = new ArrayList<AbstractInsnNode>();
        for (AbstractInsnNode insn = constructor.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            instructions.add(insn);
            if (insn instanceof LabelNode) {
                labelIndex.put((LabelNode) insn, Integer.valueOf(index));
            }
            index++;
        }
        if (constructor.tryCatchBlocks != null) {
            for (org.objectweb.asm.tree.TryCatchBlockNode block : constructor.tryCatchBlocks) {
                Integer start = labelIndex.get(block.start);
                Integer end = labelIndex.get(block.end);
                Integer handler = labelIndex.get(block.handler);
                if (start == null || end == null || handler == null
                        || start.intValue() <= initializerIndex
                        || end.intValue() <= initializerIndex
                        || handler.intValue() <= initializerIndex) {
                    return null;
                }
            }
        }
        // Final fields may only be written inside the declaring class's <init>.
        for (int i = initializerIndex + 1; i < instructions.size(); i++) {
            AbstractInsnNode insn = instructions.get(i);
            if (insn instanceof FieldInsnNode) {
                FieldInsnNode field = (FieldInsnNode) insn;
                if (field.getOpcode() == Opcodes.PUTFIELD) {
                    for (FieldNode candidate : owner.fields) {
                        if (candidate.name.equals(field.name)
                                && (candidate.access & Opcodes.ACC_FINAL) != 0) {
                            return null;
                        }
                    }
                }
            }
        }
        List<AbstractInsnNode> bodyNodes = new ArrayList<AbstractInsnNode>();
        AbstractInsnNode node = initializer.getNext();
        while (node != null) {
            bodyNodes.add(node);
            node = node.getNext();
        }
        if (bodyNodes.size() < 2) {
            return null;
        }
        String name = uniqueMethodName(context, owner, CONSTRUCTOR_BODY_PREFIX);
        MethodNode body = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_SYNTHETIC, name, constructor.desc, null, null);
        for (AbstractInsnNode moved : bodyNodes) {
            constructor.instructions.remove(moved);
            body.instructions.add(moved);
        }
        body.tryCatchBlocks = new ArrayList<org.objectweb.asm.tree.TryCatchBlockNode>();
        if (constructor.tryCatchBlocks != null) {
            body.tryCatchBlocks.addAll(constructor.tryCatchBlocks);
            constructor.tryCatchBlocks = new ArrayList<org.objectweb.asm.tree.TryCatchBlockNode>();
        }
        body.maxStack = Math.max(4, constructor.maxStack);
        body.maxLocals = constructor.maxLocals;
        body.localVariables = null;
        body.visibleLocalVariableAnnotations = null;
        body.invisibleLocalVariableAnnotations = null;

        int argumentSlots = argumentSlots(constructor);
        constructor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        int slot = 1;
        for (Type argument : Type.getArgumentTypes(constructor.desc)) {
            constructor.instructions.add(new VarInsnNode(AsmUtil.loadOpcode(argument), slot));
            slot += argument.getSize();
        }
        constructor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, owner.name,
                name, constructor.desc, false));
        constructor.instructions.add(new InsnNode(Opcodes.RETURN));
        constructor.maxStack = Math.max(constructor.maxStack, argumentSlots + 2);
        constructor.maxLocals = Math.max(constructor.maxLocals, argumentSlots);
        constructor.localVariables = null;
        constructor.visibleLocalVariableAnnotations = null;
        constructor.invisibleLocalVariableAnnotations = null;
        owner.methods.add(body);
        return body;
    }

    private static String uniqueMethodName(PassContext context, ClassNode owner, String prefix) {
        String candidate;
        int guard = 0;
        do {
            candidate = prefix + Long.toHexString(context.random().nextLong());
            if (++guard > 100000) {
                throw new IllegalStateException("unable to allocate a synthetic method name");
            }
        } while (hasMethodNamed(owner, candidate));
        return candidate;
    }

    private static boolean hasMethodNamed(ClassNode owner, String name) {
        for (MethodNode method : owner.methods) {
            if (method.name.equals(name)) {
                return true;
            }
        }
        return false;
    }
    /** Eligibility rules for the hardened engine. */
    private boolean eligibleVm2(PassContext context, ClassNode owner, MethodNode method,
                                Vm2Counters counters) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            // Constructors and class initializers stay in the class file.
            return false;
        }
        if (isIndyBridge(method)) {
            // Bridges intentionally keep the original invokedynamic.
            return false;
        }
        if (method.instructions == null || method.instructions.size() < 3
                || method.instructions.size() > counters.maxInstructions) {
            return false;
        }
        if (method.maxLocals > MAX_LOCALS) {
            return false;
        }
        if (method.tryCatchBlocks != null && !method.tryCatchBlocks.isEmpty() && !counters.trys) {
            return false;
        }
        Boolean methodEnabled = AsmUtil.annotationBoolean(method.invisibleAnnotations, ANNOTATION, "enabled");
        if (methodEnabled == null) {
            methodEnabled = AsmUtil.annotationBoolean(method.visibleAnnotations, ANNOTATION, "enabled");
        }
        if (Boolean.FALSE.equals(methodEnabled)) {
            return false;
        }
        boolean interfaceOwner = (owner.access & Opcodes.ACC_INTERFACE) != 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode < 0) {
                continue;
            }
            if (insn instanceof InvokeDynamicInsnNode) {
                if (!counters.indy) {
                    return false;
                }
                if (interfaceOwner && (owner.version & 0xFFFF) < Opcodes.V1_8) {
                    return false;
                }
            }
            if (opcode == Opcodes.JSR || opcode == Opcodes.RET
                    || opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT) {
                return false;
            }
            if (opcode == Opcodes.NEW && !counters.news) {
                return false;
            }
            if (insn instanceof LdcInsnNode) {
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof Handle || constant instanceof ConstantDynamic) {
                    return false;
                }
                if (constant instanceof Type && ((Type) constant).getSort() == Type.METHOD) {
                    return false;
                }
            }
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;
                if (call.getOpcode() == Opcodes.INVOKESPECIAL) {
                    if ("<init>".equals(call.name)) {
                        if (!counters.news) {
                            return false;
                        }
                    } else if (!owner.name.equals(call.owner) || call.itf) {
                        // super/default-super calls dispatch differently under reflection.
                        return false;
                    }
                }
                if (isCallerSensitive(call.owner, call.name)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Reflection performed inside a virtualized method sees the interpreter as
     * its caller, which changes access control checks. Methods that rely on
     * caller-sensitive APIs are therefore kept as ordinary bytecode.
     */
    private static boolean isCallerSensitive(String owner, String name) {
        if (owner.startsWith("java/lang/reflect/") || owner.startsWith("java/lang/invoke/")
                || owner.startsWith("sun/misc/") || owner.startsWith("jdk/internal/")) {
            return true;
        }
        if ("java/lang/ClassLoader".equals(owner) || "java/security/AccessController".equals(owner)
                || "java/util/ServiceLoader".equals(owner)) {
            return true;
        }
        if ("java/lang/Class".equals(owner) && "newInstance".equals(name)) {
            return true;
        }
        if (("java/lang/System".equals(owner) || "java/lang/Runtime".equals(owner))
                && ("load".equals(name) || "loadLibrary".equals(name))) {
            return true;
        }
        return false;
    }

    /** One fused superinstruction selected by {@link #matchFusion}. */
    private static final class Fusion {
        final int opcode;
        final int[] operands;
        final LabelNode target;
        final AbstractInsnNode last;

        Fusion(int opcode, int[] operands, LabelNode target, AbstractInsnNode last) {
            this.opcode = opcode;
            this.operands = operands;
            this.target = target;
            this.last = last;
        }
    }

    /** Superinstruction number for the six int arithmetic opcodes, in opcode order. */
    private static final int[] SUPER_INT_ARITH = {
            Vm2Format.SUPER_IADD_LL, Vm2Format.SUPER_ISUB_LL, Vm2Format.SUPER_IMUL_LL,
            Vm2Format.SUPER_IAND_LL, Vm2Format.SUPER_IOR_LL, Vm2Format.SUPER_IXOR_LL
    };
    /** Superinstruction number for the six "load + constant + arithmetic" opcodes. */
    private static final int[] SUPER_INT_ARITH_CONST = {
            Vm2Format.SUPER_ILOAD_CONST_ADD, Vm2Format.SUPER_ILOAD_CONST_SUB,
            Vm2Format.SUPER_ILOAD_CONST_MUL, Vm2Format.SUPER_ILOAD_CONST_AND,
            Vm2Format.SUPER_ILOAD_CONST_OR, Vm2Format.SUPER_ILOAD_CONST_XOR
    };
    /** Superinstruction number for the six long arithmetic opcodes. */
    private static final int[] SUPER_LONG_ARITH = {
            Vm2Format.SUPER_LADD_LL, Vm2Format.SUPER_LSUB_LL, Vm2Format.SUPER_LMUL_LL,
            Vm2Format.SUPER_LAND_LL, Vm2Format.SUPER_LOR_LL, Vm2Format.SUPER_LXOR_LL
    };
    /** Superinstruction number for the six int compare/branch opcodes. */
    private static final int[] SUPER_INT_COMPARE = {
            Vm2Format.SUPER_IF_ICMPEQ_LL, Vm2Format.SUPER_IF_ICMPNE_LL,
            Vm2Format.SUPER_IF_ICMPLT_LL, Vm2Format.SUPER_IF_ICMPGE_LL,
            Vm2Format.SUPER_IF_ICMPGT_LL, Vm2Format.SUPER_IF_ICMPLE_LL
    };

    /**
     * Translates one method body into a {@link Vm2Format.Program}.
     *
     * <p>When {@code vm2.fusion} is enabled, runs of two or three adjacent
     * instructions with a single fused equivalent are replaced by one
     * superinstruction (see {@link #matchFusion}). Fusion never crosses a
     * {@link LabelNode}, so branch targets and exception-handler boundaries
     * always stay on instruction starts.</p>
     */
    private Vm2Format.Program translateVm2(PassContext context, ClassNode owner, MethodNode method,
                                           Vm2Counters counters, int[] encodedByReal,
                                           Map<AbstractInsnNode, String> indyBridges) {
        IntList code = new IntList();
        IntList opcodeSlots = new IntList();
        Map<LabelNode, Integer> labels = new IdentityHashMap<LabelNode, Integer>();
        List<Integer> patchSlots = new ArrayList<Integer>();
        List<LabelNode> patchLabels = new ArrayList<LabelNode>();
        List<Object> constants = new ArrayList<Object>();
        Map<Object, Integer> constantIndex = new LinkedHashMap<Object, Integer>();
        List<String> refs = new ArrayList<String>();
        Map<String, Integer> refIndex = new LinkedHashMap<String, Integer>();

        AbstractInsnNode cursor = method.instructions.getFirst();
        while (cursor != null) {
            if (cursor instanceof LabelNode) {
                labels.put((LabelNode) cursor, Integer.valueOf(code.size()));
                cursor = cursor.getNext();
                continue;
            }
            if (cursor.getOpcode() < 0) {
                cursor = cursor.getNext();
                continue;
            }
            if (counters.fusion) {
                Fusion fusion = matchFusion(cursor, refs, refIndex);
                if (fusion != null) {
                    emitVm2Opcode(code, opcodeSlots, fusion.opcode, encodedByReal);
                    for (int i = 0; i < fusion.operands.length; i++) {
                        code.add(fusion.operands[i]);
                    }
                    if (fusion.target != null) {
                        patchSlots.add(Integer.valueOf(code.size()));
                        patchLabels.add(fusion.target);
                        code.add(0);
                    }
                    counters.fused++;
                    cursor = fusion.last.getNext();
                    continue;
                }
            }
            emitVm2Instruction(method, cursor, code, opcodeSlots, patchSlots, patchLabels,
                    constants, constantIndex, refs, refIndex, encodedByReal, indyBridges);
            cursor = cursor.getNext();
        }

        int[] codeArray = code.toArray();
        int[] opcodePositions = opcodeSlots.toArray();
        for (int i = 0; i < patchSlots.size(); i++) {
            Integer slot = labels.get(patchLabels.get(i));
            if (slot == null) {
                throw new SkipMethod("unresolved label");
            }
            codeArray[patchSlots.get(i).intValue()] = slot.intValue();
            if (!vm2InstructionBoundary(opcodePositions, slot.intValue())) {
                throw new SkipMethod("label target " + slot + " is not an instruction boundary (label "
                        + method.instructions.indexOf(patchLabels.get(i)) + ")");
            }
        }

        List<HandlerEntry> handlerEntries = new ArrayList<HandlerEntry>();
        if (method.tryCatchBlocks != null) {
            for (org.objectweb.asm.tree.TryCatchBlockNode block : method.tryCatchBlocks) {
                handlerEntries.add(new HandlerEntry(block.start, block.end, block.handler, block.type));
            }
        }
        int[] handlerTable = new int[handlerEntries.size() * 4];
        for (int i = 0; i < handlerEntries.size(); i++) {
            HandlerEntry entry = handlerEntries.get(i);
            Integer start = labels.get(entry.start);
            Integer end = labels.get(entry.end);
            Integer target = labels.get(entry.handler);
            if (start == null || end == null || target == null) {
                throw new SkipMethod("unresolved handler label");
            }
            if (!vm2InstructionBoundary(opcodePositions, start.intValue())
                    || !vm2InstructionBoundary(opcodePositions, target.intValue())) {
                throw new SkipMethod("handler label is not an instruction boundary");
            }
            handlerTable[i * 4] = start.intValue();
            handlerTable[i * 4 + 1] = end.intValue();
            handlerTable[i * 4 + 2] = entry.type == null ? -1
                    : vm2Ref(refs, refIndex, "T|" + entry.type);
            handlerTable[i * 4 + 3] = target.intValue();
        }

        boolean isStatic = (method.access & Opcodes.ACC_STATIC) != 0;
        int argSlots = isStatic ? 0 : 1;
        for (Type argument : Type.getArgumentTypes(method.desc)) {
            argSlots += argument.getSize();
        }
        int[] argKinds = new int[argSlots];
        int slot = isStatic ? 0 : 1;
        if (!isStatic) {
            argKinds[0] = Vm2Format.KIND_REF;
        }
        for (Type argument : Type.getArgumentTypes(method.desc)) {
            argKinds[slot] = vm2Kind(argument);
            if (argument.getSize() == 2) {
                argKinds[slot + 1] = Vm2Format.KIND_UNUSED;
            }
            slot += argument.getSize();
        }
        int maxLocals = Math.max(method.maxLocals, argSlots);
        int stackHint = Math.max(32, method.maxStack + 16);
        Vm2Format.Program program = new Vm2Format.Program(codeArray,
                constants.toArray(new Object[0]), refs.toArray(new String[0]), handlerTable,
                maxLocals, argSlots, argKinds, stackHint, counters.flags, opcodePositions);
        validateVm2Program(program, opcodePositions, method, encodedByReal);
        return program;
    }

    /**
     * Emits one un-fused VM2 instruction. Kept separate from the translation
     * loop so the fusion fast path above stays readable.
     */
    private static void emitVm2Instruction(MethodNode method, AbstractInsnNode insn,
                                           IntList code, IntList opcodeSlots,
                                           List<Integer> patchSlots, List<LabelNode> patchLabels,
                                           List<Object> constants, Map<Object, Integer> constantIndex,
                                           List<String> refs, Map<String, Integer> refIndex,
                                           int[] encodedByReal,
                                           Map<AbstractInsnNode, String> indyBridges) {
        int opcode = insn.getOpcode();
        if (insn instanceof LdcInsnNode) {
            emitVm2Opcode(code, opcodeSlots, Opcodes.LDC, encodedByReal);
            code.add(vm2Constant(constants, constantIndex, ((LdcInsnNode) insn).cst));
        } else if (insn instanceof IntInsnNode) {
            IntInsnNode value = (IntInsnNode) insn;
            if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH
                    || opcode == Opcodes.NEWARRAY) {
                emitVm2Opcode(code, opcodeSlots, opcode, encodedByReal);
                code.add(value.operand);
            } else {
                throw new SkipMethod("unsupported integer instruction " + opcode);
            }
        } else if (insn instanceof VarInsnNode) {
            emitVm2Opcode(code, opcodeSlots, opcode, encodedByReal);
            code.add(((VarInsnNode) insn).var);
        } else if (insn instanceof IincInsnNode) {
            emitVm2Opcode(code, opcodeSlots, Opcodes.IINC, encodedByReal);
            code.add(((IincInsnNode) insn).var);
            code.add(((IincInsnNode) insn).incr);
        } else if (insn instanceof FieldInsnNode) {
            FieldInsnNode field = (FieldInsnNode) insn;
            emitVm2Opcode(code, opcodeSlots, opcode, encodedByReal);
            code.add(vm2Ref(refs, refIndex, "F|" + field.owner + "|" + field.name + "|" + field.desc));
        } else if (insn instanceof MethodInsnNode) {
            MethodInsnNode call = (MethodInsnNode) insn;
            emitVm2Opcode(code, opcodeSlots, opcode, encodedByReal);
            code.add(vm2Ref(refs, refIndex, "M|" + call.owner + "|" + call.name + "|" + call.desc));
        } else if (insn instanceof TypeInsnNode) {
            TypeInsnNode type = (TypeInsnNode) insn;
            emitVm2Opcode(code, opcodeSlots, opcode, encodedByReal);
            code.add(vm2Ref(refs, refIndex, "T|" + type.desc));
        } else if (insn instanceof JumpInsnNode) {
            emitVm2Opcode(code, opcodeSlots, opcode, encodedByReal);
            patchSlots.add(Integer.valueOf(code.size()));
            patchLabels.add(((JumpInsnNode) insn).label);
            code.add(0);
        } else if (insn instanceof TableSwitchInsnNode) {
            TableSwitchInsnNode table = (TableSwitchInsnNode) insn;
            emitVm2Opcode(code, opcodeSlots, Opcodes.TABLESWITCH, encodedByReal);
            patchSlots.add(Integer.valueOf(code.size()));
            patchLabels.add(table.dflt);
            code.add(0);
            code.add(table.min);
            code.add(table.max);
            for (LabelNode target : table.labels) {
                patchSlots.add(Integer.valueOf(code.size()));
                patchLabels.add(target);
                code.add(0);
            }
        } else if (insn instanceof LookupSwitchInsnNode) {
            LookupSwitchInsnNode lookup = (LookupSwitchInsnNode) insn;
            emitVm2Opcode(code, opcodeSlots, Opcodes.LOOKUPSWITCH, encodedByReal);
            patchSlots.add(Integer.valueOf(code.size()));
            patchLabels.add(lookup.dflt);
            code.add(0);
            code.add(lookup.keys.size());
            for (int i = 0; i < lookup.keys.size(); i++) {
                code.add(((Integer) lookup.keys.get(i)).intValue());
                patchSlots.add(Integer.valueOf(code.size()));
                patchLabels.add(lookup.labels.get(i));
                code.add(0);
            }
        } else if (insn instanceof MultiANewArrayInsnNode) {
            MultiANewArrayInsnNode multi = (MultiANewArrayInsnNode) insn;
            emitVm2Opcode(code, opcodeSlots, Opcodes.MULTIANEWARRAY, encodedByReal);
            code.add(vm2Ref(refs, refIndex, "T|" + multi.desc));
            code.add(multi.dims);
        } else if (insn instanceof InvokeDynamicInsnNode) {
            String bridge = indyBridges == null ? null : indyBridges.get(insn);
            if (bridge == null) {
                throw new SkipMethod("invokedynamic without bridge");
            }
            emitVm2Opcode(code, opcodeSlots, Opcodes.INVOKESTATIC, encodedByReal);
            code.add(vm2Ref(refs, refIndex, bridge));
        } else if (insn instanceof InsnNode) {
            emitVm2Opcode(code, opcodeSlots, opcode, encodedByReal);
        } else {
            throw new SkipMethod("unsupported instruction " + insn.getClass().getSimpleName());
        }
    }

    /**
     * Matches a superinstruction starting at {@code first}; returns {@code null}
     * when the instruction is not the start of a fusable run.
     *
     * <p>Every step is verified to be adjacent (only line-number/frame pseudo
     * nodes in between) and no label may sit inside the run, so a branch target
     * or an exception-handler boundary can never end up in the middle of a
     * fused instruction.</p>
     */
    private static Fusion matchFusion(AbstractInsnNode first, List<String> refs,
                                      Map<String, Integer> refIndex) {
        int opcode = first.getOpcode();
        AbstractInsnNode second = nextFusable(first);
        if (second == null) {
            return null;
        }
        if (opcode == Opcodes.ILOAD) {
            int variable = ((VarInsnNode) first).var;
            if (second.getOpcode() == Opcodes.ILOAD) {
                AbstractInsnNode third = nextFusable(second);
                if (third == null) {
                    return null;
                }
                int compare = compareIndex(third.getOpcode());
                if (compare >= 0 && third instanceof JumpInsnNode) {
                    int[] operands = { variable, ((VarInsnNode) second).var };
                    return new Fusion(SUPER_INT_COMPARE[compare], operands,
                            ((JumpInsnNode) third).label, third);
                }
                int arithmetic = intArithmeticIndex(third.getOpcode());
                if (arithmetic >= 0) {
                    int[] operands = { variable, ((VarInsnNode) second).var };
                    return new Fusion(SUPER_INT_ARITH[arithmetic], operands, null, third);
                }
                return null;
            }
            Integer constant = constantValue(second);
            if (constant != null) {
                AbstractInsnNode third = nextFusable(second);
                if (third == null) {
                    return null;
                }
                int arithmetic = intArithmeticIndex(third.getOpcode());
                if (arithmetic >= 0) {
                    int[] operands = { variable, constant.intValue() };
                    return new Fusion(SUPER_INT_ARITH_CONST[arithmetic], operands, null, third);
                }
                return null;
            }
            if (second instanceof FieldInsnNode && second.getOpcode() == Opcodes.GETFIELD) {
                FieldInsnNode field = (FieldInsnNode) second;
                int[] operands = { variable,
                        vm2Ref(refs, refIndex, "F|" + field.owner + "|" + field.name + "|" + field.desc) };
                return new Fusion(Vm2Format.SUPER_ALOAD_GETFIELD, operands, null, second);
            }
            return null;
        }
        if (opcode == Opcodes.LLOAD) {
            if (second.getOpcode() == Opcodes.LLOAD) {
                AbstractInsnNode third = nextFusable(second);
                if (third == null) {
                    return null;
                }
                int arithmetic = longArithmeticIndex(third.getOpcode());
                if (arithmetic >= 0) {
                    int[] operands = { ((VarInsnNode) first).var, ((VarInsnNode) second).var };
                    return new Fusion(SUPER_LONG_ARITH[arithmetic], operands, null, third);
                }
            }
            return null;
        }
        Integer constant = constantValue(first);
        if (constant != null && second instanceof VarInsnNode
                && second.getOpcode() == Opcodes.ISTORE) {
            int[] operands = { constant.intValue(), ((VarInsnNode) second).var };
            return new Fusion(Vm2Format.SUPER_CONST_ISTORE, operands, null, second);
        }
        return null;
    }

    /** Next real instruction when no label interrupts the run, {@code null} otherwise. */
    private static AbstractInsnNode nextFusable(AbstractInsnNode node) {
        for (AbstractInsnNode next = node.getNext(); next != null; next = next.getNext()) {
            if (next instanceof LabelNode) {
                return null;
            }
            if (next.getOpcode() >= 0) {
                return next;
            }
        }
        return null;
    }

    /** Integer value pushed by a constant instruction, or {@code null}. */
    private static Integer constantValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return Integer.valueOf(opcode - Opcodes.ICONST_0);
        }
        if (insn instanceof IntInsnNode
                && (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH)) {
            return Integer.valueOf(((IntInsnNode) insn).operand);
        }
        return null;
    }

    private static int intArithmeticIndex(int opcode) {
        switch (opcode) {
            case Opcodes.IADD: return 0;
            case Opcodes.ISUB: return 1;
            case Opcodes.IMUL: return 2;
            case Opcodes.IAND: return 3;
            case Opcodes.IOR: return 4;
            case Opcodes.IXOR: return 5;
            default: return -1;
        }
    }

    private static int longArithmeticIndex(int opcode) {
        switch (opcode) {
            case Opcodes.LADD: return 0;
            case Opcodes.LSUB: return 1;
            case Opcodes.LMUL: return 2;
            case Opcodes.LAND: return 3;
            case Opcodes.LOR: return 4;
            case Opcodes.LXOR: return 5;
            default: return -1;
        }
    }

    private static int compareIndex(int opcode) {
        switch (opcode) {
            case Opcodes.IF_ICMPEQ: return 0;
            case Opcodes.IF_ICMPNE: return 1;
            case Opcodes.IF_ICMPLT: return 2;
            case Opcodes.IF_ICMPGE: return 3;
            case Opcodes.IF_ICMPGT: return 4;
            case Opcodes.IF_ICMPLE: return 5;
            default: return -1;
        }
    }

    /**
     * Walks the translated stream exactly like the interpreter does and asserts
     * that every decoded instruction starts on a recorded opcode slot. This
     * catches translation/decoder drift (for example a wrong operand count)
     * before the payload is emitted; on mismatch the method is skipped instead
     * of producing a broken virtualized body.
     */
    private static void validateVm2Program(Vm2Format.Program program, int[] opcodePositions,
                                           MethodNode method, int[] encodedByReal) {
        int[] decoder = null;
        if ((program.flags & Vm2Format.FLAG_OPCODES) != 0 && encodedByReal != null) {
            decoder = Vm2Format.decoderTable(encodedByReal);
        }
        int[] code = program.code;
        int p = 0;
        int slotIndex = 0;
        while (p < code.length) {
            if (slotIndex >= opcodePositions.length || opcodePositions[slotIndex] != p) {
                throw new SkipMethod("translated stream desynchronized at slot " + p
                        + " (expected " + (slotIndex < opcodePositions.length
                        ? opcodePositions[slotIndex] : -1) + ") in " + method.name);
            }
            slotIndex++;
            int op;
            if (decoder == null) {
                op = code[p];
            } else {
                int encoded = code[p];
                if (encoded < 0 || encoded >= decoder.length || decoder[encoded] < 0) {
                    throw new SkipMethod("undecodable opcode " + encoded + " at " + p);
                }
                op = decoder[encoded];
            }
            int operands = Vm2Format.operandSlots(op, code, p);
            if (operands < 0 || p + 1 + operands > code.length) {
                throw new SkipMethod("operand overflow at slot " + p + " in " + method.name);
            }
            p += 1 + operands;
        }
        if (slotIndex != opcodePositions.length) {
            throw new SkipMethod("translated stream has trailing slots in " + method.name);
        }
    }

    private static void emitVm2Opcode(IntList code, IntList opcodeSlots, int opcode,
                                      int[] encodedByReal) {
        opcodeSlots.add(code.size());
        code.add(encodedByReal == null ? opcode : encodedByReal[opcode]);
    }

    /** Binary search in the sorted opcode slot list. */
    private static boolean vm2InstructionBoundary(int[] positions, int value) {
        int low = 0;
        int high = positions.length - 1;
        while (low <= high) {
            int middle = (low + high) >>> 1;
            int candidate = positions[middle];
            if (candidate == value) {
                return true;
            }
            if (candidate < value) {
                low = middle + 1;
            } else {
                high = middle - 1;
            }
        }
        return false;
    }

    private static int vm2Constant(List<Object> constants, Map<Object, Integer> index, Object value) {
        Integer existing = index.get(value);
        if (existing != null) {
            return existing.intValue();
        }
        int position = constants.size();
        constants.add(value);
        index.put(value, Integer.valueOf(position));
        return position;
    }

    private static int vm2Ref(List<String> refs, Map<String, Integer> index, String value) {
        Integer existing = index.get(value);
        if (existing != null) {
            return existing.intValue();
        }
        int position = refs.size();
        refs.add(value);
        index.put(value, Integer.valueOf(position));
        return position;
    }

    private static int vm2Kind(Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT:
                return Vm2Format.KIND_INT;
            case Type.LONG:
                return Vm2Format.KIND_LONG;
            case Type.FLOAT:
                return Vm2Format.KIND_FLOAT;
            case Type.DOUBLE:
                return Vm2Format.KIND_DOUBLE;
            default:
                return Vm2Format.KIND_REF;
        }
    }

    /** Builds the synthetic holder classes and returns the call-site handles. */
    private Vm2Holder createVm2Holders(PassContext context, int[] meta, List<int[]> blocks) {
        List<Vm2Chunk> chunkHolders = new ArrayList<Vm2Chunk>(blocks.size());
        for (int[] block : blocks) {
            chunkHolders.add(createVm2Chunk(context, block, "umbra/runtime/X",
                    "virtualization.holders"));
        }
        String name = uniqueClassName(context, "umbra/runtime/V");
        NameGenerator names = new NameGenerator(context.random(), "");
        String metaField = names.random(5);
        String blocksField = names.random(5);

        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC;
        node.name = name;
        node.superName = "java/lang/Object";
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                metaField, "[I", null, null));
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                blocksField, "[[I", null, null));

        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList code = clinit.instructions;
        AsmUtil.pushInt(code, meta.length);
        code.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        code.add(new FieldInsnNode(Opcodes.PUTSTATIC, name, metaField, "[I"));
        for (int i = 0; i < meta.length; i++) {
            code.add(new FieldInsnNode(Opcodes.GETSTATIC, name, metaField, "[I"));
            AsmUtil.pushInt(code, i);
            pushOpaqueInt(context, code, meta[i]);
            code.add(new InsnNode(Opcodes.IASTORE));
        }
        AsmUtil.pushInt(code, chunkHolders.size());
        code.add(new TypeInsnNode(Opcodes.ANEWARRAY, "[I"));
        code.add(new FieldInsnNode(Opcodes.PUTSTATIC, name, blocksField, "[[I"));
        for (int i = 0; i < chunkHolders.size(); i++) {
            Vm2Chunk chunk = chunkHolders.get(i);
            code.add(new FieldInsnNode(Opcodes.GETSTATIC, name, blocksField, "[[I"));
            AsmUtil.pushInt(code, i);
            code.add(new FieldInsnNode(Opcodes.GETSTATIC, chunk.className, chunk.fieldName, "[I"));
            code.add(new InsnNode(Opcodes.AASTORE));
        }
        code.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 0;
        // array + index + two literal halves of an opaque value
        clinit.maxStack = 4;
        node.methods.add(clinit);
        context.classes().addGenerated(node);
        context.stats().add("virtualization.holders", 1);
        return new Vm2Holder(name, metaField, blocksField);
    }

    /**
     * Creates a synthetic class exposing one {@code int[]} payload block.
     *
     * <p>The values are stored as a printable-ASCII string constant and decoded
     * by a constant-size {@code <clinit>} loop (see
     * {@link Vm2Format#encodeBlock(int[])}). This keeps the class file cost near
     * six bytes per payload int instead of a constant-pool entry plus store
     * bytecode for every element.</p>
     *
     * @param prefix internal-name prefix (for example {@code "umbra/runtime/X"})
     * @param statKey statistics counter incremented for the new holder
     */
    /**
     * Cantrip variant of a VM2 payload chunk: the encrypted values are
     * reconstructed by the injected Cantrip dialect interpreter instead of a
     * plain decode loop. The program is split into class-file-safe chunks
     * (each far below the 65535-byte UTF-8 constant limit).
     */
    private Vm2Chunk createCantripChunk(PassContext context, int[] values, String name,
                                          String field, ClassNode node, String statKey) {
        if (cantripInterpreter == null) {
            cantripInterpreter = TemplateInjector.inject(context.classes(), UmbraCantrip.class,
                    "umbra/runtime/B", context.config().seed());
        }
        List<String> chunks = encodeCantripChunks(values);
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList code = clinit.instructions;
        AsmUtil.pushInt(code, chunks.size());
        code.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"));
        for (int i = 0; i < chunks.size(); i++) {
            code.add(new InsnNode(Opcodes.DUP));
            AsmUtil.pushInt(code, i);
            code.add(new LdcInsnNode(chunks.get(i)));
            code.add(new InsnNode(Opcodes.AASTORE));
        }
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cantripInterpreter,
                "run", "([Ljava/lang/String;)[I", false));
        code.add(new FieldInsnNode(Opcodes.PUTSTATIC, name, field, "[I"));
        code.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 0;
        clinit.maxStack = 5;
        node.methods.add(clinit);
        context.classes().addGenerated(node);
        context.stats().add(statKey, 1);
        cantripPrograms++;
        cantripChunks += chunks.size();
        cantripValues += values.length;
        return new Vm2Chunk(name, field);
    }

    /** Encodes integer values as {@code ~value;.} Cantrip dialect chunks. */
    private static List<String> encodeCantripChunks(int[] values) {
        List<String> chunks = new ArrayList<String>();
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < values.length; i++) {
            String token = "~" + values[i] + ";.";
            if (current.length() + token.length() > 6000) {
                chunks.add(current.toString());
                current.setLength(0);
            }
            current.append(token);
        }
        if (current.length() > 0) {
            chunks.add(current.toString());
        }
        return chunks;
    }

    private Vm2Chunk createVm2Chunk(PassContext context, int[] values, String prefix,
                                    String statKey) {
        String name = uniqueClassName(context, prefix);
        NameGenerator names = new NameGenerator(context.random(), "");
        String field = names.random(5);
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC;
        node.name = name;
        node.superName = "java/lang/Object";
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                field, "[I", null, null));
        if (cantripEnabled && (cantripLevel >= 2 || !prefix.startsWith("umbra/runtime/M"))) {
            return createCantripChunk(context, values, name, field, node, statKey);
        }
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList code = clinit.instructions;
        String encoded = Vm2Format.encodeBlock(values);
        if (encoded.length() > 60000) {
            throw new IllegalStateException("VM2 block string too large");
        }
        AsmUtil.pushInt(code, values.length);
        code.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        code.add(new FieldInsnNode(Opcodes.PUTSTATIC, name, field, "[I"));
        code.add(new LdcInsnNode(encoded));
        code.add(new VarInsnNode(Opcodes.ASTORE, 2));
        AsmUtil.pushInt(code, 0);
        code.add(new VarInsnNode(Opcodes.ISTORE, 0));
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        code.add(loop);
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        code.add(new FieldInsnNode(Opcodes.GETSTATIC, name, field, "[I"));
        code.add(new InsnNode(Opcodes.ARRAYLENGTH));
        code.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        // decode six chars: ((c0) | c1<<6 | c2<<12 | c3<<18 | c4<<24 | c5<<30)
        AsmUtil.pushInt(code, 0);
        code.add(new VarInsnNode(Opcodes.ISTORE, 3));
        for (int group = 0; group < Vm2Format.CHARS_PER_INT; group++) {
            code.add(new VarInsnNode(Opcodes.ILOAD, 3));
            code.add(new VarInsnNode(Opcodes.ALOAD, 2));
            code.add(new VarInsnNode(Opcodes.ILOAD, 0));
            AsmUtil.pushInt(code, Vm2Format.CHARS_PER_INT);
            code.add(new InsnNode(Opcodes.IMUL));
            AsmUtil.pushInt(code, group);
            code.add(new InsnNode(Opcodes.IADD));
            code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                    "charAt", "(I)C", false));
            AsmUtil.pushInt(code, Vm2Format.BLOCK_BASE);
            code.add(new InsnNode(Opcodes.ISUB));
            if (group > 0) {
                AsmUtil.pushInt(code, group * 6);
                code.add(new InsnNode(Opcodes.ISHL));
            }
            code.add(new InsnNode(Opcodes.IOR));
            code.add(new VarInsnNode(Opcodes.ISTORE, 3));
        }
        code.add(new FieldInsnNode(Opcodes.GETSTATIC, name, field, "[I"));
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 3));
        code.add(new InsnNode(Opcodes.IASTORE));
        code.add(new IincInsnNode(0, 1));
        code.add(new JumpInsnNode(Opcodes.GOTO, loop));
        code.add(end);
        code.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 4;
        clinit.maxStack = 6;
        node.methods.add(clinit);
        context.classes().addGenerated(node);
        context.stats().add(statKey, 1);
        return new Vm2Chunk(name, field);
    }

    /** Pushes an int through a degenerate XOR expression to hide the literal. */
    private static void pushOpaqueInt(PassContext context, InsnList code, int value) {
        if ((context.random().nextInt() & 3) == 0) {
            AsmUtil.pushInt(code, value);
            return;
        }
        int left = context.random().nextInt();
        int right = value ^ left;
        AsmUtil.pushInt(code, left);
        AsmUtil.pushInt(code, right);
        code.add(new InsnNode(Opcodes.IXOR));
    }

    private String uniqueClassName(PassContext context, String prefix) {
        String candidate;
        int guard = 0;
        do {
            candidate = prefix + Long.toHexString(context.random().nextLong());
            if (++guard > 100000) {
                throw new IllegalStateException("unable to allocate a unique VM2 holder name");
            }
        } while (context.classes().getClass(candidate) != null);
        return candidate;
    }

    /** Rewrites the method body into "build locals, call interpreter, unbox". */
    private void rewriteVm2(PassContext context, ClassNode owner, MethodNode method,
                            Vm2Holder holder, boolean hasOpcodeMap) {
        int argumentSlots = argumentSlots(method);
        int localsSlot = Math.max(1, Math.max(method.maxLocals, argumentSlots));
        int resultSlot = localsSlot + 1;
        InsnList out = new InsnList();
        AsmUtil.pushInt(out, localsSlot);
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        out.add(new VarInsnNode(Opcodes.ASTORE, localsSlot));

        boolean isStatic = (method.access & Opcodes.ACC_STATIC) != 0;
        if (!isStatic) {
            out.add(new VarInsnNode(Opcodes.ALOAD, localsSlot));
            AsmUtil.pushInt(out, 0);
            out.add(new VarInsnNode(Opcodes.ALOAD, 0));
            out.add(new InsnNode(Opcodes.AASTORE));
        }
        int slot = isStatic ? 0 : 1;
        for (Type argument : Type.getArgumentTypes(method.desc)) {
            out.add(new VarInsnNode(Opcodes.ALOAD, localsSlot));
            AsmUtil.pushInt(out, slot);
            out.add(new VarInsnNode(AsmUtil.loadOpcode(argument), slot));
            boxVm2(out, argument);
            out.add(new InsnNode(Opcodes.AASTORE));
            slot += argument.getSize();
        }

        out.add(new FieldInsnNode(Opcodes.GETSTATIC, holder.name, holder.metaField, "[I"));
        if (hasOpcodeMap && vm2MapHolder != null) {
            out.add(new FieldInsnNode(Opcodes.GETSTATIC, vm2MapHolder.className,
                    vm2MapHolder.fieldName, "[I"));
        } else {
            out.add(new InsnNode(Opcodes.ACONST_NULL));
        }
        out.add(new FieldInsnNode(Opcodes.GETSTATIC, holder.name, holder.blocksField, "[[I"));
        out.add(new VarInsnNode(Opcodes.ALOAD, localsSlot));
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, vm2Engine, "run", VM2_DESC, false));

        Type returns = Type.getReturnType(method.desc);
        if (returns.getSort() == Type.VOID) {
            out.add(new InsnNode(Opcodes.POP));
            out.add(new InsnNode(Opcodes.RETURN));
        } else {
            out.add(new VarInsnNode(Opcodes.ASTORE, resultSlot));
            emitVm2Unbox(out, returns, resultSlot);
        }

        method.instructions = out;
        method.maxLocals = localsSlot + 2;
        method.maxStack = 6;
        method.tryCatchBlocks = new ArrayList<org.objectweb.asm.tree.TryCatchBlockNode>();
        method.localVariables = null;
        method.visibleLocalVariableAnnotations = null;
        method.invisibleLocalVariableAnnotations = null;
    }

    private static void boxVm2(InsnList out, Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT:
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf",
                        "(I)Ljava/lang/Integer;", false));
                break;
            case Type.LONG:
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf",
                        "(J)Ljava/lang/Long;", false));
                break;
            case Type.FLOAT:
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf",
                        "(F)Ljava/lang/Float;", false));
                break;
            case Type.DOUBLE:
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf",
                        "(D)Ljava/lang/Double;", false));
                break;
            default:
                break;
        }
    }

    private static void emitVm2Unbox(InsnList out, Type returns, int resultSlot) {
        switch (returns.getSort()) {
            case Type.BOOLEAN: {
                LabelNode numeric = new LabelNode();
                out.add(new VarInsnNode(Opcodes.ALOAD, resultSlot));
                out.add(new InsnNode(Opcodes.DUP));
                out.add(new TypeInsnNode(Opcodes.INSTANCEOF, "java/lang/Boolean"));
                out.add(new JumpInsnNode(Opcodes.IFEQ, numeric));
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Boolean"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Boolean",
                        "booleanValue", "()Z", false));
                out.add(new InsnNode(Opcodes.IRETURN));
                out.add(numeric);
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number",
                        "intValue", "()I", false));
                out.add(new InsnNode(Opcodes.IRETURN));
                break;
            }
            case Type.CHAR: {
                LabelNode numeric = new LabelNode();
                out.add(new VarInsnNode(Opcodes.ALOAD, resultSlot));
                out.add(new InsnNode(Opcodes.DUP));
                out.add(new TypeInsnNode(Opcodes.INSTANCEOF, "java/lang/Character"));
                out.add(new JumpInsnNode(Opcodes.IFEQ, numeric));
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Character"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Character",
                        "charValue", "()C", false));
                out.add(new InsnNode(Opcodes.IRETURN));
                out.add(numeric);
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number",
                        "intValue", "()I", false));
                out.add(new InsnNode(Opcodes.IRETURN));
                break;
            }
            case Type.BYTE:
            case Type.SHORT:
            case Type.INT:
                out.add(new VarInsnNode(Opcodes.ALOAD, resultSlot));
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number",
                        "intValue", "()I", false));
                out.add(new InsnNode(Opcodes.IRETURN));
                break;
            case Type.LONG:
                out.add(new VarInsnNode(Opcodes.ALOAD, resultSlot));
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number",
                        "longValue", "()J", false));
                out.add(new InsnNode(Opcodes.LRETURN));
                break;
            case Type.FLOAT:
                out.add(new VarInsnNode(Opcodes.ALOAD, resultSlot));
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number",
                        "floatValue", "()F", false));
                out.add(new InsnNode(Opcodes.FRETURN));
                break;
            case Type.DOUBLE:
                out.add(new VarInsnNode(Opcodes.ALOAD, resultSlot));
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number",
                        "doubleValue", "()D", false));
                out.add(new InsnNode(Opcodes.DRETURN));
                break;
            default:
                out.add(new VarInsnNode(Opcodes.ALOAD, resultSlot));
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, returns.getSort() == Type.ARRAY
                        ? returns.getDescriptor() : returns.getInternalName()));
                out.add(new InsnNode(Opcodes.ARETURN));
                break;
        }
    }

    /** Growable int array used while translating one method. */
    private static final class IntList {
        private int[] values = new int[64];
        private int size;

        void add(int value) {
            if (size == values.length) {
                int[] grown = new int[values.length * 2];
                System.arraycopy(values, 0, grown, 0, values.length);
                values = grown;
            }
            values[size++] = value;
        }

        int get(int index) {
            return values[index];
        }

        int size() {
            return size;
        }

        int[] toArray() {
            int[] out = new int[size];
            System.arraycopy(values, 0, out, 0, size);
            return out;
        }
    }

    private static final class Payload {
        final IntList code = new IntList();
        final List<Object> constants = new ArrayList<Object>();
        final Map<Object, Integer> constantIndex = new LinkedHashMap<Object, Integer>();
        final Map<String, Integer> refIndex = new LinkedHashMap<String, Integer>();
        String[] refs = new String[0];

        int constant(Object value) {
            Integer index = constantIndex.get(value);
            if (index == null) {
                index = Integer.valueOf(constants.size());
                constants.add(value);
                constantIndex.put(value, index);
            }
            return index.intValue();
        }

        int ref(String value) {
            Integer index = refIndex.get(value);
            if (index == null) {
                index = Integer.valueOf(refIndex.size());
                refIndex.put(value, index);
            }
            return index.intValue();
        }

        void finish() {
            refs = refIndex.keySet().toArray(new String[0]);
        }

        int slots() {
            return code.size() + constants.size() + refs.length;
        }
    }

    private static final class Shield {
        final String holderName;
        final String keyField;
        final int[] keys;

        Shield(String holderName, String keyField, int[] keys) {
            this.holderName = holderName;
            this.keyField = keyField;
            this.keys = keys;
        }
    }

    private static final class Holder {
        final String name;
        final String codeField;
        final String constantField;
        final String refField;

        Holder(String name, String codeField, String constantField, String refField) {
            this.name = name;
            this.codeField = codeField;
            this.constantField = constantField;
            this.refField = refField;
        }
    }

    /** One translated exception handler, still referencing ASM label nodes. */
    private static final class HandlerEntry {
        final LabelNode start;
        final LabelNode end;
        final LabelNode handler;
        final String type;

        HandlerEntry(LabelNode start, LabelNode end, LabelNode handler, String type) {
            this.start = start;
            this.end = end;
            this.handler = handler;
            this.type = type;
        }
    }

    /** Call-site handles of a VM2 payload holder. */
    private static final class Vm2Holder {
        final String name;
        final String metaField;
        final String blocksField;

        Vm2Holder(String name, String metaField, String blocksField) {
            this.name = name;
            this.metaField = metaField;
            this.blocksField = blocksField;
        }
    }

    /** One encrypted payload block holder class. */
    private static final class Vm2Chunk {
        final String className;
        final String fieldName;

        Vm2Chunk(String className, String fieldName) {
            this.className = className;
            this.fieldName = fieldName;
        }
    }

    private static final class SkipMethod extends RuntimeException {
        SkipMethod(String message) {
            super(message);
        }
    }
}
