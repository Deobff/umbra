package io.umbra.core.pass.impl.salt;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Bytecode shapes and small utilities shared by the salt pass and its dispatcher.
 *
 * <p>The central shape is the self-cancelling mask of the reference
 * implementation ({@code (S &amp; m) ^ ((S &amp; m) ^ salt)}). The reference
 * computes the second term from the build-time value of the class salt, which
 * cancels only while the runtime value still equals it. This port reads the
 * class salt field <em>twice</em> instead: both terms are then produced by the
 * same runtime value, so the result is the constant {@code salt} even when the
 * field was written with a different value (a replayed or patched dispatcher
 * therefore cannot change any method salt), and it degrades to the same
 * expression when the field holds the planned value.</p>
 */
public final class SaltCode implements Opcodes {

    /** FNV-1a 64-bit offset basis, mirrored in the generated hasher. */
    public static final long FNV_OFFSET = 0xcbf29ce484222325L;

    /** FNV-1a 64-bit prime, mirrored in the generated hasher. */
    public static final long FNV_PRIME = 0x100000001b3L;

    public static final String MAP_DESC = "Ljava/util/Map;";
    public static final String MAP_NAME = "java/util/Map";
    public static final String HASH_MAP = "java/util/HashMap";
    public static final String LONG_NAME = "java/lang/Long";
    public static final String INT_NAME = "java/lang/Integer";
    public static final String STRING_NAME = "java/lang/String";
    public static final String OBJECT_NAME = "java/lang/Object";
    public static final String CLASS_NAME = "java/lang/Class";
    public static final String THROWABLE = "java/lang/Throwable";
    public static final String STACK_ELEMENT = "java/lang/StackTraceElement";
    public static final String HANDLES = "java/lang/invoke/MethodHandles";
    public static final String LOOKUP = "java/lang/invoke/MethodHandles$Lookup";

    /** {@code (Object, int) -> int} of both retriever methods. */
    public static final String RETRIEVE_DESC = "(Ljava/lang/Object;I)I";

    private SaltCode() {
    }

    /**
     * Emits {@code (F & mask) ^ ((F & mask) ^ value)} where {@code F} is a static
     * int field: always {@code value}, independent of what the field holds.
     */
    public static void emitSelfCancelField(InsnList list, String owner, String field, int mask, int value) {
        list.add(new FieldInsnNode(GETSTATIC, owner, field, "I"));
        AsmUtil.pushInt(list, mask);
        list.add(new InsnNode(IAND));
        list.add(new FieldInsnNode(GETSTATIC, owner, field, "I"));
        AsmUtil.pushInt(list, mask);
        list.add(new InsnNode(IAND));
        AsmUtil.pushInt(list, value);
        list.add(new InsnNode(IXOR));
        list.add(new InsnNode(IXOR));
    }

    /**
     * Emits {@code (L & mask) ^ ((L & mask) ^ value)} where {@code L} is a caller
     * local holding the caller salt: the call-site half of the parameter salt.
     */
    public static void emitSelfCancelLocal(InsnList list, int local, int mask, int value) {
        list.add(new VarInsnNode(ILOAD, local));
        AsmUtil.pushInt(list, mask);
        list.add(new InsnNode(IAND));
        list.add(new VarInsnNode(ILOAD, local));
        AsmUtil.pushInt(list, mask);
        list.add(new InsnNode(IAND));
        AsmUtil.pushInt(list, value);
        list.add(new InsnNode(IXOR));
        list.add(new InsnNode(IXOR));
    }

    /**
     * Emits the strict-dispatcher variant of the class-salt store:
     * {@code PUTSTATIC this.salt = Dispatcher.retrieve(MethodHandles.lookup().lookupClass(), fake)}.
     */
    public static void emitDispatcherStore(InsnList list, SaltPlan.DispatcherNames names,
                                           int fakeValue, String owner, String field) {
        list.add(new MethodInsnNode(INVOKESTATIC, HANDLES, "lookup",
                "()L" + LOOKUP + ";", false));
        list.add(new MethodInsnNode(INVOKEVIRTUAL, LOOKUP, "lookupClass", "()Ljava/lang/Class;", false));
        AsmUtil.pushInt(list, fakeValue);
        list.add(new MethodInsnNode(INVOKESTATIC, names.className, names.retrieve, RETRIEVE_DESC, false));
        list.add(new FieldInsnNode(PUTSTATIC, owner, field, "I"));
    }

    /** Emits the constant fallback store used when the dispatcher is disabled. */
    public static void emitConstantStore(InsnList list, int value, String owner, String field) {
        AsmUtil.pushInt(list, value);
        list.add(new FieldInsnNode(PUTSTATIC, owner, field, "I"));
    }

    /** Build-time mirror of the generated FNV-1a hasher; keys the dispatcher maps. */
    public static long fnv(String text) {
        long hash = FNV_OFFSET;
        for (int i = 0; i < text.length(); i++) {
            hash ^= text.charAt(i);
            hash *= FNV_PRIME;
        }
        return hash;
    }

    /** Appends one {@code int} parameter: {@code (...)X} becomes {@code (...I)X}. */
    public static String appendInt(String desc) {
        int close = desc.indexOf(')');
        if (close < 0) {
            return desc;
        }
        return desc.substring(0, close) + "I" + desc.substring(close);
    }

    /** Descriptor slots consumed by the receiver plus the declared parameters. */
    public static int argumentSlots(MethodNode method) {
        int slots = (method.access & ACC_STATIC) == 0 ? 1 : 0;
        Type[] arguments = Type.getArgumentTypes(method.desc);
        for (Type argument : arguments) {
            slots += argument.getSize();
        }
        return slots;
    }

    public static int argumentSlots(String desc, boolean isStatic) {
        int slots = isStatic ? 0 : 1;
        Type[] arguments = Type.getArgumentTypes(desc);
        for (Type argument : arguments) {
            slots += argument.getSize();
        }
        return slots;
    }

    /**
     * Moves every local slot at or above {@code from} by {@code delta} so an
     * appended trailing parameter has room, and keeps the local-variable table in
     * step. The new parameter occupies slot {@code from}, exactly where the first
     * body local used to start.
     */
    public static void shiftLocalSlots(MethodNode method, int from, int delta) {
        if (method.instructions != null) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof VarInsnNode) {
                    VarInsnNode variable = (VarInsnNode) insn;
                    if (variable.var >= from) {
                        variable.var += delta;
                    }
                } else if (insn instanceof IincInsnNode) {
                    IincInsnNode increment = (IincInsnNode) insn;
                    if (increment.var >= from) {
                        increment.var += delta;
                    }
                }
            }
        }
        if (method.localVariables != null) {
            for (LocalVariableNode local : method.localVariables) {
                if (local.index >= from) {
                    local.index += delta;
                }
            }
        }
        method.maxLocals += delta;
    }
}
