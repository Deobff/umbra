package io.umbra.core.pass.impl.optimize;

import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Instruction predicates and small helpers shared by the body optimization passes.
 *
 * <p>Everything here is a pure read of the instruction list; nothing mutates the
 * method it is handed.</p>
 */
public final class InsnSupport implements Opcodes {

    private InsnSupport() {
    }

    /** True when the method contains JSR/JSR_W/RET, i.e. the legacy subroutine form. */
    public static boolean hasJsrRet(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode == JSR || opcode == 201 /* JSR_W */ || opcode == RET) {
                return true;
            }
        }
        return false;
    }

    /** True for ICONST_M1..ICONST_5, BIPUSH, SIPUSH and LDC of an Integer. */
    public static boolean isIntPush(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= ICONST_M1 && opcode <= ICONST_5) {
            return true;
        }
        if (insn instanceof IntInsnNode) {
            IntInsnNode node = (IntInsnNode) insn;
            return node.getOpcode() == BIPUSH || node.getOpcode() == SIPUSH;
        }
        if (insn instanceof LdcInsnNode) {
            return ((LdcInsnNode) insn).cst instanceof Integer;
        }
        return false;
    }

    /** The value pushed by an {@link #isIntPush(AbstractInsnNode)} instruction. */
    public static int intPushValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= ICONST_M1 && opcode <= ICONST_5) {
            return opcode - ICONST_0;
        }
        if (insn instanceof IntInsnNode) {
            return ((IntInsnNode) insn).operand;
        }
        return ((Integer) ((LdcInsnNode) insn).cst).intValue();
    }

    public static boolean isPseudo(AbstractInsnNode insn) {
        return insn.getOpcode() < 0;
    }

    public static AbstractInsnNode nextReal(AbstractInsnNode insn) {
        AbstractInsnNode next = insn.getNext();
        while (next != null && isPseudo(next)) {
            next = next.getNext();
        }
        return next;
    }

    public static AbstractInsnNode previousReal(AbstractInsnNode insn) {
        AbstractInsnNode previous = insn.getPrevious();
        while (previous != null && isPseudo(previous)) {
            previous = previous.getPrevious();
        }
        return previous;
    }

    /**
     * True when the instruction pushes exactly one value without any observable
     * side effect (constant, local read, or an LDC that is neither a handle nor a
     * dynamic constant).
     */
    public static boolean isSimpleProducer(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode == ACONST_NULL) {
            return true;
        }
        if (opcode >= ICONST_M1 && opcode <= ICONST_5) {
            return true;
        }
        if (opcode == LCONST_0 || opcode == LCONST_1) {
            return true;
        }
        if (opcode >= FCONST_0 && opcode <= FCONST_2) {
            return true;
        }
        if (opcode == DCONST_0 || opcode == DCONST_1) {
            return true;
        }
        if (opcode == BIPUSH || opcode == SIPUSH) {
            return true;
        }
        if (opcode >= ILOAD && opcode <= ALOAD) {
            return true;
        }
        if (insn instanceof LdcInsnNode) {
            Object constant = ((LdcInsnNode) insn).cst;
            // Handles and dynamic constants can run code; a class literal can throw
            // NoClassDefFoundError, which is observable. Only plain values are safe.
            return !(constant instanceof ConstantDynamic) && !(constant instanceof Handle)
                    && !(constant instanceof Type);
        }
        return false;
    }

    /** First local slot past the declared parameters. */
    public static int firstFreeParamSlot(MethodNode method) {
        int slot = (method.access & ACC_STATIC) == 0 ? 1 : 0;
        Type[] arguments = Type.getArgumentTypes(method.desc);
        for (int i = 0; i < arguments.length; i++) {
            slot += arguments[i].getSize();
        }
        return slot;
    }

    public static boolean isStore(int opcode) {
        return opcode >= ISTORE && opcode <= ASTORE;
    }

    public static boolean isLoad(int opcode) {
        return opcode >= ILOAD && opcode <= ALOAD;
    }
}
