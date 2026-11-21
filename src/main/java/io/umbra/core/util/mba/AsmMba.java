package io.umbra.core.util.mba;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

public final class AsmMba {

    private AsmMba() {
    }

    public static InsnList generateMba(int slotX, int slotY, boolean isTrue, int seed) {
        final InsnList insnList = new InsnList();
        int[] mbaExpr = MBAUtils.genMbaExpr(seed);
        int opa = (seed % 1000) - 500;
        int opb = opa * 5 + (isTrue ? 1 : 0);
        int x = slotX;
        int y = slotY;
        insnList.add(new IntInsnNode(Opcodes.SIPUSH, 32767));
        insnList.add(new VarInsnNode(Opcodes.ISTORE, x));
        insnList.add(new IntInsnNode(Opcodes.SIPUSH, opa));
        insnList.add(new VarInsnNode(Opcodes.ISTORE, y));
        insnList.add(new IntInsnNode(Opcodes.BIPUSH, mbaExpr[0]));
        insnList.add(new VarInsnNode(Opcodes.ILOAD, x));
        insnList.add(new VarInsnNode(Opcodes.ILOAD, y));
        insnList.add(new InsnNode(Opcodes.ICONST_M1));
        insnList.add(new InsnNode(Opcodes.IXOR));
        insnList.add(new InsnNode(Opcodes.IAND));
        insnList.add(new InsnNode(Opcodes.IMUL));
        insnList.add(new IntInsnNode(Opcodes.BIPUSH, mbaExpr[1]));
        insnList.add(new VarInsnNode(Opcodes.ILOAD, x));
        insnList.add(new VarInsnNode(Opcodes.ILOAD, y));
        insnList.add(new InsnNode(Opcodes.IOR));
        insnList.add(new InsnNode(Opcodes.IMUL));
        insnList.add(new InsnNode(Opcodes.IADD));
        insnList.add(new IntInsnNode(Opcodes.BIPUSH, mbaExpr[2]));
        insnList.add(new VarInsnNode(Opcodes.ILOAD, x));
        insnList.add(new VarInsnNode(Opcodes.ILOAD, y));
        insnList.add(new InsnNode(Opcodes.IXOR));
        insnList.add(new InsnNode(Opcodes.IMUL));
        insnList.add(new InsnNode(Opcodes.IADD));
        insnList.add(new IntInsnNode(Opcodes.BIPUSH, mbaExpr[3]));
        insnList.add(new VarInsnNode(Opcodes.ILOAD, x));
        insnList.add(new InsnNode(Opcodes.ICONST_M1));
        insnList.add(new InsnNode(Opcodes.IXOR));
        insnList.add(new InsnNode(Opcodes.IMUL));
        insnList.add(new VarInsnNode(Opcodes.ILOAD, y));
        insnList.add(new InsnNode(Opcodes.IAND));
        insnList.add(new InsnNode(Opcodes.ISUB));
        insnList.add(new InsnNode(Opcodes.I2D));
        insnList.add(new IntInsnNode(Opcodes.SIPUSH, opb));
        insnList.add(new InsnNode(Opcodes.I2D));
        insnList.add(new InsnNode(Opcodes.DCMPL));
        return insnList;
    }

    public static InsnList generateTrue() {
        final InsnList insnList = new InsnList();
        insnList.add(new IntInsnNode(Opcodes.SIPUSH, 32767));
        insnList.add(new InsnNode(Opcodes.I2D));
        insnList.add(new IntInsnNode(Opcodes.SIPUSH, 32766));
        insnList.add(new InsnNode(Opcodes.I2D));
        insnList.add(new InsnNode(Opcodes.DCMPL));
        return insnList;
    }

    public static InsnList generateFalse() {
        final InsnList insnList = new InsnList();
        insnList.add(new IntInsnNode(Opcodes.SIPUSH, 32766));
        insnList.add(new InsnNode(Opcodes.I2D));
        insnList.add(new IntInsnNode(Opcodes.SIPUSH, 32767));
        insnList.add(new InsnNode(Opcodes.I2D));
        insnList.add(new InsnNode(Opcodes.DCMPL));
        return insnList;
    }

    public static boolean isJumpOrReturnOpcode(int opcode) {
        switch (opcode) {
            case Opcodes.ATHROW:
            case Opcodes.RETURN:
            case Opcodes.IRETURN:
            case Opcodes.LRETURN:
            case Opcodes.FRETURN:
            case Opcodes.DRETURN:
            case Opcodes.ARETURN:
            case Opcodes.GOTO:
            case Opcodes.LOOKUPSWITCH:
            case Opcodes.TABLESWITCH:
                return true;
            default:
                return false;
        }
    }
}
