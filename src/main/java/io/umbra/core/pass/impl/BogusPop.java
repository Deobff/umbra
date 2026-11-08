package io.umbra.core.pass.impl;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.HashSet;
import java.util.Set;

public final class BogusPop {

    private final ClassNode owner;
    private final Set<String> stubs = new HashSet<String>();

    public BogusPop(ClassNode owner) {
        this.owner = owner;
    }

    public MethodInsnNode generateDummyPop(Type type, long seed) {
        String name = "a" + Long.toHexString(seed * 0xC2B2AE3D27D4EB4FL + 0x165667B19E3779F9L);
        String desc = descriptor(type);
        ensureStub(name, desc, type);
        return new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, name, desc, false);
    }

    private void ensureStub(String name, String desc, Type argument) {
        String key = name + desc;
        if (!stubs.add(key)) {
            return;
        }
        MethodNode stub = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC
                | Opcodes.ACC_SYNTHETIC, name, desc, null, null);
        stub.instructions.add(new InsnNode(Opcodes.RETURN));
        stub.maxLocals = Math.max(1, argument.getSize());
        stub.maxStack = 0;
        owner.methods.add(stub);
    }

    private static String descriptor(Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN:
                return "(Z)V";
            case Type.CHAR:
                return "(C)V";
            case Type.BYTE:
                return "(B)V";
            case Type.SHORT:
                return "(S)V";
            case Type.INT:
                return "(I)V";
            case Type.FLOAT:
                return "(F)V";
            case Type.LONG:
                return "(J)V";
            case Type.DOUBLE:
                return "(D)V";
            case Type.ARRAY:
            case Type.OBJECT:
                return "(" + type.getDescriptor() + ")V";
            default:
                throw new RuntimeException("Can't generate dummy pop insn");
        }
    }

    public static boolean supported(Type type) {
        int sort = type.getSort();
        return sort != Type.VOID && sort != Type.METHOD;
    }
}
