package io.umbra.core.pass.impl.opaque;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

/** Builds the {@code (II)I} helper bodies every seed loader except {@code internal} uses. */
final class XorHelper {

    private XorHelper() {
    }

    /** The donor's {@code StaticSeedLoaderRenderer} body: {@code return a ^ b} (argument order random). */
    static InsnList plain(boolean swapped) {
        InsnList out = new InsnList();
        out.add(new VarInsnNode(Opcodes.ILOAD, swapped ? 1 : 0));
        out.add(new VarInsnNode(Opcodes.ILOAD, swapped ? 0 : 1));
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new InsnNode(Opcodes.IRETURN));
        return out;
    }

    static void install(ClassState state, InsnList body, int maxLocals, int maxStack,
                        TryCatchBlockNode... handlers) {
        MethodNode helper = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                state.helperName(), "(II)I", null, null);
        helper.instructions.add(body);
        if (handlers != null && handlers.length > 0) {
            helper.tryCatchBlocks = new java.util.ArrayList<TryCatchBlockNode>();
            for (TryCatchBlockNode handler : handlers) {
                helper.tryCatchBlocks.add(handler);
            }
        }
        helper.maxLocals = maxLocals;
        helper.maxStack = maxStack;
        state.installHelper(helper);
    }
}
