package io.umbra.core.pass.impl.opaque;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Donor {@code InternalSeedLoaderRenderer} used as a guard shape: the seed is
 * handed to the per-class {@code (II)I} helper instead of being compared inline,
 * so the check itself is a call with two opaque operands.
 */
public final class InternalGuard implements PredicateRenderer {

    @Override
    public String name() {
        return "internal";
    }

    @Override
    public void emitGuard(InsnList out, InsnList deferred, MethodNode method, ClassState state,
                          int local, int value, boolean junk, boolean throwDead) {
        String helper = state.ensureXorHelper();
        LabelNode body = new LabelNode();
        out.add(new VarInsnNode(Opcodes.ILOAD, local));
        AsmUtil.pushInt(out, value);
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, state.node().name, helper, "(II)I", false));
        out.add(new JumpInsnNode(Opcodes.IFEQ, body));
        DeadCode.emitBody(out, state, body, junk, throwDead);
        out.add(body);
    }
}
