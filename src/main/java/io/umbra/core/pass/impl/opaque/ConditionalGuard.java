package io.umbra.core.pass.impl.opaque;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

/** Donor {@code ConditionalJumpRenderer}: {@code if ((state ^ seed) == 0) body else dead}. */
public final class ConditionalGuard implements PredicateRenderer {

    @Override
    public String name() {
        return "conditional";
    }

    @Override
    public void emitGuard(InsnList out, InsnList deferred, MethodNode method, ClassState state,
                          int local, int value, boolean junk, boolean throwDead) {
        LabelNode body = new LabelNode();
        out.add(new VarInsnNode(Opcodes.ILOAD, local));
        AsmUtil.pushInt(out, value);
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new JumpInsnNode(Opcodes.IFEQ, body));
        DeadCode.emitBody(out, state, body, junk, throwDead);
        out.add(body);
    }
}
