package io.umbra.core.pass.impl.opaque;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Donor {@code UnconditionalJumpRenderer}: the guard jumps straight to the body
 * when the state matches and the dead block (which jumps back) is only reachable
 * through the unconditional branch below it.
 */
public final class UnconditionalGuard implements PredicateRenderer {

    @Override
    public String name() {
        return "unconditional";
    }

    @Override
    public void emitGuard(InsnList out, InsnList deferred, MethodNode method, ClassState state,
                          int local, int value, boolean junk, boolean throwDead) {
        LabelNode body = new LabelNode();
        LabelNode dead = new LabelNode();
        out.add(new VarInsnNode(Opcodes.ILOAD, local));
        AsmUtil.pushInt(out, value);
        out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, body));
        out.add(new JumpInsnNode(Opcodes.GOTO, dead));
        out.add(dead);
        DeadCode.emitBody(out, state, body, junk, throwDead);
        out.add(body);
    }
}
