package io.umbra.core.pass.impl.opaque;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Donor {@code SwitchJumpRenderer}: the low bit of {@code state ^ seed} selects
 * the body through a two-entry {@code tableswitch}; the other entry is the dead
 * block.
 */
public final class SwitchGuard implements PredicateRenderer {

    @Override
    public String name() {
        return "switch";
    }

    @Override
    public void emitGuard(InsnList out, InsnList deferred, MethodNode method, ClassState state,
                          int local, int value, boolean junk, boolean throwDead) {
        LabelNode body = new LabelNode();
        LabelNode dead = new LabelNode();
        out.add(new VarInsnNode(Opcodes.ILOAD, local));
        AsmUtil.pushInt(out, value);
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new InsnNode(Opcodes.ICONST_1));
        out.add(new InsnNode(Opcodes.IAND));
        out.add(new TableSwitchInsnNode(0, 1, dead, new LabelNode[] { body, dead }));
        out.add(dead);
        DeadCode.emitBody(out, state, body, junk, throwDead);
        out.add(body);
    }
}
