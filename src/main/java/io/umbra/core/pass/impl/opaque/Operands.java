package io.umbra.core.pass.impl.opaque;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.VarInsnNode;

/** Pushes the run-time half of a {@link SeedSite}. */
final class Operands {

    private Operands() {
    }

    static void push(InsnList out, ClassState state, int local, SeedSite site) {
        switch (site.operand) {
            case SeedSite.OPERAND_ZERO:
                out.add(new InsnNode(Opcodes.ICONST_0));
                return;
            case SeedSite.OPERAND_PRIVATE:
                state.pushMethodPrivate(out, site.privateValue);
                return;
            default:
                out.add(new VarInsnNode(Opcodes.ILOAD, local));
        }
    }
}
