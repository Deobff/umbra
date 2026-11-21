package io.umbra.core.pass.impl.opaque;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Donor {@code SwitchSeedLoaderRenderer}'s dispatch idea, moved where it keeps
 * the stack map frames valid: the XOR value is routed through a
 * {@code tableswitch} over {@code (a ^ b) & 3}, so there is no straight-line
 * {@code a ^ b} left to pattern-match and every case rebuilds the same result
 * with a different operator.
 */
public final class SwitchSeedLoader implements SeedLoader {

    @Override
    public String name() {
        return "switch";
    }

    @Override
    public boolean needsHelper() {
        return true;
    }

    @Override
    public void install(ClassState state) {
        InsnList body = new InsnList();
        LabelNode case0 = new LabelNode();
        LabelNode case1 = new LabelNode();
        LabelNode case2 = new LabelNode();
        LabelNode case3 = new LabelNode();

        body.add(new VarInsnNode(Opcodes.ILOAD, 0));
        body.add(new VarInsnNode(Opcodes.ILOAD, 1));
        body.add(new InsnNode(Opcodes.IXOR));
        body.add(new VarInsnNode(Opcodes.ISTORE, 2));
        body.add(new VarInsnNode(Opcodes.ILOAD, 2));
        body.add(new InsnNode(Opcodes.ICONST_3));
        body.add(new InsnNode(Opcodes.IAND));
        body.add(new TableSwitchInsnNode(0, 3, case3,
                new LabelNode[] { case0, case1, case2, case3 }));

        body.add(case0);
        body.add(new VarInsnNode(Opcodes.ILOAD, 2));
        body.add(new InsnNode(Opcodes.ICONST_0));
        body.add(new InsnNode(Opcodes.IXOR));
        body.add(new InsnNode(Opcodes.IRETURN));

        body.add(case1);
        body.add(new VarInsnNode(Opcodes.ILOAD, 2));
        body.add(new InsnNode(Opcodes.ICONST_0));
        body.add(new InsnNode(Opcodes.IADD));
        body.add(new InsnNode(Opcodes.IRETURN));

        body.add(case2);
        body.add(new VarInsnNode(Opcodes.ILOAD, 2));
        body.add(new InsnNode(Opcodes.ICONST_0));
        body.add(new InsnNode(Opcodes.IOR));
        body.add(new InsnNode(Opcodes.IRETURN));

        body.add(case3);
        body.add(new VarInsnNode(Opcodes.ILOAD, 2));
        body.add(new InsnNode(Opcodes.ICONST_0));
        body.add(new InsnNode(Opcodes.ISUB));
        body.add(new InsnNode(Opcodes.IRETURN));
        XorHelper.install(state, body, 3, 2);
    }

    @Override
    public void pushValue(InsnList out, ClassState state, int local, SeedSite site) {
        Operands.push(out, state, local, site);
        state.pushConstant(out, site.mask());
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, state.node().name,
                state.helperName(), "(II)I", false));
    }

    @Override
    public void materialize(ClassState state) {
    }
}
