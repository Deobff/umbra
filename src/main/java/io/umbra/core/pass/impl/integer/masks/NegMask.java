package io.umbra.core.pass.impl.integer.masks;

import io.umbra.core.pass.impl.integer.IntMask;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;

/**
 * {@code -num}.
 *
 * <p>Port of {@code polymorph/semi/impl/NegMask.java}: the mask carries no
 * operand and {@code insns()} is a bare {@code INEG}. The inverse is
 * {@code -num} as well (negation is its own inverse), which the donor leaves to
 * the base class; is the only operand-free member of the family set.</p>
 */
public final class NegMask extends IntMask<NegMask> {
    @Override
    public int apply(int num) {
        return -num;
    }

    @Override
    public int applyInverse(int num) {
        return -num;
    }

    @Override
    public InsnList insns() {
        InsnList list = new InsnList();
        list.add(new InsnNode(Opcodes.INEG));
        return list;
    }

    @Override
    public String family() {
        return "neg";
    }
}
