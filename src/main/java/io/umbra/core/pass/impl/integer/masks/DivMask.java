package io.umbra.core.pass.impl.integer.masks;

import io.umbra.core.pass.impl.integer.IntMask;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;

/**
 * {@code num / value}.
 *
 * <p>Port of {@code polymorph/semi/impl/DivMask.java}: division truncates and is
 * therefore not invertible, so {@code applyInverse} is missing on purpose.
 * {@code insns()} is {@code push(value); IDIV}; a zero operand throws
 * {@link ArithmeticException} on both sides, exactly like the donor.</p>
 */
public final class DivMask extends IntMask<DivMask> {
    @Override
    public int apply(int num) {
        return num / value;
    }

    @Override
    public InsnList insns() {
        InsnList list = new InsnList();
        AsmUtil.pushInt(list, value);
        list.add(new InsnNode(Opcodes.IDIV));
        return list;
    }

    @Override
    public String family() {
        return "div";
    }
}
