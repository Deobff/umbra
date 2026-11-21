package io.umbra.core.pass.impl.integer.masks;

import io.umbra.core.pass.impl.integer.IntMask;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;

/**
 * {@code num >> value}.
 *
 * <p>Port of {@code polymorph/semi/impl/RightShiftMask.java}: an arithmetic
 * right shift drops the low bits, so {@code applyInverse} is missing on purpose.
 * {@code insns()} is {@code push(value); ISHR}.</p>
 */
public final class RightShiftMask extends IntMask<RightShiftMask> {
    @Override
    public int apply(int num) {
        return num >> value;
    }

    @Override
    public InsnList insns() {
        InsnList list = new InsnList();
        AsmUtil.pushInt(list, value);
        list.add(new InsnNode(Opcodes.ISHR));
        return list;
    }

    @Override
    public String family() {
        return "shr";
    }
}
