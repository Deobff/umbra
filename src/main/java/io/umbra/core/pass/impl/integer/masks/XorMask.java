package io.umbra.core.pass.impl.integer.masks;

import io.umbra.core.pass.impl.integer.IntMask;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;

/**
 * {@code num ^ value}.
 *
 * <p>Port of {@code polymorph/semi/impl/XorMask.java}: the inverse is the mask
 * itself, and {@code insns()} is {@code push(value); IXOR}.</p>
 */
public final class XorMask extends IntMask<XorMask> {
    @Override
    public int apply(int num) {
        return num ^ value;
    }

    @Override
    public int applyInverse(int num) {
        return num ^ value;
    }

    @Override
    public InsnList insns() {
        InsnList list = new InsnList();
        AsmUtil.pushInt(list, value);
        list.add(new InsnNode(Opcodes.IXOR));
        return list;
    }

    @Override
    public String family() {
        return "xor";
    }
}
