package io.umbra.core.pass.impl.integer.masks;

import io.umbra.core.pass.impl.integer.IntMask;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;

/**
 * {@code num | value}.
 *
 * <p>Port of {@code polymorph/semi/impl/OrMask.java}: OR only sets bits, so
 * {@code applyInverse} is missing on purpose. {@code insns()} is
 * {@code push(value); IOR}.</p>
 */
public final class OrMask extends IntMask<OrMask> {
    @Override
    public int apply(int num) {
        return num | value;
    }

    @Override
    public InsnList insns() {
        InsnList list = new InsnList();
        AsmUtil.pushInt(list, value);
        list.add(new InsnNode(Opcodes.IOR));
        return list;
    }

    @Override
    public String family() {
        return "or";
    }
}
