package io.umbra.core.pass.impl.integer.masks;

import io.umbra.core.pass.impl.integer.IntMask;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;

/**
 * {@code num * value}.
 *
 * <p>Port of {@code polymorph/semi/impl/MulMask.java}: multiplication has no
 * inverse over {@code int} (it is lossy modulo {@code 2^32}), so
 * {@code applyInverse} is missing on purpose and the family is decode-only.
 * {@code insns()} is {@code push(value); IMUL}.</p>
 */
public final class MulMask extends IntMask<MulMask> {
    @Override
    public int apply(int num) {
        return num * value;
    }

    @Override
    public InsnList insns() {
        InsnList list = new InsnList();
        AsmUtil.pushInt(list, value);
        list.add(new InsnNode(Opcodes.IMUL));
        return list;
    }

    @Override
    public String family() {
        return "mul";
    }
}
