package io.umbra.core.pass.impl.integer;

import org.objectweb.asm.tree.InsnList;

import java.util.Random;

/**
 * One polymorphic integer mask.
 *
 * <p>Port of {@code dev.lvstrng.aidsfuscator.polymorph.semi.IntMask}: a mask
 * owns one {@code int} operand and can (a) transform a value in Java, for the
 * build-time encoding step, and (b) emit the instruction sequence that applies
 * the very same transformation at runtime. Both sides must stay in sync: every
 * {@code apply} has a byte-for-byte counterpart in {@link #insns()}.</p>
 *
 * <p>The masks compose in insertion order: {@code stack.apply(x)} runs mask 1,
 * then mask 2, and so on; {@code stack.applyInverse(x)} runs them in reverse.
 * {@link #applyInverse} is only defined for the algebraically invertible
 * families ({@code add}, {@code sub}, {@code xor}, {@code neg}); the rest throw
 * {@link UnsupportedOperationException} exactly like the donor source, so a
 * caller that needs encoding must keep non-invertible families decode-only.</p>
 *
 * <p>The random stream is always supplied by the caller: the donor uses an
 * unseeded {@code SecureRandom}, which CONTRACT §0.6 forbids. Nothing in this
 * class draws randomness on its own.</p>
 *
 * @param <T> self type, so {@code new AddMask().ofValue(7)} stays an
 *            {@code AddMask}
 */
public abstract class IntMask<T extends IntMask<T>> {

    /** The mask operand, read by {@link #apply} and by {@link #insns()}. */
    protected int value;

    /** Applies the mask in Java. Mirrors the emitted bytecode exactly. */
    public abstract int apply(int num);

    /** Emits the runtime instruction sequence for this mask. */
    public abstract InsnList insns();

    /**
     * Undoes the mask in Java. Families without an inverse refuse here; the
     * caller is responsible for building encode-capable stacks from the
     * invertible families only.
     */
    public int applyInverse(int num) {
        throw new UnsupportedOperationException(
                "No implementation for applyInverse in class (" + getClass().getName() + ")");
    }

    public T ofValue(int value) {
        this.value = value;
        return self();
    }

    public T ofRandomValue(Random random, int bound) {
        this.value = random.nextInt(bound);
        return self();
    }

    public T ofRandomValue(Random random) {
        this.value = random.nextInt();
        return self();
    }

    @SuppressWarnings("unchecked")
    private T self() {
        return (T) this;
    }

    /** The mask operand. */
    public int value() {
        return value;
    }

    /** Short lowercase family tag, used by the statistics line. */
    public abstract String family();

    /**
     * Whether {@link #applyInverse} is implemented. Probed by calling it rather
     * than by a type switch, so a new mask family is classified automatically.
     */
    public boolean invertible() {
        try {
            applyInverse(0);
            return true;
        } catch (UnsupportedOperationException expected) {
            return false;
        }
    }

    @Override
    public String toString() {
        return family() + "(0x" + Integer.toHexString(value) + ")";
    }
}
