package io.umbra.core.pass.impl.numberhash;

/**
 * The exact hash formulas ported from the reference implementation, kept separate from
 * the invertible codecs.
 *
 * <p>The reference uses three different hashes in three places and the port has to
 * be honest about which of them can be used as an <em>encoder</em>. A codec must
 * be a bijection on {@code int}; a hash does not have to be, and two of the
 * reference's are not:</p>
 *
 * <ul>
 *   <li>{@link #skidStrict(int)} - {@code x ^ (x >>> 16)}. This is the constant
 *       side of {@code the hash formula} and the whole of
 *       {@code the IntelliJ-style hash transformer.hash(int)}. It is an involution
 *       ({@code h(h(x)) == x}), therefore a bijection on the full 32-bit domain.
 *       <b>Usable as a codec.</b></li>
 *   <li>{@link #skidDonorEmitted(int)} - {@code x ^ (x >>> 29)}. This is what
 *       {@code the block-level hash}
 *       actually emitted, while its constant side computed the 16-shift form.
 *       The mismatch is a real reference bug (a switch keyed by one would never
 *       match the other), so the emitted form is recorded here but never used.
 *       It is still a bijection on its own - the problem is that it disagrees
 *       with {@link #skidStrict(int)}.</li>
 *   <li>{@link #bitwiseStrict(int)} -
 *       {@code ((x &amp; (7 &lt;&lt; 29)) &gt;&gt; 29) | (x &lt;&lt; 3)}. The
 *       {@code >>} is an <b>arithmetic</b> shift, so for every negative input
 *       the mask result is negative and sign-extends: the map collapses large
 *       parts of the domain onto {@code -1} and friends. It agrees with
 *       {@code Integer.rotateLeft(x, 3)} only on {@code [0, 2^31)}.
 *       <b>Not usable as a codec</b>; the port uses a real 32-bit rotate
 *       ({@link #rotateLeft3(int)}) instead, which is what the reference meant.</li>
 *   <li>{@link #legacyStrict(int)} -
 *       {@code (((x * 31) &gt;&gt;&gt; 4) % x) ^ (x &gt;&gt;&gt; 16)} with the
 *       reference's {@code x == 0} branch. {@code >>> 4} throws away four bits and
 *       {@code % x} is not injective, so this is not a bijection; it also throws
 *       {@link ArithmeticException} at {@code x == 0} unless the branch is kept.
 *       <b>Not usable as a codec</b>; the port uses the invertible subset of the
 *       same constant family ({@code *31}, a rotation instead of the truncating
 *       shift, and the 16-shift perturbation).</li>
 * </ul>
 */
public final class Hashes {

    /** Codec validity: every {@code int} round-trips. */
    public static final String DOMAIN_FULL = "full int domain (bijective)";

    private Hashes() {
    }

    /** {@code the hash formula} / {@code the IntelliJ-style hash transformer.hash(int)}. */
    public static int skidStrict(int value) {
        return value ^ (value >>> 16);
    }

    /** The expression {@code the reference hash transformer} emitted (shift 29, inconsistent). */
    public static int skidDonorEmitted(int value) {
        return value ^ (value >>> 29);
    }

    /** {@code the IntelliJ-style hash transformer.hash(int)} - identical to {@link #skidStrict(int)}. */
    public static int intellijStrict(int value) {
        return value ^ (value >>> 16);
    }

    /** {@code BitwiseHashTransformer.hash(int)}, exactly as the reference wrote it. */
    public static int bitwiseStrict(int value) {
        return ((value & (7 << 29)) >> 29) | (value << 3);
    }

    /** What the reference's bitwise hash was supposed to be: a full 32-bit rotation. */
    public static int rotateLeft3(int value) {
        return Integer.rotateLeft(value, 3);
    }

    /** {@code LegacyHashTransformer.hash(int)} with its {@code x == 0} guard. */
    public static int legacyStrict(int value) {
        if (value == 0) {
            return 0;
        }
        return (((value * 31) >>> 4) % value) ^ (value >>> 16);
    }

    /**
     * Build-time check that a hash is one-to-one on a sample of the domain.
     *
     * <p>Used by the self-test to record which reference formulas can be codecs.
     * The sample is checked through a 2^16-element table plus random values, so
     * a collision inside the sample is reported as a hard failure. Absence of a
     * collision in a sample is not a proof, which is why the codecs themselves
     * are proven by the involution/algebra of their steps instead.</p>
     *
     * @param inputs distinct inputs
     * @param hashes {@code hashes[i] == h(inputs[i])}
     * @return {@code null} when no collision was found, otherwise a collision
     *         pair {@code {a, b}} with {@code a != b} and {@code h(a) == h(b)}
     */
    public static int[] findCollision(int[] inputs, int[] hashes) {
        java.util.HashMap<Integer, Integer> seen = new java.util.HashMap<Integer, Integer>();
        for (int i = 0; i < inputs.length; i++) {
            Integer previous = seen.put(Integer.valueOf(hashes[i]), Integer.valueOf(inputs[i]));
            if (previous != null && previous.intValue() != inputs[i]) {
                return new int[] { previous.intValue(), inputs[i] };
            }
        }
        return null;
    }
}
