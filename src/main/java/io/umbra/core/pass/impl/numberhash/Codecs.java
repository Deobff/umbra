package io.umbra.core.pass.impl.numberhash;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * The codec catalogue and the per-class pool the pass draws sites from.
 *
 * <p>Every codec offered here is a bijection on the full {@code int} domain, so
 * an encoded literal is never ambiguous. Two reference formulas are <em>not</em>
 * bijections and are therefore exposed as hashes only (see {@link Hashes}):
 * the arithmetic-shift bitwise hash collapses negatives, and the legacy hash is
 * neither injective nor defined at zero.</p>
 *
 * <table summary="codecs">
 * <tr><th>name</th><th>program</th><th>note</th></tr>
 * <tr><td>{@code skid}</td><td>{@code x ^ (x >>> 16)}</td>
 *     <td>the reference's the reference/IntelliJ constant formula; an involution</td></tr>
 * <tr><td>{@code bitwise}</td><td>{@code rotateLeft(x, 3)}</td>
 *     <td>the reference's intent, with a real 32-bit rotate instead of {@code >>}</td></tr>
 * <tr><td>{@code intellij}</td><td>{@code 31 * x + c}</td>
 *     <td>IDEA's 31-multiplier idiom; the multiplier is odd so it is invertible</td></tr>
 * <tr><td>{@code legacy}</td><td>{@code rotl(31 * x, 4) + c} then
 *     {@code ^ (v >>> 16)}</td>
 *     <td>the invertible subset of the legacy constant family</td></tr>
 * <tr><td>{@code xor}</td><td>{@code x ^ key}</td>
 *     <td>{@code XorNumberTransformer}</td></tr>
 * <tr><td>{@code randomshift}</td><td>{@code x ^ firstSeed(chain)}</td>
 *     <td>{@code RandomShiftNumberTransformer}'s mask chain, folded at build time</td></tr>
 * <tr><td>{@code vm}</td><td>3..8 random reversible steps</td>
 *     <td>the "pure evaluation" codec: one build-time interpreter, one emitted
 *     straight-line program, optional byte-table lookup and spill local</td></tr>
 * </table>
 */
public final class Codecs {

    public static final String SKID = "skid";
    public static final String BITWISE = "bitwise";
    public static final String INTELLIJ = "intellij";
    public static final String LEGACY = "legacy";
    public static final String XOR = "xor";
    public static final String RANDOMSHIFT = "randomshift";
    public static final String VM = "vm";
    public static final String MIX = "mix";

    /** Order used by {@link #MIX} so a pool is balanced and reproducible. */
    public static final String[] MIX_ORDER = {
            SKID, BITWISE, INTELLIJ, LEGACY, VM, XOR, RANDOMSHIFT
    };

    private static final int TABLE_SIZE = 256;
    private static final int VM_MIN_STEPS = 3;
    private static final int VM_MAX_STEPS = 8;

    private Codecs() {
    }

    public static boolean known(String name) {
        if (name == null) {
            return false;
        }
        for (int i = 0; i < MIX_ORDER.length; i++) {
            if (MIX_ORDER[i].equals(name)) {
                return true;
            }
        }
        return false;
    }

    /** Normalises a spec to a known codec name or {@link #MIX}. */
    public static String canonical(String spec) {
        if (spec == null) {
            return MIX;
        }
        String trimmed = spec.trim().toLowerCase(Locale.ROOT);
        if (known(trimmed)) {
            return trimmed;
        }
        return MIX;
    }

    /**
     * Builds the pool for one class.
     *
     * @param spec   {@code numberHash.codec}: a single codec name or {@code mix}
     * @param random deterministic per-class stream
     * @param size   how many instances to draw (ignored for {@code mix}, which
     *               returns one of each codec in {@link #MIX_ORDER})
     */
    public static List<NumberHashCodec> pool(String spec, Random random, int size) {
        String canonical = canonical(spec);
        List<NumberHashCodec> pool = new ArrayList<NumberHashCodec>();
        if (MIX.equals(canonical)) {
            for (int i = 0; i < MIX_ORDER.length; i++) {
                pool.add(create(MIX_ORDER[i], random));
            }
            return pool;
        }
        int count = Math.max(1, size);
        for (int i = 0; i < count; i++) {
            pool.add(create(canonical, random));
        }
        return pool;
    }

    /** One codec instance. Unknown names fall back to {@link #MIX}'s first entry. */
    public static NumberHashCodec create(String name, Random random) {
        String canonical = canonical(name);
        if (SKID.equals(canonical)) {
            return new ProgramCodec(SKID, new Step[] { Step.xorshift16() }, true, Hashes.DOMAIN_FULL);
        }
        if (BITWISE.equals(canonical)) {
            return new ProgramCodec(BITWISE, new Step[] { Step.rotl(3) }, true,
                    "full int domain; the reference's arithmetic >> collapses negatives, a real rotate is used");
        }
        if (INTELLIJ.equals(canonical)) {
            return new ProgramCodec(INTELLIJ,
                    new Step[] { Step.mul(31), Step.add(random.nextInt()) }, true, Hashes.DOMAIN_FULL);
        }
        if (LEGACY.equals(canonical)) {
            return new ProgramCodec(LEGACY,
                    new Step[] { Step.mul(31), Step.rotl(4), Step.add(random.nextInt()), Step.xorshift16() },
                    true,
                    "invertible subset of the legacy family; the reference's >>> 4 and % x are dropped because "
                            + "they are not injective");
        }
        if (XOR.equals(canonical)) {
            return new ProgramCodec(XOR, new Step[] { Step.xor(random.nextInt()) }, true, Hashes.DOMAIN_FULL);
        }
        if (RANDOMSHIFT.equals(canonical)) {
            return new RandomShiftNumberCodec(random);
        }
        if (VM.equals(canonical)) {
            return new ProgramCodec(VM, vmProgram(random), true,
                    "full int domain; the program is one build-time interpreter and one emitted sequence");
        }
        return new ProgramCodec(SKID, new Step[] { Step.xorshift16() }, true, Hashes.DOMAIN_FULL);
    }

    /** The "pure evaluation" program: 3..8 reversible steps, at most one table. */
    static Step[] vmProgram(Random random) {
        int length = VM_MIN_STEPS + random.nextInt(VM_MAX_STEPS - VM_MIN_STEPS + 1);
        Step[] steps = new Step[length];
        boolean tableUsed = false;
        for (int i = 0; i < length; i++) {
            int kind = random.nextInt(9);
            if (kind == 8 && tableUsed) {
                kind = 0;
            }
            switch (kind) {
                case 0:
                    steps[i] = Step.xor(random.nextInt());
                    break;
                case 1:
                    steps[i] = Step.add(random.nextInt());
                    break;
                case 2:
                    steps[i] = Step.sub(random.nextInt());
                    break;
                case 3:
                    steps[i] = Step.mul(random.nextInt() | 1);
                    break;
                case 4:
                    steps[i] = Step.rotl(1 + random.nextInt(31));
                    break;
                case 5:
                    steps[i] = Step.rotr(1 + random.nextInt(31));
                    break;
                case 6:
                    steps[i] = Step.xorshift16();
                    break;
                case 7:
                    steps[i] = Step.neg();
                    break;
                case 8:
                default: {
                    String[] tables = tablePair(random);
                    steps[i] = Step.table(tables[0], tables[1]);
                    tableUsed = true;
                    break;
                }
            }
        }
        return steps;
    }

    /**
     * A 256-entry permutation and its inverse, encoded as two {@link String}s.
     * The low-byte table is a genuine lookup: it needs no field and no helper
     * method, which is why a site can carry one without creating class members.
     */
    public static String[] tablePair(Random random) {
        int[] forward = new int[TABLE_SIZE];
        for (int i = 0; i < TABLE_SIZE; i++) {
            forward[i] = i;
        }
        for (int i = TABLE_SIZE - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            int swap = forward[i];
            forward[i] = forward[j];
            forward[j] = swap;
        }
        char[] encode = new char[TABLE_SIZE];
        char[] decode = new char[TABLE_SIZE];
        for (int i = 0; i < TABLE_SIZE; i++) {
            encode[i] = (char) forward[i];
            decode[forward[i]] = (char) i;
        }
        return new String[] { new String(encode), new String(decode) };
    }
}
