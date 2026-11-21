package io.umbra.core.util.mba;

/**
 * Coefficients of the four-term mixed-boolean-arithmetic identity
 * {@code a*(x&~y) + b*(x|y) + c*(x^y) - s*(~x&y) = 5y}.
 *
 * <p>The identity is solved from {@code s} with Gaussian elimination, so the
 * coefficient set is fully determined by one integer. It used to be drawn from
 * {@link java.util.concurrent.ThreadLocalRandom} inside a static initializer,
 * which made every run of the obfuscator emit a different {@code bipush}
 * coefficient set for the very same seed - the archive bytes were then not
 * reproducible at all, and {@code DeterminismTest} could not pin them.</p>
 *
 * <p>{@link #genMbaExpr(int)} therefore takes the draw explicitly: callers pass a
 * value from their own seeded stream, so the coefficients vary per site and per
 * build but are identical for a fixed {@code --seed}.</p>
 */
public final class MBAUtils {

    private static final double[] xor = {0, 1, 1, 0};
    private static final double[] xand = {0, 0, 1, 0};
    private static final double[] or = {0, 1, 1, 1};
    private static final double[] one = {1, 1, 1, 1};
    private static final double[] xnot = {0, 1, 0, 0};
    private static final double[] xi = {0, 0, 1, 1};
    private static final double[] yi = {0, 1, 0, 1};

    /** Coefficient set for the default draw, kept for source compatibility. */
    private static final int[] DEFAULT = genMbaExpr(0x5A17);

    private MBAUtils() {
    }

    /** The default coefficient set (draw {@code 0x5A17}). */
    public static int[] genMbaExpr() {
        return DEFAULT.clone();
    }

    /**
     * Solved coefficient set for one draw.
     *
     * @param seed any integer; callers pass a value from their seeded stream
     * @return {@code {a, b, c, s}} for the identity above
     */
    public static int[] genMbaExpr(int seed) {
        int shuffle1 = ((seed * 0x9E3779B1) >>> 24) - 128;
        double[] all = new double[4];
        for (int i = 0; i < 4; i++) {
            all[i] = xi[i] * 0 + yi[i] * 5;
        }
        for (int i = 0; i < 4; i++) {
            all[i] += xnot[i] * shuffle1;
        }
        double[][] matrix = {xand, or, xor, one};
        double[][] problem = GaussUtils.T(matrix);
        double[] result = GaussUtils.solveLinearSystem(problem, all);
        int[] res = new int[4];
        for (int i = 0; i < 4; i++) {
            res[i] = (int) Math.round(result[i]);
            if (Math.abs(result[i] - res[i]) > 1e-6) {
                throw new RuntimeException("Not integer" + result[i]);
            }
        }
        if (res[3] != 0) {
            throw new IllegalStateException("WTF - Non 0 constant in x-y expression");
        }
        res[3] = shuffle1;
        int xTest = Short.MAX_VALUE;
        int yTest = -5000 + Math.abs(seed % 10000);
        int expected = yTest * 5;
        int actual = res[0] * (xTest & ~yTest) + res[1] * (xTest | yTest)
                + res[2] * (xTest ^ yTest) - res[3] * (~xTest & yTest);
        if (expected != actual) {
            throw new IllegalStateException("WTF - Wrong expression");
        }
        return res;
    }
}
