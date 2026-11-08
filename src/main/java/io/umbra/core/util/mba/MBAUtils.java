package io.umbra.core.util.mba;

public class MBAUtils {
    private static final double[] xor = {0, 1, 1, 0};
    private static final double[] xand = {0, 0, 1, 0};
    private static final double[] or = {0, 1, 1, 1};
    private static final double[] one = {1, 1, 1, 1};
    private static final double[] xnot = {0, 1, 0, 0};
    private static final double[] xi = {0, 0, 1, 1};
    private static final double[] yi = {0, 1, 0, 1};
    private static final int[] cache;

    static {
        cache = genMbaExpr0();
    }

    public static int[] genMbaExpr() {
        return cache;
    }

    private static int[] genMbaExpr0() {
        int shuffle1 = RandomUtils.getRandomInt(-256, 256);
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
        int yTest = RandomUtils.getRandomInt(-5000, 5000);
        int expected = yTest * 5;
        int actual = res[0] * (xTest & ~yTest) + res[1] * (xTest | yTest)
                + res[2] * (xTest ^ yTest) - res[3] * (~xTest & yTest);
        if (expected != actual) {
            throw new IllegalStateException("WTF - Wrong expression");
        }
        return res;
    }
}
