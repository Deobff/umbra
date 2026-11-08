package io.umbra.core.util.mba;

public class GaussUtils {
    public static void swapRows(double[][] a, double[] b, int i, int j) {
        double[] row = a[i];
        a[i] = a[j];
        a[j] = row;
        double tmp = b[i];
        b[i] = b[j];
        b[j] = tmp;
    }

    private static void subtractRow(double[][] a, double[] b, int i, int j, double multiplier) {
        for (int k = 0; k < a.length; k++) {
            a[j][k] -= a[i][k] * multiplier;
        }
        b[j] -= b[i] * multiplier;
    }

    public static double[] solveLinearSystem(double[][] a, double[] b) {
        int n = a.length;
        if (b.length != n) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < n; i++) {
            int maxRow = i;
            for (int j = i + 1; j < n; j++) {
                if (Math.abs(a[j][i]) > Math.abs(a[maxRow][i])) {
                    maxRow = j;
                }
            }
            swapRows(a, b, i, maxRow);
            for (int j = i + 1; j < n; j++) {
                subtractRow(a, b, i, j, a[j][i] / a[i][i]);
            }
        }
        for (int i = n - 1; i > 0; i--) {
            for (int j = i - 1; j >= 0; j--) {
                subtractRow(a, b, i, j, a[j][i] / a[i][i]);
            }
        }
        double[] result = new double[n];
        for (int i = 0; i < n; i++) {
            result[i] = b[i] / a[i][i];
        }
        return result;
    }

    public static double[][] T(double[][] input) {
        int n = input.length;
        double[][] result = new double[n][n];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                result[i][j] = input[j][i];
            }
        }
        return result;
    }
}
