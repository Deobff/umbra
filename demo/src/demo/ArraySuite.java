package demo;

import java.util.Arrays;

/**
 * Array coverage: 1D, 2D, jagged arrays, arraycopy, sorting and searching.
 */
public final class ArraySuite {

    private ArraySuite() {
    }

    public static void run() throws DemoException {
        int[] values = new int[]{3, 1, 4, 1, 5, 9, 2, 6};
        Checks.eq(values.length, 8, "1d length");
        int sum = 0;
        for (int value : values) {
            sum += value;
        }
        Checks.eq(sum, 31, "1d sum");
        Checks.eq(values[0], 3, "1d first");
        Checks.eq(values[7], 6, "1d last");

        int[] sorted = new int[values.length];
        System.arraycopy(values, 0, sorted, 0, values.length);
        Arrays.sort(sorted);
        Checks.eq(Arrays.toString(sorted), "[1, 1, 2, 3, 4, 5, 6, 9]", "sorted copy");
        Checks.eq(Arrays.binarySearch(sorted, 5), 5, "binary search");
        Checks.eq(Arrays.equals(sorted, new int[]{1, 1, 2, 3, 4, 5, 6, 9}), true, "arrays equals");

        int[][] grid = new int[3][4];
        for (int row = 0; row < grid.length; row++) {
            for (int column = 0; column < grid[row].length; column++) {
                grid[row][column] = row * 10 + column;
            }
        }
        int gridSum = 0;
        for (int row = 0; row < grid.length; row++) {
            for (int column = 0; column < grid[row].length; column++) {
                gridSum += grid[row][column];
            }
        }
        Checks.eq(gridSum, 138, "2d sum");
        Checks.eq(grid[1][2], 12, "2d cell");
        Checks.eq(grid.length, 3, "2d rows");
        Checks.eq(grid[2].length, 4, "2d columns");

        int[][] jagged = new int[][]{{1, 2}, {3, 4, 5}, {6}};
        int jaggedSum = 0;
        for (int[] row : jagged) {
            for (int value : row) {
                jaggedSum += value;
            }
        }
        Checks.eq(jaggedSum, 21, "jagged sum");
        Checks.eq(jagged[1].length, 3, "jagged row length");

        String[] names = new String[]{"umbra", "demo", "qa"};
        Checks.eq(String.join("+", names), "umbra+demo+qa", "string array join");
        names[1] = "suite";
        Checks.eq(names[1], "suite", "string array write");

        Object[] objects = new Object[]{Integer.valueOf(1), "two", Double.valueOf(3.0)};
        Checks.eq(objects.length, 3, "object array");
        Checks.eq((Integer) objects[0], 1, "object array element");

        int[] copy = Arrays.copyOf(sorted, 4);
        Checks.eq(Arrays.toString(copy), "[1, 1, 2, 3]", "copyOf");
        int[] range = Arrays.copyOfRange(sorted, 2, 6);
        Checks.eq(Arrays.toString(range), "[2, 3, 4, 5]", "copyOfRange");
        Arrays.fill(copy, 7);
        Checks.eq(copy[0] + copy[3], 14, "fill");
    }
}
