package demo;

/**
 * Control-flow coverage: for/while/do-while/for-each, nested loops with
 * labelled break/continue, int/String/char/enum switches, if/else chains,
 * ternary operators and short-circuit boolean evaluation.
 */
public final class FlowSuite {

    private static int sideEffects;

    private FlowSuite() {
    }

    public static void run() throws DemoException {
        int sum = 0;
        for (int i = 1; i <= 100; i++) {
            sum += i;
        }
        Checks.eq(sum, 5050, "for loop sum");

        int digits = 0;
        int value = 123456;
        while (value > 0) {
            digits++;
            value /= 10;
        }
        Checks.eq(digits, 6, "while loop digits");

        int attempts = 0;
        do {
            attempts++;
        } while (attempts < 1);
        Checks.eq(attempts, 1, "do while executes once");

        Checks.eq(collatzSteps(27), 111, "collatz 27");

        int evenSum = 0;
        for (int i = 0; i <= 20; i++) {
            if (i % 2 != 0) {
                continue;
            }
            evenSum += i;
        }
        Checks.eq(evenSum, 110, "continue skips odd");

        int pairs = 0;
        for (int a = 1; a <= 5; a++) {
            for (int b = 1; b <= 5; b++) {
                if (a * b > 12) {
                    continue;
                }
                pairs++;
            }
        }
        Checks.eq(pairs, 19, "nested continue");

        int foundA = -1;
        int foundB = -1;
        outer:
        for (int a = 0; a < 30; a++) {
            for (int b = 0; b < 60; b++) {
                if (a + b == 42 && b == 2 * a) {
                    foundA = a;
                    foundB = b;
                    break outer;
                }
            }
        }
        Checks.eq(foundA, 14, "labelled break a");
        Checks.eq(foundB, 28, "labelled break b");

        Checks.eq(dayName(1), "mon", "switch int 1");
        Checks.eq(dayName(3), "wed", "switch int 3");
        Checks.eq(dayName(7), "sun", "switch int 7");
        Checks.eq(dayName(9), "unknown", "switch int default");

        Checks.eq(wordRank("alpha"), 1, "switch string alpha");
        Checks.eq(wordRank("beta"), 2, "switch string beta");
        Checks.eq(wordRank("gamma"), 3, "switch string gamma");
        Checks.eq(wordRank("delta"), 0, "switch string default");

        Checks.eq(charClass('x'), "letter", "switch char letter");
        Checks.eq(charClass('7'), "digit", "switch char digit");
        Checks.eq(charClass('#'), "other", "switch char other");

        Checks.eq(Color.values().length, 3, "enum values");
        Checks.eq(Color.BLUE.ordinal(), 2, "enum ordinal");
        Checks.eq(Color.BLUE.weight(), 3, "enum field");
        Checks.check(Color.valueOf("GREEN") == Color.GREEN, "enum valueOf");
        Checks.eq(temperature(Color.RED), "warm", "switch enum red");
        Checks.eq(temperature(Color.BLUE), "cold", "switch enum blue");

        int maximum = 0;
        int[] numbers = {4, 8, 15, 16, 23, 42};
        for (int number : numbers) {
            if (number > maximum) {
                maximum = number;
            }
        }
        Checks.eq(maximum, 42, "for each maximum");

        sideEffects = 0;
        boolean flag = false;
        if (flag && bump()) {
            Checks.check(false, "short circuit branch must not run");
        }
        Checks.eq(sideEffects, 0, "short circuit and");
        flag = true;
        if (flag || bump()) {
            sideEffects++;
        }
        Checks.eq(sideEffects, 1, "short circuit or");

        int clamped = clamp(120, 0, 100);
        Checks.eq(clamped, 100, "ternary clamp high");
        Checks.eq(clamp(-5, 0, 100), 0, "ternary clamp low");
        Checks.eq(clamp(50, 0, 100), 50, "ternary clamp middle");
    }

    static int collatzSteps(int start) {
        long value = start;
        int steps = 0;
        while (value != 1L) {
            if ((value & 1L) == 0L) {
                value /= 2L;
            } else {
                value = 3L * value + 1L;
            }
            steps++;
        }
        return steps;
    }

    static String dayName(int day) {
        switch (day) {
            case 1:
                return "mon";
            case 2:
                return "tue";
            case 3:
                return "wed";
            case 4:
                return "thu";
            case 5:
                return "fri";
            case 6:
                return "sat";
            case 7:
                return "sun";
            default:
                return "unknown";
        }
    }

    static int wordRank(String word) {
        switch (word) {
            case "alpha":
                return 1;
            case "beta":
                return 2;
            case "gamma":
                return 3;
            default:
                return 0;
        }
    }

    static String charClass(char value) {
        switch (value) {
            case 'a':
            case 'b':
            case 'c':
            case 'x':
            case 'y':
            case 'z':
                return "letter";
            case '0':
            case '1':
            case '7':
            case '9':
                return "digit";
            default:
                return "other";
        }
    }

    static String temperature(Color color) {
        switch (color) {
            case RED:
                return "warm";
            case GREEN:
                return "mild";
            case BLUE:
                return "cold";
            default:
                return "unknown";
        }
    }

    static int clamp(int value, int low, int high) {
        return value < low ? low : (value > high ? high : value);
    }

    static boolean bump() {
        sideEffects++;
        return true;
    }
}
