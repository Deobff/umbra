package demo;

/**
 * int/long/double arithmetic coverage: overflow, shifts, bit operations,
 * integer and long constants, floating point comparison, rounding and loops
 * that compute classic integer sequences.
 */
public final class MathSuite {

    /** Distinctive constants: integer encryption evidence looks for these. */
    private static final int INT_MAGIC = 0x5EED;
    private static final long LONG_MAGIC = 987654321987L;
    private static final double DOUBLE_MAGIC = 2.718281828459045;

    private MathSuite() {
    }

    public static void run() throws DemoException {
        int x = 17;
        int y = 5;
        Checks.eq(x + y, 22, "int add");
        Checks.eq(x - y, 12, "int sub");
        Checks.eq(x * y, 85, "int mul");
        Checks.eq(x / y, 3, "int div truncates");
        Checks.eq(x % y, 2, "int mod");
        Checks.eq(-x / y, -3, "negative div truncates toward zero");
        Checks.eq(-x % y, -2, "negative mod keeps sign");
        Checks.eq(1 << 10, 1024, "left shift");
        Checks.eq(-8 >> 1, -4, "arithmetic right shift");
        Checks.eq(-8 >>> 28, 15, "logical right shift");
        Checks.eq(0xF0 & 0x3C, 0x30, "bit and");
        Checks.eq(0xF0 | 0x0F, 0xFF, "bit or");
        Checks.eq(0xAA ^ 0xFF, 0x55, "bit xor");
        Checks.eq(~0, -1, "bit not");
        Checks.eq(Integer.bitCount(0xABCD), 10, "bit count");
        Checks.eq(Integer.highestOneBit(100), 64, "highest one bit");
        Checks.eq(Integer.MAX_VALUE + 1, Integer.MIN_VALUE, "int overflow wraps");
        Checks.eq(Math.abs(-42), 42, "abs");
        Checks.eq(Math.max(3, 9), 9, "max");
        Checks.eq(Math.min(-3, 9), -3, "min");
        Checks.eq(INT_MAGIC, 24301, "int magic constant");

        Checks.eq(1L << 40, 1099511627776L, "long shift");
        Checks.eq(LONG_MAGIC / 1000L, 987654321L, "long division");
        Checks.eq(LONG_MAGIC % 1000L, 987L, "long remainder");
        Checks.eq(Long.MAX_VALUE + 1L, Long.MIN_VALUE, "long overflow wraps");
        Checks.eq(Long.bitCount(0xFL), 4, "long bit count");
        Checks.eq(LONG_MAGIC, 987654321987L, "long magic constant");

        Checks.check(Math.abs((0.1 + 0.2) - 0.3) < 1e-9, "floating point tolerance");
        Checks.eq(Math.sqrt(144.0), 12.0, 1e-12, "sqrt");
        Checks.eq(Math.pow(2.0, 10.0), 1024.0, 1e-9, "pow");
        Checks.eq(Math.hypot(3.0, 4.0), 5.0, 1e-12, "hypot");
        Checks.eq(7.0 / 2.0, 3.5, 0.0, "double division");
        Checks.eq(Math.floor(-2.5), -3.0, 0.0, "floor");
        Checks.eq(Math.ceil(-2.5), -2.0, 0.0, "ceil");
        Checks.eq(Math.round(2.5), 3L, "round");
        Checks.eq(Math.round(-2.5), -2L, "round negative");
        Checks.eq(Double.isNaN(0.0 / 0.0), true, "NaN");
        Checks.eq(Double.isInfinite(1.0 / 0.0), true, "infinity");
        Checks.eq(Double.compare(1.5, 2.5) < 0, true, "double compare");
        Checks.eq(DOUBLE_MAGIC, 2.718281828459045, 1e-15, "double magic constant");

        Checks.eq(factorial(10), 3628800L, "factorial 10");
        Checks.eq(factorial(20), 2432902008176640000L, "factorial 20");
        Checks.eq(fibonacci(30), 832040L, "fibonacci 30");
        Checks.eq(gcd(48, 18), 6, "gcd");
        Checks.eq(power(3, 7), 2187, "integer power loop");

        int accumulated = 0;
        for (int i = 1; i <= 50; i++) {
            accumulated += i * i;
        }
        Checks.eq(accumulated, 42925, "sum of squares 1..50");
    }

    static long factorial(int n) {
        long result = 1L;
        for (int i = 2; i <= n; i++) {
            result *= i;
        }
        return result;
    }

    static long fibonacci(int n) {
        long a = 0L;
        long b = 1L;
        for (int i = 0; i < n; i++) {
            long next = a + b;
            a = b;
            b = next;
        }
        return a;
    }

    static int gcd(int a, int b) {
        while (b != 0) {
            int remainder = a % b;
            a = b;
            b = remainder;
        }
        return a;
    }

    static int power(int base, int exponent) {
        int result = 1;
        int factor = base;
        int remaining = exponent;
        while (remaining > 0) {
            if ((remaining & 1) != 0) {
                result *= factor;
            }
            factor *= factor;
            remaining >>= 1;
        }
        return result;
    }
}
