package demo;

/**
 * Exception coverage: custom checked exceptions, try/catch/finally ordering,
 * nested handlers, standard runtime exceptions, try-with-resources and
 * exception re-wrapping.
 */
public final class ExceptionSuite {

    private ExceptionSuite() {
    }

    public static void run() throws DemoException {
        boolean caught = false;
        int finallyRuns = 0;
        try {
            divide(10, 0);
        } catch (DemoException expected) {
            caught = true;
            Checks.eq(expected.code(), DemoException.CODE_RANGE, "custom exception code");
            Checks.check(expected.getMessage().contains("zero"), "custom exception message");
        } finally {
            finallyRuns++;
        }
        Checks.check(caught, "custom exception was caught");
        Checks.eq(finallyRuns, 1, "finally ran once");

        int nestedFinally = 0;
        try {
            try {
                throw new DemoException(DemoException.CODE_STATE, "nested");
            } finally {
                nestedFinally = 1;
            }
        } catch (DemoException nested) {
            Checks.eq(nested.code(), DemoException.CODE_STATE, "nested code");
        }
        Checks.eq(nestedFinally, 1, "inner finally ran before outer catch");

        int steps = 0;
        try {
            steps = 1;
            throw new IllegalStateException("boom");
        } catch (IllegalStateException runtime) {
            steps = 2;
            Checks.eq(runtime.getMessage(), "boom", "runtime exception message");
        } finally {
            steps = steps * 10 + 3;
        }
        Checks.eq(steps, 23, "try catch finally order");

        int standardCaught = 0;
        try {
            int[] array = new int[2];
            array[3] = 1;
        } catch (ArrayIndexOutOfBoundsException expected) {
            standardCaught++;
        }
        try {
            Object value = null;
            value.toString();
        } catch (NullPointerException expected) {
            standardCaught++;
        }
        try {
            int divisor = 0;
            int quotient = 5 / divisor;
            Checks.eq(quotient, 0, "unreachable division");
        } catch (ArithmeticException expected) {
            standardCaught++;
        }
        Checks.eq(standardCaught, 3, "standard exceptions caught");

        Tracker tracker = new Tracker("t1");
        try (Tracker resource = tracker) {
            resource.use();
        }
        Checks.check(tracker.closed, "try-with-resources closed");
        Checks.eq(tracker.uses, 1, "try-with-resources used");

        try {
            try {
                divide(1, 0);
            } catch (DemoException inner) {
                throw new DemoException(DemoException.CODE_STATE, "wrapped:" + inner.code());
            }
        } catch (DemoException wrapped) {
            Checks.eq(wrapped.code(), DemoException.CODE_STATE, "wrapped code");
            Checks.check(wrapped.getMessage().startsWith("wrapped:"), "wrapped message");
        }

        Checks.eq(safeParse("42"), 42, "safe parse ok");
        Checks.eq(safeParse("not-a-number"), -1, "safe parse failure");
    }

    static int divide(int dividend, int divisor) throws DemoException {
        if (divisor == 0) {
            throw new DemoException(DemoException.CODE_RANGE, "division by zero");
        }
        return dividend / divisor;
    }

    static int safeParse(String text) {
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException expected) {
            return -1;
        }
    }

    static final class Tracker implements AutoCloseable {

        private final String name;
        int uses;
        boolean closed;

        Tracker(String name) {
            this.name = name;
        }

        void use() {
            uses++;
        }

        @Override
        public void close() {
            closed = true;
        }

        @Override
        public String toString() {
            return "Tracker(" + name + ")";
        }
    }
}
