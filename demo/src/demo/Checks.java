package demo;

/**
 * Assertion helpers for the demo self-checks.
 *
 * <p>Every assertion increments a global counter, so {@link Main} can prove
 * that the whole suite actually executed instead of silently short-circuiting
 * after a transformation bug.</p>
 */
public final class Checks {

    private static int performed;

    private Checks() {
    }

    public static int count() {
        return performed;
    }

    public static void check(boolean condition, String what) throws DemoException {
        performed++;
        if (!condition) {
            throw new DemoException(DemoException.CODE_CHECK, "self-check failed: " + what);
        }
    }

    public static void eq(int actual, int expected, String what) throws DemoException {
        performed++;
        if (actual != expected) {
            throw new DemoException(DemoException.CODE_CHECK,
                    what + ": expected int " + expected + " but was " + actual);
        }
    }

    public static void eq(long actual, long expected, String what) throws DemoException {
        performed++;
        if (actual != expected) {
            throw new DemoException(DemoException.CODE_CHECK,
                    what + ": expected long " + expected + " but was " + actual);
        }
    }

    public static void eq(boolean actual, boolean expected, String what) throws DemoException {
        performed++;
        if (actual != expected) {
            throw new DemoException(DemoException.CODE_CHECK,
                    what + ": expected " + expected + " but was " + actual);
        }
    }

    public static void eq(double actual, double expected, double epsilon, String what)
            throws DemoException {
        performed++;
        if (Math.abs(actual - expected) > epsilon) {
            throw new DemoException(DemoException.CODE_CHECK,
                    what + ": expected double " + expected + " but was " + actual);
        }
    }

    public static void eq(String actual, String expected, String what) throws DemoException {
        performed++;
        if (actual == null ? expected != null : !actual.equals(expected)) {
            throw new DemoException(DemoException.CODE_CHECK,
                    what + ": expected \"" + expected + "\" but was \"" + actual + "\"");
        }
    }

    public static void notNull(Object value, String what) throws DemoException {
        performed++;
        if (value == null) {
            throw new DemoException(DemoException.CODE_CHECK, what + ": value is null");
        }
    }
}
