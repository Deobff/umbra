package demo;

/**
 * Custom checked exception used by the demo self-checks.
 *
 * <p>The demo exercises custom exception construction, propagation, catching
 * and re-wrapping. An obfuscator must preserve the exception hierarchy, the
 * exception table and the message plumbing.</p>
 */
public class DemoException extends Exception {

    /** A self-check assertion failed. */
    public static final int CODE_CHECK = 1;
    /** A value was outside the accepted range. */
    public static final int CODE_RANGE = 2;
    /** An object was used in the wrong state. */
    public static final int CODE_STATE = 3;

    private static final long serialVersionUID = 1L;

    private final int code;

    public DemoException(int code, String message) {
        super(message);
        this.code = code;
    }

    public int code() {
        return code;
    }
}
