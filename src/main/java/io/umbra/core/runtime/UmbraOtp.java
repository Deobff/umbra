package io.umbra.core.runtime;

/**
 * One-time-program state shared by the protected methods of a program.
 *
 * <p>This class is a runtime template: {@code DefaultRuntimeSupport} copies its
 * bytecode into the protected JAR under a randomized name and
 * {@code FlowObfuscationPass} calls {@link #carrier()} at the entry of every
 * protected method. The state therefore advances once per protected call, which
 * is what makes the injected guards one-time: the carrier the opaque predicates
 * are built on, the branch that selects the junk path and the value a guard
 * compares all differ between two invocations with identical arguments, so an
 * execution recorded by a red team cannot be replayed against the next call.</p>
 *
 * <p>The low bit returned by {@link #carrier()} strictly alternates, so the
 * guard path is guaranteed to differ on two consecutive protected calls instead
 * of merely usually differing. The high bits keep the full 64-bit state mixed in,
 * so the existing opaque predicates still see a value that no decompiler can
 * fold.</p>
 *
 * <p>The class is deliberately self-contained (JDK types only, no nested or
 * anonymous classes, no references to other Umbra classes) because the injection
 * path remaps it as a single class file.</p>
 */
public final class UmbraOtp {

    /** Serializes the advance; also the only lock the runtime helpers share. */
    private static final Object LOCK = new Object();

    /** Current one-time state. */
    private static long state = seed();

    /** Low bit exposed to the guards; flips on every advance. */
    private static int toggle;

    /**
     * Native advance bound by the generated guard library
     * ({@code RegisterNatives} from its {@code JNI_OnLoad}). Unregistered when the
     * build has no native guard, in which case the Java path is used.
     */
    private static native long nativeNext(long state);

    /** {@code 0} = not tried yet, {@code 1} = linked, {@code 2} = Java only. */
    private static int nativeState;

    /** Bounded retries while the guard library has not been loaded yet. */
    private static int nativeTries;

    private UmbraOtp() {
    }

    /**
     * Advances the one-time state.
     *
     * @return the new state, never {@code 0} after the first advance
     */
    public static long next() {
        synchronized (LOCK) {
            return advance();
        }
    }

    /**
     * Advances the one-time state and returns the carrier used by the guards.
     *
     * <p>Bit 0 alternates between calls, the remaining bits are the mixed state,
     * so a method that guards on {@code carrier & 1} provably takes the other
     * path on its next invocation.</p>
     *
     * @return carrier value for this call
     */
    public static int carrier() {
        synchronized (LOCK) {
            long value = advance();
            int mixed = (int) (value ^ (value >>> 32));
            return (mixed & ~1) | toggle;
        }
    }

    /** Current state without advancing (used by the self-test). */
    public static long peek() {
        synchronized (LOCK) {
            return state;
        }
    }

    /** Low bit of the last advance without advancing again (used by the self-test). */
    public static int bit() {
        synchronized (LOCK) {
            return toggle;
        }
    }

    /**
     * Whether the advance is currently computed by the native guard
     * ({@code 1}) or by the Java fallback ({@code 0}). Self-test hook only: the
     * value says nothing about the state itself.
     */
    public static int nativeBound() {
        synchronized (LOCK) {
            return nativeState == 1 ? 1 : 0;
        }
    }

    private static long advance() {
        long value = state;
        value ^= value << 13;
        value ^= value >>> 7;
        value ^= value << 17;
        // A zero state would be a xorshift fixed point; the odd constant keeps
        // every state non-zero, including a seed that came out as zero.
        value ^= 0x9E3779B97F4A7C15L;
        value = nativeMix(value);
        state = value;
        toggle ^= 1;
        return value;
    }

    /**
     * Hands the advance to the guard library when it registered
     * {@code nativeNext}, so the state transition is not a plain Java xorshift a
     * patcher can reimplement. The guard loads lazily (its {@code JNI_OnLoad} runs
     * when the native library is loaded), so the first protected calls can happen
     * before the binding exists: those are retried a bounded number of times and
     * then the Java path is kept for good. Nothing escapes, because this runs
     * inside the entry prelude of every protected method.
     */
    private static long nativeMix(long value) {
        if (nativeState == 2 || (nativeState == 0 && nativeTries >= 8)) {
            return value;
        }
        try {
            long mixed = nativeNext(value);
            nativeState = 1;
            return mixed == 0L ? value : mixed;
        } catch (Throwable unavailable) {
            if (nativeState == 1) {
                nativeState = 2;
            } else {
                nativeTries++;
            }
            return value;
        }
    }

    private static long seed() {
        long value = System.nanoTime();
        value ^= ((long) (Thread.currentThread().getId() & 0xFFFFL)) << 48;
        value ^= ((long) System.identityHashCode(Thread.currentThread())) << 16;
        value ^= 0x2545F4914F6CDD1DL;
        return value == 0L ? 0x2545F4914F6CDD1DL : value;
    }
}
