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

    private static final Object LOCK = new Object();

    private static long state = seed();

    private static int toggle;

    private static native long nativeNext(long state);

    private static int nativeState;

    private static int nativeTries;

    private UmbraOtp() {
    }

    public static long next() {
        synchronized (LOCK) {
            return advance();
        }
    }

    public static int carrier() {
        synchronized (LOCK) {
            long value = advance();
            int mixed = (int) (value ^ (value >>> 32));
            return (mixed & ~1) | toggle;
        }
    }

    public static long peek() {
        synchronized (LOCK) {
            return state;
        }
    }

    public static int bit() {
        synchronized (LOCK) {
            return toggle;
        }
    }

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

        value ^= 0x9E3779B97F4A7C15L;
        value = nativeMix(value);
        state = value;
        toggle ^= 1;
        return value;
    }

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
