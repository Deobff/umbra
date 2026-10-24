package io.umbra.core.runtime.crypto;

/**
 * Background watchdog thread used by the runtime, integrity and anti-debug
 * guards.
 *
 * <p>Runtime template: no nested/anonymous classes, no references to other
 * Umbra classes. The guard starts it reflectively (the injected class name is
 * substituted into the guard's placeholder) and it calls a public static
 * no-argument method on the guard class every {@code delayMillis} (with a
 * randomized jitter of up to half the base interval) for at most
 * {@code maxIterations} iterations ({@code 0} = until the daemon JVM exits).
 * The randomized interval makes the periodic check harder to locate and patch
 * from a static analysis of the protected JAR, and the thread is a daemon so it
 * can never keep a normal program alive. The guards keep the single-instance
 * invariant themselves, so at most one watchdog thread exists per guard class.</p>
 */
public final class UmbraWatchdog extends Thread {

    private final String targetClass;
    private final String targetMethod;
    private final long delayMillis;
    private final int maxIterations;
    private final java.util.Random random;

    public UmbraWatchdog(String targetClass, String targetMethod, long delayMillis, int maxIterations) {
        this.targetClass = targetClass;
        this.targetMethod = targetMethod;
        this.delayMillis = delayMillis <= 0L ? 1000L : delayMillis;
        this.maxIterations = maxIterations;
        this.random = new java.util.Random(0x5DEECE66DL ^ System.nanoTime());
        setDaemon(true);
        setName("u" + Integer.toHexString(System.identityHashCode(this))
                + Integer.toHexString((int) (System.nanoTime() & 0xFFFF)));
    }

    /** Randomized sleep so the re-check period is not a constant. */
    private long nextDelayMillis() {
        long jitter = (long) (random.nextDouble() * Math.max(1L, delayMillis / 2L));
        return delayMillis + jitter;
    }

    @Override
    public void run() {
        int iteration = 0;
        while (maxIterations == 0 || iteration < maxIterations) {
            iteration++;
            try {
                Thread.sleep(nextDelayMillis());
            } catch (InterruptedException e) {
                return;
            }
            try {
                ClassLoader loader = getClass().getClassLoader();
                Class<?> type = Class.forName(targetClass, true, loader);
                java.lang.reflect.Method method = type.getDeclaredMethod(targetMethod);
                method.setAccessible(true);
                method.invoke(null);
            } catch (java.lang.reflect.InvocationTargetException e) {
                // The guard itself decided that the process must stop.
                Throwable cause = e.getCause();
                if (cause != null) {
                    cause.printStackTrace();
                }
                Runtime.getRuntime().halt(1);
            } catch (Throwable ignored) {
                // A watch iteration must never crash the program by itself.
            }
        }
    }
}
