package io.umbra.core.runtime;

/**
 * Watchdog thread of the native anti-tamper guard.
 *
 * <p>Runtime template: single top-level class, JDK-only, copied into the output
 * under a random name. It periodically calls
 * {@link UmbraNativeGuard#check()} (remapped to the injected guard class) so a
 * debugger/Frida/instrumentation tool that attaches after startup is still
 * noticed.</p>
 */
public final class UmbraGuard extends Thread {

    private final long intervalMs;

    private UmbraGuard(long intervalMs) {
        super("umbra-guard-wd");
        this.intervalMs = Math.max(250L, intervalMs);
        setDaemon(true);
    }

    /** Starts the single watchdog thread; called once by the guard class. */
    public static void startGuard(long intervalMs) {
        UmbraGuard thread = new UmbraGuard(intervalMs);
        thread.start();
    }

    @Override
    public void run() {
        while (true) {
            try {
                Thread.sleep(intervalMs);
            } catch (InterruptedException interrupted) {
                return;
            }
            try {
                UmbraNativeGuard.check();
            } catch (Throwable failure) {
                UmbraNativeGuard.onWatchdogFailure(failure);
            }
        }
    }
}
