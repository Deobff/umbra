package io.umbra.core.runtime;

/**
 * Guard launcher template.
 *
 * <p>Injected as the manifest entry point by the anti-debug guard pass: it runs
 * the guard before the real main class is even loaded, then invokes the original
 * {@code main(String[])} reflectively. This prevents a premain agent from
 * backfilling the main class to remove the guard call.</p>
 *
 * <p>Must stay a single self-contained class (no nested classes, JDK only); the
 * placeholders are replaced at injection time.</p>
 */
public final class UmbraGuardLauncher {

    private static final String GUARD = "@@GUARD@@";
    private static final String TARGET = "@@MAIN@@";

    private UmbraGuardLauncher() {
    }

    public static void main(String[] args) throws Throwable {
        ClassLoader loader = UmbraGuardLauncher.class.getClassLoader();
        Class<?> guard = Class.forName(GUARD, true, loader);
        guard.getMethod("check").invoke(null);
        Class<?> target = Class.forName(TARGET, true, loader);
        try {
            target.getMethod("main", String[].class).invoke(null, (Object) args);
        } catch (java.lang.reflect.InvocationTargetException failure) {
            throw failure.getCause();
        }
    }
}
