package io.umbra.core.runtime.crypto;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Configurable anti-debug / anti-instrumentation guard.
 *
 * <p>Runtime template: no nested/anonymous classes and no references to other
 * Umbra classes. The pass calls {@link #check()} at the start of every program
 * entry point.</p>
 *
 * <ul>
 *   <li>level 1 - JVM input arguments: {@code jdwp}, {@code -Xdebug}; with
 *       {@code antiDebug.jvmti} also {@code -javaagent}/{@code -agentlib}/
 *       {@code -agentpath}.</li>
 *   <li>level 2 - additionally attach detection: the JDWP listener system
 *       property, JDWP thread names (ManagementFactory/ThreadMXBean), and a
 *       real {@code JDWP-Handshake} probe of the common debug ports (a plain
 *       open port is not reported, only one that answers the JDWP handshake).</li>
 *   <li>level 3 - additionally a background watchdog re-runs the checks.</li>
 * </ul>
 *
 * <p>Every probe is individually wrapped: an unavailable management API, a
 * blocked socket or a restrictive security manager is ignored instead of being
 * reported, so a normal {@code java -jar} launch never trips the guard. Only
 * positive debugger/agent evidence triggers the configured action.</p>
 *
 * @deprecated since 3.1: superseded by the unified
 *             {@link UmbraRuntimeGuard} template (JVM arguments, agent args,
 *             environment markers, attach-pid artifacts, JDWP threads/property,
 *             fast JDWP handshake probe, Linux {@code /proc} checks, timing
 *             drift, {@code log} action and a shared injectable copy for the
 *             integrity/loader layers). Kept as a standalone template for
 *             compatibility with archives built by 3.0; the anti-debug pass no
 *             longer injects this class.
 */
@Deprecated
public final class UmbraAntiDebugGuard {

    // Substituted at injection time.
    private static final String LEVEL_TEXT = "@@LEVEL@@";
    private static final String THREAD_TEXT = "@@THREAD@@";
    private static final String JVMTI_TEXT = "@@JVMTI@@";
    private static final String ATTACH_TEXT = "@@ATTACH@@";
    private static final String ACTION = "@@ACTION@@";
    private static final String WATCHDOG = "@@WATCHDOG@@";

    private static final int[] DEBUG_PORTS = {
            5005, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009
    };

    private static final byte[] JDWP_HANDSHAKE = "JDWP-Handshake".getBytes(StandardCharsets.US_ASCII);

    private static volatile boolean checked;
    private static volatile boolean watchdogStarted;

    private UmbraAntiDebugGuard() {
    }

    /** Called at the start of every program entry point. */
    public static void check() {
        if (checked) {
            return;
        }
        synchronized (UmbraAntiDebugGuard.class) {
            if (checked) {
                return;
            }
            checked = true;
        }
        int level = level();
        if (level <= 0) {
            return;
        }
        if (level >= 3 && isTrue(THREAD_TEXT)) {
            startWatchdog();
        }
        if (detect(level)) {
            fail();
        }
    }

    /** Re-check entry point used by the background watchdog. */
    public static void watch() {
        int level = level();
        if (level > 0 && detect(level)) {
            fail();
        }
    }

    // ------------------------------------------------------------------
    // Detection
    // ------------------------------------------------------------------

    private static boolean detect(int level) {
        if (level >= 1 && scanInputArguments(level)) {
            return true;
        }
        if (level >= 2 && isTrue(ATTACH_TEXT)) {
            if (hasJdwpListenerProperty() || hasJdwpThread() || hasJdwpPort()) {
                return true;
            }
        }
        return false;
    }

    private static boolean scanInputArguments(int level) {
        try {
            java.lang.management.RuntimeMXBean bean =
                    java.lang.management.ManagementFactory.getRuntimeMXBean();
            List<String> arguments = bean.getInputArguments();
            for (int i = 0; i < arguments.size(); i++) {
                String lower = arguments.get(i).toLowerCase(Locale.ROOT);
                if (lower.contains("jdwp") || lower.contains("-xdebug")) {
                    return true;
                }
                if (isTrue(JVMTI_TEXT)
                        && (lower.contains("javaagent") || lower.contains("agentlib")
                        || lower.contains("agentpath") || lower.contains("-xrun"))) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            // Management API unavailable.
        }
        return false;
    }

    private static boolean hasJdwpListenerProperty() {
        try {
            String listener = System.getProperty("sun.jdwp.listenerAddress");
            return listener != null && listener.length() > 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean hasJdwpThread() {
        try {
            Set<Thread> threads = Thread.getAllStackTraces().keySet();
            for (Thread thread : threads) {
                String name = thread.getName();
                if (name != null && name.startsWith("JDWP")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            // ignore
        }
        try {
            java.lang.management.ThreadMXBean bean =
                    java.lang.management.ManagementFactory.getThreadMXBean();
            java.lang.management.ThreadInfo[] infos = bean.dumpAllThreads(false, false);
            if (infos != null) {
                for (int i = 0; i < infos.length; i++) {
                    String name = infos[i].getThreadName();
                    if (name != null && name.startsWith("JDWP")) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
            // ignore
        }
        return false;
    }

    /**
     * Probes the common JDWP ports with the real JDWP handshake. Only a peer
     * that echoes {@code JDWP-Handshake} counts as a debugger; an arbitrary
     * listening service does not.
     */
    private static boolean hasJdwpPort() {
        for (int i = 0; i < DEBUG_PORTS.length; i++) {
            if (handshake(DEBUG_PORTS[i])) {
                return true;
            }
        }
        return false;
    }

    private static boolean handshake(int port) {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 90);
            socket.setSoTimeout(250);
            OutputStream out = socket.getOutputStream();
            out.write(JDWP_HANDSHAKE);
            out.flush();
            InputStream in = socket.getInputStream();
            byte[] response = new byte[JDWP_HANDSHAKE.length];
            int read = 0;
            while (read < response.length) {
                int chunk = in.read(response, read, response.length - read);
                if (chunk < 0) {
                    break;
                }
                read += chunk;
            }
            if (read != JDWP_HANDSHAKE.length) {
                return false;
            }
            for (int i = 0; i < response.length; i++) {
                if (response[i] != JDWP_HANDSHAKE[i]) {
                    return false;
                }
            }
            return true;
        } catch (Throwable notDebugger) {
            return false;
        } finally {
            try {
                socket.close();
            } catch (Throwable ignored) {
                // ignore
            }
        }
    }

    private static void startWatchdog() {
        synchronized (UmbraAntiDebugGuard.class) {
            if (watchdogStarted) {
                return;
            }
            watchdogStarted = true;
        }
        try {
            Class<?> watchdogType = Class.forName(WATCHDOG, true, UmbraAntiDebugGuard.class.getClassLoader());
            Object watchdog = watchdogType.getConstructor(String.class, String.class, long.class, int.class)
                    .newInstance(UmbraAntiDebugGuard.class.getName(), "watch",
                            Long.valueOf(2500L), Integer.valueOf(0));
            ((Thread) watchdog).start();
        } catch (Throwable ignored) {
            // Watchdog is best effort.
        }
    }

    private static void fail() {
        if ("exit".equals(ACTION)) {
            Runtime.getRuntime().halt(1);
        }
        if ("corrupt".equals(ACTION)) {
            System.err.close();
            Runtime.getRuntime().halt(0);
        }
        throw new SecurityException("Debugger detected");
    }

    private static int level() {
        try {
            return Integer.parseInt(LEVEL_TEXT);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static boolean isTrue(String value) {
        return "true".equalsIgnoreCase(value);
    }
}
