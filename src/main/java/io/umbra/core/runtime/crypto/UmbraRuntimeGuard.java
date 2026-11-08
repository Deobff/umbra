package io.umbra.core.runtime.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Unified Java runtime guard: multi-signal debugger / instrumentation / attach /
 * dump detection.
 *
 * <p>Runtime template: single top-level class, JDK only, no nested or anonymous
 * classes and no references to other Umbra classes. The pass injects it under a
 * random name (substituting the string constants below) and calls {@link #check()}
 * from program entry points; the encrypted-archive loader and the integrity guard
 * call {@link #check()} / {@link #detected()} through the injected name instead of
 * a compile-time reference.</p>
 *
 * <p>Signals (each probe individually try/caught, absent APIs are ignored):</p>
 *
 * <ul>
 *   <li><b>level 1</b> - JVM input arguments: {@code jdwp}, {@code -Xdebug},
 *       {@code -Xrunjdwp}; with {@code @@JVMTI@@} also
 *       {@code -javaagent}/{@code -agentlib}/{@code -agentpath}/{@code -Xrun*}
 *       and {@code -XX:+EnableDynamicAgentLoading}; with {@code @@ATTACH@@} also
 *       {@code -XX:+StartAttachListener}; plus {@code sun.java.command} agent
 *       arguments.</li>
 *   <li><b>level 2</b> - additionally attach detection ({@code @@ATTACH@@}):
 *       {@code sun.jdwp.listenerAddress} system property, {@code JDWP*} thread
 *       names, {@code .attach_pid<pid>}/{@code .java_pid<pid>} files in
 *       {@code java.io.tmpdir}, and a real {@code JDWP-Handshake} probe of the
 *       common debug ports plus the ports advertised by this JVM. With
 *       {@code @@ATTACHWATCH@@} a daemon attach watcher is installed: a
 *       {@code WatchService} on {@code java.io.tmpdir} catches the transient
 *       create/delete of {@code .attach_pid<pid>}/{@code .java_pid<pid>}, and a
 *       high-frequency thread sample flags a {@code sun.instrument}/
 *       {@code loadAgent} frame on {@code Attach Listener}/{@code JDWP*} threads
 *       (a real dynamic {@code loadAgent} attach leaves that frame for tens of
 *       milliseconds) or a {@code JDWP*}/{@code Attach Listener} thread that
 *       appeared after the install-time snapshot. Instrumentation
 *       ({@code @@JVMTI@@}): JMX remote properties. Environment
 *       ({@code @@ENV@@}): {@code JAVA_TOOL_OPTIONS}/{@code _JAVA_OPTIONS}/
 *       {@code JDK_JAVA_OPTIONS} agent/debug flags, {@code FRIDA_*}/{@code GUM_*}
 *       variables, {@code LD_PRELOAD}/{@code DYLD_INSERT_LIBRARIES} Frida/Gum
 *       markers. Platform: Linux {@code /proc/self/status} {@code TracerPid} and
 *       {@code /proc/self/maps} Frida/Gum/ptrace mappings (Windows is delegated
 *       to the native guard; only Java-visible markers are checked there).
 *       Timing ({@code @@TIMING@@}): a randomized suspend/breakpoint drift check
 *       with a generous 2 s slack.</li>
 *   <li><b>level 3</b> - additionally a randomized background watchdog
 *       ({@code @@THREAD@@}) that re-runs the full detection and detects a
 *       suspended process through watchdog-interval drift.</li>
 * </ul>
 *
 * <p>Actions ({@code @@ACTION@@}): {@code throw} (default), {@code exit},
 * {@code corrupt} or {@code log}. Every action writes one
 * {@code [umbra-guard] <signal> detected} line to stderr; {@code log} keeps the
 * program running and leaves {@link #detected()} true so the loader/integrity
 * layer can still refuse sensitive operations. A signal raised from the
 * background attach watcher cannot be thrown into the program's main thread, so
 * {@code throw} halts with exit code 1 there (same fail-loud outcome as
 * {@code exit}); a signal on the entry thread still throws
 * {@code SecurityException}.</p>
 *
 * <p>The install is idempotent (one-shot {@link #check()} plus a cheap re-check
 * {@link #detected()}), the watchdog and attach watcher are daemon threads so
 * they never keep a JVM alive, and a clean JVM has no {@code JDWP*} thread, no
 * {@code TracerPid}, no attach-pid file and no JDWP handshake peer, so a normal
 * launch stays silent (verified on JDK 8/21/26). An {@code Attach Listener}
 * thread that already exists at install time is never a signal by itself (a clean
 * HotSpot JVM already has it); only a later appearance or a live
 * {@code sun.instrument} frame on it counts.</p>
 */
public final class UmbraRuntimeGuard implements Runnable {

    private static void say(String line) {
        if (DEBUG) {
            System.err.println(line);
        }
    }

    private static final String LEVEL_TEXT = "@@LEVEL@@";
    private static final String ACTION = "@@ACTION@@";
    private static final String THREAD_TEXT = "@@THREAD@@";
    private static final String JVMTI_TEXT = "@@JVMTI@@";
    private static final String ATTACH_TEXT = "@@ATTACH@@";
    private static final String ENV_TEXT = "@@ENV@@";
    private static final String TIMING_TEXT = "@@TIMING@@";
    private static final String ATTACHWATCH_TEXT = "@@ATTACHWATCH@@";
    private static final String PORTPROBE_TEXT = "@@PORTPROBE@@";
    private static final String WATCHDOG = "@@WATCHDOG@@";
    private static final String WATCH_MS_TEXT = "@@WATCHMS@@";
    private static final String LOG_TOKEN = "@@LOGTOKEN@@";

    private static final String GATE_SECRET = "@@GATESECRET@@";

    private static volatile byte[] lastCheckDigest;
    private static volatile long lastCheckCounter;

    public static final int SIGNAL_NONE = 0;

    public static final int SIGNAL_ARGUMENTS = 1;

    public static final int SIGNAL_ENVIRONMENT = 2;

    public static final int SIGNAL_JMX = 3;

    public static final int SIGNAL_LISTENER = 4;

    public static final int SIGNAL_THREAD = 5;

    public static final int SIGNAL_ATTACH_FILE = 6;

    public static final int SIGNAL_HANDSHAKE = 7;

    public static final int SIGNAL_TRACER = 8;

    public static final int SIGNAL_MODULE = 9;

    public static final int SIGNAL_TIMING = 10;

    public static final int SIGNAL_DRIFT = 11;

    public static final int SIGNAL_ATTACH = 12;

    public static final int SIGNAL_HEAP_DUMP = 13;

    public static final int SIGNAL_ATTACH_SELF = 14;

    private static final boolean DEBUG = Boolean.getBoolean("umbra.debug");

    private static final int[] COMMON_DEBUG_PORTS = {
            5005, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009
    };

    private static final int DEFAULT_DEBUG_PORT = 5005;

    private static final int FAST_CONNECT_TIMEOUT_MS = 20;

    private static final byte[] JDWP_HANDSHAKE = {
            'J', 'D', 'W', 'P', '-', 'H', 'a', 'n', 'd', 's', 'h', 'a', 'k', 'e'
    };

    private static final int HANDSHAKE_LENGTH = 14;
    private static final long TIMING_SLACK_MS = 2000L;
    private static final int PROC_STATUS_LIMIT = 64 * 1024;
    private static final int PROC_MAPS_LIMIT = 4 * 1024 * 1024;

    private static final String[] SUSPICIOUS_MODULES = {
            "frida", "gum-js", "gumjs", "gum.so", "ptrace"
    };

    private static final int ATTACH_WATCH_POLL_MS = 1;

    private static final int ATTACH_WATCH_FALLBACK_MS = 50;

    private static final int ATTACH_WATCH_FULL_SAMPLE_TICKS = 10;

    private static volatile boolean installed;
    private static volatile boolean active;
    private static volatile boolean watchdogStarted;
    private static volatile boolean attachWatchStarted;
    private static volatile Set<String> attachThreadBaseline;
    private static volatile int lastSignal;
    private static volatile long lastWatchNanos;
    private static volatile long lastQuickNanos;
    private static volatile int fullChecks;
    private static volatile int probes;
    private static volatile int cachedLevel = -1;
    private static volatile File cachedTmp;
    private static volatile long cachedPid = -2L;

    private static final UmbraRuntimeGuard WATCHER = new UmbraRuntimeGuard();

    private UmbraRuntimeGuard() {
    }

    public static void check() {
        int level = level();
        if (level <= 0) {
            return;
        }
        boolean first;
        synchronized (UmbraRuntimeGuard.class) {
            first = !installed;
            installed = true;
        }
        if (!first) {
            return;
        }
        if (level >= 3 && isTrue(THREAD_TEXT) && substituted(WATCHDOG)) {
            startWatchdog();
        }
        if (level >= 2 && isTrue(ATTACH_TEXT) && isTrue(ATTACHWATCH_TEXT)) {
            startAttachWatch();
        }
        fullChecks++;
        int signal = detect(level);
        recordCheckEvidence(signal);
        if (signal != SIGNAL_NONE) {
            setActive(signal);
            fail(signal);
        }
    }

    private static void recordCheckEvidence(int signal) {
        byte[] secret = gateSecret();
        if (secret == null) {
            return;
        }
        try {
            long counter = lastCheckCounter + 1L;
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
            mac.update("umbra.check.v1".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] counterBytes = new byte[8];
            for (int i = 0; i < 8; i++) {
                counterBytes[i] = (byte) (counter >>> (8 * i));
            }
            mac.update(counterBytes);
            mac.update(new byte[] {
                    (byte) signal, (byte) (signal >>> 8), (byte) (signal >>> 16),
                    (byte) (signal >>> 24)
            });
            lastCheckDigest = mac.doFinal();
            lastCheckCounter = counter;
        } catch (Throwable unavailable) {

        } finally {
            java.util.Arrays.fill(secret, (byte) 0);
        }
    }

    private static byte[] gateSecret() {
        if (GATE_SECRET == null || GATE_SECRET.length() < 8 || GATE_SECRET.charAt(0) == '@') {
            return null;
        }
        try {
            byte[] secret = java.util.Base64.getDecoder().decode(GATE_SECRET.trim());
            return secret.length == 32 ? secret : null;
        } catch (Throwable unavailable) {
            return null;
        }
    }

    public static void watch() {
        int level = level();
        if (level <= 0 || active) {
            return;
        }
        if (level >= 2 && isTrue(ATTACH_TEXT) && isTrue(ATTACHWATCH_TEXT)) {
            try {
                ensureAttachBaseline();
                if (sampleAttachSignal()) {
                    attachDetected("watchdog");
                    return;
                }
            } catch (Throwable ignored) {

            }
        }
        long now = System.nanoTime();
        long previous = lastWatchNanos;
        lastWatchNanos = now;
        int signal = detect(level);
        if (signal == SIGNAL_NONE && level >= 2 && isTrue(TIMING_TEXT) && previous != 0L) {
            long elapsedMs = (now - previous) / 1000000L;
            long expectedMs = watchIntervalMs();
            if (driftExceeded(elapsedMs, expectedMs + expectedMs / 2L, 2500L)) {
                signal = SIGNAL_DRIFT;
            }
        }
        if (signal != SIGNAL_NONE) {
            setActive(signal);
            fail(signal);
        }
    }

    private static void startAttachWatch() {
        synchronized (UmbraRuntimeGuard.class) {
            if (attachWatchStarted) {
                return;
            }
            attachWatchStarted = true;
        }
        try {
            ensureAttachBaseline();
            Thread watcher = new Thread(WATCHER, "u"
                    + Integer.toHexString((int) (System.nanoTime() & 0xFFFF))
                    + Integer.toHexString(System.identityHashCode(WATCHER)));
            watcher.setDaemon(true);
            ATTACH_WATCHER_THREAD = watcher;
            watcher.start();
        } catch (Throwable unavailable) {

        }
    }

    @Override
    public void run() {
        attachWatchLoop();
    }

    public static String attachWatcherThreadName() {
        Thread watcher = ATTACH_WATCHER_THREAD;
        return watcher == null ? null : watcher.getName();
    }

    private static volatile Thread ATTACH_WATCHER_THREAD;

    private static void attachWatchLoop() {
        WatchService service = null;
        long pid = currentPid();
        int ticks = 0;
        try {
            File tmp = tmpDirectory();
            if (tmp != null && tmp.isDirectory()) {
                service = FileSystems.getDefault().newWatchService();
                tmp.toPath().register(service, StandardWatchEventKinds.ENTRY_CREATE,
                        StandardWatchEventKinds.ENTRY_DELETE, StandardWatchEventKinds.ENTRY_MODIFY,
                        StandardWatchEventKinds.OVERFLOW);
            }
        } catch (Throwable unavailable) {
            service = null;
        }
        while (true) {
            try {
                if (service != null) {

                    WatchKey key = service.poll();
                    if (key != null) {
                        List<WatchEvent<?>> events = key.pollEvents();
                        for (int i = 0; i < events.size(); i++) {
                            Object context = events.get(i).context();
                            if (context != null && isAttachArtifactName(context.toString(), pid)) {
                                attachDetected("attach-pid event");
                                return;
                            }
                        }
                        key.reset();
                    }
                }

                if (sampleAttachStacks()) {
                    attachDetected("agent-load thread");
                    return;
                }
                ticks++;

                if (ticks % ATTACH_WATCH_FULL_SAMPLE_TICKS == 0 && sampleAttachSignal()) {
                    attachDetected("new attach thread");
                    return;
                }
                if (service == null) {
                    if (attachFileSignal(tmpDirectory(), pid)) {
                        attachDetected("attach-pid scan");
                        return;
                    }
                    Thread.sleep(ATTACH_WATCH_FALLBACK_MS);
                } else {
                    Thread.sleep(ATTACH_WATCH_POLL_MS);
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            } catch (Throwable ignored) {

                if (sampleAttachStacks()) {
                    attachDetected("agent-load thread");
                    return;
                }
                try {
                    Thread.sleep(ATTACH_WATCH_FALLBACK_MS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    public static boolean isAttachArtifactName(String name, long pid) {
        if (name == null || pid <= 0L) {
            return false;
        }
        return name.equals(".attach_pid" + pid) || name.equals(".java_pid" + pid);
    }

    private static void ensureAttachBaseline() {
        if (attachThreadBaseline != null) {
            return;
        }
        synchronized (UmbraRuntimeGuard.class) {
            if (attachThreadBaseline != null) {
                return;
            }
            Set<String> baseline = new HashSet<String>();
            List<Thread> references = new ArrayList<Thread>();
            Thread[] threads = snapshotThreads();
            for (int i = 0; i < threads.length; i++) {
                if (threads[i] == null) {
                    continue;
                }
                String name = threads[i].getName();
                if (isAttachThreadName(name)) {
                    baseline.add(name);
                    references.add(threads[i]);
                }
            }
            attachThreadReferences = references;
            attachThreadBaseline = baseline;
        }
    }

    private static volatile List<Thread> attachThreadReferences;

    private static boolean isAttachThreadName(String name) {
        return name != null && (name.startsWith("JDWP") || name.startsWith("Attach Listener"));
    }

    private static boolean sampleAttachStacks() {
        List<Thread> references = attachThreadReferences;
        if (references == null) {
            ensureAttachBaseline();
            references = attachThreadReferences;
        }
        if (references == null) {
            return false;
        }
        boolean stale = false;
        for (int i = 0; i < references.size(); i++) {
            Thread thread = references.get(i);
            if (thread == null || !thread.isAlive()) {
                stale = true;
                continue;
            }
            try {
                if (hasAgentFrame(thread.getStackTrace())) {
                    return true;
                }
            } catch (Throwable ignored) {

            }
        }
        if (stale) {

            refreshAttachReferences();
            references = attachThreadReferences;
            if (references != null) {
                for (int i = 0; i < references.size(); i++) {
                    Thread thread = references.get(i);
                    if (thread == null || !thread.isAlive()) {
                        continue;
                    }
                    try {
                        if (hasAgentFrame(thread.getStackTrace())) {
                            return true;
                        }
                    } catch (Throwable ignored) {

                    }
                }
            }
        }
        return false;
    }

    private static void refreshAttachReferences() {
        Thread[] threads = snapshotThreads();
        List<Thread> references = new ArrayList<Thread>();
        for (int i = 0; i < threads.length; i++) {
            if (threads[i] != null && isAttachThreadName(threads[i].getName())) {
                references.add(threads[i]);
            }
        }
        attachThreadReferences = references;
    }

    private static boolean hasAgentFrame(StackTraceElement[] stack) {
        if (stack == null) {
            return false;
        }
        for (int i = 0; i < stack.length; i++) {
            String className = stack[i].getClassName();
            if (className == null) {
                continue;
            }
            if (className.startsWith("sun.instrument.")
                    || className.startsWith("com.sun.tools.attach")
                    || className.indexOf("InstrumentationImpl") >= 0
                    || "loadAgent".equals(stack[i].getMethodName())) {
                return true;
            }
        }
        return false;
    }

    public static boolean sampleAttachSignal() {
        try {
            ensureAttachBaseline();
            Set<String> baseline = attachThreadBaseline;
            Thread[] threads = snapshotThreads();
            for (int i = 0; i < threads.length; i++) {
                Thread thread = threads[i];
                if (thread == null) {
                    continue;
                }
                String name = thread.getName();
                if (!isAttachThreadName(name)) {
                    continue;
                }
                if (baseline != null && !baseline.contains(name)) {
                    return true;
                }
                try {
                    StackTraceElement[] stack = thread.getStackTrace();
                    for (int j = 0; j < stack.length; j++) {
                        String className = stack[j].getClassName();
                        if (className.startsWith("sun.instrument.")
                                || className.startsWith("com.sun.tools.attach")
                                || className.indexOf("InstrumentationImpl") >= 0
                                || "loadAgent".equals(stack[j].getMethodName())) {
                            return true;
                        }
                    }
                } catch (Throwable ignored) {

                }
            }
        } catch (Throwable unavailable) {

        }
        return false;
    }

    private static Thread[] snapshotThreads() {
        ThreadGroup root = Thread.currentThread().getThreadGroup();
        while (root != null && root.getParent() != null) {
            root = root.getParent();
        }
        if (root == null) {
            root = Thread.currentThread().getThreadGroup();
        }
        Thread[] threads = new Thread[Math.max(16, root.activeCount() * 2 + 8)];
        int count = root.enumerate(threads, true);
        int attempts = 0;
        while (count == threads.length && attempts < 4) {
            Thread[] larger = new Thread[threads.length * 2];
            count = root.enumerate(larger, true);
            threads = larger;
            attempts++;
        }
        return threads;
    }

    private static void attachDetected(String source) {
        if (active) {
            return;
        }
        setActive(SIGNAL_ATTACH);
        String action = ACTION;
        if ("log".equals(action)) {
            emitAttach(source);
            return;
        }
        if ("corrupt".equals(action)) {
            Runtime.getRuntime().halt(0);
        }
        Runtime.getRuntime().halt(1);
    }

    private static void emitAttach(String source) {
        try {
            System.err.println(logToken() + " attach detected"
                    + (DEBUG && source != null ? " (" + source + ")" : ""));
        } catch (Throwable ignored) {

        }
    }

    public static byte[] attest(long nonce) {

        if (lastCheckDigest == null || lastCheckCounter == 0L) {
            return null;
        }
        byte[] secret = gateSecret();
        if (secret == null) {
            return null;
        }
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
            byte[] label = "umbra.gate.v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] nonceBytes = new byte[8];
            for (int i = 0; i < 8; i++) {
                nonceBytes[i] = (byte) (nonce >>> (8 * i));
            }
            mac.update(label);
            mac.update(nonceBytes);
            byte[] response = mac.doFinal();
            java.util.Arrays.fill(secret, (byte) 0);
            return response;
        } catch (Throwable unavailable) {
            return null;
        }
    }

    public static boolean detected() {
        if (active) {
            return true;
        }
        if (level() <= 0) {
            return false;
        }

        long now = System.nanoTime();
        long previous = lastQuickNanos;
        if (previous != 0L && now > previous && now - previous < 200000000L) {
            return false;
        }
        lastQuickNanos = now;
        try {
            if (isTrue(ATTACH_TEXT)) {
                if (jdwpListenerSignal()) {
                    setActive(SIGNAL_LISTENER);
                    return true;
                }
                if (attachFileSignal(tmpDirectory(), currentPid())) {
                    setActive(SIGNAL_ATTACH_FILE);
                    return true;
                }
            }
        } catch (Throwable ignored) {

        }
        return active;
    }

    public static int fullChecks() {
        return fullChecks;
    }

    public static int probeRuns() {
        return probes;
    }

    public static boolean isActive() {
        return active;
    }

    public static int lastSignal() {
        return lastSignal;
    }

    public static String lastSignalName() {
        return signalName(lastSignal);
    }

    private static int detect(int level) {
        probes++;
        try {
            if (argumentsSignal(managementArguments(), isTrue(JVMTI_TEXT), isTrue(ATTACH_TEXT))) {
                return SIGNAL_ARGUMENTS;
            }
        } catch (Throwable ignored) {

        }
        try {
            if (commandSignal(System.getProperty("sun.java.command"), isTrue(JVMTI_TEXT),
                    isTrue(ATTACH_TEXT))) {
                return SIGNAL_ARGUMENTS;
            }
        } catch (Throwable ignored) {

        }
        if (level < 2) {
            return SIGNAL_NONE;
        }
        if (isTrue(ATTACH_TEXT)) {
            try {
                if (isTrue(PORTPROBE_TEXT) && handshakeProbe()) {
                    return SIGNAL_HANDSHAKE;
                }
            } catch (Throwable ignored) {

            }
            try {
                if (attachSelfSignal(System.getProperty("jdk.attach.allowAttachSelf"))) {
                    return SIGNAL_ATTACH_SELF;
                }
            } catch (Throwable ignored) {

            }
            try {
                if (jdwpListenerSignal()) {
                    return SIGNAL_LISTENER;
                }
            } catch (Throwable ignored) {

            }
            try {
                if (threadSignal()) {
                    return SIGNAL_THREAD;
                }
            } catch (Throwable ignored) {

            }
            try {
                if (attachFileSignal(tmpDirectory(), currentPid())) {
                    return SIGNAL_ATTACH_FILE;
                }
            } catch (Throwable ignored) {

            }
            try {
                if (sampleAttachSignal()) {
                    return SIGNAL_ATTACH;
                }
            } catch (Throwable ignored) {

            }
        }
        if (isTrue(JVMTI_TEXT)) {
            try {
                if (jmxSignal()) {
                    return SIGNAL_JMX;
                }
            } catch (Throwable ignored) {

            }
        }
        try {
            if (heapDumpSignal(managementArguments())) {
                return SIGNAL_HEAP_DUMP;
            }
        } catch (Throwable ignored) {

        }
        if (isTrue(ENV_TEXT)) {
            try {
                if (environmentSignal(System.getenv())) {
                    return SIGNAL_ENVIRONMENT;
                }
            } catch (Throwable ignored) {

            }
        }
        try {
            int platform = platformSignal();
            if (platform != SIGNAL_NONE) {
                return platform;
            }
        } catch (Throwable ignored) {

        }
        if (isTrue(TIMING_TEXT)) {
            try {
                if (timingSignal()) {
                    return SIGNAL_TIMING;
                }
            } catch (Throwable ignored) {

            }
        }
        return SIGNAL_NONE;
    }

    public static boolean argumentsSignal(List<String> arguments, boolean jvmti, boolean attach) {
        if (arguments == null) {
            return false;
        }
        for (int i = 0; i < arguments.size(); i++) {
            String argument = arguments.get(i);
            if (argument == null) {
                continue;
            }
            String lower = argument.toLowerCase(Locale.ROOT);
            if (lower.startsWith("-d")) {

                continue;
            }
            if (lower.indexOf("jdwp") >= 0 || lower.indexOf("-xdebug") >= 0) {
                return true;
            }
            if (jvmti && (lower.indexOf("-javaagent") >= 0 || lower.indexOf("-agentlib") >= 0
                    || lower.indexOf("-agentpath") >= 0 || lower.indexOf("-xrun") >= 0
                    || lower.indexOf("enabledynamicagentloading") >= 0)) {
                return true;
            }
            if (attach && lower.indexOf("startattachlistener") >= 0) {
                return true;
            }
        }
        return false;
    }

    public static boolean commandSignal(String command, boolean jvmti, boolean attach) {
        if (command == null || command.isEmpty()) {
            return false;
        }
        String[] tokens = command.split("\\s+");
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i];
            if (token == null || token.isEmpty()) {
                continue;
            }
            String lower = token.toLowerCase(Locale.ROOT);
            if (lower.indexOf("jdwp") >= 0) {
                return true;
            }
            if (jvmti && (lower.startsWith("-javaagent") || lower.startsWith("-agentlib")
                    || lower.startsWith("-agentpath") || lower.startsWith("-xrun"))) {
                return true;
            }
            if (attach && lower.indexOf("startattachlistener") >= 0) {
                return true;
            }
        }
        return false;
    }

    public static boolean environmentSignal(Map<String, String> environment) {
        if (environment == null) {
            return false;
        }
        for (Map.Entry<String, String> entry : environment.entrySet()) {
            String name = entry.getKey();
            if (name == null) {
                continue;
            }
            String value = entry.getValue() == null ? "" : entry.getValue();
            String upper = name.toUpperCase(Locale.ROOT);
            if (upper.startsWith("FRIDA") || upper.startsWith("GUM_")) {
                return true;
            }
            if ("JAVA_TOOL_OPTIONS".equals(name) || "_JAVA_OPTIONS".equals(name)
                    || "JDK_JAVA_OPTIONS".equals(name)) {
                if (optionsSignal(value)) {
                    return true;
                }
                continue;
            }
            if ("LD_PRELOAD".equals(name) || "DYLD_INSERT_LIBRARIES".equals(name)
                    || "LD_AUDIT".equals(name)) {
                String lower = value.toLowerCase(Locale.ROOT);
                if (lower.indexOf("frida") >= 0 || lower.indexOf("gum") >= 0) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean optionsSignal(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.indexOf("jdwp") >= 0 || lower.indexOf("-xdebug") >= 0
                || lower.indexOf("-xrun") >= 0 || lower.indexOf("-agentlib") >= 0
                || lower.indexOf("-agentpath") >= 0 || lower.indexOf("-javaagent") >= 0
                || lower.indexOf("javaagent") >= 0 || lower.indexOf("frida") >= 0
                || lower.indexOf("gum") >= 0 || lower.indexOf("startattachlistener") >= 0;
    }

    public static boolean attachFileSignal(File directory, long pid) {
        if (directory == null || pid <= 0L) {
            return false;
        }
        try {
            if (!directory.isDirectory()) {
                return false;
            }
            if (new File(directory, ".attach_pid" + pid).exists()) {
                return true;
            }
            if (new File(directory, ".java_pid" + pid).exists()) {
                return true;
            }
        } catch (Throwable ignored) {

        }
        return false;
    }

    public static boolean threadNamesSignal(List<String> names) {
        if (names == null) {
            return false;
        }
        for (int i = 0; i < names.size(); i++) {
            String name = names.get(i);
            if (name != null && name.startsWith("JDWP")) {
                return true;
            }
        }
        return false;
    }

    public static boolean procStatusSignal(String statusText) {
        if (statusText == null || statusText.isEmpty()) {
            return false;
        }
        String[] lines = statusText.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (!line.startsWith("TracerPid:")) {
                continue;
            }
            String value = line.substring("TracerPid:".length()).trim();
            try {
                return Integer.parseInt(value) != 0;
            } catch (NumberFormatException unreadable) {
                return false;
            }
        }
        return false;
    }

    public static boolean procMapsSignal(String mapsText) {
        if (mapsText == null || mapsText.isEmpty()) {
            return false;
        }
        String lower = mapsText.toLowerCase(Locale.ROOT);
        for (int i = 0; i < SUSPICIOUS_MODULES.length; i++) {
            if (lower.indexOf(SUSPICIOUS_MODULES[i]) >= 0) {
                return true;
            }
        }
        return false;
    }

    public static boolean driftExceeded(long observedMs, long expectedMs, long slackMs) {
        if (observedMs < 0L || expectedMs < 0L || slackMs < 0L) {
            return false;
        }
        long allowed = expectedMs + slackMs;
        if (allowed < expectedMs) {
            return false;
        }
        return observedMs > allowed;
    }

    public static int[] advertisedPorts(String listenerAddress, List<String> arguments) {
        List<Integer> ports = new ArrayList<Integer>();
        addPort(ports, listenerAddress);
        if (arguments != null) {
            for (int i = 0; i < arguments.size(); i++) {
                String argument = arguments.get(i);
                if (argument == null) {
                    continue;
                }
                String lower = argument.toLowerCase(Locale.ROOT);
                int address = lower.indexOf("address=");
                if (address < 0 || lower.indexOf("jdwp") < 0) {
                    continue;
                }
                String rest = argument.substring(address + "address=".length());
                int comma = rest.indexOf(',');
                if (comma >= 0) {
                    rest = rest.substring(0, comma);
                }
                addPort(ports, rest);
            }
        }
        int[] result = new int[ports.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = ports.get(i).intValue();
        }
        return result;
    }

    private static void addPort(List<Integer> ports, String address) {
        if (address == null) {
            return;
        }
        String text = address.trim();
        if (text.isEmpty()) {
            return;
        }
        int colon = text.lastIndexOf(':');
        String digits = colon >= 0 ? text.substring(colon + 1) : text;
        try {
            int port = Integer.parseInt(digits.trim());
            if (port > 0 && port <= 65535 && !ports.contains(Integer.valueOf(port))) {
                ports.add(Integer.valueOf(port));
            }
        } catch (NumberFormatException ignored) {

        }
    }

    public static boolean handshakeSignal(String host, int port, int timeoutMs) {
        if (host == null || host.isEmpty() || port <= 0 || port > 65535) {
            return false;
        }
        int connectTimeout = timeoutMs > 0 ? timeoutMs : 120;
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host, port), connectTimeout);
            socket.setSoTimeout(connectTimeout * 3);
            OutputStream out = socket.getOutputStream();
            out.write(JDWP_HANDSHAKE);
            out.flush();
            InputStream in = socket.getInputStream();
            byte[] response = new byte[HANDSHAKE_LENGTH];
            int read = 0;
            while (read < HANDSHAKE_LENGTH) {
                int chunk = in.read(response, read, HANDSHAKE_LENGTH - read);
                if (chunk < 0) {
                    break;
                }
                read += chunk;
            }
            if (read != HANDSHAKE_LENGTH) {
                return false;
            }
            for (int i = 0; i < HANDSHAKE_LENGTH; i++) {
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

            }
        }
    }

    private static List<String> managementArguments() {
        try {
            java.lang.management.RuntimeMXBean bean =
                    java.lang.management.ManagementFactory.getRuntimeMXBean();
            return bean.getInputArguments();
        } catch (Throwable unavailable) {
            return null;
        }
    }

    private static boolean jdwpListenerSignal() {
        String listener = System.getProperty("sun.jdwp.listenerAddress");
        return listener != null && listener.trim().length() > 0;
    }

    private static boolean threadSignal() {
        try {
            java.lang.management.ThreadMXBean bean =
                    java.lang.management.ManagementFactory.getThreadMXBean();
            long[] ids = bean.getAllThreadIds();
            if (ids != null && ids.length > 0) {

                java.lang.management.ThreadInfo[] infos = bean.getThreadInfo(ids, 0);
                if (infos != null) {
                    List<String> dumped = new ArrayList<String>();
                    for (int i = 0; i < infos.length; i++) {
                        if (infos[i] != null) {
                            dumped.add(infos[i].getThreadName());
                        }
                    }
                    if (threadNamesSignal(dumped)) {
                        return true;
                    }
                    return false;
                }
            }
        } catch (Throwable unavailable) {

        }
        try {
            List<String> names = new ArrayList<String>();
            java.util.Set<Thread> threads = Thread.getAllStackTraces().keySet();
            for (Thread thread : threads) {
                if (thread != null) {
                    names.add(thread.getName());
                }
            }
            return threadNamesSignal(names);
        } catch (Throwable unavailable) {
            return false;
        }
    }

    private static boolean handshakeProbe() {
        String listener = System.getProperty("sun.jdwp.listenerAddress");
        int[] advertised = advertisedPorts(listener, managementArguments());
        for (int i = 0; i < advertised.length; i++) {
            if (handshakeSignal("127.0.0.1", advertised[i], FAST_CONNECT_TIMEOUT_MS)) {
                return true;
            }
        }
        for (int i = 0; i < COMMON_DEBUG_PORTS.length; i++) {
            if (handshakeSignal("127.0.0.1", COMMON_DEBUG_PORTS[i], FAST_CONNECT_TIMEOUT_MS)) {
                return true;
            }
        }
        return false;
    }

    private static boolean jmxSignal() {
        if (present(System.getProperty("com.sun.management.jmxremote"))
                || present(System.getProperty("com.sun.management.jmxremote.port"))
                || present(System.getProperty("sun.management.jmxremote"))) {
            return true;
        }
        return false;
    }

    private static boolean present(String value) {
        return value != null && value.trim().length() > 0 && !"false".equalsIgnoreCase(value.trim());
    }

    public static boolean heapDumpSignal(List<String> arguments) {
        if (arguments == null) {
            return false;
        }
        for (int i = 0; i < arguments.size(); i++) {
            String argument = arguments.get(i);
            if (argument == null) {
                continue;
            }
            String lower = argument.toLowerCase(Locale.ROOT);
            if (lower.startsWith("-d")) {
                continue;
            }
            if (lower.indexOf("+heapdumponoutofmemoryerror") >= 0
                    || lower.indexOf("+heapdumpbeforefullgc") >= 0) {
                return true;
            }
        }
        return false;
    }

    public static boolean attachSelfSignal(String allowAttachSelfProperty) {
        return allowAttachSelfProperty != null
                && "true".equalsIgnoreCase(allowAttachSelfProperty.trim());
    }

    private static int platformSignal() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.indexOf("linux") < 0) {

            return SIGNAL_NONE;
        }
        String status = readTextFile("/proc/self/status", PROC_STATUS_LIMIT);
        if (procStatusSignal(status)) {
            return SIGNAL_TRACER;
        }
        String maps = readTextFile("/proc/self/maps", PROC_MAPS_LIMIT);
        if (procMapsSignal(maps)) {
            return SIGNAL_MODULE;
        }
        return SIGNAL_NONE;
    }

    private static String readTextFile(String path, int limit) {
        FileInputStream in = null;
        try {
            File file = new File(path);
            if (!file.isFile() || !file.canRead()) {
                return null;
            }
            in = new FileInputStream(file);
            byte[] buffer = new byte[8192];
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            int read;
            int total = 0;
            while ((read = in.read(buffer)) >= 0) {
                if (total + read > limit) {
                    out.write(buffer, 0, Math.max(0, limit - total));
                    break;
                }
                out.write(buffer, 0, read);
                total += read;
            }
            return new String(out.toByteArray(), "ISO-8859-1");
        } catch (Throwable unavailable) {
            return null;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignored) {

                }
            }
        }
    }

    private static boolean timingSignal() {
        long start = System.nanoTime();
        try {
            long sleepMs = 2L + (long) (Math.random() * 4.0);
            Thread.sleep(sleepMs);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
        long spinUntil = System.nanoTime() + 1000000L + (long) (Math.random() * 2000000.0);
        long sink = 0L;
        while (System.nanoTime() < spinUntil) {
            sink += 13L;
        }
        long elapsedMs = (System.nanoTime() - start) / 1000000L;
        if (sink == Long.MIN_VALUE) {
            return false;
        }
        return driftExceeded(elapsedMs, 10L, TIMING_SLACK_MS);
    }

    private static File tmpDirectory() {
        File cached = cachedTmp;
        if (cached != null) {
            return cached;
        }
        try {
            String tmp = System.getProperty("java.io.tmpdir");
            cached = tmp == null ? null : new File(tmp);
            cachedTmp = cached;
            return cached;
        } catch (Throwable unavailable) {
            return null;
        }
    }

    private static long currentPid() {
        long cached = cachedPid;
        if (cached != -2L) {
            return cached;
        }
        long pid = 0L;
        try {
            java.lang.management.RuntimeMXBean bean =
                    java.lang.management.ManagementFactory.getRuntimeMXBean();
            String name = bean.getName();
            int at = name.indexOf('@');
            String digits = at >= 0 ? name.substring(0, at) : name;
            pid = Long.parseLong(digits.trim());
        } catch (Throwable unavailable) {
            pid = 0L;
        }
        cachedPid = pid;
        return pid;
    }

    private static void startWatchdog() {
        synchronized (UmbraRuntimeGuard.class) {
            if (watchdogStarted) {
                return;
            }
            watchdogStarted = true;
        }
        try {
            Class<?> watchdogType = Class.forName(WATCHDOG, true,
                    UmbraRuntimeGuard.class.getClassLoader());
            Object watchdog = watchdogType
                    .getConstructor(String.class, String.class, long.class, int.class)
                    .newInstance(UmbraRuntimeGuard.class.getName(), "watch",
                            Long.valueOf(watchIntervalMs()), Integer.valueOf(0));
            ((Thread) watchdog).start();
        } catch (Throwable unavailable) {

        }
    }

    private static void setActive(int signal) {
        active = true;
        lastSignal = signal;
    }

    private static void fail(int signal) {
        String name = signalName(signal);
        String action = ACTION;
        if ("log".equals(action)) {
            if (signal == SIGNAL_ATTACH || signal == SIGNAL_ATTACH_FILE
                    || signal == SIGNAL_THREAD) {
                emitAttach(name);
            } else {
                emit(name);
            }
            return;
        }
        if ("exit".equals(action)) {
            Runtime.getRuntime().halt(1);
        }
        if ("corrupt".equals(action)) {
            Runtime.getRuntime().halt(0);
        }
        throw quietException(DEBUG ? logToken() + " " + name : null);
    }

    private static void emit(String name) {
        try {
            System.err.println(logToken() + " " + name + " detected");
        } catch (Throwable ignored) {

        }
    }

    private static SecurityException quietException(String message) {
        SecurityException failure = message == null ? new SecurityException()
                : new SecurityException(message);
        failure.setStackTrace(new StackTraceElement[0]);
        return failure;
    }

    private static String logToken() {
        return LOG_TOKEN == null || LOG_TOKEN.isEmpty() || LOG_TOKEN.charAt(0) == '@'
                ? "umbra" : LOG_TOKEN;
    }

    private static String signalName(int signal) {
        switch (signal) {
            case SIGNAL_ARGUMENTS:
                return "arguments";
            case SIGNAL_ENVIRONMENT:
                return "environment";
            case SIGNAL_JMX:
                return "jmx";
            case SIGNAL_LISTENER:
                return "jdwp-listener";
            case SIGNAL_THREAD:
                return "jdwp-thread";
            case SIGNAL_ATTACH_FILE:
                return "attach-file";
            case SIGNAL_HANDSHAKE:
                return "jdwp-handshake";
            case SIGNAL_TRACER:
                return "tracer";
            case SIGNAL_MODULE:
                return "module";
            case SIGNAL_TIMING:
                return "timing";
            case SIGNAL_DRIFT:
                return "suspend-drift";
            case SIGNAL_ATTACH:
                return "attach";
            case SIGNAL_HEAP_DUMP:
                return "heap-dump";
            case SIGNAL_ATTACH_SELF:
                return "attach-self";
            default:
                return "none";
        }
    }

    private static int level() {
        int cached = cachedLevel;
        if (cached >= 0) {
            return cached;
        }
        int value = 0;
        try {
            int parsed = Integer.parseInt(LEVEL_TEXT.trim());
            value = parsed < 0 ? 0 : (parsed > 3 ? 3 : parsed);
        } catch (Throwable unsubstituted) {
            value = 0;
        }
        cachedLevel = value;
        return value;
    }

    private static long watchIntervalMs() {
        try {
            long value = Long.parseLong(WATCH_MS_TEXT.trim());
            if (value < 1000L) {
                return 1000L;
            }
            return value > 60000L ? 60000L : value;
        } catch (Throwable unsubstituted) {
            return 4000L;
        }
    }

    private static boolean isTrue(String value) {
        return "true".equalsIgnoreCase(value);
    }

    private static boolean substituted(String value) {
        return value != null && value.length() > 1 && value.charAt(0) != '@';
    }
}
