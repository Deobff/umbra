package io.umbra.core.runtime;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.security.CodeSource;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Runtime anti-debug / anti-Frida / anti-backfill guard.
 *
 * <p>This is a runtime template: it must stay a single top-level class with no
 * nested or anonymous classes, use only JDK APIs and is copied into the output
 * under a random name. {@code @@PLACEHOLDER@@} string constants are replaced by
 * the native guard pass.</p>
 *
 * <p>The class performs pure-Java checks (JDWP/debug/instrumentation JVM options,
 * agent environment variables, Frida environment markers, attach/JDWP threads
 * only when they really exist, Linux {@code /proc} checks) and, when a native
 * guard library was built, loads it, verifies its file hash and code prologues,
 * runs the native debugger/Frida checks and verifies a keyed token challenge.
 * It also verifies that the methods Umbra converted to native are still native
 * (native-method backfill detection).</p>
 */
public final class UmbraNativeGuard {

    /** JAR entry of the compiled guard library (empty when no toolchain). */
    private static final String RESOURCE = "@@RESOURCE@@";
    private static final String NATIVE_FLAG = "@@NATIVE@@";
    private static final String FRIDA_FLAG = "@@FRIDA@@";
    private static final String ACTION_NAME = "@@ACTION@@";
    private static final String SECRET_HEX = "@@SECRET@@";
    private static final String FILE_HASH_HEX = "@@FILEHASH@@";
    private static final String PROLOGUE_CHECK_HEX = "@@PCHECK@@";
    private static final String PROLOGUE_TOKEN_HEX = "@@PTOKEN@@";
    private static final String WATCHDOG_MS = "@@WATCHDOG@@";
    private static final String METHODS = "@@METHODS@@";

    private static final int DETECT_JDWP = 1 << 11;
    private static final int DETECT_HASH = 1 << 12;
    private static final int DETECT_HOOK = 1 << 13;
    private static final int DETECT_TOKEN = 1 << 14;
    private static final int DETECT_BACKFILL = 1 << 15;
    private static final int DETECT_AGENT = 1 << 16;
    private static final int DETECT_REMOTE_THREAD = 1 << 17;
    private static final int DETECT_EXEC_MEMORY = 1 << 18;
    private static final int DETECT_IMAGE_BP = 1 << 19;
    private static final int DETECT_MODULE = 1 << 20;
    private static final int DETECT_TIMING = 1 << 21;
    private static final int DETECT_HANDLE_DUMP = 1 << 22;
    private static final int DETECT_CODE_SAMPLE = 1 << 23;
    private static final int DETECT_LINUX = 1 << 24;
    private static final int DETECT_FRIDA_ENV = 1 << 10;

    private static final int ACTION = parseAction(ACTION_NAME);
    private static final boolean NATIVE = Boolean.parseBoolean(NATIVE_FLAG);
    private static final boolean FRIDA = Boolean.parseBoolean(FRIDA_FLAG);
    private static final long SECRET = parseHexLong(SECRET_HEX);
    private static final long EXPECTED_FILE_HASH = parseHexLong(FILE_HASH_HEX);
    private static final long INTERVAL_MS = parseLong(WATCHDOG_MS, 4000L);

    private static final Object LOCK = new Object();
    private static volatile int state;
    private static volatile boolean corrupted;
    private static volatile boolean watchdogStarted;
    private static volatile boolean nativeLoaded;
    private static volatile long challengeCounter;

    /**
     * Neutral content marker written next to every extracted guard library. The
     * random directory/file names carry no fixed prefix; stale directories from
     * earlier runs are recognized only by this marker (and only when they are old
     * enough that no live process can still be mapping their library).
     */
    private static final String MARKER = "9f2c7a4e1b8d6350a5c9e2f7b4d1863e";
    private static final String MARKER_FILE = "m";
    private static final String NAME_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();
    private static volatile File extractedLibrary;
    private static volatile File extractedDirectory;

    private UmbraNativeGuard() {
    }

    private static native int nativeInit(int action, long secret, String fileHashHex,
                                         String prologueCheckHex, String prologueTokenHex);

    private static native int nativeCheck();

    private static native int nativeSelfTest();

    private static native long nativeToken(int challenge);

    /** Entry point inserted into program entry points and native-owner classes. */
    public static void check() {
        ensureGuard();
        if (corrupted) {
            return;
        }
        int mask = javaChecks();
        if (nativeLoaded) {
            mask |= nativeCheck();
            mask |= nativeSelfTest();
            if (tokenMismatch()) {
                mask |= DETECT_TOKEN;
            }
            mask |= verifyNativeMethods();
        }
        if (mask != 0) {
            onDetection(mask);
        }
    }

    /** Loads the native guard (when built) and performs the startup checks once. */
    public static void ensureGuard() {
        int current = state;
        if (current == 1) {
            maybeStartWatchdog();
            return;
        }
        if (current == 2) {
            onDetection(1);
            return;
        }
        int mask;
        synchronized (LOCK) {
            if (state == 1) {
                maybeStartWatchdog();
                return;
            }
            try {
                mask = javaChecks();
                if (NATIVE) {
                    mask |= loadNative();
                }
                state = 1;
            } catch (Throwable failure) {
                state = 2;
                System.err.println("[Umbra] guard initialization failure: " + failure);
                mask = DETECT_TOKEN;
            }
        }
        if (mask != 0) {
            onDetection(mask);
        }
        maybeStartWatchdog();
    }

    private static void maybeStartWatchdog() {
        if (INTERVAL_MS <= 0L || watchdogStarted) {
            return;
        }
        synchronized (LOCK) {
            if (watchdogStarted) {
                return;
            }
            watchdogStarted = true;
            UmbraGuard.startGuard(INTERVAL_MS);
            installShutdownGuard();
        }
    }

    /**
     * Last-chance anti-backfill check. An agent can retransform a native method
     * after startup and the process may exit before the periodic watchdog fires
     * (short-lived applications). The shutdown hook re-verifies that every
     * Umbra-created native method is still native and still present; a mismatch
     * forces a non-zero exit code even though the JVM is already terminating.
     */
    private static void installShutdownGuard() {
        try {
            Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        int mask = verifyNativeMethods();
                        if (mask == 0) {
                            return;
                        }
                        System.err.println("[Umbra] native method backfill detected at shutdown (0x"
                                + Integer.toHexString(mask) + ")");
                        if (ACTION == 1 || ACTION == 2) {
                            Runtime.getRuntime().halt(101);
                        }
                    } catch (Throwable ignored) {
                        // Never make a clean shutdown fail because of the guard.
                    }
                }
            }, "umbra-shutdown-guard"));
        } catch (Throwable ignored) {
            // Shutdown hooks can be unavailable during JVM teardown.
        }
    }

    /** Called by the watchdog thread when a check threw. */
    public static void onWatchdogFailure(Throwable failure) {
        if (ACTION == 1 || ACTION == 2) {
            System.err.println("[Umbra] guard watchdog failure: " + failure);
            Runtime.getRuntime().halt(87);
        } else if (ACTION == 4) {
            System.err.println("[Umbra] guard watchdog detection: " + failure);
        } else {
            corrupted = true;
        }
    }

    /**
     * Central detection handler. Called from Java checks and from the native
     * guard through JNI.
     */
    public static void onDetection(int mask) {
        String description = "0x" + Integer.toHexString(mask);
        if (ACTION == 4) {
            System.err.println("[Umbra] dynamic analysis detected (" + description + ")");
            return;
        }
        if (ACTION == 3) {
            corrupted = true;
            return;
        }
        if (ACTION == 2) {
            System.err.println("[Umbra] dynamic analysis detected (" + description + "); exiting");
            Runtime.getRuntime().halt(101);
            return;
        }
        throw new SecurityException("Umbra guard: dynamic analysis detected (" + description + ")");
    }

    // ------------------------------------------------------------------
    // Native guard loading and verification
    // ------------------------------------------------------------------

    private static int loadNative() {
        int mask = 0;
        if (nativeLoaded) {
            // Concurrent guard entry points can reach this before the state
            // flag flips; loading the same library twice would fail.
            return 0;
        }
        File library = extractLibrary();
        if (library == null) {
            return DETECT_HASH;
        }
        try {
            System.load(library.getAbsolutePath());
        } catch (Throwable failure) {
            disposeExtracted();
            return DETECT_HASH;
        }
        disposeAfterLoad(library);
        System.setProperty("umbra.guard.path", library.getAbsolutePath());
        nativeLoaded = true;
        try {
            int init = nativeInit(ACTION, SECRET, FILE_HASH_HEX, PROLOGUE_CHECK_HEX,
                    PROLOGUE_TOKEN_HEX);
            if (init != 0) {
                mask |= init;
            }
            int selfTest = nativeSelfTest();
            if (selfTest != 0) {
                mask |= selfTest;
            }
            if (tokenMismatch()) {
                mask |= DETECT_TOKEN;
            }
        } catch (Throwable failure) {
            // JNI binding/extraction failure must fail closed, not crash the app.
            return mask | DETECT_HASH;
        }
        mask |= verifyNativeMethods();
        return mask;
    }

    private static boolean tokenMismatch() {
        if (!nativeLoaded) {
            return false;
        }
        int challenge = (int) (System.nanoTime() ^ (challengeCounter += 0x9E3779B97F4A7C15L));
        long expected = mixToken(SECRET, challenge, EXPECTED_FILE_HASH);
        long actual;
        try {
            actual = nativeToken(challenge);
        } catch (Throwable failure) {
            return true;
        }
        if (actual != expected) {
            return true;
        }
        challenge = (int) (challenge * 31 + 0x5A17);
        expected = mixToken(SECRET, challenge, EXPECTED_FILE_HASH);
        return nativeToken(challenge) != expected;
    }

    /**
     * Writes the guard library into a random directory with a random
     * alphanumeric file name (no fixed prefix), plus a marker file used for
     * stale-directory cleanup.
     */
    private static File extractLibrary() {
        cleanupStaleLibraries();
        byte[] data = readResource();
        if (data == null || data.length == 0) {
            return null;
        }
        File root = new File(System.getProperty("java.io.tmpdir", "."));
        File directory = new File(root, randomName(16));
        File file = null;
        try {
            if (!directory.mkdirs()) {
                return null;
            }
            file = new File(directory, randomName(16) + librarySuffix());
            OutputStream out = new FileOutputStream(file);
            try {
                out.write(data);
            } finally {
                out.close();
            }
            writeMarker(directory);
            extractedDirectory = directory;
            extractedLibrary = file;
            file.deleteOnExit();
            // The marker intentionally survives: after this process exits the
            // cleanup of the next run needs it to identify the leftover directory.
            directory.deleteOnExit();
            return file;
        } catch (IOException failure) {
            if (file != null && file.exists() && !file.delete()) {
                file.deleteOnExit();
            }
            deleteTree(directory);
            return null;
        }
    }

    private static void writeMarker(File directory) {
        try {
            OutputStream out = new FileOutputStream(new File(directory, MARKER_FILE));
            try {
                out.write(MARKER.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            } finally {
                out.close();
            }
        } catch (IOException ignored) {
            // the extracted dir is still cleaned by deleteOnExit best effort
        }
    }

    /** Native library suffix of the current platform. */
    private static String librarySuffix() {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (os.indexOf("win") >= 0) {
            return ".dll";
        }
        if (os.indexOf("mac") >= 0) {
            return ".dylib";
        }
        return ".so";
    }

    private static String randomName(int length) {
        StringBuilder name = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            name.append(NAME_CHARS.charAt(RANDOM.nextInt(NAME_CHARS.length())));
        }
        return name.toString();
    }

    /**
     * Destroys the extracted file after {@link System#load} so a copy of the
     * on-disk library is not usable for analysis.
     *
     * <p>POSIX allows unlinking a mapped library: the directory entry disappears
     * immediately and the mapping stays valid. On Windows a mapped image file is
     * locked against write/delete; the truncate/overwrite attempt therefore fails
     * with a sharing violation and the file is left for the stale-directory
     * cleanup of the next run (documented residual, no portable workaround without
     * a manual mapper).</p>
     */
    private static void disposeAfterLoad(File library) {
        if (!isWindows()) {
            disposeExtracted();
            return;
        }
        boolean removed = false;
        try {
            java.io.RandomAccessFile file = new java.io.RandomAccessFile(library, "rw");
            try {
                file.setLength(0);
                file.seek(0);
                byte[] junk = new byte[64];
                RANDOM.nextBytes(junk);
                file.write(junk);
            } finally {
                file.close();
            }
            removed = library.delete();
        } catch (IOException lockedOnWindows) {
            removed = false;
        } catch (Throwable ignored) {
            removed = false;
        }
        if (!removed) {
            library.deleteOnExit();
        }
    }

    /** Removes the current extraction (marker, library and directory) best effort. */
    private static void disposeExtracted() {
        File library = extractedLibrary;
        File directory = extractedDirectory;
        if (library != null) {
            library.delete();
        }
        if (directory != null) {
            new File(directory, MARKER_FILE).delete();
            deleteTree(directory);
        }
    }

    /**
     * Removes stale guard directories from earlier runs. Only old directories
     * (60s+) carrying our marker are considered; a library still mapped by a live
     * process fails to delete and is retried by a later run. No file name prefix is
     * matched.
     */
    private static void cleanupStaleLibraries() {
        try {
            File root = new File(System.getProperty("java.io.tmpdir", "."));
            File[] children = root.listFiles();
            if (children == null) {
                return;
            }
            long cutoff = System.currentTimeMillis() - 60000L;
            for (File child : children) {
                if (!child.isDirectory() || child.lastModified() > cutoff) {
                    continue;
                }
                if (!MARKER.equals(readMarker(child))) {
                    continue;
                }
                deleteTree(child);
            }
        } catch (Throwable ignored) {
            // best effort: cleanup must never break the guard
        }
    }

    private static String readMarker(File directory) {
        File marker = new File(directory, MARKER_FILE);
        if (!marker.isFile()) {
            return null;
        }
        try {
            InputStream in = new FileInputStream(marker);
            try {
                byte[] buffer = new byte[64];
                int read = in.read(buffer);
                return read <= 0 ? null : new String(buffer, 0, read,
                        java.nio.charset.StandardCharsets.UTF_8);
            } finally {
                in.close();
            }
        } catch (IOException ignored) {
            return null;
        }
    }

    private static void deleteTree(File file) {
        if (file == null || !file.exists()) {
            return;
        }
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteTree(child);
            }
        }
        if (!file.delete()) {
            file.deleteOnExit();
        }
    }
    private static byte[] readResource() {
        if (RESOURCE == null || RESOURCE.isEmpty()) {
            return null;
        }
        byte[] data = readStream(UmbraNativeGuard.class.getResourceAsStream("/" + RESOURCE));
        if (data != null && data.length > 0) {
            return data;
        }
        ClassLoader context = null;
        try {
            context = Thread.currentThread().getContextClassLoader();
        } catch (RuntimeException ignored) {
            context = null;
        }
        if (context != null) {
            data = readStream(context.getResourceAsStream(RESOURCE));
            if (data != null && data.length > 0) {
                return data;
            }
        }
        data = readStream(ClassLoader.getSystemResourceAsStream(RESOURCE));
        if (data != null && data.length > 0) {
            return data;
        }
        try {
            CodeSource source = UmbraNativeGuard.class.getProtectionDomain().getCodeSource();
            if (source == null || source.getLocation() == null) {
                return null;
            }
            URL location = source.getLocation();
            if (!"file".equalsIgnoreCase(location.getProtocol())) {
                return null;
            }
            File file = new File(location.toURI());
            if (file.isDirectory()) {
                File entry = new File(file, RESOURCE);
                if (entry.isFile()) {
                    InputStream in = new java.io.FileInputStream(entry);
                    try {
                        return readStream(in);
                    } finally {
                        in.close();
                    }
                }
                return null;
            }
            if (!file.isFile()) {
                return null;
            }
            ZipFile zip = new ZipFile(file);
            try {
                ZipEntry entry = zip.getEntry(RESOURCE);
                if (entry == null) {
                    return null;
                }
                return readStream(zip.getInputStream(entry));
            } finally {
                zip.close();
            }
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static byte[] readStream(InputStream in) {
        if (in == null) {
            return null;
        }
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } catch (IOException ignored) {
            return null;
        } finally {
            try {
                in.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

    // ------------------------------------------------------------------
    // Pure-Java checks
    // ------------------------------------------------------------------

    private static int javaChecks() {
        int mask = 0;
        try {
            if (vmArgumentsLookDebug()) {
                mask |= DETECT_JDWP;
            }
        } catch (Throwable ignored) {
            // best effort
        }
        try {
            if (threadLookDebug()) {
                mask |= DETECT_JDWP;
            }
        } catch (Throwable ignored) {
            // best effort
        }
        if (FRIDA && environmentLooksFrida()) {
            mask |= DETECT_FRIDA_ENV;
        }
        if (environmentLooksDebug()) {
            mask |= DETECT_JDWP;
        }
        if (instrumentationAgentPresent()) {
            mask |= DETECT_AGENT;
        }
        if (!isWindows()) {
            mask |= procChecks();
        }
        return mask;
    }

    private static boolean vmArgumentsLookDebug() {
        try {
            List<String> arguments = ManagementFactory.getRuntimeMXBean().getInputArguments();
            for (int i = 0; i < arguments.size(); i++) {
                String argument = arguments.get(i);
                if (argument == null) {
                    continue;
                }
                String lower = argument.toLowerCase(java.util.Locale.ROOT);
                if (lower.indexOf("jdwp") >= 0 || lower.indexOf("xrunjdwp") >= 0
                        || lower.indexOf("dt_socket") >= 0 || lower.indexOf("dt_shmem") >= 0) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            return false;
        }
        return false;
    }

    private static boolean instrumentationAgentPresent() {
        try {
            List<String> arguments = ManagementFactory.getRuntimeMXBean().getInputArguments();
            for (int i = 0; i < arguments.size(); i++) {
                String argument = arguments.get(i);
                if (argument == null) {
                    continue;
                }
                String lower = argument.toLowerCase(java.util.Locale.ROOT);
                if (lower.startsWith("-javaagent:") || lower.startsWith("-agentpath:")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            return false;
        }
        return false;
    }

    private static boolean threadLookDebug() {
        try {
            Map<Thread, StackTraceElement[]> threads = Thread.getAllStackTraces();
            for (Thread thread : threads.keySet()) {
                String name = thread.getName();
                if (name == null) {
                    continue;
                }
                if (name.indexOf("JDWP") >= 0 || name.indexOf("jdwp") >= 0) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            return false;
        }
        return false;
    }

    private static boolean environmentLooksFrida() {
        try {
            Map<String, String> environment = System.getenv();
            for (Map.Entry<String, String> entry : environment.entrySet()) {
                String name = entry.getKey();
                String value = entry.getValue();
                if (name == null) {
                    continue;
                }
                String upper = name.toUpperCase(java.util.Locale.ROOT);
                if (upper.startsWith("FRIDA") || "GADGET".equals(upper)) {
                    return true;
                }
                if (value == null) {
                    continue;
                }
                String lower = value.toLowerCase(java.util.Locale.ROOT);
                if (("LD_PRELOAD".equals(upper) || "DYLD_INSERT_LIBRARIES".equals(upper)
                        || "JAVA_TOOL_OPTIONS".equals(upper) || "_JAVA_OPTIONS".equals(upper))
                        && lower.indexOf("frida") >= 0) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            return false;
        }
        return false;
    }

    private static boolean environmentLooksDebug() {
        try {
            Map<String, String> environment = System.getenv();
            for (Map.Entry<String, String> entry : environment.entrySet()) {
                String name = entry.getKey();
                String value = entry.getValue();
                if (name == null || value == null) {
                    continue;
                }
                String upper = name.toUpperCase(java.util.Locale.ROOT);
                if (!"JAVA_TOOL_OPTIONS".equals(upper) && !"_JAVA_OPTIONS".equals(upper)
                        && !"JDK_JAVA_OPTIONS".equals(upper)) {
                    continue;
                }
                String lower = value.toLowerCase(java.util.Locale.ROOT);
                if (lower.indexOf("jdwp") >= 0 || lower.indexOf("dt_socket") >= 0
                        || lower.indexOf("dt_shmem") >= 0) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            return false;
        }
        return false;
    }

    private static boolean isWindows() {
        String os = System.getProperty("os.name", "");
        return os.toLowerCase(java.util.Locale.ROOT).indexOf("win") >= 0;
    }

    private static int procChecks() {
        int mask = 0;
        try {
            byte[] status = readFile("/proc/self/status");
            if (status != null) {
                mask |= evaluateProcStatus(new String(status,
                        java.nio.charset.StandardCharsets.ISO_8859_1));
            }
        } catch (Throwable ignored) {
            // best effort: /proc is not available on every platform
        }
        if (mask == 0) {
            try {
                byte[] maps = readFile("/proc/self/maps");
                if (maps != null) {
                    mask |= evaluateProcMaps(new String(maps,
                            java.nio.charset.StandardCharsets.ISO_8859_1));
                }
            } catch (Throwable ignored) {
                // best effort
            }
        }
        return mask;
    }

    /**
     * Evaluates {@code /proc/self/status}: a non-zero {@code TracerPid} means a
     * process is ptrace-attached (debugger, strace, Frida's ptrace backend).
     * Kept public and pure so the parser is unit-testable on any host.
     */
    public static int evaluateProcStatus(String text) {
        if (text == null) {
            return 0;
        }
        try {
            int tracer = text.indexOf("TracerPid:");
            if (tracer < 0) {
                return 0;
            }
            int lineEnd = text.indexOf('\n', tracer);
            String line = lineEnd < 0 ? text.substring(tracer) : text.substring(tracer, lineEnd);
            String value = line.substring(line.indexOf(':') + 1).trim();
            if (!value.isEmpty() && !"0".equals(value)) {
                return DETECT_JDWP;
            }
        } catch (Throwable ignored) {
            return 0;
        }
        return 0;
    }

    /**
     * Evaluates {@code /proc/self/maps}: instrumentation libraries (Frida/gum) in
     * any mapping are reported. Anonymous executable mappings are intentionally
     * not flagged here: the JVM's own JIT code cache is anonymous executable
     * memory on Linux, so flagging it would false-positive on every normal run.
     */
    public static int evaluateProcMaps(String text) {
        if (text == null) {
            return 0;
        }
        String lower = text.toLowerCase(java.util.Locale.ROOT);
        if (lower.indexOf("frida") >= 0 || lower.indexOf("gum-js") >= 0
                || lower.indexOf("gum-") >= 0 || lower.indexOf("libfrida") >= 0) {
            return DETECT_FRIDA_ENV;
        }
        return 0;
    }

    private static byte[] readFile(String path) {
        try {
            java.io.File file = new java.io.File(path);
            if (!file.isFile()) {
                return null;
            }
            InputStream in = new java.io.FileInputStream(file);
            try {
                return readStream(in);
            } finally {
                in.close();
            }
        } catch (Throwable ignored) {
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Anti-backfill: methods Umbra turned native must still be native
    // ------------------------------------------------------------------

    private static int verifyNativeMethods() {
        if (METHODS == null || METHODS.isEmpty()) {
            return 0;
        }
        int mask = 0;
        String[] entries = METHODS.split("\\n");
        for (int i = 0; i < entries.length; i++) {
            String entry = entries[i];
            if (entry.isEmpty()) {
                continue;
            }
            int first = entry.indexOf('#');
            int second = entry.indexOf('#', first + 1);
            if (first <= 0 || second <= first) {
                continue;
            }
            String owner = entry.substring(0, first).replace('/', '.');
            String name = entry.substring(first + 1, second);
            String descriptor = entry.substring(second + 1);
            try {
                Class<?> type = loadOwner(owner);
                if (!hasNativeMethod(type, name, descriptor)) {
                    mask |= DETECT_BACKFILL;
                }
            } catch (Throwable missing) {
                mask |= DETECT_BACKFILL;
            }
        }
        return mask;
    }

    /**
     * Loads a protected class through the context loader first: nested JAR/WAR
     * containers (Spring Boot {@code LaunchedURLClassLoader}, WAR loaders) keep
     * application classes behind their own loader while this helper sits at the
     * archive root.
     */
    private static Class<?> loadOwner(String dottedName) throws ClassNotFoundException {
        ClassNotFoundException failure = null;
        ClassLoader context = null;
        try {
            context = Thread.currentThread().getContextClassLoader();
        } catch (RuntimeException ignored) {
            context = null;
        }
        if (context != null) {
            try {
                return Class.forName(dottedName, false, context);
            } catch (ClassNotFoundException e) {
                failure = e;
            }
        }
        ClassLoader own = UmbraNativeGuard.class.getClassLoader();
        if (own != null && own != context) {
            try {
                return Class.forName(dottedName, false, own);
            } catch (ClassNotFoundException e) {
                failure = e;
            }
        }
        ClassLoader system = ClassLoader.getSystemClassLoader();
        if (system != null && system != own && system != context) {
            try {
                return Class.forName(dottedName, false, system);
            } catch (ClassNotFoundException e) {
                failure = e;
            }
        }
        throw failure == null ? new ClassNotFoundException(dottedName) : failure;
    }

    private static boolean hasNativeMethod(Class<?> type, String name, String descriptor) {
        Method[] methods;
        try {
            methods = type.getDeclaredMethods();
        } catch (Throwable failure) {
            return false;
        }
        for (int i = 0; i < methods.length; i++) {
            Method method = methods[i];
            if (!method.getName().equals(name)) {
                continue;
            }
            if (!Modifier.isNative(method.getModifiers())) {
                continue;
            }
            if (descriptor.equals(descriptorOf(method))) {
                return true;
            }
        }
        return false;
    }

    private static String descriptorOf(Method method) {
        StringBuilder out = new StringBuilder("(");
        Class<?>[] parameters = method.getParameterTypes();
        for (int i = 0; i < parameters.length; i++) {
            out.append(descriptorOf(parameters[i]));
        }
        out.append(')');
        out.append(descriptorOf(method.getReturnType()));
        return out.toString();
    }

    private static String descriptorOf(Class<?> type) {
        if (type.isArray()) {
            return type.getName().replace('.', '/');
        }
        if (!type.isPrimitive()) {
            return "L" + type.getName().replace('.', '/') + ";";
        }
        if (type == void.class) {
            return "V";
        }
        if (type == boolean.class) {
            return "Z";
        }
        if (type == byte.class) {
            return "B";
        }
        if (type == char.class) {
            return "C";
        }
        if (type == short.class) {
            return "S";
        }
        if (type == int.class) {
            return "I";
        }
        if (type == long.class) {
            return "J";
        }
        if (type == float.class) {
            return "F";
        }
        if (type == double.class) {
            return "D";
        }
        return "V";
    }

    // ------------------------------------------------------------------
    // Small helpers (self-contained copies of the pass-side helpers)
    // ------------------------------------------------------------------

    private static long mixToken(long secret, int challenge, long fileHash) {
        long hash = 0xcbf29ce484222325L ^ secret ^ fileHash;
        hash ^= ((long) challenge) & 0xFFFFFFFFL;
        hash *= 0x100000001b3L;
        hash ^= hash >>> 33;
        hash *= 0xff51afd7ed558ccdL;
        hash ^= hash >>> 33;
        return hash;
    }

    private static long parseHexLong(String value) {
        try {
            return Long.parseUnsignedLong(value.trim(), 16);
        } catch (Throwable failure) {
            return 0L;
        }
    }

    private static long parseLong(String value, long fallback) {
        try {
            return Long.parseLong(value.trim());
        } catch (Throwable failure) {
            return fallback;
        }
    }

    private static int parseAction(String value) {
        String action = value == null ? "" : value.trim().toLowerCase(java.util.Locale.ROOT);
        if ("exit".equals(action)) {
            return 2;
        }
        if ("corrupt".equals(action)) {
            return 3;
        }
        if ("log".equals(action)) {
            return 4;
        }
        return 1;
    }
}
