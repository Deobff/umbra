package io.umbra.core.runtime.crypto;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Startup integrity / anti-tamper guard.
 *
 * <p>Runtime template: no nested/anonymous classes, no references to other
 * Umbra classes except {@link UmbraCrypto} (remapped at injection time). The
 * pass computes, after the archive is written, a sealed manifest of per-entry
 * SHA-256 digests (excluding this class and the manifest itself) plus an
 * aggregate digest; this guard re-computes it at startup and on a background
 * watchdog.</p>
 *
 * <ul>
 *   <li>level 1 - verify the aggregate manifest digest only.</li>
 *   <li>level 2 - verify the aggregate and every class entry digest.</li>
 *   <li>level 3 - verify every entry digest and re-verify periodically.</li>
 * </ul>
 *
 * <p>Failures are routed through the configured action. Missing management
 * APIs or an exploded (non-JAR) deployment are treated as "cannot verify" and
 * silently skipped so normal launches never false-positive; a present JAR with
 * a missing/broken manifest is treated as tampering.</p>
 */
public final class UmbraIntegrityGuard {

    // Substituted at injection time.
    private static final String DIGEST_ENTRY = "@@DIGEST@@";
    private static final String KEY_PART_0 = "@@P0@@";
    private static final String KEY_PART_1 = "@@P1@@";
    private static final String KEY_PART_2 = "@@P2@@";
    private static final String KEY_PART_3 = "@@P3@@";
    private static final String KEY_SALT = "@@SALT@@";
    private static final String ACTION = "@@ACTION@@";
    private static final String LEVEL_TEXT = "@@LEVEL@@";
    private static final String ANTIDUMP_TEXT = "@@ANTIDUMP@@";
    private static final String WATCHDOG = "@@WATCHDOG@@";
    private static final String RUNTIME_GUARD = "@@RUNTIMEGUARD@@";

    private static final int MAGIC = 0x554D4932;
    private static final int DEFAULT_LEVEL = 1;

    private static volatile boolean checked;
    private static volatile boolean watchdogStarted;

    private UmbraIntegrityGuard() {
    }

    /** Called at the start of every program entry point. */
    public static void check() {
        if (checked) {
            return;
        }
        synchronized (UmbraIntegrityGuard.class) {
            if (checked) {
                return;
            }
            checked = true;
        }
        runRuntimeGuard();
        try {
            verify();
        } catch (SecurityException failure) {
            throw failure;
        } catch (Throwable ignored) {
            // Unknown environment (no management API, custom loader, ...):
            // never break a legitimate run.
        }
    }

    /** Re-verification entry point used by the background watchdog. */
    public static void watch() {
        runRuntimeGuard();
        try {
            verify();
        } catch (SecurityException failure) {
            throw failure;
        } catch (Throwable ignored) {
            // See check().
        }
    }

    /**
     * Reuses the injected unified runtime guard (placeholder {@code @@RUNTIMEGUARD@@}):
     * the integrity pass and the anti-debug pass share one detector, so an
     * instrumented process is refused before the archive digests are trusted.
     * An absent/old guard class is ignored instead of breaking a legitimate run.
     */
    private static void runRuntimeGuard() {
        if (RUNTIME_GUARD == null || RUNTIME_GUARD.isEmpty()
                || RUNTIME_GUARD.charAt(0) == '@') {
            return;
        }
        try {
            Class<?> type = Class.forName(RUNTIME_GUARD, true, UmbraIntegrityGuard.class.getClassLoader());
            java.lang.reflect.Method check = type.getDeclaredMethod("check");
            check.setAccessible(true);
            check.invoke(null);
        } catch (java.lang.reflect.InvocationTargetException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof SecurityException) {
                throw (SecurityException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
        } catch (Throwable unavailable) {
            // The guard is best effort; the digest checks still run.
        }
    }

    // ------------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------------

    private static void verify() throws Exception {
        URL location = locateOwnArchive();
        if (location == null || !"file".equals(location.getProtocol())) {
            return;
        }
        File file = new File(location.toURI());
        if (!file.isFile()) {
            return;
        }
        int level = parseLevel();
        JarFile jar = new JarFile(file);
        try {
            if (level >= 3) {
                startWatchdog();
            }
            if (isAntiDump()) {
                checkNoAgents();
                checkNoDuplicates(jar);
            }
            byte[] sealed = readEntry(jar, DIGEST_ENTRY);
            if (sealed == null) {
                fail("Integrity manifest is missing");
            }
            byte[] master = UmbraCrypto.masterKey(
                    new String[] { KEY_PART_0, KEY_PART_1, KEY_PART_2, KEY_PART_3 }, KEY_SALT);
            byte[] manifest = UmbraCrypto.unseal(sealed, master, UmbraCrypto.ALG_CHACHA20);
            UmbraCrypto.wipe(sealed);
            UmbraCrypto.wipe(master);

            ByteBuffer buffer = ByteBuffer.wrap(manifest);
            if (buffer.getInt() != MAGIC) {
                fail("Integrity manifest is not valid");
            }
            if (buffer.get() != 1) {
                fail("Unsupported integrity manifest version");
            }
            int manifestLevel = buffer.get() & 0xFF;
            if (manifestLevel > level) {
                fail("Integrity manifest level mismatch");
            }
            int count = buffer.getInt();
            Map<String, byte[]> expected = new LinkedHashMap<String, byte[]>();
            for (int i = 0; i < count; i++) {
                byte[] nameBytes = new byte[buffer.getInt()];
                buffer.get(nameBytes);
                String name = new String(nameBytes, StandardCharsets.UTF_8);
                byte[] digest = new byte[32];
                buffer.get(digest);
                expected.put(name, digest);
            }
            byte[] expectedAggregate = new byte[32];
            buffer.get(expectedAggregate);

            String selfEntry = UmbraIntegrityGuard.class.getName().replace('.', '/') + ".class";
            Map<String, byte[]> actual = readArchiveDigests(jar, selfEntry);
            byte[] actualAggregate = aggregate(actual);

            if (!UmbraCrypto.constantTimeEquals(expectedAggregate, actualAggregate)) {
                UmbraCrypto.wipe(actualAggregate);
                fail("Archive digest mismatch");
            }
            UmbraCrypto.wipe(actualAggregate);

            if (level >= 2) {
                if (!expected.keySet().equals(actual.keySet())) {
                    fail("Archive entry set mismatch");
                }
                for (Map.Entry<String, byte[]> entry : expected.entrySet()) {
                    String name = entry.getKey();
                    if (level < 3 && !name.endsWith(".class")) {
                        continue;
                    }
                    byte[] found = actual.get(name);
                    if (found == null || !UmbraCrypto.constantTimeEquals(entry.getValue(), found)) {
                        fail("Archive entry digest mismatch");
                    }
                }
            }
            checked = true;
        } finally {
            try {
                jar.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

    private static void startWatchdog() {
        synchronized (UmbraIntegrityGuard.class) {
            if (watchdogStarted) {
                return;
            }
            watchdogStarted = true;
        }
        try {
            Class<?> watchdogType = Class.forName(WATCHDOG, true, UmbraIntegrityGuard.class.getClassLoader());
            Object watchdog = watchdogType.getConstructor(String.class, String.class, long.class, int.class)
                    .newInstance(UmbraIntegrityGuard.class.getName(), "watch",
                            Long.valueOf(4000L), Integer.valueOf(0));
            ((Thread) watchdog).start();
        } catch (Throwable ignored) {
            // No watchdog: startup verification already happened.
        }
    }

    private static Map<String, byte[]> readArchiveDigests(JarFile jar, String selfEntry) throws IOException {
        String digestName = DIGEST_ENTRY;
        Map<String, byte[]> digests = new LinkedHashMap<String, byte[]>();
        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            if (entry.isDirectory()) {
                continue;
            }
            String name = entry.getName();
            if (name.equals(digestName) || name.equals(selfEntry)) {
                continue;
            }
            byte[] bytes = readEntry(jar, name);
            if (bytes == null) {
                fail("Archive entry is unreadable");
            }
            digests.put(name, UmbraCrypto.sha256(bytes));
        }
        return digests;
    }

    private static byte[] aggregate(Map<String, byte[]> digests) {
        List<String> names = new ArrayList<String>(digests.keySet());
        Collections.sort(names);
        ByteArrayOutputStream collector = new ByteArrayOutputStream();
        try {
            for (int i = 0; i < names.size(); i++) {
                String name = names.get(i);
                byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
                writeInt(collector, nameBytes.length);
                collector.write(nameBytes);
                collector.write(digests.get(name));
            }
        } catch (IOException impossible) {
            throw new IllegalStateException("digest stream failed");
        }
        return UmbraCrypto.sha256(collector.toByteArray());
    }

    private static void checkNoAgents() {
        try {
            java.lang.management.RuntimeMXBean bean =
                    java.lang.management.ManagementFactory.getRuntimeMXBean();
            List<String> arguments = bean.getInputArguments();
            for (int i = 0; i < arguments.size(); i++) {
                String lower = arguments.get(i).toLowerCase(Locale.ROOT);
                if (lower.contains("jdwp") || lower.contains("javaagent") || lower.contains("agentlib")
                        || lower.contains("agentpath") || lower.contains("-xdebug")) {
                    fail("A dump/debug agent is attached");
                }
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable ignored) {
            // management API unavailable
        }
    }

    private static void checkNoDuplicates(JarFile jar) {
        Set<String> seen = new LinkedHashSet<String>();
        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            if (entry.isDirectory()) {
                continue;
            }
            if (!seen.add(entry.getName())) {
                fail("Duplicate archive entry");
            }
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static URL locateOwnArchive() {
        ProtectionDomain domain = UmbraIntegrityGuard.class.getProtectionDomain();
        if (domain == null) {
            return null;
        }
        CodeSource source = domain.getCodeSource();
        return source == null ? null : source.getLocation();
    }

    private static byte[] readEntry(JarFile jar, String name) throws IOException {
        JarEntry entry = jar.getJarEntry(name);
        if (entry == null) {
            return null;
        }
        InputStream in = jar.getInputStream(entry);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static int parseLevel() {
        try {
            int level = Integer.parseInt(LEVEL_TEXT);
            return level < 1 ? DEFAULT_LEVEL : (level > 3 ? 3 : level);
        } catch (NumberFormatException e) {
            return DEFAULT_LEVEL;
        }
    }

    private static boolean isAntiDump() {
        return "true".equalsIgnoreCase(ANTIDUMP_TEXT);
    }

    private static void fail(String message) {
        if ("exit".equals(ACTION)) {
            Runtime.getRuntime().halt(1);
        }
        if ("corrupt".equals(ACTION)) {
            System.err.close();
            Runtime.getRuntime().halt(0);
        }
        throw new SecurityException(message);
    }
}
