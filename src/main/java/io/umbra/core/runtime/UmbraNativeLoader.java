package io.umbra.core.runtime;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Runtime helper injected by {@code NativeCodePass}.
 *
 * <p>It extracts the native library embedded in the protected JAR to a unique
 * temporary file and loads it with {@link System#load(String)}. Owning classes
 * call {@link #ensureLoaded()} from a synthesized {@code <clinit>} hook before
 * any of their native methods can run, so a single call site guarantees the
 * library is registered.</p>
 *
 * <h3>Anti-dump</h3>
 *
 * <p>When {@code native.antiDump} is enabled (default), the extracted bytes are
 * hashed with SHA-256 and compared with the fingerprint embedded at protection
 * time <em>before</em> {@link System#load} runs: a dumped and rebuilt library, a
 * patched resource or a foreign DLL is refused. When
 * {@code native.antiBackfill} is enabled (default), the library must also answer
 * a per-call keyed challenge ({@link #verifyChallenge(int)}); the response mixes
 * the per-program key with a fresh nonce, so a library built for another program
 * (or rebuilt without the key) is refused. The native side additionally
 * self-checks its backfill table in {@code JNI_OnLoad}. All checks refuse by
 * throwing an {@link IOException} from the load path; {@link #ensureLoaded()}
 * then reports the failure and every native method of the protected program
 * stays unbound, so a tampered program does not run.</p>
 *
 * <p>The class is a runtime template: it must stay a single top-level class with
 * no nested or anonymous classes, must only use JDK APIs and is copied into the
 * output under a random name. {@code @@RESOURCE@@} is replaced with the JAR
 * entry name of the bundled library, {@code @@ANTIDUMP@@}/{@code @@ANTIBACKFILL@@}
 * with booleans, {@code @@FP0@@..@@FP2@@} with SHA-256 hex chunks and
 * {@code @@AKEY@@} with the per-program key.</p>
 */
public final class UmbraNativeLoader {

    /** JAR entry that holds the compiled native library. */
    private static final String RESOURCE = "@@RESOURCE@@";
    private static final String ANTI_DUMP_FLAG = "@@ANTIDUMP@@";
    private static final String ANTI_BACKFILL_FLAG = "@@ANTIBACKFILL@@";
    private static final String FINGERPRINT_0 = "@@FP0@@";
    private static final String FINGERPRINT_1 = "@@FP1@@";
    private static final String FINGERPRINT_2 = "@@FP2@@";
    private static final String KEY_HEX = "@@AKEY@@";

    private static final boolean ANTI_DUMP = Boolean.parseBoolean(ANTI_DUMP_FLAG);
    private static final boolean ANTI_BACKFILL = Boolean.parseBoolean(ANTI_BACKFILL_FLAG);
    private static final long KEY = parseHexLong(KEY_HEX);

    private static final Object LOCK = new Object();
    /** Neutral marker for stale-directory cleanup (no fixed file-name prefix). */
    private static final String MARKER = "9f2c7a4e1b8d6350a5c9e2f7b4d1863e";
    private static final String MARKER_FILE = "m";
    private static final String NAME_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    private static volatile int state;
    private static volatile String failure;

    /** Keyed backfill challenge implemented by the generated native library. */
    private static native long verifyChallenge(int nonce);

    private UmbraNativeLoader() {
    }

    /**
     * Loads the embedded native library once.
     *
     * @return {@code true} when the library is loaded and registered
     */
    public static boolean ensureLoaded() {
        int current = state;
        if (current == 1) {
            return true;
        }
        if (current == 2) {
            return false;
        }
        synchronized (LOCK) {
            if (state == 1) {
                return true;
            }
            if (state == 2) {
                return false;
            }
            try {
                loadLibrary();
                state = 1;
                return true;
            } catch (Throwable error) {
                failure = describe(error);
                state = 2;
                String message = String.valueOf(error.getMessage());
                if (message.indexOf("rejected") >= 0 || message.indexOf("mismatch") >= 0
                        || message.indexOf("refused") >= 0) {
                    System.err.println("[Umbra] native library refused ("
                            + RESOURCE + "): " + failure);
                } else {
                    System.err.println("[Umbra] native library could not be loaded ("
                            + RESOURCE + "): " + failure);
                }
                return false;
            }
        }
    }

    /** True when the native library has been loaded successfully. */
    public static boolean isLoaded() {
        return state == 1;
    }

    /** Diagnostic message for the failed load attempt, or {@code null}. */
    public static String failureReason() {
        return failure;
    }

    private static void loadLibrary() throws IOException {
        byte[] data = readResource();
        if (data == null || data.length == 0) {
            throw new IOException("native payload is missing from the JAR");
        }
        if (ANTI_DUMP) {
            verifyFingerprint(data);
        }
        File file = writeLibrary(data);
        try {
            System.load(file.getAbsolutePath());
        } catch (Throwable error) {
            if (file.exists() && !file.delete()) {
                file.deleteOnExit();
            }
            if (error instanceof IOException) {
                throw (IOException) error;
            }
            throw new IOException(describe(error));
        }
        disposeAfterLoad(file);
        if (ANTI_BACKFILL) {
            verifyChallenge();
        }
    }

    /**
     * Refuses a library whose bytes do not match the fingerprint embedded at
     * protection time: dumped, rebuilt, patched or replaced native payloads all
     * change the SHA-256 digest.
     */
    private static void verifyFingerprint(byte[] data) throws IOException {
        String expected = FINGERPRINT_0 + FINGERPRINT_1 + FINGERPRINT_2;
        if (expected.length() != 64) {
            throw new IOException("native library fingerprint is missing");
        }
        String actual = sha256Hex(data);
        if (actual == null) {
            throw new IOException("native library fingerprint could not be computed");
        }
        if (!actual.equalsIgnoreCase(expected)) {
            throw new IOException("native library fingerprint mismatch (dumped or rebuilt payload)");
        }
    }

    /**
     * Keyed challenge: the loaded library must return the mix of the per-program
     * key and the caller nonce. A library built for another program (or one
     * rebuilt without the embedded key) cannot answer it.
     */
    private static void verifyChallenge() throws IOException {
        int nonce = challengeNonce();
        long expected = mixChallenge(nonce);
        long actual;
        try {
            actual = verifyChallenge(nonce);
        } catch (Throwable error) {
            throw new IOException("native method table rejected (backfill challenge failed: "
                    + describe(error) + ")");
        }
        if (actual != expected) {
            throw new IOException("native method table rejected (backfill challenge mismatch)");
        }
    }

    /** Fresh per-load nonce (time + identity, then folded to 32 bits). */
    private static int challengeNonce() {
        long value = System.nanoTime()
                ^ (System.currentTimeMillis() * 0x9E3779B97F4A7C15L)
                ^ (((long) System.identityHashCode(LOCK)) << 17);
        return (int) (value ^ (value >>> 32));
    }

    /** Mirrors {@code umbra_mix} in the generated C library. */
    private static long mixChallenge(int nonce) {
        long hash = 0xcbf29ce484222325L ^ KEY ^ (((long) nonce) & 0xFFFFFFFFL);
        hash *= 0x100000001b3L;
        hash ^= hash >>> 33;
        hash *= 0xff51afd7ed558ccdL;
        hash ^= hash >>> 33;
        return hash;
    }

    /** Lower-case SHA-256 hex, or {@code null} when the digest is unavailable. */
    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            char[] hex = new char[hash.length * 2];
            for (int i = 0; i < hash.length; i++) {
                int value = hash[i] & 0xFF;
                hex[i * 2] = HEX[value >>> 4];
                hex[i * 2 + 1] = HEX[value & 0x0F];
            }
            return new String(hex);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static final char[] HEX = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private static File writeLibrary(byte[] data) throws IOException {
        cleanupStaleLibraries();
        File root = new File(System.getProperty("java.io.tmpdir", "."));
        File directory = new File(root, randomName(16));
        if (!directory.mkdirs()) {
            throw new IOException("could not create the native library directory");
        }
        File file = new File(directory, randomName(16) + librarySuffix());
        OutputStream out = new FileOutputStream(file);
        try {
            out.write(data);
        } finally {
            out.close();
        }
        writeMarker(directory);
        file.deleteOnExit();
        // The marker intentionally survives: after this process exits the cleanup
        // of the next run needs it to identify the leftover directory.
        directory.deleteOnExit();
        return file;
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
            // deleteOnExit remains the fallback
        }
    }

    private static String randomName(int length) {
        StringBuilder name = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            name.append(NAME_CHARS.charAt(RANDOM.nextInt(NAME_CHARS.length())));
        }
        return name.toString();
    }

    /**
     * Removes the mapped library file after it was loaded. POSIX allows unlinking
     * a mapped library; Windows locks a mapped image against delete/write, so the
     * directory is removed by the marker-based stale cleanup of a later run.
     */
    private static void disposeAfterLoad(File file) {
        File directory = file.getParentFile();
        if (!isWindows()) {
            file.delete();
            if (directory != null) {
                new File(directory, MARKER_FILE).delete();
                deleteTree(directory);
            }
            return;
        }
        try {
            java.io.RandomAccessFile locked = new java.io.RandomAccessFile(file, "rw");
            try {
                locked.setLength(0);
            } finally {
                locked.close();
            }
            if (file.delete() && directory != null) {
                new File(directory, MARKER_FILE).delete();
                deleteTree(directory);
            }
        } catch (Throwable ignored) {
            file.deleteOnExit();
        }
    }

    /**
     * Best-effort cleanup of native library directories left by earlier runs.
     * Only old directories carrying the neutral marker are considered; no file
     * name prefix is matched and libraries locked by a live process are skipped.
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
            // cleanup must never break loading
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

    private static boolean isWindows() {
        String os = System.getProperty("os.name", "");
        return os.toLowerCase(java.util.Locale.ROOT).indexOf("win") >= 0;
    }
    /** Parses the 16-hex-digit per-program key (unsigned, no sign extension). */
    private static long parseHexLong(String value) {
        if (value == null || value.length() != 16) {
            return 0L;
        }
        long result = 0L;
        for (int i = 0; i < 16; i++) {
            int digit = Character.digit(value.charAt(i), 16);
            if (digit < 0) {
                return 0L;
            }
            result = (result << 4) | (digit & 0x0FL);
        }
        return result;
    }

    private static String librarySuffix() {
        String os = System.getProperty("os.name", "");
        String lower = os.toLowerCase(java.util.Locale.ROOT);
        if (lower.indexOf("win") >= 0) {
            return ".dll";
        }
        if (lower.indexOf("mac") >= 0) {
            return ".dylib";
        }
        return ".so";
    }

    /** Reads the library bytes from the first available location. */
    private static byte[] readResource() {
        byte[] data = readStream(UmbraNativeLoader.class.getResourceAsStream("/" + RESOURCE));
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
        data = readFromCodeSource();
        if (data != null && data.length > 0) {
            return data;
        }
        return null;
    }

    /**
     * Last resort: read the entry straight out of the JAR the class was loaded
     * from. This also works when a custom loader (encrypted-class loader) does not
     * implement resource lookups.
     */
    private static byte[] readFromCodeSource() {
        try {
            CodeSource source = UmbraNativeLoader.class.getProtectionDomain().getCodeSource();
            if (source == null) {
                return null;
            }
            URL location = source.getLocation();
            if (location == null || !"file".equalsIgnoreCase(location.getProtocol())) {
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

    private static String describe(Throwable error) {
        String message = error.getMessage();
        return error.getClass().getName() + (message == null ? "" : ": " + message);
    }
}
