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

    private static final String MARKER = "9f2c7a4e1b8d6350a5c9e2f7b4d1863e";
    private static final String MARKER_FILE = "m";
    private static final String NAME_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    private static final boolean DEBUG = Boolean.getBoolean("umbra.debug");

    private static void say(String line) {
        if (DEBUG) {
            System.err.println(line);
        }
    }

    private static volatile int state;
    private static volatile String failure;

    private static native long verifyChallenge(int nonce);

    public static native int register(int classId, Class<?> owner);

    public static native int keyRoot(int slot, int sub, byte[] out);

    public static native int keyRoot2(int slot, int sub, byte[] nonce, byte[] out);

    public static native int installCodeLibrary(String path, Class<?> loaderClass);

    public static native int bindNames(int version, String[] names);

    public static native int verifyLoader(byte[] loaderBytes);

    public static native int verifyLoader(byte[] loaderBytes, byte[] bridgeBytes);

    public static native int verifyLoader(String loaderSha, String bridgeSha);

    public static final int BIND_NAMES_VERSION = 2;

    public static boolean bindOwnNames(Class<?> owner) {
        if (owner == null) {
            return false;
        }
        try {
            if (!ensureLoaded()) {
                return false;
            }
            String[] names = new String[] {
                    nameFor(owner, "(II[B[B)I"),
                    nameFor(owner, "([J)I"),
                    nameFor(owner, "(J[B)I"),
                    nameFor(owner, "(I[B)I"),
                    nameFor(owner, "(Ljava/lang/String;Ljava/lang/Class;)I"),
                    nameFor(owner, "(ILjava/lang/Class;)I"),
                    nameFor(owner, "(I)J"),

                    firstNonEmpty(nameFor(owner, "(Ljava/lang/String;Ljava/lang/String;)I"),
                            nameFor(owner, "([B[B)I"),
                            nameFor(owner, "([B)I")),
            };
            if (names[0].isEmpty() || names[5].isEmpty()) {
                say("[umbra-diag] owner=" + owner.getName()
                        + " keyRoot2=[] register=[] - descriptors do not match");
                return false;
            }

            for (java.lang.reflect.Method method : owner.getDeclaredMethods()) {
                if (method.getName().equals(names[0]) || method.getName().equals(names[5])) {
                    if (!java.lang.reflect.Modifier.isNative(method.getModifiers())) {
                        say("[umbra-diag] not-native " + method.getName()
                                + " modifiers=0x" + Integer.toHexString(method.getModifiers()));
                    }
                }
            }
            int rc = bindNames(BIND_NAMES_VERSION, names);
            if (rc != 0) {
                say("[umbra-diag] bindNames rc=" + rc + " owner=" + owner.getName());
            }
            return rc == 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean bindOwnNames() {
        try {
            boolean loaded = ensureLoaded();
            say("[umbra-diag] bindOwnNames enter loaded=" + loaded);
            if (!loaded) {
                return false;
            }

            Class<?> self = new Object() {
            }.getClass().getEnclosingClass();
            if (self == null) {
                say("[umbra-diag] no caller class; call bindOwnNames(Class)");
                return false;
            }
            String[] names = new String[] {
                    nameFor(self, "(II[B[B)I"),
                    nameFor(self, "([J)I"),
                    nameFor(self, "(J[B)I"),
                    nameFor(self, "(I[B)I"),
                    nameFor(self, "(Ljava/lang/String;Ljava/lang/Class;)I"),
                    nameFor(self, "(ILjava/lang/Class;)I"),
                    nameFor(self, "(I)J"),
            };

            if (names[0] == null || names[0].isEmpty() || names[5] == null || names[5].isEmpty()) {
                say("[umbra-diag] self=" + self.getName() + " declared="
                        + self.getDeclaredMethods().length + " keyRoot2=[" + names[0]
                        + "] register=[" + names[5] + "]");
                return false;
            }
            for (int i = 0; i < names.length; i++) {
                if (names[i] == null) {
                    names[i] = "";
                }
            }
            int rc = bindNames(BIND_NAMES_VERSION, names);
            if (rc != 0) {
                say("[umbra-diag] bindNames rc=" + rc + " self=" + self.getName()
                        + " keyRoot2=[" + names[0] + "] register=[" + names[5] + "]");
            }
            return rc == 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String firstNonEmpty(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isEmpty()) {
                return candidate;
            }
        }
        return "";
    }

    private static String nameFor(Class<?> owner, String descriptor) {
        for (java.lang.reflect.Method method : owner.getDeclaredMethods()) {

            if ((method.getModifiers() & java.lang.reflect.Modifier.NATIVE) == 0) {
                continue;
            }
            if (descriptor.equals(describe(method))) {
                return method.getName();
            }
        }
        return "";
    }

    private static String describe(java.lang.reflect.Method method) {
        StringBuilder out = new StringBuilder();
        out.append('(');
        for (Class<?> type : method.getParameterTypes()) {
            out.append(typeName(type));
        }
        out.append(')').append(typeName(method.getReturnType()));
        return out.toString();
    }

    private static String typeName(Class<?> type) {
        if (type == void.class) {
            return "V";
        }
        if (type == int.class) {
            return "I";
        }
        if (type == long.class) {
            return "J";
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
        if (type == float.class) {
            return "F";
        }
        if (type == double.class) {
            return "D";
        }
        if (type.isArray()) {
            return "[" + typeName(type.getComponentType());
        }
        return "L" + type.getName().replace('.', '/') + ";";
    }

    public static native int gateChallenge(long[] out);

    public static native int gateAttest(long nonce, byte[] response);

    public static native int gateTick(int index, byte[] out);

    public static byte[] tick(int index) {
        try {
            if (!ensureLoaded()) {
                return null;
            }
            byte[] out = new byte[32];
            return gateTick(index, out) == 0 ? out : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    public static long challenge() {
        try {
            if (!ensureLoaded()) {
                return 0L;
            }
            long[] out = new long[1];
            return gateChallenge(out) == 0 ? out[0] : 0L;
        } catch (Throwable ignored) {
            return 0L;
        }
    }

    public static boolean attest(long nonce, byte[] response) {
        try {
            if (!ensureLoaded()) {
                return false;
            }
            return gateAttest(nonce, response) == 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static volatile byte[] handshake;

    public static void setHandshake(byte[] value) {
        handshake = value == null ? null : value.clone();
    }

    public static byte[] deriveKey(int slot, int sub) {
        byte[] nonce = handshake;
        if (nonce == null) {

            return null;
        }
        try {
            if (!ensureLoaded()) {
                return null;
            }
            byte[] out = new byte[32];
            if (keyRoot2(slot, sub, nonce, out) == 0) {
                return out;
            }
        } catch (Throwable ignored) {

        }
        return null;
    }

    private UmbraNativeLoader() {
    }

    public static boolean install(java.io.File library) {
        if (library == null) {
            return false;
        }
        synchronized (LOCK) {
            if (state == 1) {
                return true;
            }
            try {
                System.load(library.getAbsolutePath());
                state = 1;
                return true;
            } catch (Throwable error) {
                failure = describe(error);
                state = 2;
                return false;
            }
        }
    }

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
                    say("[Umbra] native library refused ("
                            + RESOURCE + "): " + failure);
                } else {
                    say("[Umbra] native library could not be loaded ("
                            + RESOURCE + "): " + failure);
                }
                return false;
            }
        }
    }

    public static boolean isLoaded() {
        return state == 1;
    }

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

    private static void verifyFingerprint(byte[] data) throws IOException {
        String expected = FINGERPRINT_0 + FINGERPRINT_1 + FINGERPRINT_2;
        if (expected.length() != 64) {
            throw new IOException("native library fingerprint is missing");
        }
        String actual = fingerprintWithoutDigestSlot(data);
        if (actual == null) {
            throw new IOException("native library fingerprint could not be computed");
        }
        if (!actual.equalsIgnoreCase(expected)) {
            say("umbra-fp-mismatch actual=" + actual.substring(0, 16)
                    + " expected=" + expected.substring(0, 16) + " len=" + data.length);
            throw new IOException("native library fingerprint mismatch (dumped or rebuilt payload)");
        }
    }

    private static int indexOfBytes(byte[] haystack, byte[] needle, int from) {
        outer:
        for (int i = Math.max(0, from); i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static String fingerprintWithoutDigestSlot(byte[] data) {
        byte[] magic1 = {'U', 'M', 'B', 'R', 'A', 'D', 'G', '1'};
        byte[] magic2 = {'U', 'M', 'B', 'R', 'A', 'D', 'G', '2'};
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            int cursor = 0;
            int skipped = 0;
            while (true) {
                int at1 = indexOfBytes(data, magic1, cursor);
                int at2 = indexOfBytes(data, magic2, cursor);
                int at = at1 < 0 ? at2 : (at2 < 0 ? at1 : Math.min(at1, at2));
                if (at < 0) {
                    break;
                }
                int from = at + magic1.length;
                int to = from + 32;
                if (to > data.length) {
                    break;
                }
                digest.update(data, cursor, from - cursor);
                cursor = to;
                skipped++;
            }
            if (skipped == 0) {
                return sha256Hex(data);
            }
            digest.update(data, cursor, data.length - cursor);
            byte[] hash = digest.digest();
            StringBuilder text = new StringBuilder(hash.length * 2);
            for (byte value : hash) {
                text.append(Character.forDigit((value >> 4) & 0xF, 16));
                text.append(Character.forDigit(value & 0xF, 16));
            }
            return text.toString();
        } catch (java.security.NoSuchAlgorithmException missing) {
            return sha256Hex(data);
        }
    }

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

    private static int challengeNonce() {
        long value = System.nanoTime()
                ^ (System.currentTimeMillis() * 0x9E3779B97F4A7C15L)
                ^ (((long) System.identityHashCode(LOCK)) << 17);
        return (int) (value ^ (value >>> 32));
    }

    private static long mixChallenge(int nonce) {
        long hash = 0xcbf29ce484222325L ^ KEY ^ (((long) nonce) & 0xFFFFFFFFL);
        hash *= 0x100000001b3L;
        hash ^= hash >>> 33;
        hash *= 0xff51afd7ed558ccdL;
        hash ^= hash >>> 33;
        return hash;
    }

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

        }
    }

    private static String randomName(int length) {
        StringBuilder name = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            name.append(NAME_CHARS.charAt(RANDOM.nextInt(NAME_CHARS.length())));
        }
        return name.toString();
    }

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

            }
        }
    }

    private static String describe(Throwable error) {
        String message = error.getMessage();
        return error.getClass().getName() + (message == null ? "" : ": " + message);
    }
}
