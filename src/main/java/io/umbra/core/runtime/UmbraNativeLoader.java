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
    private static final String LAYOUT_ENTRY = "@@LAYOUT@@";
    /** "1" when the resource is an LZMA2 payload, "0" when it is the library. */
    private static final String PAYLOAD_FLAG = "@@PAYLOAD@@";

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
                say("[Umbra] " + refusalMessage(failure));
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

    /**
     * Fail-closed entry point for the generated {@code <clinit>} hook.
     *
     * <p>The anti-dump fingerprint is compared with the extracted bytes
     * <em>before</em> {@link System#load} and the anti-backfill challenge runs right
     * after it, so both checks already sit on the load path and both have the
     * library bytes in hand. What used to be missing was the caller: the hook
     * dropped the {@link #ensureLoaded()} boolean and called the first native method
     * ({@code register}) anyway, which the JVM answered with a bare
     * {@code UnsatisfiedLinkError: register} - indistinguishable from a wiring bug
     * and silent unless {@code -Dumbra.debug=true} was set. The hook now calls this
     * method, which aborts class initialization with the real refusal reason.</p>
     */
    public static void assertLoaded() {
        if (ensureLoaded()) {
            return;
        }
        String reason = failure == null ? "unknown failure" : failure;
        throw new IllegalStateException(refusalMessage(reason));
    }

    private static String refusalMessage(String reason) {
        // A protected build only ever loads a payload it has verified, so any load
        // failure under anti-dump/anti-backfill is a refusal, not a missing file.
        String head = (ANTI_DUMP || ANTI_BACKFILL)
                ? "Umbra native library refused"
                : "Umbra native library could not be loaded";
        return head + " (" + RESOURCE + "): " + reason;
    }

    /**
     * Refuses to load the payload when the JVM runs with a Java agent.
     *
     * <p>the reference implementation's loader skips its whole extraction routine when an agent is
     * attached, so instrumentation faces a library that was never loaded instead
     * of one that was loaded and then verified. The argument form matters:
     * HotSpot takes {@code -javaagent:<jar>} and {@code -agentlib:<name>}, so a
     * bare equals() test would miss every real invocation. Both the bare token
     * and the colon form therefore count as an agent.</p>
     */
    static boolean agentAttached() {
        try {
            return agentAttached(java.lang.management.ManagementFactory
                    .getRuntimeMXBean().getInputArguments());
        } catch (Throwable unavailable) {
            return false;
        }
    }

    static boolean agentAttached(java.util.List<String> arguments) {
        if (arguments == null) {
            return false;
        }
        for (String argument : arguments) {
            if (argument == null) {
                continue;
            }
            if ("-javaagent".equals(argument) || argument.startsWith("-javaagent:")) {
                return true;
            }
            if ("-agentlib".equals(argument) || argument.startsWith("-agentlib:")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Decodes the stored-chunk LZMA2 stream produced by the build.
     *
     * <p>The loader stays a single self-contained class, so only the stored chunk
     * kind is understood here: the build never emits range-coded LZMA chunks. A
     * resource that is not a stream at all (an older build) is returned as-is,
     * which keeps loaders injected by other passes working.</p>
     */
    /**
     * Decodes the stored-chunk LZMA2 stream produced by the build.
     *
     * <p>The decision is a build-time flag, never a guess: the pass substitutes
     * {@code @@PAYLOAD@@} with "1" when it wrote a container and "0" when the
     * resource is the library itself (the shape other passes still produce). A
     * build that says "1" is decoded or refused - it is never written out raw,
     * because that is exactly the failure mode where an undecoded stream reaches
     * {@code System.load} and surfaces as "Can't find dependent libraries".</p>
     */
    private static byte[] decodePayload(byte[] raw) throws IOException {
        if (!payloadEnabled()) {
            say("[umbra-native] payload=raw bytes=" + raw.length);
            return raw;
        }
        int control = raw[0] & 0xFF;
        if (control != 0 && control != 1 && control != 2) {
            throw new IOException("native payload uses an unsupported LZMA2 chunk: " + control);
        }
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(raw.length + 16);
        int index = 0;
        boolean resetSeen = false;
        while (true) {
            if (index >= raw.length) {
                throw new IOException("native payload is truncated");
            }
            int kind = raw[index++] & 0xFF;
            if (kind == 0) {
                break;
            }
            if (kind == 1) {
                resetSeen = true;
            } else if (kind != 2) {
                throw new IOException("native payload uses an unsupported LZMA2 chunk: " + kind);
            } else if (!resetSeen) {
                throw new IOException("native payload does not start with a dictionary reset");
            }
            if (index + 2 > raw.length) {
                throw new IOException("native payload is truncated");
            }
            int size = (((raw[index] & 0xFF) << 8) | (raw[index + 1] & 0xFF)) + 1;
            index += 2;
            if (index + size > raw.length) {
                throw new IOException("native payload chunk overruns the resource");
            }
            out.write(raw, index, size);
            index += size;
        }
        return out.toByteArray();
    }

    /** Build-time switch; an unsubstituted placeholder means "raw library". */
    private static boolean payloadEnabled() {
        return "1".equals(PAYLOAD_FLAG);
    }

    /** Entry name of the layout table, or null when this build has none. */
    private static String layoutEntry() {
        // A char test on purpose: a "@@" string literal inside this method would be
        // flagged by the build-time placeholder assertion in NativeCodePass, which
        // scans the injected loader for leftover '@@' constants.
        if (LAYOUT_ENTRY == null || LAYOUT_ENTRY.isEmpty() || LAYOUT_ENTRY.indexOf('@') >= 0) {
            return null;
        }
        return LAYOUT_ENTRY;
    }

    /** Cuts the platform slice out of the decompressed payload. */
    private static byte[] sliceFor(byte[] payload) throws IOException {
        String entry = layoutEntry();
        if (entry == null) {
            say("[umbra-native] layout=none bytes=" + payload.length);
            return payload;
        }
        byte[] table = readNamed(entry);
        if (table == null || table.length == 0) {
            // Single-target build or a stripped archive: the payload *is* this
            // platform's library, already fully decoded above.
            say("[umbra-native] layout=missing bytes=" + payload.length);
            return payload;
        }
        String target = targetName(System.getProperty("os.name", ""),
                System.getProperty("os.arch", ""));
        if (target == null) {
            return payload;
        }
        String text = new String(table, java.nio.charset.StandardCharsets.UTF_8);
        for (String line : text.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            int space = trimmed.indexOf(' ');
            if (space <= 0) {
                continue;
            }
            if (!trimmed.substring(0, space).equals(target)) {
                continue;
            }
            String rest = trimmed.substring(space + 1).trim();
            int second = rest.indexOf(' ');
            if (second < 0) {
                continue;
            }
            try {
                long start = Long.parseLong(rest.substring(0, second).trim());
                long end = Long.parseLong(rest.substring(second + 1).trim());
                if (start < 0 || end < start || end > payload.length) {
                    throw new IOException("native payload layout is out of range");
                }
                byte[] slice = new byte[(int) (end - start)];
                System.arraycopy(payload, (int) start, slice, 0, slice.length);
                say("[umbra-native] layout=" + target + " bytes=" + slice.length);
                return slice;
            } catch (NumberFormatException malformed) {
                throw new IOException("native payload layout is malformed");
            }
        }
        throw new IOException("native payload has no slice for " + target);
    }

    private static String targetName(String osName, String archName) {
        String os = osName == null ? "" : osName.toLowerCase(java.util.Locale.ROOT);
        String arch = archName == null ? "" : archName.toLowerCase(java.util.Locale.ROOT);
        boolean x86 = arch.contains("x86_64") || arch.contains("amd64") || arch.contains("x64");
        boolean arm = arch.contains("aarch64") || arch.contains("arm64");
        if (os.contains("win")) {
            return x86 ? "WINDOWS_X86_64" : (arm ? "WINDOWS_AARCH64" : null);
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return x86 ? "MACOS_X86_64" : (arm ? "MACOS_AARCH64" : null);
        }
        if (os.contains("lin")) {
            return x86 ? "LINUX_X86_64" : (arm ? "LINUX_AARCH64" : null);
        }
        return null;
    }

    private static byte[] readNamed(String entry) {
        byte[] data = readStream(UmbraNativeLoader.class.getResourceAsStream("/" + entry));
        if (data != null && data.length > 0) {
            return data;
        }
        try {
            ClassLoader context = Thread.currentThread().getContextClassLoader();
            if (context != null) {
                data = readStream(context.getResourceAsStream(entry));
                if (data != null && data.length > 0) {
                    return data;
                }
            }
        } catch (RuntimeException ignored) {
            // A hostile context loader must not break the fallback chain.
        }
        data = readStream(ClassLoader.getSystemResourceAsStream(entry));
        if (data != null && data.length > 0) {
            return data;
        }
        return readFromCodeSource(entry);
    }

    private static void loadLibrary() throws IOException {
        if (agentAttached()) {
            throw new IOException("Java agent attached; the native payload stays unloaded");
        }
        byte[] raw = readResource();
        if (raw == null || raw.length == 0) {
            throw new IOException("native payload is missing from the JAR");
        }
        byte[] payload = decodePayload(raw);
        byte[] library = sliceFor(payload);
        if (ANTI_DUMP) {
            verifyFingerprint(payload);
        }
        File file = writeLibrary(library);
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
        // The suffix stays: Windows refuses to load a module whose path has no
        // .dll extension ("Can't find dependent libraries", reproduced with
        // System.load on an identical copy), so a suffix-less temp name would make
        // every protected build unloadable on the platform this pass targets most.
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
        data = readFromCodeSource(RESOURCE);
        if (data != null && data.length > 0) {
            return data;
        }
        return null;
    }

    private static byte[] readFromCodeSource(String entry) {
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
                File named = new File(file, entry);
                if (named.isFile()) {
                    InputStream in = new java.io.FileInputStream(named);
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
                ZipEntry archived = zip.getEntry(entry);
                if (archived == null) {
                    return null;
                }
                return readStream(zip.getInputStream(archived));
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
