package io.umbra.core.runtime.crypto;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Strong string decryptor template injected into protected programs.
 *
 * <p>Call sites pass the Base64 payload split into one or more parts, an
 * optional 256-bit per-class key (Base64) or a 64-bit per-site seed, the
 * per-class call-site index and a per-site engine code. Key and nonce are
 * derived with SHA-256 from those values (see {@link UmbraCrypto}); the payload
 * is then decrypted with the selected stream cipher:</p>
 *
 * <ul>
 *   <li>{@link #XOR} - fast xorshift64 stream (weak, opt-in);</li>
 *   <li>{@link #CHACHA20} - RFC 8439 ChaCha20 (default);</li>
 *   <li>{@link #AES_CTR} - AES-256-CTR through {@code javax.crypto};</li>
 *   <li>{@link #RC4} - RC4 with a full 256-bit derived key;</li>
 *   <li>{@link #SPECK} - Speck64/128 in counter mode (32-bit words, pure
 *       Java, no provider dependency).</li>
 * </ul>
 *
 * <p>The engine primitive {@link #transform(int, byte[], byte[], byte[], long)}
 * is symmetric (all engines are stream ciphers), so the same method both
 * encrypts at build time and decrypts at run time: there is exactly one
 * implementation of each engine in the code base, which removes the
 * build/runtime drift risk that duplicated templates normally have. The pass
 * calls it directly; the injected copy calls it too.</p>
 *
 * <p>The {@code e} overloads memoize the decrypted value per call site; the
 * {@code d} overloads always decrypt. Values are interned so string identity
 * semantics of the original constants are preserved.</p>
 *
 * <p>Two hardening flags are substituted at injection time through
 * {@code @@FLAGS@@}: bit 0 enables decrypt-and-wipe (every intermediate byte /
 * char buffer is zeroed before returning), bit 1 enables stack-trace hiding
 * (a decryption failure is replaced by a sanitized exception with an empty
 * stack trace, so the helper's class, method and internal values never leak
 * into a report).</p>
 *
 * <p>Runtime template: no nested/anonymous classes and no references to other
 * Umbra classes (the {@link UmbraCrypto} reference is remapped by
 * {@code CryptoSupport} at injection time).</p>
 */
public final class UmbraStringCipher {

    /** Engine codes used by the emitted call sites and the bootstrap. */
    public static final int XOR = 0;
    public static final int CHACHA20 = 1;
    public static final int AES_CTR = 2;
    public static final int RC4 = 3;
    public static final int SPECK = 4;

    /** "0" for plain, bit 0 = wipe, bit 1 = stack-trace hiding; replaced at injection time. */
    private static final String FLAGS_SPEC = "@@FLAGS@@";

    private static final int FLAGS = parseFlags(FLAGS_SPEC);
    private static final boolean WIPE = (FLAGS & 1) != 0;
    private static final boolean HIDE_TRACE = (FLAGS & 2) != 0;

    private static final ConcurrentHashMap<String, String> CACHE =
            new ConcurrentHashMap<String, String>();

    private UmbraStringCipher() {
    }

    // ------------------------------------------------------------------
    // Call-site entry points (emitted by StringEncryptionPass)
    // ------------------------------------------------------------------

    /** Per-class key, no memoization. */
    public static String d(String[] parts, String classKey, int siteId, int engine) {
        return decrypt(parts, classKey, 0L, siteId, true, false, engine);
    }

    /** Per-class key, memoized per call site. */
    public static String e(String[] parts, String classKey, int siteId, int engine) {
        return decrypt(parts, classKey, 0L, siteId, true, true, engine);
    }

    /** Per-site 64-bit seed, no memoization. */
    public static String d(String[] parts, long siteSeed, int siteId, int engine) {
        return decrypt(parts, null, siteSeed, siteId, false, false, engine);
    }

    /** Per-site 64-bit seed, memoized per call site. */
    public static String e(String[] parts, long siteSeed, int siteId, int engine) {
        return decrypt(parts, null, siteSeed, siteId, false, true, engine);
    }

    /**
     * Decodes one packed payload (parts joined with {@code '|'}). Used by the
     * invokedynamic string bootstrap, which cannot pass a {@code String[]}.
     */
    public static String decode(String packed, String classKeyBase64, long siteSeed, int siteId,
                                int engine) {
        String[] parts = split(packed);
        return decrypt(parts, classKeyBase64, siteSeed, siteId,
                classKeyBase64 != null && classKeyBase64.length() > 0, false, engine);
    }

    // ------------------------------------------------------------------
    // Per-site decryption
    // ------------------------------------------------------------------

    private static String decrypt(String[] parts, String classKeyBase64, long siteSeed, int siteId,
                                  boolean perClass, boolean cached, int engine) {
        try {
            String cacheKey = cached ? cacheKey(parts, classKeyBase64, siteSeed, siteId, engine) : null;
            if (cacheKey != null) {
                String hit = CACHE.get(cacheKey);
                if (hit != null) {
                    return hit;
                }
            }
            byte[] ciphertext = join(parts);
            byte[] classKey = null;
            byte[] key = null;
            byte[] nonce = null;
            boolean temporaryKey = false;
            try {
                if (perClass) {
                    classKey = UmbraCrypto.base64Decode(classKeyBase64);
                    key = classKey;
                    nonce = UmbraCrypto.classNonce(classKey, siteId);
                } else {
                    key = UmbraCrypto.siteKey(siteSeed, siteId);
                    nonce = UmbraCrypto.siteNonce(siteSeed, siteId);
                    temporaryKey = true;
                }
                byte[] plain = transform(engine, ciphertext, key, nonce, siteSeed);
                String value = internUtf8(plain);
                Arrays.fill(plain, (byte) 0);
                if (cacheKey != null) {
                    CACHE.putIfAbsent(cacheKey, value);
                }
                return value;
            } finally {
                UmbraCrypto.wipe(ciphertext);
                UmbraCrypto.wipe(classKey);
                if (temporaryKey) {
                    UmbraCrypto.wipe(key);
                }
                UmbraCrypto.wipe(nonce);
            }
        } catch (RuntimeException failure) {
            if (HIDE_TRACE) {
                throw sanitized(failure);
            }
            throw failure;
        }
    }

    /** Builds the interned value; with wipe enabled the UTF-16 buffer is zeroed. */
    private static String internUtf8(byte[] plain) {
        if (!WIPE) {
            return UmbraCrypto.fromUtf8(plain).intern();
        }
        CharBuffer decoded = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(plain));
        char[] chars = new char[decoded.remaining()];
        decoded.get(chars);
        try {
            return new String(chars).intern();
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /** A failure that cannot be used to locate the helper or read its state. */
    private static IllegalStateException sanitized(RuntimeException failure) {
        IllegalStateException sanitized = new IllegalStateException("");
        sanitized.setStackTrace(new StackTraceElement[0]);
        return sanitized;
    }

    private static String cacheKey(String[] parts, String classKeyBase64, long siteSeed,
                                   int siteId, int engine) {
        StringBuilder builder = new StringBuilder();
        builder.append(engine).append(':').append(siteId).append('/').append(siteSeed).append('/');
        if (classKeyBase64 != null) {
            builder.append(classKeyBase64);
        }
        builder.append('|');
        for (int i = 0; i < parts.length; i++) {
            builder.append(parts[i]).append('\u0000');
        }
        return builder.toString();
    }

    private static byte[] join(String[] parts) {
        int length = 0;
        for (int i = 0; i < parts.length; i++) {
            length += ((parts[i].length() * 3) >>> 2) + 2;
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (int i = 0; i < parts.length; i++) {
            byte[] decoded = UmbraCrypto.base64Decode(parts[i]);
            System.arraycopy(decoded, 0, out, offset, decoded.length);
            offset += decoded.length;
        }
        if (offset == out.length) {
            return out;
        }
        byte[] exact = new byte[offset];
        System.arraycopy(out, 0, exact, 0, offset);
        Arrays.fill(out, (byte) 0);
        return exact;
    }

    private static String[] split(String packed) {
        int count = 1;
        for (int i = 0; i < packed.length(); i++) {
            if (packed.charAt(i) == '|') {
                count++;
            }
        }
        String[] parts = new String[count];
        int index = 0;
        int start = 0;
        while (index < count - 1) {
            int separator = packed.indexOf('|', start);
            parts[index++] = packed.substring(start, separator);
            start = separator + 1;
        }
        parts[index] = packed.substring(start);
        return parts;
    }

    // ------------------------------------------------------------------
    // Engine primitive (shared by the build-time pass and the runtime)
    // ------------------------------------------------------------------

    /**
     * Stream-cipher transform: XORs {@code data} with the keystream of the
     * selected engine. Symmetric, so encryption and decryption are the same
     * call.
     *
     * @param engine engine code ({@link #XOR}, {@link #CHACHA20}, {@link #AES_CTR},
     *               {@link #RC4}, {@link #SPECK})
     * @param data   input bytes (never mutated)
     * @param key    256-bit derived key; ignored by {@link #XOR}
     * @param nonce  96-bit derived nonce
     * @param seed   64-bit per-site seed (xorshift engine only)
     * @return transformed copy of {@code data}
     */
    public static byte[] transform(int engine, byte[] data, byte[] key, byte[] nonce, long seed) {
        switch (engine) {
            case XOR:
                return UmbraCrypto.xorStream(data, seed);
            case AES_CTR:
                return UmbraCrypto.aesCtr(key, UmbraCrypto.aesIv(key, nonce), data);
            case RC4:
                return rc4(UmbraCrypto.sha256(UmbraCrypto.concat(
                        UmbraCrypto.utf8("io.umbra.string.rc4.key.v1"), key, nonce)), data);
            case SPECK:
                return speckCtr(UmbraCrypto.first(UmbraCrypto.sha256(UmbraCrypto.concat(
                        UmbraCrypto.utf8("io.umbra.string.speck.key.v1"), key, nonce)), 16), nonce, data);
            default:
                return UmbraCrypto.chacha20(key, nonce, 1, data);
        }
    }

    /** Human-readable engine id for logs (build side only). */
    public static String engineId(int engine) {
        switch (engine) {
            case XOR: return "xor";
            case AES_CTR: return "aes-ctr";
            case RC4: return "rc4";
            case SPECK: return "speck";
            default: return "chacha20";
        }
    }

    // ------------------------------------------------------------------
    // RC4
    // ------------------------------------------------------------------

    private static byte[] rc4(byte[] key, byte[] data) {
        int[] state = new int[256];
        byte[] out = data.clone();
        try {
            for (int i = 0; i < 256; i++) {
                state[i] = i;
            }
            int j = 0;
            for (int i = 0; i < 256; i++) {
                j = (j + state[i] + (key[i % key.length] & 0xFF)) & 0xFF;
                int swap = state[i];
                state[i] = state[j];
                state[j] = swap;
            }
            int i = 0;
            j = 0;
            for (int offset = 0; offset < out.length; offset++) {
                i = (i + 1) & 0xFF;
                j = (j + state[i]) & 0xFF;
                int swap = state[i];
                state[i] = state[j];
                state[j] = swap;
                out[offset] ^= (byte) state[(state[i] + state[j]) & 0xFF];
            }
            return out;
        } finally {
            Arrays.fill(state, 0);
            Arrays.fill(key, (byte) 0);
        }
    }

    // ------------------------------------------------------------------
    // Speck64/128 in counter mode (pure Java, no provider dependency)
    // ------------------------------------------------------------------

    private static final int SPECK_ROUNDS = 27;

    private static byte[] speckCtr(byte[] key16, byte[] nonce, byte[] data) {
        byte[] out = data.clone();
        int[] roundKeys = new int[SPECK_ROUNDS];
        int[] schedule = new int[4];
        try {
            for (int i = 0; i < 4; i++) {
                schedule[i] = readIntLE(key16, i * 4);
            }
            speckSchedule(schedule, roundKeys);
            int baseX = readIntLE(nonce, 0);
            int baseY = readIntLE(nonce, 4);
            int blockIndex = 0;
            for (int offset = 0; offset < out.length; offset += 8) {
                int x = baseX + blockIndex;
                int y = baseY ^ blockIndex;
                for (int round = 0; round < SPECK_ROUNDS; round++) {
                    x = Integer.rotateRight(x, 8) + y ^ roundKeys[round];
                    y = Integer.rotateLeft(y, 3) ^ x;
                }
                int length = Math.min(8, out.length - offset);
                for (int i = 0; i < length; i++) {
                    int word = i < 4 ? x >>> (8 * i) : y >>> (8 * (i - 4));
                    out[offset + i] ^= (byte) word;
                }
                blockIndex++;
            }
            return out;
        } finally {
            Arrays.fill(roundKeys, 0);
            Arrays.fill(schedule, 0);
            Arrays.fill(key16, (byte) 0);
        }
    }

    /** Speck64/128 key schedule: 4 key words, 27 round keys. */
    private static void speckSchedule(int[] key, int[] roundKeys) {
        int[] l = new int[SPECK_ROUNDS + 2];
        roundKeys[0] = key[0];
        l[0] = key[1];
        l[1] = key[2];
        l[2] = key[3];
        try {
            for (int i = 0; i < SPECK_ROUNDS - 1; i++) {
                int nextL = (Integer.rotateRight(l[i], 8) + roundKeys[i]) ^ i;
                roundKeys[i + 1] = Integer.rotateLeft(roundKeys[i], 3) ^ nextL;
                l[i + 3] = nextL;
            }
        } finally {
            Arrays.fill(l, 0);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static int parseFlags(String value) {
        if (value == null) {
            return 0;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static int readIntLE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }
}
