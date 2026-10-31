package io.umbra.core.runtime.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Self-contained crypto primitives injected next to Umbra's runtime templates.
 *
 * <p>This class is a runtime template: its bytecode is copied into the
 * protected program under a random name and the templates that need AES,
 * ChaCha20, SHA-256 or HMAC-SHA-256 (string decryptor, encrypted-class loader,
 * integrity guard) are remapped to call it. It must therefore stay free of any
 * reference to other Umbra classes and free of nested/anonymous classes.</p>
 *
 * <p>Every formula here mirrors {@code io.umbra.core.util.Cipher}. Both sides
 * are validated by the round-trip and known-answer tests in
 * {@code io.umbra.tests.CryptoTest}.</p>
 */
public final class UmbraCrypto {

    public static final int ALG_XOR = 0;
    public static final int ALG_CHACHA20 = 1;
    public static final int ALG_AES_CTR = 2;

    public static final int KEY_BYTES = 32;
    public static final int NONCE_BYTES = 12;
    public static final int TAG_BYTES = 32;
    public static final int AES_IV_BYTES = 16;

    private UmbraCrypto() {
    }

    // ------------------------------------------------------------------
    // Encoding / byte helpers
    // ------------------------------------------------------------------

    public static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    public static String fromUtf8(byte[] value) {
        return new String(value, StandardCharsets.UTF_8);
    }

    public static byte[] base64Decode(String value) {
        return Base64.getDecoder().decode(value);
    }

    public static String base64Encode(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    public static byte[] concat(byte[]... parts) {
        int length = 0;
        for (int i = 0; i < parts.length; i++) {
            length += parts[i].length;
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (int i = 0; i < parts.length; i++) {
            System.arraycopy(parts[i], 0, out, offset, parts[i].length);
            offset += parts[i].length;
        }
        return out;
    }

    public static byte[] le32(int value) {
        return new byte[] {
                (byte) value, (byte) (value >>> 8), (byte) (value >>> 16), (byte) (value >>> 24)
        };
    }

    public static byte[] le64(long value) {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (value >>> (8 * i));
        }
        return out;
    }

    public static byte[] first(byte[] data, int count) {
        return Arrays.copyOfRange(data, 0, Math.min(count, data.length));
    }

    // ------------------------------------------------------------------
    // Digests and HMAC
    // ------------------------------------------------------------------

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable");
        }
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable");
        }
    }

    // ------------------------------------------------------------------
    // ChaCha20 (RFC 8439) and AES-256-CTR
    // ------------------------------------------------------------------

    public static byte[] chacha20(byte[] key, byte[] nonce, int counter, byte[] data) {
        byte[] out = data.clone();
        int[] state = new int[16];
        int[] working = new int[16];
        int[] block = new int[16];
        try {
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;
            for (int i = 0; i < 8; i++) {
                state[4 + i] = readIntLE(key, i * 4);
            }
            state[12] = counter;
            state[13] = readIntLE(nonce, 0);
            state[14] = readIntLE(nonce, 4);
            state[15] = readIntLE(nonce, 8);
            for (int offset = 0; offset < out.length; offset += 64) {
                System.arraycopy(state, 0, working, 0, 16);
                for (int round = 0; round < 10; round++) {
                    quarterRound(working, 0, 4, 8, 12);
                    quarterRound(working, 1, 5, 9, 13);
                    quarterRound(working, 2, 6, 10, 14);
                    quarterRound(working, 3, 7, 11, 15);
                    quarterRound(working, 0, 5, 10, 15);
                    quarterRound(working, 1, 6, 11, 12);
                    quarterRound(working, 2, 7, 8, 13);
                    quarterRound(working, 3, 4, 9, 14);
                }
                for (int i = 0; i < 16; i++) {
                    block[i] = working[i] + state[i];
                }
                int length = Math.min(64, out.length - offset);
                for (int i = 0; i < length; i++) {
                    out[offset + i] ^= (byte) (block[i >>> 2] >>> (8 * (i & 3)));
                }
                state[12]++;
            }
            return out;
        } finally {
            Arrays.fill(working, 0);
            Arrays.fill(block, 0);
            Arrays.fill(state, 0);
        }
    }

    private static void quarterRound(int[] x, int a, int b, int c, int d) {
        x[a] += x[b];
        x[d] = Integer.rotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = Integer.rotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = Integer.rotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = Integer.rotateLeft(x[b] ^ x[c], 7);
    }

    public static byte[] aesCtr(byte[] key, byte[] iv, byte[] data) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-CTR unavailable");
        }
    }

    public static byte[] xorStream(byte[] data, long key) {
        byte[] out = data.clone();
        long state = key == 0L ? 0x9E3779B97F4A7C15L : key;
        for (int i = 0; i < out.length; i++) {
            state ^= state << 13;
            state ^= state >>> 7;
            state ^= state << 17;
            out[i] ^= (byte) (state >>> 24);
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Key derivation (mirrors io.umbra.core.util.Cipher)
    // ------------------------------------------------------------------

    /**
     * Literal domain separators. Template injection rewrites the constants (they
     * are {@code ConstantValue} attributes) so the injected copy starts from the
     * per-build values; the build side sets the {@code TAG_*} fields through
     * {@link #applyDomainTags(java.util.Map)}.
     */
    private static final String LIT_SITE_KEY = "io.umbra.string.site.key.v1";
    private static final String LIT_SITE_NONCE = "io.umbra.string.site.nonce.v1";
    private static final String LIT_CLASS_NONCE = "io.umbra.string.class.nonce.v1";
    private static final String LIT_AES_IV = "io.umbra.aes.iv.v1";

    private static String TAG_SITE_KEY = LIT_SITE_KEY;
    private static String TAG_SITE_NONCE = LIT_SITE_NONCE;
    private static String TAG_CLASS_NONCE = LIT_CLASS_NONCE;
    private static String TAG_AES_IV = LIT_AES_IV;

    /**
     * Build-side hook: installs the per-build separators. Never called at runtime
     * (the injected copy has them baked into its static initializer).
     */
    public static void applyDomainTags(java.util.Map<String, String> tags) {
        TAG_SITE_KEY = pick(tags, LIT_SITE_KEY);
        TAG_SITE_NONCE = pick(tags, LIT_SITE_NONCE);
        TAG_CLASS_NONCE = pick(tags, LIT_CLASS_NONCE);
        TAG_AES_IV = pick(tags, LIT_AES_IV);
    }

    private static String pick(java.util.Map<String, String> tags, String literal) {
        String value = tags.get(literal);
        return value == null ? literal : value;
    }

    public static byte[] siteKey(long siteSeed, int siteId) {
        return sha256(concat(utf8(TAG_SITE_KEY), le64(siteSeed), le32(siteId)));
    }

    public static byte[] siteNonce(long siteSeed, int siteId) {
        return first(sha256(concat(utf8(TAG_SITE_NONCE), le64(siteSeed), le32(siteId))),
                NONCE_BYTES);
    }

    public static byte[] classNonce(byte[] classKey, int siteId) {
        return first(sha256(concat(utf8(TAG_CLASS_NONCE), classKey, le32(siteId))),
                NONCE_BYTES);
    }

    public static byte[] aesIv(byte[] key, byte[] nonce) {
        return first(sha256(concat(utf8(TAG_AES_IV), key, nonce)), AES_IV_BYTES);
    }

    /**
     * Decrypts a string payload accepted by the injected string decryptor.
     *
     * @param ciphertext ciphertext bytes (already Base64-decoded and joined)
     * @param classKey   256-bit per-class key, or {@code null} for per-site keys
     * @param siteSeed   64-bit per-site seed embedded at the call site
     * @param siteId     per-class call-site index
     * @param alg        one of {@link #ALG_XOR}, {@link #ALG_CHACHA20}, {@link #ALG_AES_CTR}
     * @return plaintext bytes
     */
    public static byte[] stringPlain(byte[] ciphertext, byte[] classKey, long siteSeed, int siteId, int alg) {
        if (alg == ALG_XOR) {
            return xorStream(ciphertext, siteSeed);
        }
        byte[] key;
        boolean temporary = false;
        if (classKey != null) {
            key = classKey;
        } else {
            key = siteKey(siteSeed, siteId);
            temporary = true;
        }
        try {
            byte[] nonce = classKey != null ? classNonce(key, siteId) : siteNonce(siteSeed, siteId);
            if (alg == ALG_AES_CTR) {
                return aesCtr(key, aesIv(key, nonce), ciphertext);
            }
            return chacha20(key, nonce, 1, ciphertext);
        } finally {
            if (temporary) {
                wipe(key);
            }
        }
    }

    /**
     * Per-entry key derivation used by the class-encryption loader (index v3):
     * the entry's own nonce is mixed into the KDF, so the same class name in two
     * builds has different keys even though the label is stable.
     *
     * @param master  archive master key
     * @param label   {@code "c:<binary name>"} or {@code "r:<logical resource>"}
     * @param nonce   the 12-byte envelope nonce of that payload
     * @return 256-bit payload key
     */
    public static byte[] entryKey(byte[] master, String label, byte[] nonce) {
        return hmacSha256(master, concat(utf8(label), nonce));
    }

    /** Extracts and validates the nonce prefix of a sealed envelope. */
    public static byte[] nonceOf(byte[] envelope) {
        if (envelope == null || envelope.length < NONCE_BYTES + TAG_BYTES) {
            throw new SecurityException("Malformed protected payload");
        }
        return Arrays.copyOfRange(envelope, 0, NONCE_BYTES);
    }

    /**
     * Keyed digest for index v3 integrity metadata: an attacker who decrypts a
     * payload cannot locally verify the result without the master key.
     */
    public static byte[] keyedDigest(byte[] master, String label, byte[] data) {
        return hmacSha256(master, concat(utf8(label), data));
    }

    /**
     * Sample-bound master key (class-encryption index v3). The ZIP comment and
     * entry count are stable only after the archive is written, so the master key
     * is bound to the concrete built sample and not just to the tool version.
     */
    public static byte[] masterFromSample(byte[] siteSeed, byte[] commentBytes, int entryCount) {
        byte[] count = le32(entryCount);
        return hmacSha256(siteSeed,
                concat(utf8("umbra.master.v3"), commentBytes == null ? new byte[0] : commentBytes,
                        count));
    }

    /** Diagnostic fallback binding (no comment/entry-count dependency). */
    public static byte[] masterFromSeed(byte[] siteSeed) {
        return hmacSha256(siteSeed, utf8("umbra.master.v3.seed"));
    }

    // ------------------------------------------------------------------
    // Authenticated envelopes (mirrors Cipher.seal/unseal)
    // ------------------------------------------------------------------

    public static byte[] unseal(byte[] envelope, byte[] key, int alg) {
        if (envelope == null || envelope.length < NONCE_BYTES + TAG_BYTES) {
            throw new SecurityException("Malformed protected payload");
        }
        requireSupportedAlgorithm(alg);
        byte[] nonce = Arrays.copyOfRange(envelope, 0, NONCE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(envelope, NONCE_BYTES, envelope.length - TAG_BYTES);
        byte[] tag = Arrays.copyOfRange(envelope, envelope.length - TAG_BYTES, envelope.length);
        byte[] expected = hmacSha256(key, concat(nonce, ciphertext));
        boolean valid = constantTimeEquals(expected, tag);
        wipe(expected);
        if (!valid) {
            throw new SecurityException("Protected payload authentication failed");
        }
        if (alg == ALG_AES_CTR) {
            return aesCtr(key, aesIv(key, nonce), ciphertext);
        }
        return chacha20(key, nonce, 1, ciphertext);
    }

    public static byte[] seal(byte[] plain, byte[] key, byte[] nonce, int alg) {
        requireSupportedAlgorithm(alg);
        if (nonce == null || nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("unexpected nonce length");
        }
        byte[] ciphertext;
        if (alg == ALG_AES_CTR) {
            ciphertext = aesCtr(key, aesIv(key, nonce), plain);
        } else {
            ciphertext = chacha20(key, nonce, 1, plain);
        }
        byte[] tag = hmacSha256(key, concat(nonce, ciphertext));
        return concat(nonce, ciphertext, tag);
    }

    /** Archive payloads only support ChaCha20 (1) and AES-256-CTR (2); no XOR. */
    private static void requireSupportedAlgorithm(int alg) {
        if (alg != ALG_CHACHA20 && alg != ALG_AES_CTR) {
            throw new SecurityException("Unsupported payload algorithm");
        }
    }

    /**
     * Rebuilds the archive master key from split key parts.
     *
     * <p>The parts and the salt are embedded in the injected loader/guard as
     * separate string constants; the final key is an HMAC over their bytes.</p>
     */
    public static byte[] masterKey(String[] parts, String saltB64) {
        byte[] material = new byte[0];
        for (int i = 0; i < parts.length; i++) {
            material = concat(material, base64Decode(parts[i]));
        }
        try {
            return hmacSha256(material, base64Decode(saltB64));
        } finally {
            wipe(material);
        }
    }

    // ------------------------------------------------------------------
    // Security helpers
    // ------------------------------------------------------------------

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    public static void wipe(byte[] secret) {
        if (secret != null) {
            Arrays.fill(secret, (byte) 0);
        }
    }

    private static int readIntLE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }
}
