package io.umbra.core.util;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Symmetric cryptography used by Umbra's data-protection passes.
 *
 * <p>This class is the build-time counterpart of the injected runtime helpers
 * ({@code UmbraCrypto}, {@code UmbraStringDecryptor}, {@code UmbraIndyBootstrap},
 * {@code UmbraClassLoader}). The wire format and every key-derivation formula
 * here is mirrored byte-for-byte in those templates; any change must be made on
 * both sides and is covered by {@code CryptoTest}.</p>
 *
 * <p>Primitives:</p>
 * <ul>
 *   <li>{@link Algorithm#CHACHA20} - RFC 8439 (RFC 7539) ChaCha20, 20 rounds,
 *       96-bit nonce, 32-bit block counter, 256-bit key.</li>
 *   <li>{@link Algorithm#AES_CTR} - AES-256 in CTR mode through
 *       {@code javax.crypto} (JDK 8+).</li>
 *   <li>{@link Algorithm#XOR} - fast xorshift64 stream for weak/legacy string
 *       payloads; explicitly not cryptographically strong.</li>
 *   <li>HMAC-SHA-256 for authenticated class payloads and constant-time tag
 *       comparison.</li>
 * </ul>
 *
 * <p>The legacy {@link #encrypt(String, long)} / {@link #decrypt(String, long)}
 * pair keeps working for existing call sites (virtualization, reference
 * obfuscation) and now uses ChaCha20 with a 256-bit key derived from the
 * 64-bit site key.</p>
 */
public final class Cipher {

    /** Size of the symmetric key in bytes (256 bits). */
    public static final int KEY_BYTES = 32;
    /** Size of the ChaCha20 nonce in bytes (96 bits). */
    public static final int NONCE_BYTES = 12;
    /** Size of the HMAC-SHA-256 authentication tag in bytes. */
    public static final int TAG_BYTES = 32;
    /** Size of the AES-CTR initialisation vector in bytes. */
    public static final int AES_IV_BYTES = 16;

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Cipher() {
    }

    /** Supported payload ciphers. */
    public enum Algorithm {
        XOR("xor"),
        CHACHA20("chacha20"),
        AES_CTR("aes-ctr");

        private final String id;

        Algorithm(String id) {
            this.id = id;
        }

        /** Stable identifier used in option values and logs. */
        public String id() {
            return id;
        }

        /** Parses an option value, falling back to {@code fallback}. */
        public static Algorithm parse(String value, Algorithm fallback) {
            if (value != null) {
                String normalized = value.trim().toLowerCase(java.util.Locale.ROOT);
                if ("xor".equals(normalized)) {
                    return XOR;
                }
                if ("chacha20".equals(normalized) || "chacha".equals(normalized)) {
                    return CHACHA20;
                }
                if ("aes-ctr".equals(normalized) || "aes".equals(normalized) || "aes128-ctr".equals(normalized)) {
                    return AES_CTR;
                }
            }
            return fallback;
        }
    }

    // ------------------------------------------------------------------
    // Legacy string API (kept binary/source compatible for existing passes)
    // ------------------------------------------------------------------

    /**
     * Encrypts a UTF-8 string into a Base64 ChaCha20 payload. Deterministic for
     * a given key.
     *
     * @param plain plaintext string
     * @param key   64-bit call-site key
     * @return Base64 ciphertext
     */
    public static String encrypt(String plain, long key) {
        byte[] data = plain.getBytes(StandardCharsets.UTF_8);
        byte[] derivedKey = legacyKey(key);
        byte[] nonce = legacyNonce(key);
        try {
            byte[] out = chacha20(derivedKey, nonce, 1, data);
            return Base64.getEncoder().encodeToString(out);
        } finally {
            wipe(derivedKey);
        }
    }

    /**
     * Decrypts a payload produced by {@link #encrypt(String, long)}.
     *
     * @param payload Base64 ciphertext
     * @param key     64-bit call-site key
     * @return plaintext string
     */
    public static String decrypt(String payload, long key) {
        byte[] data = Base64.getDecoder().decode(payload);
        byte[] derivedKey = legacyKey(key);
        byte[] nonce = legacyNonce(key);
        try {
            byte[] plain = chacha20(derivedKey, nonce, 1, data);
            return new String(plain, StandardCharsets.UTF_8);
        } finally {
            wipe(derivedKey);
        }
    }

    /** Derives the 256-bit key used by the legacy string API. */
    public static byte[] legacyKey(long key) {
        return sha256(concat(utf8(DomainTags.tag(DomainTags.I_LEGACY_KEY)), le64(key)));
    }

    /** Derives the 96-bit nonce used by the legacy string API. */
    public static byte[] legacyNonce(long key) {
        return first(sha256(concat(utf8(DomainTags.tag(DomainTags.I_LEGACY_NONCE)), le64(key))),
                NONCE_BYTES);
    }

    // ------------------------------------------------------------------
    // String payload key derivation (mirrored by the runtime decryptor)
    // ------------------------------------------------------------------

    /** Deterministic per-call-site seed embedded in the class file. */
    public static long deriveSiteSeed(long seed, String className, int siteId) {
        byte[] digest = sha256(concat(utf8(DomainTags.tag(DomainTags.I_SITE_SEED)), le64(seed),
                utf8(className), le32(siteId)));
        return readLongBE(digest, 0);
    }

    /** Deterministic 256-bit per-class key. */
    public static byte[] deriveClassKey(long seed, String className) {
        return sha256(concat(utf8(DomainTags.tag(DomainTags.I_CLASS_KEY)), le64(seed),
                utf8(className)));
    }

    /** Per-site key (32 bytes) derived from the embedded 64-bit site seed. */
    public static byte[] stringSiteKey(long siteSeed, int siteId) {
        return sha256(concat(utf8(DomainTags.tag(DomainTags.I_SITE_KEY)), le64(siteSeed),
                le32(siteId)));
    }

    /** Per-site nonce (12 bytes) derived from the embedded 64-bit site seed. */
    public static byte[] stringSiteNonce(long siteSeed, int siteId) {
        return first(sha256(concat(utf8(DomainTags.tag(DomainTags.I_SITE_NONCE)), le64(siteSeed),
                le32(siteId))), NONCE_BYTES);
    }

    /** Per-class nonce (12 bytes) derived from the 256-bit class key. */
    public static byte[] stringClassNonce(byte[] classKey, int siteId) {
        return first(sha256(concat(utf8(DomainTags.tag(DomainTags.I_CLASS_NONCE)), classKey,
                le32(siteId))), NONCE_BYTES);
    }

    /** AES-CTR IV derived from the key and the payload nonce. */
    public static byte[] aesIv(byte[] key, byte[] nonce) {
        return first(sha256(concat(utf8(DomainTags.tag(DomainTags.I_AES_IV)), key, nonce)),
                AES_IV_BYTES);
    }

    // ------------------------------------------------------------------
    // Authenticated payload envelopes (class encryption)
    // ------------------------------------------------------------------

    /**
     * Encrypts a class payload and authenticates it.
     *
     * <p>Envelope layout: {@code nonce(12) | ciphertext | tag(32)}. The tag is
     * {@code HMAC-SHA-256(key, nonce | ciphertext)}.</p>
     *
     * @param plain  plaintext bytes
     * @param key    256-bit key
     * @param nonce  96-bit nonce
     * @param alg    payload cipher ({@link Algorithm#CHACHA20} or {@link Algorithm#AES_CTR})
     * @return sealed envelope
     */
    public static byte[] seal(byte[] plain, byte[] key, byte[] nonce, Algorithm alg) {
        requireLength(key, KEY_BYTES, "key");
        requireLength(nonce, NONCE_BYTES, "nonce");
        byte[] ciphertext = encryptPayload(plain, key, nonce, alg);
        byte[] tag = hmacSha256(key, concat(nonce, ciphertext));
        return concat(nonce, ciphertext, tag);
    }

    /**
     * Verifies and decrypts an envelope produced by {@link #seal}.
     *
     * @throws SecurityException when the payload was tampered with
     */
    public static byte[] unseal(byte[] envelope, byte[] key, Algorithm alg) {
        requireLength(key, KEY_BYTES, "key");
        if (envelope == null || envelope.length < NONCE_BYTES + TAG_BYTES) {
            throw new SecurityException("Malformed protected payload");
        }
        byte[] nonce = Arrays.copyOfRange(envelope, 0, NONCE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(envelope, NONCE_BYTES, envelope.length - TAG_BYTES);
        byte[] tag = Arrays.copyOfRange(envelope, envelope.length - TAG_BYTES, envelope.length);
        byte[] expected = hmacSha256(key, concat(nonce, ciphertext));
        boolean valid = constantTimeEquals(expected, tag);
        wipe(expected);
        if (!valid) {
            throw new SecurityException("Protected payload authentication failed");
        }
        return decryptPayload(ciphertext, key, nonce, alg);
    }

    /** Encrypts raw bytes with the requested cipher (no authentication). */
    public static byte[] encryptPayload(byte[] plain, byte[] key, byte[] nonce, Algorithm alg) {
        requireLength(key, KEY_BYTES, "key");
        requireLength(nonce, NONCE_BYTES, "nonce");
        if (alg == Algorithm.AES_CTR) {
            byte[] iv = aesIv(key, nonce);
            return aesCtr(key, iv, plain);
        }
        return chacha20(key, nonce, 1, plain);
    }

    /** Decrypts raw bytes with the requested cipher (no authentication). */
    public static byte[] decryptPayload(byte[] data, byte[] key, byte[] nonce, Algorithm alg) {
        return encryptPayload(data, key, nonce, alg);
    }

    // ------------------------------------------------------------------
    // Primitives
    // ------------------------------------------------------------------

    /** SHA-256 digest. */
    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /** HMAC-SHA-256. */
    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    /**
     * RFC 8439 ChaCha20: XORs {@code data} with the keystream and returns a new
     * array. The counter is the block counter of the first block.
     */
    public static byte[] chacha20(byte[] key, byte[] nonce, int counter, byte[] data) {
        requireLength(key, KEY_BYTES, "key");
        requireLength(nonce, NONCE_BYTES, "nonce");
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
                if (state[12] == 0) {
                    throw new IllegalStateException("ChaCha20 block counter overflow");
                }
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

    /** AES-256-CTR through {@code javax.crypto}; returns a new array. */
    public static byte[] aesCtr(byte[] key, byte[] iv, byte[] data) {
        requireLength(key, KEY_BYTES, "key");
        requireLength(iv, AES_IV_BYTES, "iv");
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-CTR is unavailable", e);
        }
    }

    /** Weak xorshift64 stream used by the {@code xor} option; returns a new array. */
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
    // Encoding helpers
    // ------------------------------------------------------------------

    /** Base64 encodes bytes. */
    public static String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /** Base64 decodes a string. */
    public static byte[] fromBase64(String value) {
        return Base64.getDecoder().decode(value);
    }

    /** Concatenates byte arrays. */
    public static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    /** UTF-8 bytes of a string. */
    public static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    /** Little-endian 32-bit encoding (ChaCha20 word order). */
    public static byte[] le32(int value) {
        return new byte[] {
                (byte) value, (byte) (value >>> 8), (byte) (value >>> 16), (byte) (value >>> 24)
        };
    }

    /** Little-endian 64-bit encoding. */
    public static byte[] le64(long value) {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (value >>> (8 * i));
        }
        return out;
    }

    /** First {@code count} bytes of an array. */
    public static byte[] first(byte[] data, int count) {
        return Arrays.copyOfRange(data, 0, Math.min(count, data.length));
    }

    /** Deterministic random bytes from a {@link Random} instance. */
    public static byte[] randomBytes(Random random, int length) {
        byte[] out = new byte[length];
        random.nextBytes(out);
        return out;
    }

    /** Hex string of bytes (lower case). */
    public static String hex(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xFF;
            out[i * 2] = HEX[value >>> 4];
            out[i * 2 + 1] = HEX[value & 0xF];
        }
        return new String(out);
    }

    // ------------------------------------------------------------------
    // Security helpers
    // ------------------------------------------------------------------

    /** Constant-time comparison of two byte arrays. */
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

    /** Overwrites sensitive material with zeros. */
    public static void wipe(byte[] secret) {
        if (secret != null) {
            Arrays.fill(secret, (byte) 0);
        }
    }

    /** Overwrites sensitive characters with zeros. */
    public static void wipe(char[] secret) {
        if (secret != null) {
            Arrays.fill(secret, '\0');
        }
    }

    private static void requireLength(byte[] value, int expected, String name) {
        if (value == null || value.length != expected) {
            throw new IllegalArgumentException(name + " must be exactly " + expected + " bytes");
        }
    }

    private static int readIntLE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }

    private static long readLongBE(byte[] data, int offset) {
        long value = 0L;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (data[offset + i] & 0xFFL);
        }
        return value;
    }
}
