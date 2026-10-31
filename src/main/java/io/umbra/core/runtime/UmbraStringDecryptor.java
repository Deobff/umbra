package io.umbra.core.runtime;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * Legacy string decryptor template injected into protected programs.
 *
 * <p>This class is a runtime template: its bytecode is copied into the output
 * JAR under a randomized name. It is kept self-contained (no references to
 * Umbra classes) because {@code DefaultRuntimeSupport} injects it without a
 * crypto helper; {@code VirtualizationPass} calls {@link #d(String, long)}.
 * The string-encryption pass uses the stronger
 * {@code io.umbra.core.runtime.crypto.UmbraStringCipher} template instead.</p>
 *
 * <p>Payload and key derivation mirror {@code io.umbra.core.util.Cipher}'s
 * legacy {@code encrypt(String, long)} / {@code decrypt(String, long)} pair
 * (ChaCha20, 20 rounds, 96-bit nonce, 256-bit derived key).</p>
 */
public final class UmbraStringDecryptor {

    /**
     * Literal domain separators (rewritten per build by template injection) and
     * their mutable counterparts, set by the build side through
     * {@link #applyDomainTags(java.util.Map)}.
     */
    private static final String LIT_LEGACY_KEY = "io.umbra.cipher.legacy.key.v2";
    private static final String LIT_LEGACY_NONCE = "io.umbra.cipher.legacy.nonce.v2";

    private static String TAG_LEGACY_KEY = LIT_LEGACY_KEY;
    private static String TAG_LEGACY_NONCE = LIT_LEGACY_NONCE;

    /** Build-side hook: installs the per-build separators (never called at runtime). */
    public static void applyDomainTags(java.util.Map<String, String> tags) {
        TAG_LEGACY_KEY = pick(tags, LIT_LEGACY_KEY);
        TAG_LEGACY_NONCE = pick(tags, LIT_LEGACY_NONCE);
    }

    private static String pick(java.util.Map<String, String> tags, String literal) {
        String value = tags.get(literal);
        return value == null ? literal : value;
    }

    private UmbraStringDecryptor() {
    }

    /**
     * Decrypts a Base64 payload with the supplied 64-bit key.
     *
     * <p>The result is interned so that encrypted string literals keep the
     * identity semantics of the original constants: {@code "x" == "x"} and
     * {@code "x" == new String("x").intern()} must still hold in protected
     * code (also matters for {@code synchronized("lock")} and
     * identity-keyed caches).</p>
     *
     * @param payload encrypted string
     * @param key     per-string 64-bit key embedded at the call site
     * @return decrypted, interned UTF-8 string
     */
    public static String d(String payload, long key) {
        byte[] data = Base64.getDecoder().decode(payload);
        byte[] derivedKey = sha256(concat(utf8(TAG_LEGACY_KEY), le64(key)));
        byte[] nonce = first(sha256(concat(utf8(TAG_LEGACY_NONCE), le64(key))), 12);
        byte[] plain = chacha20(derivedKey, nonce, 1, data);
        try {
            return new String(plain, StandardCharsets.UTF_8).intern();
        } finally {
            Arrays.fill(derivedKey, (byte) 0);
            Arrays.fill(plain, (byte) 0);
        }
    }

    // ------------------------------------------------------------------
    // Self-contained crypto (mirrors io.umbra.core.util.Cipher)
    // ------------------------------------------------------------------

    private static byte[] chacha20(byte[] key, byte[] nonce, int counter, byte[] data) {
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

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable");
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] le64(long value) {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (value >>> (8 * i));
        }
        return out;
    }

    private static byte[] first(byte[] data, int count) {
        return Arrays.copyOfRange(data, 0, Math.min(count, data.length));
    }

    private static int readIntLE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }
}
