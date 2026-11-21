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

    public static String sha256Hex(byte[] data) {
        byte[] digest = sha256(data);
        StringBuilder out = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            out.append(Character.forDigit((b >> 4) & 0xF, 16))
                    .append(Character.forDigit(b & 0xF, 16));
        }
        java.util.Arrays.fill(digest, (byte) 0);
        return out.toString();
    }

    public static String algName(int[] codes) {
        char[] chars = new char[codes.length];
        for (int i = 0; i < codes.length; i++) {
            chars[i] = (char) (codes[i] ^ ((i & 1) == 0 ? 0x15 : 0x2A));
        }
        try {
            return new String(chars).intern();
        } finally {
            Arrays.fill(chars, (char) 0);
        }
    }

    private static final int[] A_SHA256 = {
            0x46, 0x62, 0x54, 0x07, 0x27, 0x1F, 0x23
    };

    private static final int[] A_HMAC256 = {
            0x5D, 0x47, 0x74, 0x49, 0x46, 0x62, 0x54, 0x18, 0x20, 0x1C
    };

    private static final int[] A_AESCTR = {
            0x54, 0x6F, 0x46, 0x05, 0x56, 0x7E, 0x47, 0x05, 0x5B, 0x45, 0x45, 0x4B,
            0x71, 0x4E, 0x7C, 0x44, 0x72
    };

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance(algName(A_SHA256)).digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("");
        }
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            String name = algName(A_HMAC256);
            Mac mac = Mac.getInstance(name);
            mac.init(new SecretKeySpec(key, name));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("");
        }
    }

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
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(algName(A_AESCTR));
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("");
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

    /**
     * Key-derivation domain words.
     *
     * <p>Every KDF prefixes its hash input with a domain separator so that one
     * build root cannot be replayed across derivations. Those separators used to
     * be self-describing ASCII labels ({@code "io.umbra.string.site.key.v1"} and
     * friends) that were rewritten per build into random hex, and either way they
     * ended up as readable {@code Utf8} constants in the injected helpers - the
     * label handed the analyst the whole key schedule, and the rewritten hex was
     * still a plain constant pool string that a {@code grep} could collect.</p>
     *
     * <p>The separator is now a 4-byte little-endian domain number: it lands in the
     * method body as an {@code ICONST}/{@code BIPUSH} operand, never in the
     * constant pool, and it reveals nothing about what the domain is for. The
     * numbers are {@code 1..17} in the same order as
     * {@code io.umbra.core.util.DomainTags} used to list its labels, so the mapping
     * stays auditable. {@link UmbraStringDecryptor} and
     * {@code UmbraIndyBootstrap} are self-contained templates (they must not
     * reference this class), so they repeat the two/six numbers they need -
     * {@code CryptoTest} round-trips both pairs through {@code Cipher} so the
     * copies cannot drift.</p>
     */
    public static final int K1 = 1;
    public static final int K2 = 2;
    public static final int K3 = 3;
    public static final int K4 = 4;
    public static final int K5 = 5;
    public static final int K6 = 6;
    public static final int K7 = 7;
    public static final int K8 = 8;
    public static final int K9 = 9;
    public static final int K10 = 10;
    public static final int K11 = 11;
    public static final int K12 = 12;
    public static final int K13 = 13;
    public static final int K14 = 14;
    public static final int K15 = 15;
    public static final int K16 = 16;
    public static final int K17 = 17;

    /** The 4-byte domain word a KDF prefixes its input with. */
    public static byte[] domain(int id) {
        return le32(id);
    }

    public static byte[] aesIv(byte[] key, byte[] nonce) {
        return first(sha256(concat(domain(K8), key, nonce)), AES_IV_BYTES);
    }

    public static final int ROOT_BYTES = 32;

    public static final int SLOT_CLASS_MASTER = 1;
    public static final int SLOT_DIGEST = 2;
    public static final int SLOT_STRING = 3;
    public static final int SLOT_INTEGRITY = 4;

    private static final String SUB_KEY_LABEL = "umbra.sub.v1";

    private static final String NATIVE_ROOT_LABEL = "umbra.keyroot.v1";

    public static final int ROOT_SLOT = 1;
    public static final int ROOT_SUB = 0;

    private static final String NATIVE_MASTER_LABEL = "class.master.v1";

    private static final Object ROOT_LOCK = new Object();

    private static volatile byte[] root32;

    private static final String STRING_KEY = "__UMBRA_NO_STRING_KEY__";

    private static volatile byte[] stringKey;

    public static void installKeyRoot(byte[] value) {
        synchronized (ROOT_LOCK) {
            root32 = value == null ? null : value.clone();
        }
    }

    public static boolean hasKeyRoot() {
        return root32 != null;
    }

    public static byte[] keyRoot() {
        byte[] value = root32;
        if (value != null) {
            return value.clone();
        }
        return embeddedStringKey();
    }

    private static byte[] embeddedStringKey() {
        String encoded = STRING_KEY;
        if (encoded == null || encoded.isEmpty() || encoded.charAt(0) == '_') {
            return null;
        }
        byte[] cached = stringKey;
        if (cached != null) {
            return cached.clone();
        }
        synchronized (ROOT_LOCK) {
            if (stringKey == null) {
                try {
                    stringKey = base64Decode(encoded);
                } catch (Throwable unreadable) {
                    return null;
                }
            }
            return stringKey == null ? null : stringKey.clone();
        }
    }

    public static byte[] subKey(byte[] root, int slot, int sub) {
        if (root == null) {
            return null;
        }
        return hmacSha256(root, concat(utf8(SUB_KEY_LABEL), le32(slot), le32(sub)));
    }

    public static byte[] subKey(int slot, int sub) {
        return subKey(root32, slot, sub);
    }

    public static byte[] nativeKeyRoot(byte[] rawRoot, int slot, int sub) {
        if (rawRoot == null || rawRoot.length != ROOT_BYTES) {
            return null;
        }
        return hmacSha256(rawRoot, concat(utf8(NATIVE_ROOT_LABEL), le32(slot), le32(sub)));
    }

    public static byte[] nativeKeyRoot(byte[] rawRoot) {
        return nativeKeyRoot(rawRoot, ROOT_SLOT, ROOT_SUB);
    }

    public static final int SLOT_BOOTSTRAP = ROOT_SLOT;

    public static final int SLOT_PAYLOAD = 2;

    private static final String GATE_LABEL = "umbra.gate.v1";

    public static byte[] gateAttest(byte[] gateSecret, long nonce) {
        if (gateSecret == null || gateSecret.length != ROOT_BYTES) {
            return null;
        }
        return hmacSha256(gateSecret, concat(utf8(GATE_LABEL), le64(nonce)));
    }

    public static byte[] payloadRoot(byte[] rawRoot) {
        return nativeKeyRoot(rawRoot, SLOT_PAYLOAD, 0);
    }

    public static byte[] gateTick(byte[] payloadRoot, int index) {
        if (payloadRoot == null || payloadRoot.length != ROOT_BYTES) {
            return null;
        }
        return hmacSha256(payloadRoot, concat(utf8("umbra.tick.v1"), le32(index)));
    }

    public static byte[] checkEvidence(byte[] gateSecret, long counter, int mask) {
        if (gateSecret == null || gateSecret.length != ROOT_BYTES) {
            return null;
        }
        return hmacSha256(gateSecret,
                concat(utf8("umbra.check.v1"), le64(counter), le32(mask)));
    }

    public static byte[] entryKey(byte[] master, String label, byte[] nonce, byte[] payloadRoot) {
        if (payloadRoot == null) {
            return hmacSha256(master, concat(utf8(label), nonce));
        }
        return hmacSha256(master, concat(utf8(label), nonce, payloadRoot));
    }

    public static byte[] keyedDigest(byte[] digestKey, String label, byte[] data,
                                     byte[] payloadRoot) {
        if (payloadRoot == null) {
            return keyedDigest(digestKey, label, data);
        }

        return hmacParts(digestKey, utf8(label), data, payloadRoot);
    }

    public static byte[] masterFromRoot(byte[] root, byte[] commentBytes, int entryCount) {
        if (root == null || root.length != ROOT_BYTES) {
            return null;
        }
        return hmacSha256(root, concat(utf8(NATIVE_MASTER_LABEL),
                commentBytes == null ? new byte[0] : commentBytes, le32(entryCount)));
    }

    public static byte[] masterKeyRooted(String[] parts, String saltB64, byte[] root) {
        if (root == null || root.length != ROOT_BYTES) {
            return null;
        }
        byte[] material = concat(utf8("integrity.master.v1"), root);
        for (int i = 0; i < parts.length; i++) {
            material = concat(material, base64Decode(parts[i]));
        }
        try {
            return hmacSha256(material, base64Decode(saltB64));
        } finally {
            wipe(material);
        }
    }

    public static byte[] entryKey(byte[] master, String label, byte[] nonce) {
        return hmacSha256(master, concat(utf8(label), nonce));
    }

    public static byte[] nonceOf(byte[] envelope) {
        if (envelope == null || envelope.length < NONCE_BYTES + TAG_BYTES) {
            throw new SecurityException("Malformed protected payload");
        }
        return Arrays.copyOfRange(envelope, 0, NONCE_BYTES);
    }

    public static byte[] keyedDigest(byte[] master, String label, byte[] data) {

        return hmacParts(master, utf8(label), data);
    }

    public static byte[] hmacParts(byte[] key, byte[]... parts) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            for (int i = 0; i < parts.length; i++) {
                if (parts[i] != null && parts[i].length > 0) {
                    mac.update(parts[i]);
                }
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSha256 unavailable");
        }
    }

    public static byte[] masterFromSample(byte[] siteSeed, byte[] commentBytes, int entryCount) {
        byte[] count = le32(entryCount);
        return hmacSha256(siteSeed,
                concat(utf8("umbra.master.v3"), commentBytes == null ? new byte[0] : commentBytes,
                        count));
    }

    public static byte[] masterFromSeed(byte[] siteSeed) {
        return hmacSha256(siteSeed, utf8("umbra.master.v3.seed"));
    }

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

    private static void requireSupportedAlgorithm(int alg) {
        if (alg != ALG_CHACHA20 && alg != ALG_AES_CTR) {
            throw new SecurityException("Unsupported payload algorithm");
        }
    }

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
