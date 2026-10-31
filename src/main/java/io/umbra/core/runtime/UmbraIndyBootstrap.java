package io.umbra.core.runtime;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Invokedynamic bootstrap used to hide member references and string constants.
 *
 * <p>This is a runtime template: its bytecode is copied into the output JAR
 * under a randomized name and must stay self-contained (no references to other
 * Umbra classes). The member-reference bootstraps decrypt their bootstrap
 * arguments lazily on the first invocation; the string bootstrap returns a
 * constant {@code CallSite} bound to the decrypted, interned value so later
 * calls are a plain field/constant load.</p>
 *
 * <p>Key derivation mirrors {@code io.umbra.core.util.Cipher}: the 64-bit
 * member/legacy keys use the ChaCha20 legacy scheme, while string payloads use
 * the per-class/per-site derivation shared with
 * {@code io.umbra.core.runtime.crypto.UmbraCrypto}.</p>
 */
public final class UmbraIndyBootstrap {

    /** 0 = xorshift, 1 = ChaCha20, 2 = AES-256-CTR; replaced at injection time. */
    private static final String ALGORITHM = "@@ALG@@";

    private static final int ALG = parse(ALGORITHM);

    private UmbraIndyBootstrap() {
    }

    /** Static method call sites. */
    public static CallSite bootstrap(MethodHandles.Lookup caller, String name, MethodType type,
                                     String encOwner, long ownerKey,
                                     String encMethod, long methodKey) throws Exception {
        Class<?> owner = owner(caller, encOwner, ownerKey);
        String method = decrypt(encMethod, methodKey);
        MethodHandle handle = caller.findStatic(owner, method, type);
        return new ConstantCallSite(handle);
    }

    /** Virtual / interface call sites; the receiver is the first argument. */
    public static CallSite bootstrapVirtual(MethodHandles.Lookup caller, String name, MethodType type,
                                            String encOwner, long ownerKey,
                                            String encMethod, long methodKey) throws Exception {
        Class<?> owner = owner(caller, encOwner, ownerKey);
        String method = decrypt(encMethod, methodKey);
        MethodType targetType = type.dropParameterTypes(0, 1);
        MethodHandle handle = caller.findVirtual(owner, method, targetType);
        return new ConstantCallSite(handle.asType(type));
    }

    /** Static field read. */
    public static CallSite bootstrapFieldGetStatic(MethodHandles.Lookup caller, String name,
                                                   MethodType type, String encOwner, long ownerKey,
                                                   String encField, long fieldKey) throws Exception {
        Class<?> owner = owner(caller, encOwner, ownerKey);
        String field = decrypt(encField, fieldKey);
        MethodHandle handle = caller.findStaticGetter(owner, field, type.returnType());
        return new ConstantCallSite(handle.asType(type));
    }

    /** Instance field read; the receiver is the first argument. */
    public static CallSite bootstrapFieldGet(MethodHandles.Lookup caller, String name,
                                             MethodType type, String encOwner, long ownerKey,
                                             String encField, long fieldKey) throws Exception {
        Class<?> owner = owner(caller, encOwner, ownerKey);
        String field = decrypt(encField, fieldKey);
        MethodHandle handle = caller.findGetter(owner, field, type.returnType());
        return new ConstantCallSite(handle.asType(type));
    }

    /** Static field write. */
    public static CallSite bootstrapFieldSetStatic(MethodHandles.Lookup caller, String name,
                                                   MethodType type, String encOwner, long ownerKey,
                                                   String encField, long fieldKey) throws Exception {
        Class<?> owner = owner(caller, encOwner, ownerKey);
        String field = decrypt(encField, fieldKey);
        MethodHandle handle = caller.findStaticSetter(owner, field, type.parameterType(0));
        return new ConstantCallSite(handle.asType(type));
    }

    /** Instance field write; the receiver is the first argument. */
    public static CallSite bootstrapFieldSet(MethodHandles.Lookup caller, String name,
                                             MethodType type, String encOwner, long ownerKey,
                                             String encField, long fieldKey) throws Exception {
        Class<?> owner = owner(caller, encOwner, ownerKey);
        String field = decrypt(encField, fieldKey);
        MethodHandle handle = caller.findSetter(owner, field, type.parameterType(1));
        return new ConstantCallSite(handle.asType(type));
    }

    /**
     * String literal call site: the indy instruction has descriptor
     * {@code ()Ljava/lang/String;} and the bootstrap returns a constant
     * {@code CallSite} holding the decrypted, interned value.
     *
     * @param packed      Base64 payload parts joined with {@code '|'}
     * @param classKeySpec name of the synthetic {@code private static final
     *                    String} field holding the per-class Base64 key, or an
     *                    empty string for per-site keys
     * @param siteSeed    64-bit per-site seed
     * @param siteId      call-site index
     */
    public static CallSite bootstrapString(MethodHandles.Lookup caller, String name, MethodType type,
                                           String packed, String classKeySpec, long siteSeed,
                                           int siteId) throws Throwable {
        String classKeyBase64 = null;
        if (classKeySpec != null && classKeySpec.length() > 0) {
            // The lookup class is the class that contains this indy instruction,
            // so it may read its own private synthetic key field.
            MethodHandle getter = caller.findStaticGetter(caller.lookupClass(), classKeySpec, String.class);
            classKeyBase64 = (String) getter.invoke();
        }
        String value = decodeString(packed, classKeyBase64, siteSeed, siteId);
        MethodHandle constant = MethodHandles.constant(String.class, value);
        return new ConstantCallSite(constant.asType(type));
    }

    private static Class<?> owner(MethodHandles.Lookup caller, String encOwner, long key) throws Exception {
        String owner = decrypt(encOwner, key);
        return Class.forName(owner.replace('/', '.'), true, caller.lookupClass().getClassLoader());
    }

    /**
     * Literal domain separators (rewritten per build by template injection) and
     * their mutable counterparts, set by the build side through
     * {@link #applyDomainTags(java.util.Map)}.
     */
    private static final String LIT_LEGACY_KEY = "io.umbra.cipher.legacy.key.v2";
    private static final String LIT_LEGACY_NONCE = "io.umbra.cipher.legacy.nonce.v2";
    private static final String LIT_SITE_KEY = "io.umbra.string.site.key.v1";
    private static final String LIT_SITE_NONCE = "io.umbra.string.site.nonce.v1";
    private static final String LIT_CLASS_NONCE = "io.umbra.string.class.nonce.v1";
    private static final String LIT_AES_IV = "io.umbra.aes.iv.v1";

    private static String TAG_LEGACY_KEY = LIT_LEGACY_KEY;
    private static String TAG_LEGACY_NONCE = LIT_LEGACY_NONCE;
    private static String TAG_SITE_KEY = LIT_SITE_KEY;
    private static String TAG_SITE_NONCE = LIT_SITE_NONCE;
    private static String TAG_CLASS_NONCE = LIT_CLASS_NONCE;
    private static String TAG_AES_IV = LIT_AES_IV;

    /** Build-side hook: installs the per-build separators (never called at runtime). */
    public static void applyDomainTags(java.util.Map<String, String> tags) {
        TAG_LEGACY_KEY = pick(tags, LIT_LEGACY_KEY);
        TAG_LEGACY_NONCE = pick(tags, LIT_LEGACY_NONCE);
        TAG_SITE_KEY = pick(tags, LIT_SITE_KEY);
        TAG_SITE_NONCE = pick(tags, LIT_SITE_NONCE);
        TAG_CLASS_NONCE = pick(tags, LIT_CLASS_NONCE);
        TAG_AES_IV = pick(tags, LIT_AES_IV);
    }

    private static String pick(java.util.Map<String, String> tags, String literal) {
        String value = tags.get(literal);
        return value == null ? literal : value;
    }

    /** Decrypts a legacy ChaCha20 payload (matches {@code Cipher.encrypt(String,long)}). */
    private static String decrypt(String payload, long key) {
        byte[] data = Base64.getDecoder().decode(payload);
        byte[] derivedKey = sha256(concat(utf8(TAG_LEGACY_KEY), le64(key)));
        byte[] nonce = first(sha256(concat(utf8(TAG_LEGACY_NONCE), le64(key))), 12);
        byte[] plain = chacha20(derivedKey, nonce, 1, data);
        try {
            return new String(plain, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(derivedKey, (byte) 0);
            Arrays.fill(plain, (byte) 0);
        }
    }

    private static String decodeString(String packed, String classKeyBase64, long siteSeed, int siteId) {
        byte[] ciphertext = join(split(packed));
        byte[] classKey = null;
        try {
            if (classKeyBase64 != null && classKeyBase64.length() > 0) {
                classKey = Base64.getDecoder().decode(classKeyBase64);
            }
            byte[] plain = stringPlain(ciphertext, classKey, siteSeed, siteId);
            return new String(plain, StandardCharsets.UTF_8).intern();
        } finally {
            Arrays.fill(ciphertext, (byte) 0);
            if (classKey != null) {
                Arrays.fill(classKey, (byte) 0);
            }
        }
    }

    // ------------------------------------------------------------------
    // Payload plumbing
    // ------------------------------------------------------------------

    private static List<String> split(String packed) {
        List<String> parts = new ArrayList<String>();
        int start = 0;
        int index = packed.indexOf('|');
        while (index >= 0) {
            parts.add(packed.substring(start, index));
            start = index + 1;
            index = packed.indexOf('|', start);
        }
        parts.add(packed.substring(start));
        return parts;
    }

    private static byte[] join(List<String> parts) {
        int total = 0;
        byte[][] decoded = new byte[parts.size()][];
        for (int i = 0; i < decoded.length; i++) {
            decoded[i] = Base64.getDecoder().decode(parts.get(i));
            total += decoded[i].length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (int i = 0; i < decoded.length; i++) {
            System.arraycopy(decoded[i], 0, out, offset, decoded[i].length);
            offset += decoded[i].length;
        }
        return out;
    }

    // ------------------------------------------------------------------
    // String payload decryption (mirrors UmbraCrypto.stringPlain)
    // ------------------------------------------------------------------

    private static byte[] stringPlain(byte[] ciphertext, byte[] classKey, long siteSeed, int siteId) {
        if (ALG == 0) {
            return xorStream(ciphertext, siteSeed);
        }
        byte[] key;
        boolean temporary = false;
        if (classKey != null) {
            key = classKey;
        } else {
            key = sha256(concat(utf8(TAG_SITE_KEY), le64(siteSeed), le32(siteId)));
            temporary = true;
        }
        try {
            byte[] nonce;
            if (classKey != null) {
                nonce = first(sha256(concat(utf8(TAG_CLASS_NONCE), key, le32(siteId))), 12);
            } else {
                nonce = first(sha256(concat(utf8(TAG_SITE_NONCE), le64(siteSeed),
                        le32(siteId))), 12);
            }
            if (ALG == 2) {
                byte[] iv = first(sha256(concat(utf8(TAG_AES_IV), key, nonce)), 16);
                return aesCtr(key, iv, ciphertext);
            }
            return chacha20(key, nonce, 1, ciphertext);
        } finally {
            if (temporary) {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    private static int parse(String value) {
        if (value != null) {
            if ("2".equals(value) || "aes-ctr".equals(value)) {
                return 2;
            }
            if ("0".equals(value) || "xor".equals(value)) {
                return 0;
            }
        }
        return 1;
    }

    // ------------------------------------------------------------------
    // Self-contained crypto (mirrors io.umbra.core.util.Cipher)
    // ------------------------------------------------------------------

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable");
        }
    }

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

    private static byte[] aesCtr(byte[] key, byte[] iv, byte[] data) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                    new javax.crypto.spec.SecretKeySpec(key, "AES"),
                    new javax.crypto.spec.IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-CTR unavailable");
        }
    }

    private static byte[] xorStream(byte[] data, long key) {
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

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (int i = 0; i < parts.length; i++) {
            total += parts[i].length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (int i = 0; i < parts.length; i++) {
            System.arraycopy(parts[i], 0, out, offset, parts[i].length);
            offset += parts[i].length;
        }
        return out;
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] le32(int value) {
        return new byte[] {
                (byte) value, (byte) (value >>> 8), (byte) (value >>> 16), (byte) (value >>> 24)
        };
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
