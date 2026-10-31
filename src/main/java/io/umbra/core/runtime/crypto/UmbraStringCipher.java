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
 * <p>Payload layout v3 also has a dual-engine form: one call site carries the
 * same value encrypted twice, first half of the {@code parts} array with
 * {@code engineA}, second half with {@code engineB}, and a {@code selector}
 * argument picks the half to decrypt ({@code selector & 1}). The injected call
 * site passes the one-time state's {@code carrier()}, whose low bit strictly
 * alternates, so two consecutive calls at the same site provably take different
 * decryption paths; the build-time pass guarantees both halves have the same
 * number of parts and that the array length is even, and the runtime rejects
 * anything else instead of guessing a boundary. Each half is keyed with its own
 * domain-separated site index (see {@link #dualSiteId(int, int)}), so the two
 * ciphertexts never share a keystream.</p>
 *
 * <p>Two hardening flags are substituted at injection time through
 * {@code @@FLAGS@@}: bit 0 enables decrypt-and-wipe (every intermediate byte /
 * char buffer is zeroed before returning), bit 1 enables stack-trace hiding
 * (a decryption failure is replaced by a sanitized exception with an empty
 * stack trace, so the helper's class, method and internal values never leak
 * into a report), bit 2 enables the opt-in plaintext memoization cache. With
 * bit 2 clear (the 3.2 default) the class does not even allocate the map.</p>
 *
 * <p>Payload format v3 adds a build-time artifact salt, substituted through
 * {@code @@SALT@@}. It is mixed into the class-key, per-site seed, key and
 * nonce derivations below, so the historical fixed domain strings are no
 * longer a universal key schedule: the same input protected by two builds with
 * different seeds produces unrelated key material. Each protected archive is
 * self-contained (it carries its own decryptor bytecode), so old 3.x archives
 * keep working unchanged; no cross-version reader is needed.</p>
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

    /** Payload/key-schedule version implemented by this template. */
    public static final int PAYLOAD_VERSION = 3;

    /** "0" for plain, bit 0 = wipe, bit 1 = stack-trace hiding, bit 2 = plaintext cache. */
    private static final String FLAGS_SPEC = "@@FLAGS@@";
    /** Build-time artifact salt (decimal 64-bit); replaced at injection time. */
    private static final String SALT_SPEC = "@@SALT@@";

    private static final int FLAGS = parseFlags(FLAGS_SPEC);
    private static final boolean WIPE = (FLAGS & 1) != 0;
    private static final boolean HIDE_TRACE = (FLAGS & 2) != 0;
    private static final boolean CACHE_ENABLED = (FLAGS & 4) != 0;

    /**
     * Only allocated when the opt-in cache bit is set; the default build keeps
     * no plaintext map reachable from the decryptor at all.
     */
    private static final ConcurrentHashMap<String, String> CACHE =
            CACHE_ENABLED ? new ConcurrentHashMap<String, String>() : null;

    /** Artifact salt embedded by the pass (0 when a foreign template is used). */
    private static final long SALT = parseLong(SALT_SPEC);

    /**
     * Engine code of the most recent decryption. Self-test hook: a protected
     * program can assert that two consecutive calls at one site really used
     * different engines. Holds no key material.
     */
    private static int lastEngine = -1;

    private UmbraStringCipher() {
    }

    // ------------------------------------------------------------------
    // Call-site entry points (emitted by StringEncryptionPass)
    // ------------------------------------------------------------------

    /** Per-class key, no memoization. */
    public static String d(String[] parts, String classKey, int siteId, int engine) {
        return decrypt(parts, classKey, 0L, siteId, true, false, engine);
    }

    /** Per-class key, memoized per call site (only when the cache bit is set). */
    public static String e(String[] parts, String classKey, int siteId, int engine) {
        return decrypt(parts, classKey, 0L, siteId, true, CACHE_ENABLED, engine);
    }

    /** Per-site 64-bit seed, no memoization. */
    public static String d(String[] parts, long siteSeed, int siteId, int engine) {
        return decrypt(parts, null, siteSeed, siteId, false, false, engine);
    }

    /** Per-site 64-bit seed, memoized per call site (only when the cache bit is set). */
    public static String e(String[] parts, long siteSeed, int siteId, int engine) {
        return decrypt(parts, null, siteSeed, siteId, false, CACHE_ENABLED, engine);
    }

    /** Per-class key, dual payload, no memoization. */
    public static String d(String[] parts, String classKey, int siteId, int engineA, int engineB,
                           int selector) {
        return decryptDual(parts, classKey, 0L, siteId, true, false, engineA, engineB, selector);
    }

    /** Per-class key, dual payload, memoized per call site (only when the cache bit is set). */
    public static String e(String[] parts, String classKey, int siteId, int engineA, int engineB,
                           int selector) {
        return decryptDual(parts, classKey, 0L, siteId, true, CACHE_ENABLED, engineA, engineB,
                selector);
    }

    /** Per-site 64-bit seed, dual payload, no memoization. */
    public static String d(String[] parts, long siteSeed, int siteId, int engineA, int engineB,
                           int selector) {
        return decryptDual(parts, null, siteSeed, siteId, false, false, engineA, engineB, selector);
    }

    /** Per-site 64-bit seed, dual payload, memoized per call site (cache bit only). */
    public static String e(String[] parts, long siteSeed, int siteId, int engineA, int engineB,
                           int selector) {
        return decryptDual(parts, null, siteSeed, siteId, false, CACHE_ENABLED, engineA, engineB,
                selector);
    }

    /**
     * Engine code used by the most recent decryption ({@code -1} before the first
     * one). Self-test hook only: it lets a protected program assert that two
     * consecutive calls at one site really used different engines.
     */
    public static int lastEngine() {
        return lastEngine;
    }

    /**
     * Site index of one half of a dual payload. The second half is domain
     * separated, so the two ciphertexts of the same value never derive the same
     * key/nonce and therefore never share a keystream. Shared by the build-side
     * pass (encryption) and this template (decryption), so the two sides cannot
     * drift.
     */
    public static int dualSiteId(int siteId, int half) {
        return half == 0 ? siteId : siteId ^ 0x7F4A7C15;
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
    // Salted key schedule (payload format v3, shared build/runtime)
    // ------------------------------------------------------------------

    /**
     * Literal domain separators (rewritten per build by template injection) and
     * their mutable counterparts, which the build side sets through
     * {@link #applyDomainTags(java.util.Map)}. The passes call this class at build
     * time, so both sides have to read the same field.
     */
    private static final String LIT_CLASS_KEY = "io.umbra.string.v3.class.key";
    private static final String LIT_SITE_SEED = "io.umbra.string.v3.site.seed";
    private static final String LIT_SITE_KEY = "io.umbra.string.v3.site.key";
    private static final String LIT_SITE_NONCE = "io.umbra.string.v3.site.nonce";
    private static final String LIT_CLASS_NONCE = "io.umbra.string.v3.class.nonce";
    private static final String LIT_ARTIFACT_SALT = "io.umbra.string.v3.artifact.salt";
    private static final String LIT_USER_SALT = "io.umbra.string.v3.user.salt";
    private static final String LIT_RC4_KEY = "io.umbra.string.rc4.key.v1";
    private static final String LIT_SPECK_KEY = "io.umbra.string.speck.key.v1";

    private static String TAG_CLASS_KEY = LIT_CLASS_KEY;
    private static String TAG_SITE_SEED = LIT_SITE_SEED;
    private static String TAG_SITE_KEY = LIT_SITE_KEY;
    private static String TAG_SITE_NONCE = LIT_SITE_NONCE;
    private static String TAG_CLASS_NONCE = LIT_CLASS_NONCE;
    private static String TAG_ARTIFACT_SALT = LIT_ARTIFACT_SALT;
    private static String TAG_USER_SALT = LIT_USER_SALT;
    private static String TAG_RC4_KEY = LIT_RC4_KEY;
    private static String TAG_SPECK_KEY = LIT_SPECK_KEY;

    /**
     * Build-side hook: installs the per-build separators. Never called at runtime
     * (the injected copy has them baked into its static initializer).
     */
    public static void applyDomainTags(java.util.Map<String, String> tags) {
        TAG_CLASS_KEY = pick(tags, LIT_CLASS_KEY);
        TAG_SITE_SEED = pick(tags, LIT_SITE_SEED);
        TAG_SITE_KEY = pick(tags, LIT_SITE_KEY);
        TAG_SITE_NONCE = pick(tags, LIT_SITE_NONCE);
        TAG_CLASS_NONCE = pick(tags, LIT_CLASS_NONCE);
        TAG_ARTIFACT_SALT = pick(tags, LIT_ARTIFACT_SALT);
        TAG_USER_SALT = pick(tags, LIT_USER_SALT);
        TAG_RC4_KEY = pick(tags, LIT_RC4_KEY);
        TAG_SPECK_KEY = pick(tags, LIT_SPECK_KEY);
    }

    private static String pick(java.util.Map<String, String> tags, String literal) {
        String value = tags.get(literal);
        return value == null ? literal : value;
    }

    /**
     * Derives the 256-bit per-class key from the artifact salt, the build seed
     * and the class name. Build-time only (the runtime reads the Base64 form),
     * but kept here so the pass and the template share one implementation.
     */
    public static byte[] classKeyV2(long salt, long buildSeed, String className) {
        return UmbraCrypto.sha256(UmbraCrypto.concat(
                UmbraCrypto.utf8(TAG_CLASS_KEY),
                UmbraCrypto.le64(salt), UmbraCrypto.le64(buildSeed),
                UmbraCrypto.utf8(className)));
    }

    /** Derives the per-site 64-bit seed with the artifact salt folded in. */
    public static long siteSeedV2(long salt, long buildSeed, String className, int siteId) {
        byte[] digest = UmbraCrypto.sha256(UmbraCrypto.concat(
                UmbraCrypto.utf8(TAG_SITE_SEED),
                UmbraCrypto.le64(salt), UmbraCrypto.le64(buildSeed),
                UmbraCrypto.utf8(className), UmbraCrypto.le32(siteId)));
        return readLongLE(digest, 0);
    }

    /** Per-site key: SHA-256 over salt, site seed and random site index. */
    public static byte[] siteKeyV2(long salt, long siteSeed, int siteId) {
        return UmbraCrypto.sha256(UmbraCrypto.concat(
                UmbraCrypto.utf8(TAG_SITE_KEY),
                UmbraCrypto.le64(salt), UmbraCrypto.le64(siteSeed), UmbraCrypto.le32(siteId)));
    }

    /** Per-site nonce: 96 bits of SHA-256 over salt, site seed and site index. */
    public static byte[] siteNonceV2(long salt, long siteSeed, int siteId) {
        return UmbraCrypto.first(UmbraCrypto.sha256(UmbraCrypto.concat(
                UmbraCrypto.utf8(TAG_SITE_NONCE),
                UmbraCrypto.le64(salt), UmbraCrypto.le64(siteSeed), UmbraCrypto.le32(siteId))),
                12);
    }

    /** Per-class nonce: 96 bits of SHA-256 over salt, class key and site index. */
    public static byte[] classNonceV2(long salt, byte[] classKey, int siteId) {
        return UmbraCrypto.first(UmbraCrypto.sha256(UmbraCrypto.concat(
                UmbraCrypto.utf8(TAG_CLASS_NONCE),
                UmbraCrypto.le64(salt), classKey, UmbraCrypto.le32(siteId))), 12);
    }

    /** Default artifact salt derived from the build seed (build-time only). */
    public static long deriveArtifactSalt(long buildSeed) {
        byte[] digest = UmbraCrypto.sha256(UmbraCrypto.concat(
                UmbraCrypto.utf8(TAG_ARTIFACT_SALT),
                UmbraCrypto.le64(buildSeed)));
        long salt = readLongLE(digest, 0);
        return salt == 0L ? 0x5A17C0DEL : salt;
    }

    /** Deterministic salt derived from an explicit {@code string.siteSalt} text. */
    public static long hashSaltText(String text) {
        byte[] digest = UmbraCrypto.sha256(UmbraCrypto.concat(
                UmbraCrypto.utf8(TAG_USER_SALT), UmbraCrypto.utf8(text)));
        long salt = readLongLE(digest, 0);
        return salt == 0L ? 0x5A17C0DEL : salt;
    }

    // ------------------------------------------------------------------
    // Per-site decryption
    // ------------------------------------------------------------------

    private static String decrypt(String[] parts, String classKeyBase64, long siteSeed, int siteId,
                                  boolean perClass, boolean cached, int engine) {
        return decryptRange(parts, 0, parts.length, classKeyBase64, siteSeed, siteId, perClass,
                cached, engine);
    }

    /**
     * Decrypts one dual-engine payload: the first {@code parts.length / 2} entries
     * are the {@code engineA} ciphertext, the rest the {@code engineB} ciphertext,
     * and bit 0 of {@code selector} chooses which one is used. Both halves decrypt
     * to the same value, so the choice is invisible except in the executed
     * instructions and the cipher state.
     */
    private static String decryptDual(String[] parts, String classKeyBase64, long siteSeed,
                                      int siteId, boolean perClass, boolean cached, int engineA,
                                      int engineB, int selector) {
        int half = dualHalf(parts);
        boolean second = (selector & 1) != 0;
        int engine = second ? engineB : engineA;
        // The halves are domain separated by site index (see dualSiteId), so the
        // key material of the selected half is derived from its own index.
        int halfSiteId = dualSiteId(siteId, second ? 1 : 0);
        return decryptRange(parts, second ? half : 0, second ? parts.length : half, classKeyBase64,
                siteSeed, halfSiteId, perClass, cached, engine);
    }

    /**
     * Number of entries in the first half of a dual payload. The build side emits
     * two equal halves, so an odd length or a single part is a corrupt payload,
     * not something to guess a boundary for.
     */
    private static int dualHalf(String[] parts) {
        if (parts == null || parts.length < 2 || (parts.length & 1) != 0) {
            throw new IllegalArgumentException();
        }
        return parts.length >>> 1;
    }

    private static String decryptRange(String[] parts, int from, int to, String classKeyBase64,
                                       long siteSeed, int siteId, boolean perClass, boolean cached,
                                       int engine) {
        try {
            cached = cached && CACHE != null;
            String cacheKey = cached ? cacheKey(parts, classKeyBase64, siteSeed, siteId, engine) : null;
            if (cacheKey != null) {
                String hit = CACHE.get(cacheKey);
                if (hit != null) {
                    lastEngine = engine;
                    return hit;
                }
            }
            byte[] ciphertext = join(parts, from, to);
            byte[] classKey = null;
            byte[] key = null;
            byte[] nonce = null;
            boolean temporaryKey = false;
            try {
                if (perClass) {
                    classKey = UmbraCrypto.base64Decode(classKeyBase64);
                    key = classKey;
                    nonce = classNonceV2(SALT, classKey, siteId);
                } else {
                    key = siteKeyV2(SALT, siteSeed, siteId);
                    nonce = siteNonceV2(SALT, siteSeed, siteId);
                    temporaryKey = true;
                }
                byte[] plain = transform(engine, ciphertext, key, nonce, siteSeed);
                String value = internUtf8(plain);
                Arrays.fill(plain, (byte) 0);
                lastEngine = engine;
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

    /** Concatenates the Base64 parts in {@code [from, to)} into one ciphertext. */
    private static byte[] join(String[] parts, int from, int to) {
        int length = 0;
        for (int i = from; i < to; i++) {
            length += ((parts[i].length() * 3) >>> 2) + 2;
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (int i = from; i < to; i++) {
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
                        UmbraCrypto.utf8(TAG_RC4_KEY), key, nonce)), data);
            case SPECK:
                return speckCtr(UmbraCrypto.first(UmbraCrypto.sha256(UmbraCrypto.concat(
                        UmbraCrypto.utf8(TAG_SPECK_KEY), key, nonce)), 16), nonce, data);
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

    private static long parseLong(String value) {
        if (value == null) {
            return 0L;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException ignored) {
            return 0L;
        }
    }

    private static long readLongLE(byte[] data, int offset) {
        long value = 0L;
        for (int i = 0; i < 8; i++) {
            value |= (data[offset + i] & 0xFFL) << (8 * i);
        }
        return value;
    }

    private static int readIntLE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }
}
