package io.umbra.core.util;

import io.umbra.core.runtime.UmbraIndyBootstrap;
import io.umbra.core.runtime.UmbraStringDecryptor;
import io.umbra.core.runtime.crypto.UmbraCrypto;
import io.umbra.core.runtime.crypto.UmbraStringCipher;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Per-build domain separators for the key-derivation formulas the obfuscator and
 * the injected runtime helpers share.
 *
 * <p>Every KDF is prefixed with a fixed ASCII label ({@code
 * "io.umbra.string.site.key.v1"} and friends). The label is a domain separator -
 * it makes one seed derive unrelated keys for the string pool, the class pool
 * and the AES IV - but a self-describing label also hands an analyst the whole
 * derivation structure out of the constant pool.</p>
 *
 * <p>{@link #install(long)} replaces every label with a value derived from the
 * run seed, so two builds no longer share them. Each template keeps the literal
 * in a {@code static final} field (whose {@code ConstantValue} is what template
 * injection rewrites) plus a mutable {@code TAG_*} field the build side sets.
 * That two-step indirection is required because the passes call
 * {@code UmbraStringCipher} directly at build time: rewriting only the injected
 * copy would desynchronise the build side from the runtime side.</p>
 */
public final class DomainTags {

    private static final String LEGACY_KEY = "io.umbra.cipher.legacy.key.v2";
    private static final String LEGACY_NONCE = "io.umbra.cipher.legacy.nonce.v2";
    private static final String SITE_SEED = "io.umbra.string.site.seed.v1";
    private static final String CLASS_KEY = "io.umbra.string.class.key.v1";
    private static final String SITE_KEY = "io.umbra.string.site.key.v1";
    private static final String SITE_NONCE = "io.umbra.string.site.nonce.v1";
    private static final String CLASS_NONCE = "io.umbra.string.class.nonce.v1";
    private static final String AES_IV = "io.umbra.aes.iv.v1";

    private static final String V3_CLASS_KEY = "io.umbra.string.v3.class.key";
    private static final String V3_SITE_SEED = "io.umbra.string.v3.site.seed";
    private static final String V3_SITE_KEY = "io.umbra.string.v3.site.key";
    private static final String V3_SITE_NONCE = "io.umbra.string.v3.site.nonce";
    private static final String V3_CLASS_NONCE = "io.umbra.string.v3.class.nonce";
    private static final String V3_ARTIFACT_SALT = "io.umbra.string.v3.artifact.salt";
    private static final String V3_USER_SALT = "io.umbra.string.v3.user.salt";
    private static final String RC4_KEY = "io.umbra.string.rc4.key.v1";
    private static final String SPECK_KEY = "io.umbra.string.speck.key.v1";

    private static final String[] LITERALS = {
            LEGACY_KEY, LEGACY_NONCE, SITE_SEED, CLASS_KEY, SITE_KEY, SITE_NONCE,
            CLASS_NONCE, AES_IV, V3_CLASS_KEY, V3_SITE_SEED, V3_SITE_KEY, V3_SITE_NONCE,
            V3_CLASS_NONCE, V3_ARTIFACT_SALT, V3_USER_SALT, RC4_KEY, SPECK_KEY
    };

    /** Offset of each label inside {@link #LITERALS}. */
    public static final int I_LEGACY_KEY = 0;
    public static final int I_LEGACY_NONCE = 1;
    public static final int I_SITE_SEED = 2;
    public static final int I_CLASS_KEY = 3;
    public static final int I_SITE_KEY = 4;
    public static final int I_SITE_NONCE = 5;
    public static final int I_CLASS_NONCE = 6;
    public static final int I_AES_IV = 7;

    private static final String DERIVATION_LABEL = "umbra.domain.v1";

    private static volatile Map<String, String> current;

    private DomainTags() {
    }

    /**
     * Installs the separators for one build and pushes them into the runtime
     * templates the passes call directly.
     *
     * @param seed run seed
     */
    public static void install(long seed) {
        Map<String, String> tags = new LinkedHashMap<String, String>();
        for (int i = 0; i < LITERALS.length; i++) {
            tags.put(LITERALS[i], derive(seed, i));
        }
        current = tags;
        UmbraCrypto.applyDomainTags(tags);
        UmbraStringCipher.applyDomainTags(tags);
        UmbraIndyBootstrap.applyDomainTags(tags);
        UmbraStringDecryptor.applyDomainTags(tags);
    }

    /** Current separator for one of the {@code I_*} indexes. */
    public static String tag(int index) {
        Map<String, String> tags = current;
        return tags == null ? LITERALS[index] : tags.get(LITERALS[index]);
    }

    /**
     * Literal-to-current mapping for template injection.
     *
     * @return a fresh map; callers may mutate it
     */
    public static Map<String, String> replacements() {
        Map<String, String> tags = current;
        if (tags == null) {
            return new LinkedHashMap<String, String>();
        }
        return new LinkedHashMap<String, String>(tags);
    }

    /** A 16-character hex separator derived from the seed and the label index. */
    private static String derive(long seed, int index) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required", e);
        }
        digest.update(DERIVATION_LABEL.getBytes(StandardCharsets.UTF_8));
        digest.update(le64(seed));
        digest.update(le32(index));
        byte[] out = digest.digest();
        StringBuilder hex = new StringBuilder(16);
        for (int i = 0; i < 8; i++) {
            int value = out[i] & 0xFF;
            hex.append(Character.forDigit(value >>> 4, 16));
            hex.append(Character.forDigit(value & 0x0F, 16));
        }
        return hex.toString();
    }

    private static byte[] le64(long value) {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (value >>> (8 * i));
        }
        return out;
    }

    private static byte[] le32(int value) {
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            out[i] = (byte) (value >>> (8 * i));
        }
        return out;
    }
}