package io.umbra.core.util;

/**
 * Deterministic derivation of the per-build key root.
 *
 * <p>{@code ARCHITECTURE.md} requires that a run be reproducible for a given
 * {@code ctx.config().seed()}. The root that every crypto layer derives from used
 * to come from an <em>unseeded</em> {@code SecureRandom}, so two runs with the same
 * seed agreed only on the generated entry names: every payload byte differed and
 * the archives landed a few bytes apart in size. Pinning {@code --seed} promised
 * exactly the opposite of what it delivered.</p>
 *
 * <p>The derivation is {@code SHA-256(label || LE64(seed))}. It is deliberately
 * byte-identical to {@code io.umbra.core.runtime.crypto.NativeKeySupport
 * .ensureBuildRoot}, because the compiled JNI bridge derives its half of the key
 * from the same root; {@code DeterminismTest} pins the two implementations
 * together so a future edit cannot silently split them.</p>
 *
 * <p><strong>Keep the deployment seed private.</strong> Two archives built from the
 * same seed carry the same root, so one recovery covers both. The CLI therefore
 * draws a fresh seed for every build unless {@code --seed} pins one, and prints the
 * value it used so a build can still be reproduced on demand.</p>
 */
public final class BuildRoot {

    /** Must stay equal to {@code NativeKeySupport.DETERMINISTIC_ROOT_LABEL}. */
    public static final String LABEL = "umbra.flow.mask.v1";

    /** Root length in bytes; must stay equal to {@code NativeKeySupport.ROOT_BYTES}. */
    public static final int BYTES = 32;

    private BuildRoot() {
    }

    /** The build root for a seed, using the shared domain label. */
    public static byte[] derive(long seed) {
        return derive(seed, LABEL);
    }

    /** The build root for a seed and an explicit domain label. */
    public static byte[] derive(long seed, String label) {
        if (label == null) {
            label = LABEL;
        }
        byte[] labelBytes = label.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] material = new byte[labelBytes.length + 8];
        System.arraycopy(labelBytes, 0, material, 0, labelBytes.length);
        for (int i = 0; i < 8; i++) {
            material[labelBytes.length + i] = (byte) (seed >>> (i * 8));
        }
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(material);
        } catch (java.security.NoSuchAlgorithmException missing) {
            throw new IllegalStateException("SHA-256 unavailable", missing);
        }
    }
}
