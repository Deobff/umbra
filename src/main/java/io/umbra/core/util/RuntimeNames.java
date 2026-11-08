package io.umbra.core.util;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.model.ClassPool;

import java.util.Locale;
import java.util.Random;

/**
 * Where the generated runtime helpers live inside the protected archive.
 *
 * <p>The helpers (VM interpreter, payload holders, guards, loaders, decryptors)
 * are ordinary classes, and {@code invokedynamic} has to name their host class in
 * the constant pool, so the name cannot be hidden. It can still be made
 * unattributable: by default the package is derived from the build seed, which
 * leaves no vendor name in the artifact and makes the fingerprint differ between
 * builds. Set {@code runtime.package} to a fixed name when a stable, project-like
 * package is preferred.</p>
 */
public final class RuntimeNames {

    public static final String DEFAULT = "umbra/runtime";

    private static final String OPTION = "runtime.package";

    static final String FLAT_DEFAULT_PREFIX = "u";

    private static volatile String base = DEFAULT;
    private static volatile String flatPrefix = FLAT_DEFAULT_PREFIX;

    private RuntimeNames() {
    }

    public static String base() {
        return base;
    }

    public static String path(String suffix) {
        String trimmed = suffix == null ? "" : suffix;
        if (trimmed.isEmpty()) {
            return base;
        }
        if (base.isEmpty()) {

            return flatPrefix + trimmed.replace("/", "");
        }
        return trimmed.startsWith("/") ? base + trimmed : base + "/" + trimmed;
    }

    public static String prefix() {
        return base.isEmpty() ? flatPrefix : base + "/";
    }

    public static boolean isRuntime(String internalName) {
        if (internalName == null) {
            return false;
        }
        if (base.isEmpty()) {
            return internalName.startsWith(flatPrefix);
        }
        return internalName.startsWith(base + "/");
    }

    public static void reset() {
        base = DEFAULT;
        flatPrefix = FLAT_DEFAULT_PREFIX;
    }

    public static void configure(UmbraConfig config, ClassPool pool) {
        String configured = config.option(OPTION, "auto");
        String name = configured == null ? "auto" : configured.trim();
        if ("flat".equalsIgnoreCase(name)) {

            base = "";
            flatPrefix = segment(new Random(config.seed() ^ 0x9E3779B97F4A7C15L)) + "u";
            return;
        }
        if (!name.isEmpty() && !"auto".equalsIgnoreCase(name)) {
            base = name.replace('.', '/');
            flatPrefix = FLAT_DEFAULT_PREFIX;
            return;
        }
        Random random = new Random(config.seed() ^ 0x5DEECE66DL);
        for (int attempt = 0; attempt < 128; attempt++) {
            String candidate = segment(random);
            if (random.nextInt(3) == 0) {
                candidate = candidate + "/" + segment(random);
            }
            if (!collides(pool, candidate)) {
                base = candidate;
                return;
            }
        }
        base = DEFAULT;
    }

    private static boolean collides(ClassPool pool, String candidate) {
        for (String existing : pool.classes().keySet()) {
            if (existing.startsWith(candidate + "/") || existing.equals(candidate)) {
                return true;
            }
        }
        return false;
    }

    private static String segment(Random random) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        int length = 2 + random.nextInt(2);
        StringBuilder out = new StringBuilder(length);
        out.append(alphabet.charAt(random.nextInt(alphabet.length())));
        for (int i = 1; i < length; i++) {
            out.append(random.nextBoolean()
                    ? alphabet.charAt(random.nextInt(alphabet.length()))
                    : digits.charAt(random.nextInt(digits.length())));
        }
        return out.toString().toLowerCase(Locale.ROOT);
    }
}
