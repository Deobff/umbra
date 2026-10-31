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

    /** Historical package name; still the documented {@code runtime.package} example. */
    public static final String DEFAULT = "umbra/runtime";

    private static final String OPTION = "runtime.package";

    /** Marker prefix used when helpers live in the default package. */
    static final String FLAT_DEFAULT_PREFIX = "u";

    private static volatile String base = DEFAULT;
    private static volatile String flatPrefix = FLAT_DEFAULT_PREFIX;

    private RuntimeNames() {
    }

    /** Current package internal name, for example {@code q7/mx}. */
    public static String base() {
        return base;
    }

    /**
     * Builds a class name inside the runtime package.
     *
     * @param suffix suffix appended after the package, for example {@code V} or
     *               {@code class-loader/Le3f1}
     */
    public static String path(String suffix) {
        String trimmed = suffix == null ? "" : suffix;
        if (trimmed.isEmpty()) {
            return base;
        }
        if (base.isEmpty()) {
            // Flattened build: helpers sit in the default package next to the
            // business classes, so only a per-build prefix marks them.
            return flatPrefix + trimmed.replace("/", "");
        }
        return trimmed.startsWith("/") ? base + trimmed : base + "/" + trimmed;
    }

    /**
     * Namespace prefix for callers that concatenate their own suffix, for
     * example {@code "ru/"} normally and the flat prefix in a flattened build.
     */
    public static String prefix() {
        return base.isEmpty() ? flatPrefix : base + "/";
    }
    /** True when the internal name belongs to the generated runtime package. */
    public static boolean isRuntime(String internalName) {
        if (internalName == null) {
            return false;
        }
        if (base.isEmpty()) {
            return internalName.startsWith(flatPrefix);
        }
        return internalName.startsWith(base + "/");
    }

    /** Restores the historical default; used by tests that inspect the package. */
    public static void reset() {
        base = DEFAULT;
        flatPrefix = FLAT_DEFAULT_PREFIX;
    }

    /**
     * Chooses the package for this build.
     *
     * <p>{@code runtime.package=auto} (the default) derives a short random
     * package from the seed, so two builds of the same input do not share a
     * fingerprint while a fixed seed still produces reproducible output.</p>
     */
    public static void configure(UmbraConfig config, ClassPool pool) {
        String configured = config.option(OPTION, "auto");
        String name = configured == null ? "auto" : configured.trim();
        if ("flat".equalsIgnoreCase(name)) {
            // Everything in the default package, like a flattened ZKM build.
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
