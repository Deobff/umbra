package io.umbra.core.util;

import java.util.Random;

/**
 * Semantic-decoy names for the renamer (P7).
 *
 * <p>A flat rename turns the archive into a pile of one-letter classes, which
 * makes the real business classes stand out as soon as an analyst sorts by size
 * or references. This helper supplies names that look like ordinary third-party
 * libraries instead: an analyst skimming {@code org/apache/commons/lang3/...}
 * deprioritises it, and a class named {@code StringUtils} is a much less
 * attractive target than one named {@code AccountService}.</p>
 *
 * <p>Two hard constraints drive the design:</p>
 * <ul>
 *   <li>the mapping is applied to a <em>whole source package</em> at once, so
 *       package-private and protected access between moved classes keeps
 *       working (splitting a package across two new packages raises
 *       {@code IllegalAccessError} at run time);</li>
 *   <li>every generated package carries a short per-build segment, so it can
 *       never collide with the real library of the same name and never lands in
 *       a JDK-owned namespace ({@code java.*}, {@code javax.*}, {@code jdk.*});
 *       {@link #existsInJdk(String)} is an extra runtime check on top.</li>
 * </ul>
 */
public final class DecoyNames {

    private static final String[] PACKAGES = {
            "org/apache/commons/io",
            "org/apache/commons/lang3",
            "org/apache/commons/collections4",
            "com/sun/security/util",
            "com/google/common/collect",
            "org/slf4j/helpers",
            "com/fasterxml/jackson/core",
            "org/jetbrains/annotations",
            "net/bytebuddy/utility",
            "org/objectweb/asm/tree"
    };

    private static final String[] SIMPLE = {
            "IOUtils", "StringUtils", "Base64", "Cache", "Preconditions", "Objects",
            "Collections", "TypePool", "ByteVector", "Serialization", "Loader", "Utils",
            "Helper", "Charsets", "Conversion", "Unsafe", "Reporter", "Streams",
            "Optional", "Resources", "Checks", "Suppliers"
    };

    private static final String SEGMENT_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

    private DecoyNames() {
    }

    public static String buildSegment(long seed) {
        long mixed = seed * 0x9E3779B97F4A7C15L;
        mixed ^= mixed >>> 29;
        int a = (int) (mixed & 0xFFFF) % SEGMENT_ALPHABET.length();
        int b = (int) ((mixed >>> 16) & 0xFFFF) % SEGMENT_ALPHABET.length();
        return "" + SEGMENT_ALPHABET.charAt(a) + SEGMENT_ALPHABET.charAt(b);
    }

    public static String packageName(Random random, String segment) {
        String base = PACKAGES[random.nextInt(PACKAGES.length)];
        return base + "/" + segment;
    }

    public static String simpleName(Random random) {
        return SIMPLE[random.nextInt(SIMPLE.length)];
    }

    public static boolean existsInJdk(String internalName) {
        String dotted = internalName.replace('/', '.');
        try {
            Class.forName(dotted, false, ClassLoader.getSystemClassLoader());
            return true;
        } catch (Throwable missing) {
            return false;
        }
    }

    public static boolean reservedPackage(String internalName) {
        return internalName.startsWith("java/")
                || internalName.startsWith("javax/")
                || internalName.startsWith("jdk/")
                || internalName.startsWith("sun/");
    }
}
