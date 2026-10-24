package io.umbra.core.pass.impl.noise;

import java.util.Random;

/**
 * Seed-deterministic generator for metadata noise.
 *
 * <p>Everything is derived from the pass' shared {@link Random} so a run with
 * the same seed produces byte-identical output. The helpers intentionally
 * produce values that are legal in a class file but confusing to humans and
 * tools: implausible attribute names, invisible-character identifiers,
 * truncated SMAP blobs and generic signatures that reference classes and type
 * variables which do not exist.</p>
 */
public final class NoiseGenerator {

    private static final String ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    /** Characters that are valid in a class-file UTF-8 string but invisible in editors. */
    private static final char[] INVISIBLE = {
            '\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF', '\u00AD' };
    /**
     * Attribute names of other JVM tooling (Scala, Kotlin, GraalVM...). The JVM
     * ignores them; analysts and decompilers waste time on them.
     */
    private static final String[] TOOL_ATTRIBUTE_NAMES = {
            "ScalaSig", "TastyHeader", "Kotlin.Metadata", "ai-index", "SYMTAB",
            "Metalava", "jvm-metadata", "CompilerNotes", "Lambdas", "SourceInfo"
    };
    /** Single-slot field descriptors: safe for any valid local-variable slot. */
    private static final String[] SINGLE_SLOT_DESCRIPTORS = {
            "I", "Z", "B", "C", "S", "F",
            "Ljava/lang/Object;", "Ljava/lang/String;", "Ljava/lang/Integer;",
            "[B", "[I", "[Ljava/lang/Object;"
    };
    private static final String[] EXISTING_EXCEPTIONS = {
            "java/lang/RuntimeException", "java/lang/Exception", "java/lang/Error"
    };

    private final Random random;

    public NoiseGenerator(Random random) {
        this.random = random == null ? new Random(0L) : random;
    }

    public Random random() {
        return random;
    }

    public int nextInt(int bound) {
        return bound <= 0 ? 0 : random.nextInt(bound);
    }

    public boolean chance(int percent) {
        return random.nextInt(100) < percent;
    }

    /** Random alphanumeric tag. */
    public String tag(int minLength, int maxLength) {
        int length = minLength + nextInt(Math.max(1, maxLength - minLength + 1));
        StringBuilder out = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            out.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
        }
        return out.toString();
    }

    /** Attribute name: random garbage, a foreign-tool name or a plausible pseudo-name. */
    public String attributeName() {
        int pick = nextInt(10);
        if (pick < 5) {
            return "Noise" + tag(3, 9);
        }
        if (pick < 8) {
            return TOOL_ATTRIBUTE_NAMES[random.nextInt(TOOL_ATTRIBUTE_NAMES.length)];
        }
        return (chance(50) ? "ai." : "meta.") + tag(2, 6);
    }

    /** Random payload whose length is at most {@code maxLength}. */
    public byte[] payload(int maxLength) {
        return bytes(maxLength <= 0 ? 0 : nextInt(maxLength + 1));
    }

    /** Random payload of exactly {@code length} bytes. */
    public byte[] bytes(int length) {
        byte[] bytes = new byte[Math.max(0, length)];
        if (chance(50)) {
            random.nextBytes(bytes);
        } else {
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) (32 + random.nextInt(95));
            }
        }
        return bytes;
    }

    /** A local-variable/parameter name with invisible suffix characters. */
    public String junkName() {
        StringBuilder out = new StringBuilder();
        out.append(chance(50) ? "l" : "var").append(tag(1, 4));
        int invisible = 1 + nextInt(3);
        for (int i = 0; i < invisible; i++) {
            out.append(INVISIBLE[random.nextInt(INVISIBLE.length)]);
        }
        return out.toString();
    }

    /** A parameter name that is not a legal Java identifier (legal in a class file). */
    public String weirdParameterName() {
        int pick = nextInt(4);
        if (pick == 0) {
            return "1" + tag(1, 4) + INVISIBLE[random.nextInt(INVISIBLE.length)];
        }
        if (pick == 1) {
            return "<" + tag(1, 3) + ">";
        }
        if (pick == 2) {
            return tag(2, 5) + INVISIBLE[random.nextInt(INVISIBLE.length)]
                    + INVISIBLE[random.nextInt(INVISIBLE.length)];
        }
        return "\u200B" + tag(1, 3);
    }

    /** A plausible but fictitious source file name. */
    public String sourceFile() {
        return tag(3, 10) + (chance(50) ? ".java" : ".kt");
    }

    /**
     * An oversized, deliberately truncated JSR-45 SMAP blob. The JVM stores it
     * verbatim and only debuggers read it.
     */
    public String sourceDebugExtension(int size) {
        int target = Math.max(96, size);
        StringBuilder out = new StringBuilder(target + 16);
        out.append("SMAP\n").append(sourceFile()).append("\nKotlin\n");
        out.append("*S KotlinDebug\n*F\n+ 1 ").append(sourceFile()).append("\n*L\n");
        int line = 1;
        while (out.length() < target) {
            out.append("+ ").append(line).append(' ').append(sourceFile()).append('\n');
            line += 1 + nextInt(7);
        }
        // Truncate in the middle of a record and append non-printable bytes so
        // naive SMAP parsers see an invalid, unfinished table.
        return out.substring(0, target - 13) + "\u0000\u0001trunc";
    }

    /** Random line number including duplicates and extreme values. */
    public int lineNumber() {
        int pick = nextInt(10);
        if (pick == 0) {
            return 0;
        }
        if (pick == 1) {
            return 65535;
        }
        return nextInt(65536);
    }

    /** A valid single-slot descriptor for a local-variable row. */
    public String localDescriptor() {
        return SINGLE_SLOT_DESCRIPTORS[random.nextInt(SINGLE_SLOT_DESCRIPTORS.length)];
    }

    /** Grammar-valid class signature with a type parameter referencing a missing class. */
    public String classSignature() {
        return "<T:L" + phantomClass() + ";>L" + phantomClass() + ";";
    }

    /** Grammar-valid method signature; reflection fails to resolve the type variable/class. */
    public String methodSignature() {
        return "<T:L" + phantomClass() + ";>(TT;)TT;";
    }

    /** Grammar-valid field signature referencing an undeclared type variable. */
    public String fieldSignature() {
        return "TT;";
    }

    /** Internal name of a class that does not exist in the archive. */
    public String phantomClass() {
        return "noise/" + tag(2, 5) + "/" + tag(3, 7);
    }

    /** Simple name of a class that does not exist in the archive. */
    public String phantomSimpleName() {
        return "N" + tag(3, 8);
    }

    /** One of the always-resolvable JDK exception classes. */
    public String existingException() {
        return EXISTING_EXCEPTIONS[random.nextInt(EXISTING_EXCEPTIONS.length)];
    }
}
