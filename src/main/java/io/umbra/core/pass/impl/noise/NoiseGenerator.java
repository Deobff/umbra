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

    private static final char[] INVISIBLE = {
            '\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF', '\u00AD' };

    private static final String[] TOOL_ATTRIBUTE_NAMES = {
            "ScalaSig", "TastyHeader", "Kotlin.Metadata", "ai-index", "SYMTAB",
            "Metalava", "jvm-metadata", "CompilerNotes", "Lambdas", "SourceInfo"
    };

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

    public String tag(int minLength, int maxLength) {
        int length = minLength + nextInt(Math.max(1, maxLength - minLength + 1));
        StringBuilder out = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            out.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
        }
        return out.toString();
    }

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

    public byte[] payload(int maxLength) {
        return bytes(maxLength <= 0 ? 0 : nextInt(maxLength + 1));
    }

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

    public String junkName() {
        StringBuilder out = new StringBuilder();
        out.append(chance(50) ? "l" : "var").append(tag(1, 4));
        int invisible = 1 + nextInt(3);
        for (int i = 0; i < invisible; i++) {
            out.append(INVISIBLE[random.nextInt(INVISIBLE.length)]);
        }
        return out.toString();
    }

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

    public String sourceFile() {
        return tag(3, 10) + (chance(50) ? ".java" : ".kt");
    }

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

        return out.substring(0, target - 13) + "\u0000\u0001trunc";
    }

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

    public String localDescriptor() {
        return SINGLE_SLOT_DESCRIPTORS[random.nextInt(SINGLE_SLOT_DESCRIPTORS.length)];
    }

    public String classSignature() {
        return "<T:L" + phantomClass() + ";>L" + phantomClass() + ";";
    }

    public String methodSignature() {
        return "<T:L" + phantomClass() + ";>(TT;)TT;";
    }

    public String fieldSignature() {
        return "TT;";
    }

    public String phantomClass() {
        return "noise/" + tag(2, 5) + "/" + tag(3, 7);
    }

    public String phantomSimpleName() {
        return "N" + tag(3, 8);
    }

    public String existingException() {
        return EXISTING_EXCEPTIONS[random.nextInt(EXISTING_EXCEPTIONS.length)];
    }
}
