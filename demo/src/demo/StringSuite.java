package demo;

import java.util.Locale;

/**
 * String coverage: ASCII, accented Latin, Greek, CJK (BMP) and a supplementary
 * plane code point (surrogate pair), plus builder/format/split/join operations.
 */
public final class StringSuite {

    static final String HELLO = "Hello, Umbra!";
    static final String UNICODE = "\u4f60\u597d\uff0c\u4e16\u754c";
    static final String EMOJI = "\uD83D\uDE80";
    static final String ACCENTED = "\u00dcn\u00efc\u00f6d\u00e9 Caf\u00e9";
    static final String GREEK = "\u03b1\u03b2\u03b3\u03b4\u03b5";
    static final String SENTENCE =
            "the quick brown fox jumps over the lazy dog 0123456789";
    /** Distinctive literal: used by the deobfuscation evidence scan. */
    static final String SENTINEL = "umbra-demo-string-sentinel-42";

    private StringSuite() {
    }

    public static void run() throws DemoException {
        Checks.eq(HELLO.length(), 13, "hello length");
        Checks.check(HELLO.startsWith("Hello") && HELLO.endsWith("!"), "prefix and suffix");
        Checks.eq(HELLO.indexOf("Umbra"), 7, "indexOf");
        Checks.eq(HELLO.indexOf('U'), 7, "indexOf char");
        Checks.eq(HELLO.substring(7, 12), "Umbra", "substring");
        Checks.eq(HELLO.charAt(0), 'H', "charAt");
        Checks.eq(HELLO.toUpperCase(Locale.ROOT), "HELLO, UMBRA!", "toUpperCase");
        Checks.eq(HELLO.toLowerCase(Locale.ROOT), "hello, umbra!", "toLowerCase");
        Checks.eq(HELLO.replace("Umbra", "World"), "Hello, World!", "replace");
        Checks.eq("  padded  ".trim(), "padded", "trim");
        Checks.eq(HELLO.concat("!").length(), 14, "concat");
        Checks.check(HELLO.equals("Hello, Umbra!"), "equals");
        Checks.check(!HELLO.equals("hello, umbra!"), "case sensitive");
        Checks.check("alpha".compareTo("beta") < 0, "compareTo");

        Checks.eq(UNICODE.length(), 5, "cjk utf-16 length");
        Checks.eq(UNICODE.codePointCount(0, UNICODE.length()), 5, "cjk code points");
        Checks.check(UNICODE.indexOf('\u4f60') == 0, "cjk first char");
        Checks.check(UNICODE.contains("\u4e16\u754c"), "cjk contains tail");
        Checks.eq(EMOJI.length(), 2, "supplementary character utf-16 length");
        Checks.eq(EMOJI.codePointCount(0, EMOJI.length()), 1, "supplementary code points");
        Checks.eq(EMOJI.codePointAt(0), 0x1F680, "supplementary code point value");
        Checks.eq(ACCENTED.length(), 12, "accented length");
        Checks.check(ACCENTED.indexOf('\u00e9') > 0, "accented acute");
        Checks.eq(GREEK.length(), 5, "greek length");
        Checks.eq(GREEK.toUpperCase(Locale.ROOT), "\u0391\u0392\u0393\u0394\u0395", "greek upper");
        Checks.eq(SENTINEL, "umbra-demo-string-sentinel-42", "sentinel literal");

        StringBuilder builder = new StringBuilder();
        builder.append(HELLO).append(' ').append(UNICODE).append(' ').append(EMOJI);
        String combined = builder.toString();
        Checks.check(combined.contains(HELLO), "builder hello");
        Checks.check(combined.contains(UNICODE), "builder unicode");
        Checks.check(combined.contains(EMOJI), "builder emoji");
        Checks.eq(new StringBuilder("abcdef").reverse().toString(), "fedcba", "reverse");

        String[] words = SENTENCE.split(" ");
        Checks.eq(words.length, 10, "split length");
        Checks.eq(words[0], "the", "split first");
        Checks.eq(words[9], "0123456789", "split last");
        Checks.eq(String.join("|", words), SENTENCE.replace(' ', '|'), "join");
        Checks.eq(String.valueOf(12345), "12345", "valueOf int");
        Checks.eq(Integer.parseInt("12345"), 12345, "parseInt");
        Checks.eq(Long.parseLong("-987654321"), -987654321L, "parseLong");
        Checks.eq(String.format(Locale.ROOT, "%s/%d/%.2f/%c", "tag", 42, 3.5, 'Z'),
                "tag/42/3.50/Z", "format");

        char[] chars = HELLO.toCharArray();
        Checks.eq(chars.length, 13, "toCharArray");
        Checks.eq(new String(chars, 7, 5), "Umbra", "string from chars");
        Checks.eq(("um" + "bra").intern(), "umbra", "intern");
        Checks.eq(String.valueOf(new char[]{'o', 'k'}), "ok", "chars valueOf");
    }
}
