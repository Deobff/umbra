package io.umbra.core.util;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

/** Generates short, deterministic identifiers for classes and members. */
public final class NameGenerator {

    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String ALPHABET_DIGITS = ALPHABET + "0123456789";

    private static final Set<String> KEYWORDS = new HashSet<String>(Arrays.asList(
            "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class",
            "const", "continue", "default", "do", "double", "else", "enum", "extends", "final",
            "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int",
            "interface", "long", "native", "new", "package", "private", "protected", "public",
            "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this",
            "throw", "throws", "transient", "try", "void", "volatile", "while", "true", "false",
            "null", "var", "record", "sealed", "permits", "yield"));

    private final Random random;
    private final String prefix;
    private final String alphabet;
    private final String alphabetStart;
    private final String alphabetDigits;
    private final int minimumLength;
    private final long offset;
    private long counter;

    public NameGenerator(Random random, String prefix) {
        this(random, prefix, ALPHABET, 1);
    }

    /**
     * @param random        deterministic random source
     * @param prefix        prefix added to every generated name
     * @param dictionary    allowed characters (at least two unique characters)
     * @param minimumLength minimum identifier length
     */
    public NameGenerator(Random random, String prefix, String dictionary, int minimumLength) {
        this.random = random;
        this.prefix = prefix == null ? "" : prefix;
        String sanitized = sanitize(dictionary);
        this.alphabet = sanitized.isEmpty() ? ALPHABET : sanitized;
        StringBuilder starts = new StringBuilder();
        for (int i = 0; i < this.alphabet.length(); i++) {
            char c = this.alphabet.charAt(i);
            if (Character.isLetter(c)) {
                starts.append(c);
            }
        }
        this.alphabetStart = starts.length() == 0 ? ALPHABET : starts.toString();
        StringBuilder digits = new StringBuilder(this.alphabet);
        for (int i = 0; i < 10; i++) {
            char c = (char) ('0' + i);
            if (digits.indexOf(String.valueOf(c)) < 0) {
                digits.append(c);
            }
        }
        this.alphabetDigits = digits.toString();
        this.minimumLength = Math.max(1, minimumLength);
        long base = this.alphabetDigits.length();
        long start = 0L;
        for (int i = 1; i < this.minimumLength; i++) {
            start += power(base, i);
        }
        this.offset = start;
    }

    /** Deterministic sequence: a, b, ..., z, A, ..., Z, aa, ab, ... */
    public synchronized String next() {
        long value = offset + counter++;
        StringBuilder out = new StringBuilder();
        do {
            int digit = (int) (value % alphabetDigits.length());
            out.append(alphabetDigits.charAt(digit));
            value /= alphabetDigits.length();
        } while (value > 0);
        String name = out.reverse().toString();
        if (Character.isDigit(name.charAt(0))) {
            name = alphabet.charAt(0) + name;
        }
        if (KEYWORDS.contains(name)) {
            name = name + "_";
        }
        return prefix + name;
    }

    /** Random identifier of at least {@code minLength} characters. */
    public String random(int minLength) {
        int length = Math.max(Math.max(minLength, 1), minimumLength);
        StringBuilder out = new StringBuilder(length);
        out.append(alphabetStart.charAt(random.nextInt(alphabetStart.length())));
        for (int i = 1; i < length; i++) {
            out.append(alphabetDigits.charAt(random.nextInt(alphabetDigits.length())));
        }
        String name = out.toString();
        if (KEYWORDS.contains(name)) {
            name = name + "_";
        }
        return prefix + name;
    }

    private static long power(long base, int exponent) {
        long result = 1L;
        for (int i = 0; i < exponent; i++) {
            result *= base;
        }
        return result;
    }

    private static String sanitize(String dictionary) {
        if (dictionary == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < dictionary.length(); i++) {
            char c = dictionary.charAt(i);
            if (Character.isLetterOrDigit(c) && out.indexOf(String.valueOf(c)) < 0) {
                out.append(c);
            }
        }
        return out.toString();
    }

    public static boolean isKeyword(String name) {
        return KEYWORDS.contains(name);
    }

    /** Ensures a package name is usable as an internal package path. */
    public static String normalizePackage(String value) {
        if (value == null) {
            return "";
        }
        String out = value.trim().replace('.', '/');
        while (out.startsWith("/")) {
            out = out.substring(1);
        }
        while (out.endsWith("/")) {
            out = out.substring(0, out.length() - 1);
        }
        return out;
    }
}
