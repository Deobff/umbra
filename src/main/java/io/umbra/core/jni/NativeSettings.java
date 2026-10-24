package io.umbra.core.jni;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.rules.Glob;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Parsed {@code native.*} options plus the method eligibility filter.
 *
 * <p>Filter entries are glob lists separated by commas, semicolons or
 * whitespace. An entry may be {@code Class}, {@code Class#method} or
 * {@code Class#method#descriptor}; {@code *} matches everything. Class globs use
 * the same syntax as keep rules ({@code **}, {@code *}, {@code ?}) and are
 * matched against the current (possibly renamed) class name as well as the
 * original name recorded by the renamer, so filters written against source names
 * keep working.</p>
 */
public final class NativeSettings {

    private final int maxInstructions;
    private final int maxMethodsPerClass;
    private final String compiler;
    private final String compilerFlags;
    private final String target;
    private final String arch;
    private final boolean atomic;
    private final boolean keepDll;
    private final boolean antiDump;
    private final boolean antiBackfill;
    private final boolean constructors;
    private final boolean indy;
    private final List<Entry> include = new ArrayList<Entry>();
    private final List<Entry> exclude = new ArrayList<Entry>();

    private NativeSettings(UmbraConfig config) {
        this.maxInstructions = Math.max(1, config.optionInt("native.maxInstructions", 800));
        this.maxMethodsPerClass = Math.max(0, config.optionInt("native.maxMethodsPerClass", 0));
        this.compiler = config.option("native.compiler", "");
        this.compilerFlags = config.option("native.compilerFlags", "");
        this.target = config.option("native.target", "windows").trim();
        this.arch = config.option("native.arch", "auto").trim();
        this.atomic = config.optionBool("native.atomic", true);
        this.keepDll = config.optionBool("native.keepDll", false);
        this.antiDump = config.optionBool("native.antiDump", true);
        this.antiBackfill = config.optionBool("native.antiBackfill", true);
        this.constructors = config.optionBool("native.constructors", true);
        this.indy = config.optionBool("native.indy", true);
        String includeList = config.option("native.methods", "**");
        String excludeList = config.option("native.exclude", "");
        for (String text : splitList(includeList)) {
            include.add(new Entry(text));
        }
        for (String text : splitList(excludeList)) {
            exclude.add(new Entry(text));
        }
        if (include.isEmpty()) {
            include.add(new Entry("**"));
        }
    }

    public static NativeSettings from(UmbraConfig config) {
        return new NativeSettings(config);
    }

    public int maxInstructions() { return maxInstructions; }
    public int maxMethodsPerClass() { return maxMethodsPerClass; }
    public String compiler() { return compiler; }
    public String compilerFlags() { return compilerFlags; }
    public String target() { return target; }
    public String arch() { return arch; }
    public boolean atomic() { return atomic; }
    public boolean keepDll() { return keepDll; }
    /** Verify the embedded library fingerprint and native backfill table before use. */
    public boolean antiDump() { return antiDump; }
    /** Emit/verify the native method backfill table and keyed challenge. */
    public boolean antiBackfill() { return antiBackfill; }
    /** Extract constructor bodies after super()/this() into translatable helpers. */
    public boolean constructors() { return constructors; }
    /** Bridge invokedynamic (lambdas, string concat) through Java helper methods. */
    public boolean indy() { return indy; }

    /** True when the method passes {@code native.methods}/{@code native.exclude}. */
    public boolean accepts(String owner, String originalOwner, String name, String descriptor) {
        boolean included = false;
        for (Entry entry : include) {
            if (entry.matches(owner, originalOwner, name, descriptor)) {
                included = true;
                break;
            }
        }
        if (!included) {
            return false;
        }
        for (Entry entry : exclude) {
            if (entry.matches(owner, originalOwner, name, descriptor)) {
                return false;
            }
        }
        return true;
    }

    public static String originalOwner(MappingSet mappings, String current) {
        if (mappings == null) {
            return current;
        }
        Map<String, String> reverse = mappings.reverseClasses();
        String original = reverse.get(current);
        return original == null ? current : original;
    }

    private static List<String> splitList(String value) {
        List<String> result = new ArrayList<String>();
        if (value == null) {
            return result;
        }
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ',' || c == ';' || Character.isWhitespace(c)) {
                if (current.length() > 0) {
                    result.add(current.toString());
                    current.setLength(0);
                }
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) {
            result.add(current.toString());
        }
        return result;
    }

    private static final class Entry {
        private final Glob classGlob;
        private final String methodPattern;
        private final String descriptorPattern;

        Entry(String text) {
            String value = text.trim();
            int first = value.indexOf('#');
            String classPart;
            String methodPart = null;
            String descPart = null;
            if (first < 0) {
                classPart = value;
            } else {
                classPart = value.substring(0, first);
                String rest = value.substring(first + 1);
                int second = rest.indexOf('#');
                if (second < 0) {
                    methodPart = rest;
                } else {
                    methodPart = rest.substring(0, second);
                    descPart = rest.substring(second + 1);
                }
            }
            if (classPart.isEmpty()) {
                classPart = "*";
            }
            if (methodPart == null || methodPart.isEmpty()) {
                methodPart = "*";
            }
            this.classGlob = new Glob(classPart.replace('.', '/'));
            this.methodPattern = methodPart;
            this.descriptorPattern = descPart == null || descPart.isEmpty() ? null : descPart;
        }

        boolean matches(String owner, String originalOwner, String name, String descriptor) {
            if (!classGlob.matches(owner) && !classGlob.matches(originalOwner)) {
                return false;
            }
            if (!wildcard(methodPattern, name)) {
                return false;
            }
            return descriptorPattern == null || "*".equals(descriptorPattern)
                    || descriptorPattern.equals(descriptor);
        }
    }

    /** Simple glob match: {@code *} any sequence, {@code ?} one character. */
    public static boolean wildcard(String pattern, String value) {
        int p = 0;
        int v = 0;
        int star = -1;
        int mark = 0;
        while (v < value.length()) {
            if (p < pattern.length() && (pattern.charAt(p) == '?' || pattern.charAt(p) == value.charAt(v))) {
                p++;
                v++;
            } else if (p < pattern.length() && pattern.charAt(p) == '*') {
                star = p++;
                mark = v;
            } else if (star >= 0) {
                p = star + 1;
                v = ++mark;
            } else {
                return false;
            }
        }
        while (p < pattern.length() && pattern.charAt(p) == '*') {
            p++;
        }
        return p == pattern.length();
    }

    @Override
    public String toString() {
        return "maxInstructions=" + maxInstructions
                + ", maxMethodsPerClass=" + maxMethodsPerClass
                + ", compiler=" + (compiler.isEmpty() ? "auto" : compiler)
                + ", target=" + target.toLowerCase(Locale.ROOT)
                + ", arch=" + arch
                + ", atomic=" + atomic
                + ", antiDump=" + antiDump
                + ", antiBackfill=" + antiBackfill
                + ", constructors=" + constructors
                + ", indy=" + indy;
    }
}
