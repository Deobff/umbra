package io.umbra.core.compat;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Rewrites class names in a JAR manifest while keeping unrelated attributes and
 * per-entry sections intact.
 *
 * <p>Covered attributes:</p>
 *
 * <ul>
 *   <li>class attributes: {@code Main-Class}, {@code Start-Class},
 *       {@code Premain-Class}, {@code Agent-Class}, {@code Launcher-Agent-Class},
 *       {@code Bundle-Activator}, {@code Rsrc-Main-Class};</li>
 *   <li>OSGi package headers: {@code Export-Package}, {@code Import-Package},
 *       {@code Private-Package}, {@code DynamicImport-Package};</li>
 *   <li>capability headers ({@code Provide-Capability}, {@code Require-Capability});</li>
 *   <li>JPMS agent options: {@code Add-Exports}, {@code Add-Opens};</li>
 *   <li>{@code Multi-Release} for preserve/flatten mode;</li>
 *   <li>signature metadata is always removed (output is unsigned).</li>
 * </ul>
 *
 * <p>{@code Class-Path}, {@code Automatic-Module-Name} and
 * {@code Bundle-ClassPath} do not contain binary class names, so they are left
 * untouched (all referenced entries keep their names).</p>
 */
public final class ManifestRewriter {

    /** Manifest entry name. */
    public static final String MANIFEST_ENTRY = "META-INF/MANIFEST.MF";

    private static final String[] CLASS_ATTRIBUTES = {
            "Main-Class", "Start-Class", "Premain-Class", "Agent-Class",
            "Launcher-Agent-Class", "Bundle-Activator", "Rsrc-Main-Class"
    };

    private static final String[] PACKAGE_HEADERS = {
            "Export-Package", "Import-Package", "Private-Package", "DynamicImport-Package"
    };

    private static final String[] CAPABILITY_HEADERS = {
            "Provide-Capability", "Require-Capability"
    };

    private static final String[] PACKAGE_LIST_HEADERS = {
            "Add-Exports", "Add-Opens"
    };

    private ManifestRewriter() {
    }

    /** Result of one manifest rewrite; {@code bytes} are the original array when unchanged. */
    public static final class Result {
        private final byte[] bytes;
        private final boolean changed;
        private final int attributesRewritten;
        private final List<String> warnings;

        Result(byte[] bytes, boolean changed, int attributesRewritten, List<String> warnings) {
            this.bytes = bytes;
            this.changed = changed;
            this.attributesRewritten = attributesRewritten;
            this.warnings = warnings;
        }

        public byte[] bytes() {
            return bytes;
        }

        public boolean changed() {
            return changed;
        }

        /** Number of manifest attributes added, removed or rewritten. */
        public int attributesRewritten() {
            return attributesRewritten;
        }

        public List<String> warnings() {
            return warnings;
        }
    }

    /**
     * Rewrites the manifest if a mapping or layout decision requires it.
     *
     * @param manifestBytes       raw manifest bytes (may be {@code null})
     * @param rename              class/member mapping
     * @param preserveMultiRelease true when {@code META-INF/versions} is preserved
     * @param versionedEntries    true when versioned entries remain in the archive
     * @return rewrite result; the input bytes when nothing changed
     */
    public static Result rewrite(byte[] manifestBytes, ClassRenameMap rename,
                                 boolean preserveMultiRelease, boolean versionedEntries) {
        List<String> warnings = new ArrayList<String>();
        if (manifestBytes == null || manifestBytes.length == 0) {
            return new Result(manifestBytes, false, 0, warnings);
        }
        Parsed parsed = parse(manifestBytes);
        if (parsed == null) {
            warnings.add("manifest could not be interpreted; left unchanged");
            return new Result(manifestBytes, false, 0, warnings);
        }
        int rewritten = 0;

        // 1. Class attributes.
        if (rename != null && !rename.isEmpty()) {
            for (String attribute : CLASS_ATTRIBUTES) {
                String value = parsed.main.get(attribute);
                if (value == null) {
                    continue;
                }
                String mapped = rename.mapDotted(value.trim());
                if (!mapped.equals(value.trim())) {
                    parsed.main.put(attribute, mapped);
                    rewritten++;
                }
            }
        }

        // 2. OSGi package headers.
        if (rename != null && !rename.isEmpty()) {
            for (String header : PACKAGE_HEADERS) {
                String value = parsed.main.get(header);
                if (value == null) {
                    continue;
                }
                String mapped = rewritePackageHeader(value, rename);
                if (!mapped.equals(value)) {
                    parsed.main.put(header, mapped);
                    rewritten++;
                }
            }
            for (String header : CAPABILITY_HEADERS) {
                String value = parsed.main.get(header);
                if (value == null) {
                    continue;
                }
                String mapped = rewriteCapabilityHeader(value, rename);
                if (!mapped.equals(value)) {
                    parsed.main.put(header, mapped);
                    rewritten++;
                }
            }
            for (String header : PACKAGE_LIST_HEADERS) {
                String value = parsed.main.get(header);
                if (value == null) {
                    continue;
                }
                String mapped = rewritePackageListHeader(value, rename);
                if (!mapped.equals(value)) {
                    parsed.main.put(header, mapped);
                    rewritten++;
                }
            }
        }

        // 3. Signature metadata must never survive a rewrite.
        List<String> signatureKeys = new ArrayList<String>();
        for (String key : parsed.main.keySet()) {
            if (isSignatureKey(key)) {
                signatureKeys.add(key);
            }
        }
        for (String key : signatureKeys) {
            parsed.main.remove(key);
            rewritten++;
        }
        List<Section> emptySections = new ArrayList<Section>();
        for (Section section : parsed.sections) {
            List<String> digestKeys = new ArrayList<String>();
            for (String key : section.attributes.keySet()) {
                if (isSignatureKey(key)) {
                    digestKeys.add(key);
                }
            }
            for (String key : digestKeys) {
                section.attributes.remove(key);
                rewritten++;
            }
            if (section.attributes.isEmpty() && section.name != null && !section.name.isEmpty()) {
                emptySections.add(section);
            }
        }
        if (!emptySections.isEmpty()) {
            parsed.sections.removeAll(emptySections);
            rewritten += emptySections.size();
        }

        // 4. Multi-Release attribute follows the layout decision.
        String multiRelease = parsed.main.get("Multi-Release");
        if (!preserveMultiRelease) {
            if (multiRelease != null) {
                parsed.main.remove("Multi-Release");
                rewritten++;
            }
        } else if (versionedEntries && !"true".equalsIgnoreCase(multiRelease == null ? "" : multiRelease.trim())) {
            parsed.main.put("Multi-Release", "true");
            rewritten++;
        }

        if (rewritten == 0 && !parsed.dirty) {
            return new Result(manifestBytes, false, 0, warnings);
        }
        if (parsed.dirty && rewritten == 0) {
            warnings.add("malformed manifest lines removed while keeping the archive valid");
        }
        if (!parsed.main.containsKey("Manifest-Version")) {
            Map<String, String> updated = new LinkedHashMap<String, String>();
            updated.put("Manifest-Version", "1.0");
            updated.putAll(parsed.main);
            parsed.main = updated;
        }
        return new Result(serialize(parsed), true, rewritten, warnings);
    }

    /** Parses only the main attributes; used by inspection and detection code. */
    public static Map<String, String> parseMainAttributes(byte[] manifestBytes) {
        Parsed parsed = parse(manifestBytes);
        if (parsed == null) {
            return new LinkedHashMap<String, String>();
        }
        return parsed.main;
    }

    private static boolean isSignatureKey(String key) {
        String lower = key.toLowerCase(Locale.ROOT);
        return "signature-version".equals(lower) || "magic".equals(lower)
                || lower.endsWith("-digest") || lower.contains("-digest-");
    }

    // ------------------------------------------------------------------
    // Header rewriting
    // ------------------------------------------------------------------

    private static String rewritePackageHeader(String value, ClassRenameMap rename) {
        List<String> segments = splitTopLevel(value, ',');
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < segments.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            String segment = segments.get(i);
            int semi = segment.indexOf(';');
            String head = semi < 0 ? segment : segment.substring(0, semi);
            String rest = semi < 0 ? "" : segment.substring(semi);
            String leading = leadingWhitespace(head);
            String packageName = head.trim();
            if (packageName.isEmpty()) {
                out.append(segment);
                continue;
            }
            String mapped = rename.mapPackageDotted(packageName);
            out.append(leading).append(mapped)
                    .append(rest.isEmpty() ? rest : rewriteQuotedLists(rest, rename));
        }
        return out.toString();
    }

    private static String rewriteCapabilityHeader(String value, ClassRenameMap rename) {
        // Capability headers contain class names and package names in quoted lists.
        return rewriteQuotedLists(rename.rewriteDottedNames(value), rename);
    }

    private static String rewritePackageListHeader(String value, ClassRenameMap rename) {
        List<String> segments = splitTopLevel(value, ',');
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < segments.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            String segment = segments.get(i);
            String leading = leadingWhitespace(segment);
            String trailing = trailingWhitespace(segment);
            String token = segment.trim();
            int slash = token.indexOf('/');
            if (slash > 0) {
                String module = token.substring(0, slash);
                String packageName = token.substring(slash + 1);
                out.append(leading).append(module).append('/')
                        .append(rename.mapPackageDotted(packageName)).append(trailing);
            } else if (!token.isEmpty()) {
                out.append(leading).append(rename.mapPackageDotted(token)).append(trailing);
            } else {
                out.append(segment);
            }
        }
        return out.toString();
    }

    /** Rewrites comma-separated package/class lists inside double-quoted directives. */
    private static String rewriteQuotedLists(String text, ClassRenameMap rename) {
        StringBuilder out = new StringBuilder(text.length() + 16);
        int index = 0;
        int length = text.length();
        while (index < length) {
            int quote = text.indexOf('"', index);
            if (quote < 0) {
                out.append(text, index, length);
                break;
            }
            out.append(text, index, quote + 1);
            int close = quote + 1;
            while (close < length && text.charAt(close) != '"') {
                if (text.charAt(close) == '\\') {
                    close++;
                }
                close++;
            }
            if (close >= length) {
                out.append(text, quote + 1, length);
                break;
            }
            String content = text.substring(quote + 1, close);
            out.append(rewriteCommaList(content, rename)).append('"');
            index = close + 1;
        }
        return out.toString();
    }

    private static String rewriteCommaList(String content, ClassRenameMap rename) {
        List<String> tokens = splitTopLevel(content, ',');
        StringBuilder out = new StringBuilder(content.length() + 8);
        for (int i = 0; i < tokens.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            String token = tokens.get(i);
            String leading = leadingWhitespace(token);
            String trailing = trailingWhitespace(token);
            String core = token.trim();
            if (core.isEmpty()) {
                out.append(token);
                continue;
            }
            String mapped = rename.mapPackageDotted(core);
            if (mapped.equals(core)) {
                mapped = rename.rewriteDottedNames(core);
            }
            out.append(leading).append(mapped).append(trailing);
        }
        return out.toString();
    }

    private static List<String> splitTopLevel(String value, char separator) {
        List<String> parts = new ArrayList<String>();
        boolean quoted = false;
        int start = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"') {
                quoted = !quoted;
            } else if (c == '\\' && quoted && i + 1 < value.length()) {
                i++;
            } else if (c == separator && !quoted) {
                parts.add(value.substring(start, i));
                start = i + 1;
            }
        }
        parts.add(value.substring(start));
        return parts;
    }

    // ------------------------------------------------------------------
    // Manifest text parsing/serialization (sections preserved)
    // ------------------------------------------------------------------

    private static final class Section {
        final String name;
        final Map<String, String> attributes = new LinkedHashMap<String, String>();

        Section(String name) {
            this.name = name;
        }
    }

    private static final class Parsed {
        Map<String, String> main = new LinkedHashMap<String, String>();
        final List<Section> sections = new ArrayList<Section>();
        /** True when the input had to be sanitized (invalid lines/labels dropped). */
        boolean dirty;
    }

    private static Parsed parse(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        Parsed parsed = new Parsed();
        String text = new String(bytes, StandardCharsets.UTF_8);
        if (!text.isEmpty() && text.charAt(0) == '\uFEFF') {
            // UTF-8 BOM before the first header is not part of the JAR manifest
            // spec and makes java.util.jar.Manifest reject the file.
            text = text.substring(1);
            parsed.dirty = true;
        }
        text = text.replace("\r\n", "\n").replace('\r', '\n');
        String[] lines = text.split("\n", -1);
        Map<String, String> current = parsed.main;
        Section section = null;
        String key = null;
        StringBuilder value = null;
        for (String line : lines) {
            if (line.isEmpty()) {
                flush(current, key, value);
                key = null;
                value = null;
                // A blank line terminates the current section; the next header
                // must start a new section (or be the trailing empty line).
                current = null;
                continue;
            }
            if (line.charAt(0) == ' ') {
                if (key != null && value != null) {
                    value.append(line.substring(1));
                } else {
                    // Continuation line without a preceding header.
                    parsed.dirty = true;
                }
                continue;
            }
            flush(current, key, value);
            key = null;
            value = null;
            int colon = line.indexOf(':');
            if (colon < 0) {
                // Not a header line; keeping it would make the manifest invalid.
                parsed.dirty = true;
                continue;
            }
            String attribute = line.substring(0, colon).trim();
            String attributeValue = line.substring(colon + 1).trim();
            if (attribute.isEmpty()) {
                parsed.dirty = true;
                continue;
            }
            if (current == null) {
                if ("name".equalsIgnoreCase(attribute)) {
                    section = new Section(attributeValue);
                    parsed.sections.add(section);
                    current = section.attributes;
                } else {
                    section = new Section("");
                    parsed.sections.add(section);
                    current = section.attributes;
                    parsed.dirty = true;
                    key = attribute;
                    value = new StringBuilder(attributeValue);
                }
                continue;
            }
            key = attribute;
            value = new StringBuilder(attributeValue);
        }
        flush(current, key, value);
        return parsed;
    }

    private static void flush(Map<String, String> target, String key, StringBuilder value) {
        if (target != null && key != null) {
            target.put(key, value == null ? "" : value.toString());
        }
    }

    private static byte[] serialize(Parsed parsed) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
        for (Map.Entry<String, String> entry : parsed.main.entrySet()) {
            writeAttribute(out, entry.getKey(), entry.getValue());
        }
        out.write('\r');
        out.write('\n');
        for (Section section : parsed.sections) {
            if (section.name != null && !section.name.isEmpty()) {
                writeAttribute(out, "Name", section.name);
            }
            for (Map.Entry<String, String> entry : section.attributes.entrySet()) {
                writeAttribute(out, entry.getKey(), entry.getValue());
            }
            out.write('\r');
            out.write('\n');
        }
        return out.toByteArray();
    }

    /**
     * Writes one manifest attribute with 72-byte-safe UTF-8 continuation lines
     * (never splits a multi-byte character).
     */
    static void writeAttribute(ByteArrayOutputStream out, String name, String value) {
        byte[] bytes = (name + ": " + value).getBytes(StandardCharsets.UTF_8);
        int position = 0;
        boolean first = true;
        while (true) {
            int capacity = first ? 70 : 69;
            int remaining = bytes.length - position;
            if (remaining <= capacity) {
                if (!first) {
                    out.write(' ');
                }
                out.write(bytes, position, remaining);
                out.write('\r');
                out.write('\n');
                return;
            }
            int cut = position + capacity;
            while (cut > position && (bytes[cut] & 0xC0) == 0x80) {
                cut--;
            }
            if (cut == position) {
                cut = position + capacity;
            }
            if (!first) {
                out.write(' ');
            }
            out.write(bytes, position, cut - position);
            out.write('\r');
            out.write('\n');
            position = cut;
            first = false;
        }
    }

    private static String leadingWhitespace(String value) {
        int i = 0;
        while (i < value.length() && Character.isWhitespace(value.charAt(i))) {
            i++;
        }
        return value.substring(0, i);
    }

    private static String trailingWhitespace(String value) {
        int i = value.length();
        while (i > 0 && Character.isWhitespace(value.charAt(i - 1))) {
            i--;
        }
        return value.substring(i);
    }
}
