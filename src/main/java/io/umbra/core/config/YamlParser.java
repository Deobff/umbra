package io.umbra.core.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Small YAML subset parser used by Umbra's configuration loader.
 *
 * <p>Supported constructs: nested mappings by indentation, block sequences
 * ({@code - item}), inline sequences ({@code [a, b]}), quoted and unquoted
 * scalars, comments introduced by {@code #}, booleans, integers, longs and
 * {@code null}. Anchors, aliases, multi-document streams and block scalars are
 * intentionally not supported.</p>
 */
public final class YamlParser {

    private YamlParser() {
    }

    /**
     * Parses a YAML document into nested {@link Map} / {@link List} / scalar
     * values.
     *
     * @param text YAML source
     * @return root mapping
     * @throws ConfigException if the document is malformed
     */
    public static Map<String, Object> parse(String text) throws ConfigException {
        if (text == null) {
            text = "";
        }
        // A UTF-8 BOM left by Windows editors would otherwise become part of
        // the first key. ConfigLoader also strips it, but this parser is a
        // public entry point (license files, plugins), so handle it here too.
        if (!text.isEmpty() && text.charAt(0) == '\uFEFF') {
            text = text.substring(1);
        }
        List<Line> lines = new ArrayList<Line>();
        String[] raw = text.replace("\r\n", "\n").replace('\r', '\n').split("\n");
        for (int i = 0; i < raw.length; i++) {
            String stripped = stripComment(raw[i]);
            if (stripped.trim().isEmpty()) {
                continue;
            }
            // A tab counts as four columns for indentation comparisons, but it
            // is still a single character: track the character offset
            // separately so the content is not chopped when tabs are used.
            int indent = 0;
            int offset = 0;
            while (offset < stripped.length()) {
                char c = stripped.charAt(offset);
                if (c == ' ') {
                    indent++;
                    offset++;
                } else if (c == '\t') {
                    indent += 4;
                    offset++;
                } else {
                    break;
                }
            }
            String content = stripped.substring(offset).trim();
            if (content.isEmpty()) {
                continue;
            }
            lines.add(new Line(indent, content, i + 1));
        }
        if (lines.isEmpty()) {
            return new LinkedHashMap<String, Object>();
        }
        int[] index = new int[]{0};
        Object root = parseBlock(lines, index, lines.get(0).indent);
        if (!(root instanceof Map)) {
            throw new ConfigException("Configuration root must be a mapping");
        }
        if (index[0] != lines.size()) {
            Line extra = lines.get(index[0]);
            throw new ConfigException("Unexpected indentation at line " + extra.number + ": " + extra.content);
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) root;
        return result;
    }

    private static Object parseBlock(List<Line> lines, int[] index, int indent) throws ConfigException {
        if (index[0] >= lines.size()) {
            return new LinkedHashMap<String, Object>();
        }
        Line first = lines.get(index[0]);
        if (first.indent < indent) {
            return new LinkedHashMap<String, Object>();
        }
        if (first.content.startsWith("-")) {
            return parseList(lines, index, indent);
        }
        return parseMap(lines, index, indent);
    }

    private static Map<String, Object> parseMap(List<Line> lines, int[] index, int indent) throws ConfigException {
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        while (index[0] < lines.size()) {
            Line line = lines.get(index[0]);
            if (line.indent < indent) {
                break;
            }
            if (line.indent > indent) {
                throw new ConfigException("Unexpected indentation at line " + line.number + ": " + line.content);
            }
            if (line.content.startsWith("-")) {
                break;
            }
            int colon = findColon(line.content);
            if (colon < 0) {
                throw new ConfigException("Expected 'key: value' at line " + line.number + ": " + line.content);
            }
            String key = unquote(line.content.substring(0, colon).trim());
            if (key.isEmpty()) {
                throw new ConfigException("Empty key at line " + line.number);
            }
            String rest = line.content.substring(colon + 1).trim();
            index[0]++;
            if (rest.isEmpty()) {
                if (index[0] < lines.size()) {
                    Line next = lines.get(index[0]);
                    // Accept both indented and compact sequences:
                    //   key:\n  - a        and        key:\n- a
                    if (next.indent > indent || (next.indent == indent && next.content.startsWith("-"))) {
                        map.put(key, parseBlock(lines, index, next.indent));
                    } else {
                        map.put(key, "");
                    }
                } else {
                    map.put(key, "");
                }
            } else {
                map.put(key, scalar(rest, line.number));
            }
        }
        return map;
    }

    private static List<Object> parseList(List<Line> lines, int[] index, int indent) throws ConfigException {
        List<Object> list = new ArrayList<Object>();
        while (index[0] < lines.size()) {
            Line line = lines.get(index[0]);
            if (line.indent < indent || !line.content.startsWith("-")) {
                break;
            }
            if (line.indent > indent) {
                throw new ConfigException("Unexpected indentation at line " + line.number + ": " + line.content);
            }
            String rest = line.content.substring(1).trim();
            index[0]++;
            if (rest.isEmpty()) {
                if (index[0] < lines.size() && lines.get(index[0]).indent > indent) {
                    list.add(parseBlock(lines, index, lines.get(index[0]).indent));
                } else {
                    list.add("");
                }
                continue;
            }
            int colon = findColon(rest);
            if (colon > 0 && !rest.startsWith("[")) {
                Map<String, Object> item = new LinkedHashMap<String, Object>();
                String key = unquote(rest.substring(0, colon).trim());
                String value = rest.substring(colon + 1).trim();
                if (value.isEmpty()) {
                    if (index[0] < lines.size() && lines.get(index[0]).indent > indent) {
                        item.put(key, parseBlock(lines, index, lines.get(index[0]).indent));
                    } else {
                        item.put(key, "");
                    }
                } else {
                    item.put(key, scalar(value, line.number));
                }
                if (index[0] < lines.size() && lines.get(index[0]).indent > indent) {
                    Map<String, Object> more = parseMap(lines, index, lines.get(index[0]).indent);
                    item.putAll(more);
                }
                list.add(item);
            } else {
                list.add(scalar(rest, line.number));
            }
        }
        return list;
    }

    private static int findColon(String content) {
        boolean single = false;
        boolean dbl = false;
        for (int i = 0; i < content.length(); i++) {
            char c = content.charAt(i);
            if (c == '\'' && !dbl) {
                single = !single;
            } else if (c == '"' && !single) {
                dbl = !dbl;
            } else if (c == ':' && !single && !dbl) {
                if (i + 1 == content.length() || Character.isWhitespace(content.charAt(i + 1))) {
                    return i;
                }
            }
        }
        return -1;
    }

    private static Object scalar(String text, int line) throws ConfigException {
        String value = text.trim();
        if (value.isEmpty()) {
            return "";
        }
        if (value.startsWith("[") && value.endsWith("]")) {
            List<Object> items = new ArrayList<Object>();
            String inner = value.substring(1, value.length() - 1).trim();
            if (!inner.isEmpty()) {
                for (String part : splitInline(inner)) {
                    items.add(scalar(part, line));
                }
            }
            return items;
        }
        if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
            return unquote(value);
        }
        if ("true".equalsIgnoreCase(value)) {
            return Boolean.TRUE;
        }
        if ("false".equalsIgnoreCase(value)) {
            return Boolean.FALSE;
        }
        if ("null".equalsIgnoreCase(value) || "~".equals(value)) {
            return null;
        }
        try {
            if (value.endsWith("L") || value.endsWith("l")) {
                return Long.parseLong(value.substring(0, value.length() - 1));
            }
            if (value.indexOf('.') >= 0 || value.indexOf('e') >= 0 || value.indexOf('E') >= 0) {
                return Double.parseDouble(value);
            }
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return value;
        }
    }

    private static List<String> splitInline(String inner) {
        List<String> parts = new ArrayList<String>();
        StringBuilder current = new StringBuilder();
        boolean single = false;
        boolean dbl = false;
        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);
            if (c == '\'' && !dbl) {
                single = !single;
            } else if (c == '"' && !single) {
                dbl = !dbl;
            }
            if (c == ',' && !single && !dbl) {
                parts.add(current.toString().trim());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) {
            parts.add(current.toString().trim());
        }
        return parts;
    }

    private static String unquote(String value) {
        if (value.length() >= 2) {
            char first = value.charAt(0);
            char last = value.charAt(value.length() - 1);
            if (first == '"' && last == '"') {
                return unescape(value.substring(1, value.length() - 1));
            }
            if (first == '\'' && last == '\'') {
                // YAML single-quoted scalars are literal: the only escape is
                // '' for a single quote, backslashes are kept as-is (so a
                // Windows path such as 'C:\new\file' is not mangled).
                return value.substring(1, value.length() - 1).replace("''", "'");
            }
        }
        return value;
    }

    private static String unescape(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\\' || i + 1 >= value.length()) {
                out.append(c);
                continue;
            }
            char n = value.charAt(++i);
            switch (n) {
                case 'n': out.append('\n'); break;
                case 't': out.append('\t'); break;
                case 'r': out.append('\r'); break;
                case '"': out.append('"'); break;
                case '\'': out.append('\''); break;
                case '\\': out.append('\\'); break;
                default: out.append(n);
            }
        }
        return out.toString();
    }

    private static String stripComment(String line) {
        boolean single = false;
        boolean dbl = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '\'' && !dbl) {
                single = !single;
            } else if (c == '"' && !single) {
                dbl = !dbl;
            } else if (c == '#' && !single && !dbl) {
                if (i == 0 || Character.isWhitespace(line.charAt(i - 1))) {
                    return line.substring(0, i);
                }
            }
        }
        return line;
    }

    private static final class Line {
        final int indent;
        final String content;
        final int number;

        Line(int indent, String content, int number) {
            this.indent = indent;
            this.content = content;
            this.number = number;
        }
    }
}
