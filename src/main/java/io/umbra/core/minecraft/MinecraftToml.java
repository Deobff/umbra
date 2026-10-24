package io.umbra.core.minecraft;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal TOML reader for Forge/NeoForge {@code mods.toml} metadata.
 *
 * <p>Supports what mod metadata actually contains: tables ({@code [table]}),
 * arrays of tables ({@code [[mods]]}), dotted table names, basic/literal
 * strings (single- and multi-line), integers/floats/booleans and arrays. It is
 * intentionally not a complete TOML implementation; malformed input raises
 * {@link IllegalArgumentException} and the caller falls back to a partial,
 * line-based extraction.</p>
 */
final class MinecraftToml {

    private MinecraftToml() {
    }

    /** Parses a TOML document into nested maps/lists/scalars. */
    static Map<String, Object> parse(String text) {
        Map<String, Object> root = new LinkedHashMap<String, Object>();
        if (text == null || text.isEmpty()) {
            return root;
        }
        String[] lines = text.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        StringBuilder pending = null;
        Map<String, Object> current = root;
        for (int i = 0; i < lines.length; i++) {
            String line = stripComment(lines[i]).trim();
            if (pending != null) {
                if (!line.isEmpty()) {
                    pending.append(' ').append(line);
                }
                if (isComplete(pending.toString())) {
                    String statement = pending.toString();
                    pending = null;
                    current = statement(root, current, statement);
                }
                continue;
            }
            if (line.isEmpty()) {
                continue;
            }
            if (line.charAt(0) == '[' && line.length() > 2) {
                current = header(root, current, line);
                continue;
            }
            if (!isComplete(line)) {
                pending = new StringBuilder(line);
                continue;
            }
            current = statement(root, current, line);
        }
        if (pending != null) {
            throw new IllegalArgumentException("unterminated TOML value");
        }
        return root;
    }

    private static Map<String, Object> header(Map<String, Object> root, Map<String, Object> current,
                                              String line) {
        boolean array = line.startsWith("[[");
        String inner;
        if (array) {
            if (!line.endsWith("]]")) {
                throw new IllegalArgumentException("malformed array-of-tables header: " + line);
            }
            inner = line.substring(2, line.length() - 2);
        } else {
            if (!line.endsWith("]")) {
                throw new IllegalArgumentException("malformed table header: " + line);
            }
            inner = line.substring(1, line.length() - 1);
        }
        String[] parts = splitPath(inner);
        if (parts.length == 0) {
            return root;
        }
        Map<String, Object> container = root;
        for (int i = 0; i < parts.length - 1; i++) {
            container = childTable(container, parts[i]);
        }
        String leaf = parts[parts.length - 1];
        if (array) {
            Object existing = container.get(leaf);
            List<Object> list;
            if (existing instanceof List) {
                @SuppressWarnings("unchecked")
                List<Object> cast = (List<Object>) existing;
                list = cast;
            } else {
                list = new ArrayList<Object>();
                container.put(leaf, list);
            }
            Map<String, Object> child = new LinkedHashMap<String, Object>();
            list.add(child);
            return child;
        }
        Object existing = container.get(leaf);
        Map<String, Object> child;
        if (existing instanceof Map) {
            child = MinecraftJson.asMap(existing);
        } else {
            child = new LinkedHashMap<String, Object>();
            container.put(leaf, child);
        }
        return child;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> childTable(Map<String, Object> container, String key) {
        Object existing = container.get(key);
        if (existing instanceof Map) {
            return (Map<String, Object>) existing;
        }
        if (existing instanceof List) {
            List<Object> list = (List<Object>) existing;
            if (!list.isEmpty()) {
                Map<String, Object> last = MinecraftJson.asMap(list.get(list.size() - 1));
                if (last != null) {
                    return last;
                }
            }
        }
        Map<String, Object> child = new LinkedHashMap<String, Object>();
        container.put(key, child);
        return child;
    }

    private static Map<String, Object> statement(Map<String, Object> root, Map<String, Object> current,
                                                 String line) {
        int equals = indexOfAssignment(line);
        if (equals < 0) {
            // Be forgiving: unknown TOML constructs are skipped, not fatal.
            return current;
        }
        String key = line.substring(0, equals).trim();
        String rawValue = line.substring(equals + 1).trim();
        if (key.isEmpty()) {
            return current;
        }
        key = unquote(key);
        if (rawValue.isEmpty()) {
            current.put(key, "");
            return current;
        }
        current.put(key, value(rawValue));
        return current;
    }

    private static Object value(String raw) {
        if (raw.isEmpty()) {
            return "";
        }
        char first = raw.charAt(0);
        if (first == '"' || first == '\'') {
            return string(raw);
        }
        if (first == '[') {
            List<Object> list = new ArrayList<Object>();
            String inner = stripOuter(raw, '[', ']');
            for (String part : splitTopLevel(inner, ',')) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    list.add(value(trimmed));
                }
            }
            return list;
        }
        if (first == '{') {
            Map<String, Object> table = new LinkedHashMap<String, Object>();
            String inner = stripOuter(raw, '{', '}');
            for (String part : splitTopLevel(inner, ',')) {
                String trimmed = part.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                int equals = indexOfAssignment(trimmed);
                if (equals < 0) {
                    continue;
                }
                String key = unquote(trimmed.substring(0, equals).trim());
                Object entry = value(trimmed.substring(equals + 1).trim());
                table.put(key, entry);
            }
            return table;
        }
        String lower = raw.toLowerCase(java.util.Locale.ROOT);
        if ("true".equals(lower)) {
            return Boolean.TRUE;
        }
        if ("false".equals(lower)) {
            return Boolean.FALSE;
        }
        String numeric = raw.replace("_", "");
        try {
            if (numeric.indexOf('.') < 0 && numeric.indexOf('e') < 0 && numeric.indexOf('E') < 0) {
                return Long.valueOf(numeric);
            }
            return Double.valueOf(numeric);
        } catch (NumberFormatException ignored) {
            return raw;
        }
    }

    private static String string(String raw) {
        if (raw.length() >= 6
                && ((raw.startsWith("\"\"\"") && raw.endsWith("\"\"\""))
                || (raw.startsWith("'''") && raw.endsWith("'''")))) {
            return raw.substring(3, raw.length() - 3);
        }
        String inner = stripOuterQuotes(raw);
        if (inner == null) {
            throw new IllegalArgumentException("unterminated TOML string");
        }
        if (raw.charAt(0) == '\'') {
            return inner;
        }
        return unescape(inner);
    }

    private static String stripOuterQuotes(String raw) {
        if (raw.length() < 2) {
            return null;
        }
        char quote = raw.charAt(0);
        if (quote != '"' && quote != '\'') {
            return null;
        }
        // Find the closing quote, respecting escapes in basic strings.
        for (int i = 1; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (quote == '"' && c == '\\') {
                i++;
                continue;
            }
            if (c == quote) {
                return raw.substring(1, i);
            }
        }
        return null;
    }

    private static String unescape(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\\' || i + 1 >= value.length()) {
                out.append(c);
                continue;
            }
            char escape = value.charAt(++i);
            switch (escape) {
                case 'n': out.append('\n'); break;
                case 't': out.append('\t'); break;
                case 'r': out.append('\r'); break;
                case '"': out.append('"'); break;
                case '\\': out.append('\\'); break;
                case 'b': out.append('\b'); break;
                case 'f': out.append('\f'); break;
                case 'u':
                    if (i + 4 < value.length()) {
                        try {
                            out.append((char) Integer.parseInt(value.substring(i + 1, i + 5), 16));
                            i += 4;
                        } catch (NumberFormatException ignored) {
                            out.append("\\u");
                        }
                    } else {
                        out.append("\\u");
                    }
                    break;
                default:
                    out.append(escape);
            }
        }
        return out.toString();
    }

    /** Removes a {@code #} comment that is outside quoted strings. */
    private static String stripComment(String line) {
        char quote = 0;
        boolean triple = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quote != 0) {
                if (!triple && c == '\\' && quote == '"') {
                    i++;
                    continue;
                }
                if (c == quote) {
                    if (triple) {
                        if (i + 2 < line.length() && line.charAt(i + 1) == quote
                                && line.charAt(i + 2) == quote) {
                            i += 2;
                            quote = 0;
                            triple = false;
                        }
                    } else {
                        quote = 0;
                    }
                }
                continue;
            }
            if (c == '"' || c == '\'') {
                if (i + 2 < line.length() && line.charAt(i + 1) == c && line.charAt(i + 2) == c) {
                    quote = c;
                    triple = true;
                    i += 2;
                } else {
                    quote = c;
                    triple = false;
                }
            } else if (c == '#') {
                return line.substring(0, i);
            }
        }
        return line;
    }

    /** True when all strings/brackets on the accumulated text are closed. */
    private static boolean isComplete(String text) {
        char quote = 0;
        boolean triple = false;
        int brackets = 0;
        int braces = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (quote != 0) {
                if (!triple && c == '\\' && quote == '"') {
                    i++;
                    continue;
                }
                if (c == quote) {
                    if (triple) {
                        if (i + 2 < text.length() && text.charAt(i + 1) == quote
                                && text.charAt(i + 2) == quote) {
                            i += 2;
                            quote = 0;
                            triple = false;
                        }
                    } else {
                        quote = 0;
                    }
                }
                continue;
            }
            if (c == '"' || c == '\'') {
                if (i + 2 < text.length() && text.charAt(i + 1) == c && text.charAt(i + 2) == c) {
                    quote = c;
                    triple = true;
                    i += 2;
                } else {
                    quote = c;
                    triple = false;
                }
            } else if (c == '[') {
                brackets++;
            } else if (c == ']') {
                brackets--;
            } else if (c == '{') {
                braces++;
            } else if (c == '}') {
                braces--;
            }
        }
        return quote == 0 && brackets <= 0 && braces <= 0;
    }

    private static int indexOfAssignment(String line) {
        char quote = 0;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quote != 0) {
                if (c == '\\' && quote == '"') {
                    i++;
                    continue;
                }
                if (c == quote) {
                    quote = 0;
                }
                continue;
            }
            if (c == '"' || c == '\'') {
                quote = c;
            } else if (c == '=') {
                return i;
            }
        }
        return -1;
    }

    private static String[] splitPath(String path) {
        List<String> parts = new ArrayList<String>();
        StringBuilder current = new StringBuilder();
        char quote = 0;
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (quote != 0) {
                if (c == quote) {
                    quote = 0;
                } else {
                    current.append(c);
                }
                continue;
            }
            if (c == '"' || c == '\'') {
                quote = c;
            } else if (c == '.') {
                parts.add(unquote(current.toString().trim()));
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        if (current.toString().trim().length() > 0) {
            parts.add(unquote(current.toString().trim()));
        }
        return parts.toArray(new String[parts.size()]);
    }

    private static List<String> splitTopLevel(String text, char separator) {
        List<String> parts = new ArrayList<String>();
        StringBuilder current = new StringBuilder();
        char quote = 0;
        int brackets = 0;
        int braces = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (quote != 0) {
                current.append(c);
                if (c == '\\' && quote == '"' && i + 1 < text.length()) {
                    current.append(text.charAt(++i));
                } else if (c == quote) {
                    quote = 0;
                }
                continue;
            }
            if (c == '"' || c == '\'') {
                quote = c;
                current.append(c);
            } else if (c == '[' || c == '{') {
                brackets += c == '[' ? 1 : 0;
                braces += c == '{' ? 1 : 0;
                current.append(c);
            } else if (c == ']') {
                brackets--;
                current.append(c);
            } else if (c == '}') {
                braces--;
                current.append(c);
            } else if (c == separator && brackets == 0 && braces == 0) {
                parts.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        parts.add(current.toString());
        return parts;
    }

    private static String stripOuter(String raw, char open, char close) {
        int start = raw.indexOf(open);
        int end = raw.lastIndexOf(close);
        if (start < 0 || end <= start) {
            return "";
        }
        return raw.substring(start + 1, end);
    }

    private static String unquote(String value) {
        String trimmed = value.trim();
        if (trimmed.length() >= 2) {
            char first = trimmed.charAt(0);
            char last = trimmed.charAt(trimmed.length() - 1);
            if ((first == '"' || first == '\'') && first == last) {
                return string(trimmed);
            }
        }
        return trimmed;
    }

    /** Normalizes a table-or-array-of-tables value into a list of tables. */
    static List<Map<String, Object>> tables(Object value) {
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        if (value instanceof Map) {
            out.add(MinecraftJson.asMap(value));
            return out;
        }
        List<Object> list = MinecraftJson.asList(value);
        if (list != null) {
            for (Object item : list) {
                if (item instanceof Map) {
                    out.add(MinecraftJson.asMap(item));
                } else if (item instanceof String) {
                    Map<String, Object> wrapper = new LinkedHashMap<String, Object>();
                    wrapper.put("config", item);
                    out.add(wrapper);
                }
            }
        }
        return out;
    }
}
