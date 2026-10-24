package io.umbra.core.minecraft;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Dependency-free JSON reader used for Minecraft mod-container metadata
 * ({@code fabric.mod.json}, {@code quilt.mod.json}, mixin configurations,
 * legacy {@code mcmod.info}).
 *
 * <p>Deliberately tiny and forgiving where it is useful for obfuscator
 * detection: objects, arrays, strings, numbers, booleans and {@code null} are
 * supported. Malformed documents raise {@link IllegalArgumentException}; callers
 * turn that into a warning so a broken metadata file never aborts a run.</p>
 */
final class MinecraftJson {

    /** Nesting limit so a hostile document cannot overflow the stack. */
    private static final int MAX_DEPTH = 256;

    private MinecraftJson() {
    }

    /** Decodes resource bytes as UTF-8 and strips a leading byte-order mark. */
    static String text(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        String text = new String(bytes, StandardCharsets.UTF_8);
        if (!text.isEmpty() && text.charAt(0) == '\uFEFF') {
            return text.substring(1);
        }
        return text;
    }

    /** Parses a JSON document into maps, lists and scalars. */
    static Object parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("empty JSON document");
        }
        Parser parser = new Parser(text);
        parser.skipWhitespace();
        Object value = parser.value(0);
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw new IllegalArgumentException("trailing characters at " + parser.position());
        }
        return value;
    }

    /** Parses a JSON document that must be an object. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> parseObject(String text) {
        Object value = parse(text);
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("expected a JSON object");
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    static List<Object> asList(Object value) {
        return value instanceof List ? (List<Object>) value : null;
    }

    static String asString(Object value) {
        if (value instanceof String) {
            String text = ((String) value).trim();
            return text.isEmpty() ? null : text;
        }
        return null;
    }

    static boolean asBoolean(Object value, boolean fallback) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue();
        }
        String text = asString(value);
        if (text == null) {
            return fallback;
        }
        String lower = text.toLowerCase(java.util.Locale.ROOT);
        if ("true".equals(lower) || "yes".equals(lower) || "1".equals(lower)) {
            return true;
        }
        if ("false".equals(lower) || "no".equals(lower) || "0".equals(lower)) {
            return false;
        }
        return fallback;
    }

    /** Returns every scalar string found in a string-or-array value. */
    static List<String> strings(Object value) {
        List<String> out = new ArrayList<String>();
        collectStrings(value, out);
        return out;
    }

    private static void collectStrings(Object value, List<String> out) {
        if (value == null) {
            return;
        }
        if (value instanceof String) {
            String text = ((String) value).trim();
            if (!text.isEmpty()) {
                out.add(text);
            }
            return;
        }
        List<Object> list = asList(value);
        if (list != null) {
            for (Object item : list) {
                collectStrings(item, out);
            }
        }
    }

    private static final class Parser {
        private final String text;
        private int index;

        Parser(String text) {
            this.text = text;
        }

        int position() {
            return index;
        }

        boolean atEnd() {
            return index >= text.length();
        }

        void skipWhitespace() {
            while (index < text.length()) {
                char c = text.charAt(index);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    index++;
                } else {
                    break;
                }
            }
        }

        Object value(int depth) {
            if (depth > MAX_DEPTH) {
                throw new IllegalArgumentException("JSON nesting too deep at " + index);
            }
            skipWhitespace();
            if (atEnd()) {
                throw new IllegalArgumentException("unexpected end of JSON");
            }
            char c = text.charAt(index);
            switch (c) {
                case '{': return object(depth);
                case '[': return array(depth);
                case '"': return string();
                case 't': expect("true"); return Boolean.TRUE;
                case 'f': expect("false"); return Boolean.FALSE;
                case 'n': expect("null"); return null;
                default: return number();
            }
        }

        private Map<String, Object> object(int depth) {
            Map<String, Object> map = new LinkedHashMap<String, Object>();
            index++; // '{'
            skipWhitespace();
            if (!atEnd() && text.charAt(index) == '}') {
                index++;
                return map;
            }
            while (true) {
                skipWhitespace();
                if (atEnd() || text.charAt(index) != '"') {
                    throw new IllegalArgumentException("expected string key at " + index);
                }
                String key = string();
                skipWhitespace();
                if (atEnd() || text.charAt(index) != ':') {
                    throw new IllegalArgumentException("expected ':' at " + index);
                }
                index++;
                map.put(key, value(depth + 1));
                skipWhitespace();
                if (atEnd()) {
                    throw new IllegalArgumentException("unterminated object at " + index);
                }
                char c = text.charAt(index);
                if (c == ',') {
                    index++;
                    continue;
                }
                if (c == '}') {
                    index++;
                    return map;
                }
                throw new IllegalArgumentException("expected ',' or '}' at " + index);
            }
        }

        private List<Object> array(int depth) {
            List<Object> list = new ArrayList<Object>();
            index++; // '['
            skipWhitespace();
            if (!atEnd() && text.charAt(index) == ']') {
                index++;
                return list;
            }
            while (true) {
                list.add(value(depth + 1));
                skipWhitespace();
                if (atEnd()) {
                    throw new IllegalArgumentException("unterminated array at " + index);
                }
                char c = text.charAt(index);
                if (c == ',') {
                    index++;
                    continue;
                }
                if (c == ']') {
                    index++;
                    return list;
                }
                throw new IllegalArgumentException("expected ',' or ']' at " + index);
            }
        }

        private String string() {
            StringBuilder out = new StringBuilder();
            index++; // opening quote
            while (index < text.length()) {
                char c = text.charAt(index++);
                if (c == '"') {
                    return out.toString();
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (index >= text.length()) {
                    break;
                }
                char escape = text.charAt(index++);
                switch (escape) {
                    case '"': out.append('"'); break;
                    case '\\': out.append('\\'); break;
                    case '/': out.append('/'); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    case 'u':
                        if (index + 4 > text.length()) {
                            throw new IllegalArgumentException("truncated unicode escape at " + index);
                        }
                        try {
                            out.append((char) Integer.parseInt(text.substring(index, index + 4), 16));
                        } catch (NumberFormatException e) {
                            throw new IllegalArgumentException("bad unicode escape at " + index);
                        }
                        index += 4;
                        break;
                    default:
                        throw new IllegalArgumentException("bad escape at " + index);
                }
            }
            throw new IllegalArgumentException("unterminated string at " + index);
        }

        private Object number() {
            int start = index;
            if (!atEnd() && (text.charAt(index) == '-' || text.charAt(index) == '+')) {
                index++;
            }
            while (index < text.length()) {
                char c = text.charAt(index);
                if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '-' || c == '+') {
                    index++;
                } else {
                    break;
                }
            }
            if (start == index) {
                throw new IllegalArgumentException("unexpected character at " + index);
            }
            String raw = text.substring(start, index);
            if (raw.indexOf('.') < 0 && raw.indexOf('e') < 0 && raw.indexOf('E') < 0) {
                try {
                    return Long.valueOf(raw);
                } catch (NumberFormatException ignored) {
                    // fall through to double
                }
            }
            try {
                return Double.valueOf(raw);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("bad number '" + raw + "' at " + start);
            }
        }

        private void expect(String literal) {
            if (!text.startsWith(literal, index)) {
                throw new IllegalArgumentException("expected " + literal + " at " + index);
            }
            index += literal.length();
        }
    }
}
