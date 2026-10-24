package io.umbra.core.rules;

import java.util.regex.Pattern;

/**
 * Ant-style glob matcher for internal class names.
 *
 * <ul>
 *   <li>{@code **} matches any sequence including {@code /}</li>
 *   <li>{@code *} matches any sequence except {@code /}</li>
 *   <li>{@code ?} matches exactly one character</li>
 * </ul>
 *
 * Dotted input such as {@code com.example.Main} is normalized to
 * {@code com/example/Main}.
 */
public final class Glob {

    private final String source;
    private final Pattern pattern;

    public Glob(String source) {
        this.source = source;
        this.pattern = Pattern.compile(toRegex(normalize(source)));
    }

    public String source() {
        return source;
    }

    public boolean matches(String internalName) {
        return pattern.matcher(normalize(internalName)).matches();
    }

    /** Normalizes a dotted or slash-separated class name to internal form. */
    public static String normalize(String name) {
        if (name == null) {
            return "";
        }
        return name.replace('.', '/');
    }

    private static String toRegex(String glob) {
        StringBuilder out = new StringBuilder();
        out.append('^');
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            if (c == '*') {
                if (i + 1 < glob.length() && glob.charAt(i + 1) == '*') {
                    out.append(".*");
                    i++;
                } else {
                    out.append("[^/]*");
                }
            } else if (c == '?') {
                out.append('.');
            } else if ("\\.[]{}()+-^$|".indexOf(c) >= 0) {
                out.append('\\').append(c);
            } else {
                out.append(c);
            }
        }
        out.append('$');
        return out.toString();
    }
}
