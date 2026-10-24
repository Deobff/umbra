package io.umbra.core.jni;

import java.util.ArrayList;
import java.util.List;

/**
 * JNI symbol naming and descriptor helpers.
 *
 * <p>Implements the "Resolving Native Method Names" rules from the JNI
 * specification: a native symbol is either the <em>short</em> name
 * {@code Java_<mangled class>_<mangled method>} or, for overloaded methods, the
 * <em>long</em> name which appends {@code __} and the mangled argument
 * signature.</p>
 *
 * <p>Mangling: {@code /} becomes {@code _}, {@code _} becomes {@code _1},
 * {@code ;} becomes {@code _2}, {@code [} becomes {@code _3}, ASCII letters and
 * digits are kept and every other UTF-16 code unit becomes {@code _0} followed
 * by four lower-case hexadecimal digits (for example U+4E2D becomes
 * {@code _04e2d}).</p>
 */
public final class JniNames {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private JniNames() {
    }

    /** Mangles a class name, method name or type descriptor into a symbol fragment. */
    public static String mangle(String value) {
        if (value == null) {
            throw new IllegalArgumentException("value");
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '/') {
                out.append('_');
            } else if (c == '_') {
                out.append("_1");
            } else if (c == ';') {
                out.append("_2");
            } else if (c == '[') {
                out.append("_3");
            } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')) {
                out.append(c);
            } else {
                out.append("_0");
                out.append(HEX[(c >> 12) & 0xF]);
                out.append(HEX[(c >> 8) & 0xF]);
                out.append(HEX[(c >> 4) & 0xF]);
                out.append(HEX[c & 0xF]);
            }
        }
        return out.toString();
    }

    /** Short JNI name, {@code Java_<mangled class>_<mangled method>}. */
    public static String shortName(String ownerInternalName, String methodName) {
        return "Java_" + mangle(ownerInternalName) + "_" + mangle(methodName);
    }

    /**
     * Long JNI name, {@code Java_<mangled class>_<mangled method>__<mangled args>}.
     *
     * @param descriptor method descriptor such as {@code (ILjava/lang/String;)V}
     */
    public static String longName(String ownerInternalName, String methodName, String descriptor) {
        return shortName(ownerInternalName, methodName) + "__" + mangle(argumentSignature(descriptor));
    }

    /** Returns the argument part of a method descriptor without the parentheses. */
    public static String argumentSignature(String descriptor) {
        if (descriptor == null || descriptor.length() < 3 || descriptor.charAt(0) != '(') {
            throw new IllegalArgumentException("not a method descriptor: " + descriptor);
        }
        int close = descriptor.indexOf(')');
        if (close < 0) {
            throw new IllegalArgumentException("not a method descriptor: " + descriptor);
        }
        return descriptor.substring(1, close);
    }

    /** Returns the return type of a method descriptor, for example {@code V} or {@code [I}. */
    public static String returnType(String descriptor) {
        if (descriptor == null) {
            throw new IllegalArgumentException("descriptor");
        }
        int close = descriptor.indexOf(')');
        if (descriptor.length() < 3 || descriptor.charAt(0) != '(' || close < 0) {
            throw new IllegalArgumentException("not a method descriptor: " + descriptor);
        }
        return descriptor.substring(close + 1);
    }

    /** Splits the descriptor into its argument types (in order). */
    public static List<String> argumentTypes(String descriptor) {
        List<String> all = splitTypes(descriptor);
        all.remove(all.size() - 1);
        return all;
    }

    /**
     * Splits a field or method descriptor into its Java types. For method
     * descriptors the return type is the last element.
     */
    public static List<String> splitTypes(String descriptor) {
        if (descriptor == null) {
            throw new IllegalArgumentException("descriptor");
        }
        List<String> out = new ArrayList<String>();
        int i = 0;
        int n = descriptor.length();
        if (n > 0 && descriptor.charAt(0) == '(') {
            i = 1;
        }
        while (i < n) {
            char c = descriptor.charAt(i);
            if (c == ')') {
                i++;
                continue;
            }
            int start = i;
            while (i < n && descriptor.charAt(i) == '[') {
                i++;
            }
            if (i >= n) {
                throw new IllegalArgumentException("truncated descriptor: " + descriptor);
            }
            char kind = descriptor.charAt(i);
            if (kind == 'L') {
                int semi = descriptor.indexOf(';', i);
                if (semi < 0) {
                    throw new IllegalArgumentException("truncated object type: " + descriptor);
                }
                i = semi + 1;
            } else if ("ZBCSIJFDV".indexOf(kind) >= 0) {
                i++;
            } else {
                throw new IllegalArgumentException("bad descriptor character '" + kind
                        + "' in " + descriptor);
            }
            out.add(descriptor.substring(start, i));
        }
        if (out.isEmpty()) {
            throw new IllegalArgumentException("empty descriptor: " + descriptor);
        }
        return out;
    }
}
