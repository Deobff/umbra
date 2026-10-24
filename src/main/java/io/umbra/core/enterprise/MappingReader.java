package io.umbra.core.enterprise;

import io.umbra.core.engine.MappingSet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads Umbra and ProGuard-style mapping files into a {@link MappingSet}.
 *
 * <p>Umbra format uses JVM descriptors ({@code foo(I)V}); ProGuard format uses
 * Java signatures ({@code void foo(int)}). Both are accepted. ProGuard line
 * prefixes ({@code 12:34:}) are stripped. Class names may be dotted or use
 * {@code /}.</p>
 */
public final class MappingReader {

    private MappingReader() {
    }

    public static MappingSet read(Path file) throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        MappingSet mappings = new MappingSet();
        String currentOwner = null;
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int arrow = line.indexOf(" -> ");
            if (arrow < 0) {
                continue;
            }
            String left = line.substring(0, arrow).trim();
            String right = line.substring(arrow + 4).trim();
            if (right.endsWith(":")) {
                right = right.substring(0, right.length() - 1).trim();
                currentOwner = normalizeClass(left);
                mappings.mapClass(currentOwner, normalizeClass(right));
                continue;
            }
            if (currentOwner == null) {
                continue;
            }
            String cleaned = stripLinePrefix(left);
            if (cleaned.indexOf('(') >= 0) {
                MethodSignature signature = parseMethod(cleaned);
                if (signature != null) {
                    mappings.mapMethod(currentOwner, signature.name, signature.desc, right);
                }
            } else {
                FieldSignature signature = parseField(cleaned);
                if (signature != null) {
                    mappings.mapField(currentOwner, signature.name, signature.desc, right);
                }
            }
        }
        return mappings;
    }

    private static MethodSignature parseMethod(String left) {
        int paren = left.indexOf('(');
        int close = left.lastIndexOf(')');
        if (paren < 0 || close < paren) {
            return null;
        }
        String before = left.substring(0, paren).trim();
        String args = left.substring(paren + 1, close).trim();
        String tail = left.substring(close + 1).trim();
        boolean jvm = before.indexOf(' ') < 0 && (tail.isEmpty() || isJvmType(tail));
        String name;
        String desc;
        if (jvm) {
            name = before;
            desc = "(" + args + ")" + (tail.isEmpty() ? "V" : tail);
        } else {
            int space = before.lastIndexOf(' ');
            String returnType = space > 0 ? before.substring(0, space).trim() : "void";
            name = space > 0 ? before.substring(space + 1).trim() : before;
            if (name.indexOf('.') >= 0) {
                name = name.substring(name.lastIndexOf('.') + 1);
            }
            desc = "(" + argsToDescriptor(args) + ")" + typeToDescriptor(returnType);
        }
        if (name.isEmpty()) {
            return null;
        }
        return new MethodSignature(name, desc);
    }

    private static FieldSignature parseField(String left) {
        String cleaned = left.trim();
        int colon = cleaned.indexOf(':');
        int space = cleaned.lastIndexOf(' ');
        if (colon > 0 && (space < 0 || colon < space)) {
            String name = cleaned.substring(0, colon).trim();
            String desc = cleaned.substring(colon + 1).trim();
            return isJvmType(desc) ? new FieldSignature(name, desc) : null;
        }
        if (space > 0) {
            String type = cleaned.substring(0, space).trim();
            String name = cleaned.substring(space + 1).trim();
            if (!name.isEmpty()) {
                return new FieldSignature(name, typeToDescriptor(type));
            }
        }
        return null;
    }

    private static String argsToDescriptor(String args) {
        if (args.isEmpty()) {
            return "";
        }
        if (isJvmType(args)) {
            return args;
        }
        StringBuilder out = new StringBuilder();
        for (String part : splitArguments(args)) {
            out.append(typeToDescriptor(part));
        }
        return out.toString();
    }

    private static List<String> splitArguments(String args) {
        List<String> out = new ArrayList<String>();
        StringBuilder current = new StringBuilder();
        int genericDepth = 0;
        for (int i = 0; i < args.length(); i++) {
            char c = args.charAt(i);
            if (c == '<') {
                genericDepth++;
            } else if (c == '>') {
                genericDepth = Math.max(0, genericDepth - 1);
            }
            if (c == ',' && genericDepth == 0) {
                out.add(current.toString().trim());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) {
            out.add(current.toString().trim());
        }
        return out;
    }

    private static String typeToDescriptor(String type) {
        String value = type.trim();
        int generic = value.indexOf('<');
        if (generic >= 0) {
            value = value.substring(0, generic);
        }
        int dimensions = 0;
        while (value.endsWith("[]")) {
            dimensions++;
            value = value.substring(0, value.length() - 2).trim();
        }
        if (value.endsWith("...")) {
            dimensions++;
            value = value.substring(0, value.length() - 3).trim();
        }
        String base;
        if ("void".equals(value)) {
            base = "V";
        } else if ("boolean".equals(value)) {
            base = "Z";
        } else if ("byte".equals(value)) {
            base = "B";
        } else if ("char".equals(value)) {
            base = "C";
        } else if ("short".equals(value)) {
            base = "S";
        } else if ("int".equals(value)) {
            base = "I";
        } else if ("long".equals(value)) {
            base = "J";
        } else if ("float".equals(value)) {
            base = "F";
        } else if ("double".equals(value)) {
            base = "D";
        } else {
            base = "L" + value.replace('.', '/') + ";";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < dimensions; i++) {
            out.append('[');
        }
        return out.append(base).toString();
    }

    private static boolean isJvmType(String value) {
        if (value.isEmpty()) {
            return true;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ("[ZBCSIJFDVL;()/".indexOf(c) >= 0) {
                continue;
            }
            if (Character.isLetterOrDigit(c) || c == '_' || c == '$') {
                continue;
            }
            return false;
        }
        return true;
    }

    private static String stripLinePrefix(String value) {
        int index = 0;
        while (index < value.length() && Character.isDigit(value.charAt(index))) {
            index++;
        }
        if (index > 0 && index + 1 < value.length() && value.charAt(index) == ':') {
            int second = index + 1;
            while (second < value.length() && Character.isDigit(value.charAt(second))) {
                second++;
            }
            if (second > index + 1 && second < value.length() && value.charAt(second) == ':') {
                return value.substring(second + 1).trim();
            }
            return value.substring(index + 1).trim();
        }
        return value;
    }

    private static String normalizeClass(String value) {
        return value.replace('.', '/').trim();
    }

    private static final class MethodSignature {
        final String name;
        final String desc;

        MethodSignature(String name, String desc) {
            this.name = name;
            this.desc = desc;
        }
    }

    private static final class FieldSignature {
        final String name;
        final String desc;

        FieldSignature(String name, String desc) {
            this.name = name;
            this.desc = desc;
        }
    }
}
