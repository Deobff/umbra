package io.umbra.core.retrace;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Rewrites an obfuscated stack trace back to the names and line numbers of the
 * original source: every
 * {@code at pkg.Cls.m(File:12)} frame is split into class, method and location,
 * the class name is looked up in the change log, the method name is restored
 * from the member table and the line number is mapped back through the
 * scramble table.
 *
 * <p>Anything the map cannot prove is emitted exactly as it came in: a retrace
 * that guesses is worse than one that leaves a frame alone, and this code runs
 * on stack traces of crashed processes.</p>
 */
public final class StackTraceRetracer {

    private StackTraceRetracer() {
    }

    /** Translates one stack trace text; never throws for unparsable input. */
    public static String retrace(LineMap map, String stackTrace) {
        if (stackTrace == null) {
            return "";
        }
        String[] lines = stackTrace.split("\r?\n", -1);
        StringBuilder out = new StringBuilder(stackTrace.length() + 256);
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) {
                out.append('\n');
            }
            out.append(translateLine(map, lines[i]));
        }
        return out.toString();
    }

    /** Reads both files and returns the translated text. */
    public static String retrace(Path mapFile, Path traceFile) throws IOException {
        LineMap map = LineMap.read(mapFile);
        List<String> lines = Files.readAllLines(traceFile, StandardCharsets.UTF_8);
        StringBuilder joined = new StringBuilder(4096);
        for (int i = 0; i < lines.size(); i++) {
            if (i > 0) {
                joined.append('\n');
            }
            joined.append(lines.get(i));
        }
        return retrace(map, joined.toString());
    }

    static String translateLine(LineMap map, String line) {
        if (map == null || line == null || line.isEmpty()) {
            return line;
        }
        String trimmed = line.trim();
        if (trimmed.startsWith("at ")) {
            return translateFrame(map, line, trimmed);
        }
        return translateHeader(map, line, trimmed);
    }

    private static String translateFrame(LineMap map, String line, String trimmed) {
        String indent = line.substring(0, line.indexOf(trimmed));
        String body = trimmed.substring(3).trim();
        int open = body.lastIndexOf('(');
        if (open < 0 || !body.endsWith(")")) {
            return line;
        }
        String qualified = body.substring(0, open).trim();
        String location = body.substring(open + 1, body.length() - 1);
        int dot = qualified.lastIndexOf('.');
        if (dot <= 0 || dot == qualified.length() - 1) {
            return line;
        }
        String classPart = qualified.substring(0, dot);
        String methodPart = qualified.substring(dot + 1);

        // Frames of named modules look like "java.base/java.lang.String.charAt".
        String modulePrefix = "";
        int slash = classPart.lastIndexOf('/');
        if (slash >= 0) {
            modulePrefix = classPart.substring(0, slash + 1);
            classPart = classPart.substring(slash + 1);
        }

        String originalClass = map.originalClass(classPart.replace('.', '/'));
        String translatedClass = originalClass == null
                ? classPart : originalClass.replace('/', '.');
        String originalMethod = originalClass == null
                ? null : map.originalMethod(originalClass, methodPart);
        String translatedMethod = originalMethod == null ? methodPart : originalMethod;
        String translatedLocation = translateLocation(map, location, originalClass,
                originalMethod == null ? translatedMethod : originalMethod);

        StringBuilder out = new StringBuilder(line.length() + 16);
        out.append(indent).append("at ").append(modulePrefix).append(translatedClass)
                .append('.').append(translatedMethod).append('(').append(translatedLocation)
                .append(')');
        return out.toString();
    }

    private static String translateLocation(LineMap map, String location, String originalClass,
                                            String originalMethod) {
        if (originalClass == null || location == null) {
            return location;
        }
        int colon = location.lastIndexOf(':');
        if (colon <= 0) {
            return location;
        }
        String fileName = location.substring(0, colon);
        String number = location.substring(colon + 1).trim();
        int newLine;
        try {
            newLine = Integer.parseInt(number);
        } catch (NumberFormatException notANumber) {
            return location;
        }
        Integer oldLine = map.originalLine(originalClass, originalMethod, newLine);
        if (oldLine == null) {
            return location;
        }
        return fileName + ":" + oldLine.intValue();
    }

    private static String translateHeader(LineMap map, String line, String trimmed) {
        String lead = "";
        String body = trimmed;
        for (String marker : new String[]{"Caused by: ", "Suppressed: "}) {
            if (body.startsWith(marker)) {
                lead = marker;
                body = body.substring(marker.length());
                break;
            }
        }
        int colon = body.indexOf(':');
        String token = (colon < 0 ? body : body.substring(0, colon)).trim();
        if (token.isEmpty()) {
            return line;
        }
        String mapped = map.originalClass(token.replace('.', '/'));
        if (mapped == null) {
            return line;
        }
        String indent = line.substring(0, line.indexOf(trimmed));
        return indent + lead + mapped.replace('/', '.') + (colon < 0 ? "" : body.substring(colon));
    }

    /** Human readable summary used by the CLI. */
    public static String describe(LineMap map) {
        StringBuilder out = new StringBuilder();
        Map<String, String> classes = map.classesNewToOld();
        out.append("linemap: ").append(classes.size()).append(" classes, ")
                .append(map.methodCount()).append(" methods, ")
                .append(map.lineCount()).append(" line mappings");
        return out.toString();
    }
}
