package io.umbra.core.retrace;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * The line-number map written next to a protected archive and read back by
 * {@link StackTraceRetracer}.
 *
 * <p>Format (UTF-8, one record per line, tab separated, first line is the
 * version header):</p>
 * <pre>
 * umbra-linemap 1
 * C  oldClass              newClass
 * M  oldClass  oldMethod  oldDescriptor  newMethod
 * L  oldClass  oldMethod  oldDescriptor  oldLine  newLine1,newLine2
 * </pre>
 *
 * <p>The rename columns follow a change-log layout: the map is keyed
 * by the original names and the retracer builds the reverse (obfuscated to
 * original) index while reading. An old source line may map to several new
 * lines, which is why the line column is a list.</p>
 */
public final class LineMap {

    /** Header of the current format. Readers refuse anything else. */
    public static final String HEADER = "umbra-linemap 1";

    private final Map<String, String> classOldToNew = new LinkedHashMap<String, String>();
    private final Map<String, String> classNewToOld = new LinkedHashMap<String, String>();
    private final Map<String, String> methodOldToNew = new LinkedHashMap<String, String>();
    private final Map<String, Map<String, String>> methodNewToOld =
            new LinkedHashMap<String, Map<String, String>>();
    private final Map<String, Map<String, Map<Integer, Integer>>> lineNewToOld =
            new LinkedHashMap<String, Map<String, Map<Integer, Integer>>>();

    public void mapClass(String oldName, String newName) {
        if (oldName == null || newName == null) {
            return;
        }
        classOldToNew.put(oldName, newName);
        classNewToOld.put(newName, oldName);
    }

    public void mapMethod(String oldClass, String oldMethod, String descriptor, String newMethod) {
        if (oldClass == null || oldMethod == null || descriptor == null || newMethod == null) {
            return;
        }
        methodOldToNew.put(key(oldClass, oldMethod, descriptor), newMethod);
        Map<String, String> byNewName = methodNewToOld.get(oldClass);
        if (byNewName == null) {
            byNewName = new LinkedHashMap<String, String>();
            methodNewToOld.put(oldClass, byNewName);
        }
        // Two overloads may collapse onto one new name; the retracer then keeps the
        // obfuscated spelling instead of guessing.
        String existing = byNewName.get(newMethod);
        if (existing == null) {
            byNewName.put(newMethod, oldMethod);
        } else if (!existing.equals(oldMethod)) {
            byNewName.put(newMethod, "");
        }
    }

    public void mapLine(String oldClass, String oldMethod, String descriptor, int oldLine,
                        List<Integer> newLines) {
        if (newLines == null || newLines.isEmpty()) {
            return;
        }
        Map<String, Map<Integer, Integer>> byMethod = lineNewToOld.get(oldClass);
        if (byMethod == null) {
            byMethod = new LinkedHashMap<String, Map<Integer, Integer>>();
            lineNewToOld.put(oldClass, byMethod);
        }
        Map<Integer, Integer> byLine = byMethod.get(oldMethod);
        if (byLine == null) {
            byLine = new LinkedHashMap<Integer, Integer>();
            byMethod.put(oldMethod, byLine);
        }
        for (Integer newLine : newLines) {
            if (newLine != null && !byLine.containsKey(newLine)) {
                byLine.put(newLine, Integer.valueOf(oldLine));
            }
        }
    }

    /** Original class name for an obfuscated one, or {@code null}. */
    public String originalClass(String newName) {
        return classNewToOld.get(newName);
    }

    /** Original method name for an obfuscated one, or {@code null} when ambiguous. */
    public String originalMethod(String oldClass, String newMethod) {
        Map<String, String> byNewName = methodNewToOld.get(oldClass);
        if (byNewName == null) {
            return null;
        }
        String value = byNewName.get(newMethod);
        return value == null || value.isEmpty() ? null : value;
    }

    /** Original line for an obfuscated one, or {@code null}. */
    public Integer originalLine(String oldClass, String oldMethod, int newLine) {
        Map<String, Map<Integer, Integer>> byMethod = lineNewToOld.get(oldClass);
        if (byMethod == null) {
            return null;
        }
        Map<Integer, Integer> byLine = byMethod.get(oldMethod);
        if (byLine == null) {
            for (Map<Integer, Integer> candidate : byMethod.values()) {
                Integer mapped = candidate.get(Integer.valueOf(newLine));
                if (mapped != null) {
                    return mapped;
                }
            }
            return null;
        }
        return byLine.get(Integer.valueOf(newLine));
    }

    /** Obfuscated name to original name, for header lines and diagnostics. */
    public Map<String, String> classesNewToOld() {
        return Collections.unmodifiableMap(classNewToOld);
    }

    public boolean isEmpty() {
        return classOldToNew.isEmpty() && methodOldToNew.isEmpty() && lineNewToOld.isEmpty();
    }

    public int classCount() {
        return classOldToNew.size();
    }

    public int methodCount() {
        return methodOldToNew.size();
    }

    public int lineCount() {
        int total = 0;
        for (Map<String, Map<Integer, Integer>> byMethod : lineNewToOld.values()) {
            for (Map<Integer, Integer> byLine : byMethod.values()) {
                total += byLine.size();
            }
        }
        return total;
    }

    /** Renders the map in the format described in the class comment. */
    public String render() {
        StringBuilder out = new StringBuilder(4096);
        out.append(HEADER).append('\n');
        List<String> classes = new ArrayList<String>(classOldToNew.keySet());
        Collections.sort(classes);
        for (String oldClass : classes) {
            out.append("C\t").append(oldClass).append('\t').append(classOldToNew.get(oldClass))
                    .append('\n');
        }
        List<String> methods = new ArrayList<String>(methodOldToNew.keySet());
        Collections.sort(methods);
        for (String key : methods) {
            int first = key.indexOf('\u0000');
            int second = key.indexOf('\u0000', first + 1);
            if (first < 0 || second < 0) {
                continue;
            }
            out.append("M\t").append(key.substring(0, first)).append('\t')
                    .append(key.substring(first + 1, second)).append('\t')
                    .append(key.substring(second + 1)).append('\t')
                    .append(methodOldToNew.get(key)).append('\n');
        }
        // Line records are emitted old-line ascending, exactly like the change log does.
        Map<String, Map<String, TreeMap<Integer, List<Integer>>>> grouped =
                new LinkedHashMap<String, Map<String, TreeMap<Integer, List<Integer>>>>();
        for (Map.Entry<String, Map<String, Map<Integer, Integer>>> byClass : lineNewToOld.entrySet()) {
            for (Map.Entry<String, Map<Integer, Integer>> byMethod : byClass.getValue().entrySet()) {
                TreeMap<Integer, List<Integer>> byOld = new TreeMap<Integer, List<Integer>>();
                for (Map.Entry<Integer, Integer> pair : byMethod.getValue().entrySet()) {
                    List<Integer> list = byOld.get(pair.getValue());
                    if (list == null) {
                        list = new ArrayList<Integer>();
                        byOld.put(pair.getValue(), list);
                    }
                    list.add(pair.getKey());
                }
                Map<String, TreeMap<Integer, List<Integer>>> byMethodOut = grouped.get(byClass.getKey());
                if (byMethodOut == null) {
                    byMethodOut = new LinkedHashMap<String, TreeMap<Integer, List<Integer>>>();
                    grouped.put(byClass.getKey(), byMethodOut);
                }
                byMethodOut.put(byMethod.getKey(), byOld);
            }
        }
        for (Map.Entry<String, Map<String, TreeMap<Integer, List<Integer>>>> byClass : grouped.entrySet()) {
            for (Map.Entry<String, TreeMap<Integer, List<Integer>>> byMethod : byClass.getValue().entrySet()) {
                String descriptor = descriptorOf(byClass.getKey(), byMethod.getKey());
                for (Map.Entry<Integer, List<Integer>> pair : byMethod.getValue().entrySet()) {
                    List<Integer> news = new ArrayList<Integer>(pair.getValue());
                    Collections.sort(news);
                    out.append("L\t").append(byClass.getKey()).append('\t')
                            .append(byMethod.getKey()).append('\t').append(descriptor).append('\t')
                            .append(pair.getKey()).append('\t');
                    for (int i = 0; i < news.size(); i++) {
                        if (i > 0) {
                            out.append(',');
                        }
                        out.append(news.get(i));
                    }
                    out.append('\n');
                }
            }
        }
        return out.toString();
    }

    public void write(Path target) throws IOException {
        Path parent = target.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(target, render().getBytes(StandardCharsets.UTF_8));
    }

    /** Reads a map, ignoring blank lines and comments; unknown records are skipped. */
    public static LineMap read(Path source) throws IOException {
        List<String> lines = Files.readAllLines(source, StandardCharsets.UTF_8);
        LineMap map = new LineMap();
        boolean header = false;
        for (String raw : lines) {
            if (raw == null) {
                continue;
            }
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (!header) {
                if (!HEADER.equals(line)) {
                    throw new IOException("not an umbra line map (expected '" + HEADER + "'): " + source);
                }
                header = true;
                continue;
            }
            String[] parts = raw.split("\t");
            if (parts.length < 3) {
                continue;
            }
            String kind = parts[0].trim();
            if ("C".equals(kind) && parts.length >= 3) {
                map.mapClass(parts[1], parts[2]);
            } else if ("M".equals(kind) && parts.length >= 5) {
                map.mapMethod(parts[1], parts[2], parts[3], parts[4]);
            } else if ("L".equals(kind) && parts.length >= 6) {
                int oldLine;
                try {
                    oldLine = Integer.parseInt(parts[4].trim());
                } catch (NumberFormatException ignored) {
                    continue;
                }
                List<Integer> news = new ArrayList<Integer>();
                for (String piece : parts[5].split(",")) {
                    try {
                        news.add(Integer.valueOf(piece.trim()));
                    } catch (NumberFormatException ignored) {
                        // a malformed entry is dropped, never fatal
                    }
                }
                map.mapLine(parts[1], parts[2], parts[3], oldLine, news);
            }
        }
        if (!header) {
            throw new IOException("empty line map: " + source);
        }
        return map;
    }

    private String descriptorOf(String oldClass, String oldMethod) {
        for (String key : methodOldToNew.keySet()) {
            int first = key.indexOf('\u0000');
            int second = key.indexOf('\u0000', first + 1);
            if (first < 0 || second < 0) {
                continue;
            }
            if (key.substring(0, first).equals(oldClass)
                    && key.substring(first + 1, second).equals(oldMethod)) {
                return key.substring(second + 1);
            }
        }
        return "";
    }

    private static String key(String owner, String name, String descriptor) {
        return owner + '\u0000' + name + '\u0000' + descriptor;
    }
}
