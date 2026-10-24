package io.umbra.core.util;

import io.umbra.core.engine.MappingSet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Writes a ProGuard-style mapping file.
 *
 * <p>Member entries use {@code name:descriptor -> newName}; the descriptor is a
 * JVM descriptor so the file is unambiguous even for overloads.</p>
 */
public final class MappingWriter {

    private MappingWriter() {
    }

    /** Writes the mapping to {@code file}. */
    public static void write(Path file, MappingSet mappings) throws IOException {
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(file, toText(mappings).getBytes(StandardCharsets.UTF_8));
    }

    /** Renders the mapping as text. */
    public static String toText(MappingSet mappings) {
        StringBuilder out = new StringBuilder();
        out.append("# Umbra mapping file\n");
        out.append("# class and member descriptors are JVM descriptors\n\n");

        TreeSet<String> owners = new TreeSet<String>();
        owners.addAll(mappings.classes().keySet());
        for (String key : mappings.methods().keySet()) {
            owners.add(ownerOf(key));
        }
        for (String key : mappings.fields().keySet()) {
            owners.add(ownerOf(key));
        }

        for (String owner : owners) {
            String mappedOwner = mappings.mappedClass(owner);
            out.append(owner).append(" -> ").append(mappedOwner).append(":\n");

            List<String> fieldLines = new ArrayList<String>();
            for (Map.Entry<String, String> e : mappings.fields().entrySet()) {
                String[] parts = splitKey(e.getKey());
                if (parts != null && parts[0].equals(owner)) {
                    fieldLines.add("    " + parts[1] + ":" + parts[2] + " -> " + e.getValue());
                }
            }
            Collections.sort(fieldLines);
            for (String line : fieldLines) {
                out.append(line).append('\n');
            }

            List<String> methodLines = new ArrayList<String>();
            for (Map.Entry<String, String> e : mappings.methods().entrySet()) {
                String[] parts = splitKey(e.getKey());
                if (parts != null && parts[0].equals(owner)) {
                    methodLines.add("    " + parts[1] + parts[2] + " -> " + e.getValue());
                }
            }
            Collections.sort(methodLines);
            for (String line : methodLines) {
                out.append(line).append('\n');
            }
            out.append('\n');
        }
        return out.toString();
    }

    private static String ownerOf(String key) {
        int first = key.indexOf('#');
        return first < 0 ? key : key.substring(0, first);
    }

    private static String[] splitKey(String key) {
        String[] parts = key.split("#", 3);
        return parts.length == 3 ? parts : null;
    }
}
