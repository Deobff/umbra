package io.umbra.core.enterprise;

import io.umbra.core.engine.MappingSet;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/** Compares two Umbra/ProGuard-style mapping files for release reviews. */
public final class MappingDiff {

    private MappingDiff() {
    }

    public static String compare(Path oldFile, Path newFile) throws IOException {
        MappingSet oldSet = MappingReader.read(oldFile);
        MappingSet newSet = MappingReader.read(newFile);
        StringBuilder out = new StringBuilder();
        out.append("# Umbra mapping diff\n");
        out.append("# old: ").append(oldFile).append('\n');
        out.append("# new: ").append(newFile).append("\n\n");

        section(out, "Classes", oldSet.classes(), newSet.classes());

        TreeMap<String, String> oldMethods = flatten(oldSet.methods());
        TreeMap<String, String> newMethods = flatten(newSet.methods());
        section(out, "Methods", oldMethods, newMethods);

        TreeMap<String, String> oldFields = flatten(oldSet.fields());
        TreeMap<String, String> newFields = flatten(newSet.fields());
        section(out, "Fields", oldFields, newFields);

        return out.toString();
    }

    private static TreeMap<String, String> flatten(Map<String, String> input) {
        return new TreeMap<String, String>(input);
    }

    private static void section(StringBuilder out, String title,
                                Map<String, String> oldMap, Map<String, String> newMap) {
        TreeSet<String> removed = new TreeSet<String>(oldMap.keySet());
        removed.removeAll(newMap.keySet());
        TreeSet<String> added = new TreeSet<String>(newMap.keySet());
        added.removeAll(oldMap.keySet());
        TreeSet<String> changed = new TreeSet<String>();
        for (Map.Entry<String, String> e : oldMap.entrySet()) {
            String next = newMap.get(e.getKey());
            if (next != null && !next.equals(e.getValue())) {
                changed.add(e.getKey());
            }
        }

        out.append("## ").append(title).append('\n');
        out.append("added: ").append(added.size())
                .append(", removed: ").append(removed.size())
                .append(", changed: ").append(changed.size()).append('\n');
        for (String key : removed) {
            out.append("- ").append(key).append(" -> ").append(oldMap.get(key)).append('\n');
        }
        for (String key : added) {
            out.append("+ ").append(key).append(" -> ").append(newMap.get(key)).append('\n');
        }
        for (String key : changed) {
            out.append("~ ").append(key).append(": ")
                    .append(oldMap.get(key)).append(" -> ").append(newMap.get(key)).append('\n');
        }
        out.append('\n');
    }
}
