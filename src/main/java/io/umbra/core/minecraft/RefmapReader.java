package io.umbra.core.minecraft;

import io.umbra.core.minecraft.mixin.MixinCollector;
import io.umbra.core.minecraft.refmap.Refmap;
import io.umbra.core.model.ClassPool;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Reads Mixin refmaps from the class pool resources.
 *
 * <p>A refmap is a JSON document with a {@code mappings} table (see
 * {@link Refmap}); its file name is declared by the mixin configuration
 * ({@code "refmap": "<mod>-refmap.json"}) and, by convention, contains
 * {@code refmap}. Discovery therefore has two paths:</p>
 *
 * <ol>
 *   <li>every JSON resource whose path mentions {@code mixin} or {@code refmap}
 *       is parsed and classified: a document with a {@code mappings} object is a
 *       refmap, a document with a {@code refmap} string is a mixin configuration
 *       that names one;</li>
 *   <li>every refmap path named by such a configuration is resolved and parsed,
 *       so a refmap that is not called {@code *refmap*.json} is still found.</li>
 * </ol>
 *
 * <p>Every refmap in the archive is merged into one lookup table: a jar ships
 * one refmap per mixin configuration and Mixin resolves all of them at load time,
 * so consulting the union can only add keep rules, never remove one. Malformed
 * documents only produce a note; the caller keeps working with whatever could be
 * parsed.</p>
 */
final class RefmapReader {

    /** Refmaps are small; anything this large is not a refmap. */
    private static final long MAX_BYTES = 8L * 1024L * 1024L;

    private RefmapReader() {
    }

    static Refmap read(ClassPool pool, MixinCollector collector) {
        if (pool == null) {
            return Refmap.EMPTY;
        }

        Map<String, Map<String, Object>> documents = new LinkedHashMap<String, Map<String, Object>>();
        List<String> declared = new ArrayList<String>();
        for (Map.Entry<String, ClassPool.Resource> entry : pool.resources().entrySet()) {
            String name = entry.getKey();
            if (name == null || !looksLikeMixinMetadata(name)) {
                continue;
            }
            byte[] bytes = entry.getValue() == null ? null : entry.getValue().bytes();
            if (bytes == null || bytes.length == 0 || bytes.length > MAX_BYTES) {
                continue;
            }
            Map<String, Object> root;
            try {
                root = MinecraftJson.parseObject(MinecraftJson.text(bytes));
            } catch (RuntimeException e) {
                if (name.toLowerCase(Locale.ROOT).contains("refmap")) {
                    note(collector, "mixin refmap " + name + " could not be parsed: " + e.getMessage());
                }
                continue;
            }
            documents.put(name, root);
            String refmap = MinecraftJson.asString(root.get("refmap"));
            if (refmap != null) {
                declared.add(refmap);
            }
        }

        Map<String, Map<String, String>> members = new LinkedHashMap<String, Map<String, String>>();
        Map<String, String> aliases = new LinkedHashMap<String, String>();
        List<String> files = new ArrayList<String>();
        for (Map.Entry<String, Map<String, Object>> document : documents.entrySet()) {
            ingest(document.getKey(), document.getValue(), members, aliases, files);
        }
        for (String path : declared) {
            String resolved = resolve(pool, path);
            if (resolved == null) {
                note(collector, "mixin refmap " + path + " is declared but not present in the archive");
                continue;
            }
            if (files.contains(resolved)) {
                continue;
            }
            Map<String, Object> root = documents.get(resolved);
            if (root == null) {
                byte[] bytes = bytesOf(pool, resolved);
                if (bytes == null || bytes.length == 0 || bytes.length > MAX_BYTES) {
                    continue;
                }
                try {
                    root = MinecraftJson.parseObject(MinecraftJson.text(bytes));
                } catch (RuntimeException e) {
                    note(collector, "mixin refmap " + resolved + " could not be parsed: " + e.getMessage());
                    continue;
                }
            }
            if (!ingest(resolved, root, members, aliases, files)) {
                note(collector, "declared mixin refmap " + resolved + " has no mappings table");
            }
        }

        if (files.isEmpty() && members.isEmpty() && aliases.isEmpty()) {
            return Refmap.EMPTY;
        }
        return new Refmap(members, aliases, files);
    }

    /**
     * Ingests one parsed JSON document.
     *
     * @return {@code true} when the document carried a {@code mappings} table
     */
    private static boolean ingest(String path, Map<String, Object> root,
                                  Map<String, Map<String, String>> members,
                                  Map<String, String> aliases, List<String> files) {
        if (root == null) {
            return false;
        }
        Map<String, Object> mappings = MinecraftJson.asMap(root.get("mappings"));
        if (mappings == null) {
            return false;
        }
        if (!files.contains(path)) {
            files.add(path);
        }
        for (Map.Entry<String, Object> ownerEntry : mappings.entrySet()) {
            String owner = ownerEntry.getKey();
            Map<String, Object> table = MinecraftJson.asMap(ownerEntry.getValue());
            if (owner == null || table == null || table.isEmpty()) {
                continue;
            }
            Map<String, String> target = members.get(owner);
            if (target == null) {
                target = new LinkedHashMap<String, String>();
                members.put(owner, target);
            }
            for (Map.Entry<String, Object> member : table.entrySet()) {
                String key = member.getKey() == null ? null : member.getKey().trim();
                String value = member.getValue() instanceof String
                        ? ((String) member.getValue()).trim() : null;
                if (key == null || key.isEmpty() || value == null || value.isEmpty()) {
                    continue;
                }
                target.put(key, value);
            }
        }
        Map<String, Object> data = MinecraftJson.asMap(root.get("data"));
        if (data != null) {
            for (Map.Entry<String, Object> section : data.entrySet()) {
                Map<String, Object> table = MinecraftJson.asMap(section.getValue());
                if (table == null || table.isEmpty()) {
                    continue;
                }
                for (Map.Entry<String, Object> alias : table.entrySet()) {
                    String from = alias.getKey();
                    String to = alias.getValue() instanceof String
                            ? ((String) alias.getValue()).trim() : null;
                    if (from == null || from.trim().isEmpty() || to == null || to.isEmpty()) {
                        continue;
                    }
                    aliases.put(from.trim(), to);
                }
            }
        }
        return true;
    }

    /**
     * Cheap pre-filter: only JSON resources whose path mentions {@code mixin} or
     * {@code refmap} can be a mixin configuration or a refmap. The comparison is
     * done without allocating a lower-cased copy, because this runs once per
     * resource entry and an asset-heavy jar has thousands of them.
     */
    private static boolean looksLikeMixinMetadata(String path) {
        if (!path.endsWith(".json") && !endsWithIgnoreCase(path, ".json")) {
            return false;
        }
        return containsIgnoreCaseFast(path, "mixin") || containsIgnoreCaseFast(path, "refmap");
    }

    /**
     * Lower-case-first string search: real archives spell paths in lower case, so
     * the cheap {@code String.contains} intrinsic answers almost every call and
     * the character loop only runs for exotic entries.
     */
    private static boolean containsIgnoreCaseFast(String text, String needle) {
        return text.contains(needle) || indexOfIgnoreCase(text, needle) >= 0;
    }

    private static boolean endsWithIgnoreCase(String text, String suffix) {
        int offset = text.length() - suffix.length();
        if (offset < 0) {
            return false;
        }
        for (int i = 0; i < suffix.length(); i++) {
            if (Character.toLowerCase(text.charAt(offset + i)) != suffix.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static int indexOfIgnoreCase(String text, String needle) {
        int limit = text.length() - needle.length();
        for (int start = 0; start <= limit; start++) {
            int i = 0;
            while (i < needle.length()
                    && Character.toLowerCase(text.charAt(start + i)) == needle.charAt(i)) {
                i++;
            }
            if (i == needle.length()) {
                return start;
            }
        }
        return -1;
    }

    private static byte[] bytesOf(ClassPool pool, String name) {
        ClassPool.Resource resource = pool.resource(name);
        return resource == null ? null : resource.bytes();
    }

    /**
     * Resolves a refmap path declared inside a mixin configuration. Forge writes
     * either a jar-relative path or a bare file name; when the exact entry is
     * missing the first resource with the same file name wins so that configs in
     * sub-directories still resolve.
     */
    private static String resolve(ClassPool pool, String raw) {
        if (raw == null) {
            return null;
        }
        String path = raw.trim().replace('\\', '/');
        while (path.startsWith("/")) {
            path = path.substring(1);
        }
        if (path.isEmpty()) {
            return null;
        }
        if (pool.resource(path) != null) {
            return path;
        }
        String base = path.substring(path.lastIndexOf('/') + 1);
        for (String name : pool.resources().keySet()) {
            if (name == null) {
                continue;
            }
            if (name.equalsIgnoreCase(path)) {
                return name;
            }
            String otherBase = name.substring(name.lastIndexOf('/') + 1);
            if (otherBase.equalsIgnoreCase(base)) {
                return name;
            }
        }
        return null;
    }

    private static void note(MixinCollector collector, String text) {
        if (collector != null) {
            collector.note(text);
        }
    }
}
