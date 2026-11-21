package io.umbra.core.minecraft.refmap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Parsed Mixin refmap: the Forge 1.12-1.16 (and legacy Fabric) mapping that
 * translates the member references written in mixin annotations into the names
 * that actually exist in the shipped bytecode.
 *
 * <p>Refmap JSON shape, as written by the Mixin annotation processor (a real
 * fragment):</p>
 *
 * <pre>
 * {
 *   "mappings": {
 *     "com.example.mod.target.BlockTicker": {
 *       "tick": "func_1234_a",
 *       "counter": "field_5678_b",
 *       "runGameLoop(I)V": "func_71407_l"
 *     }
 *   },
 *   "data": {
 *     "searge": {
 *       "com.example.mod.target.BlockTicker": "com.example.mod.target.BlockTicker"
 *     }
 *   }
 * }
 * </pre>
 *
 * <p>{@code mappings} is keyed by the class name exactly as spelled in the
 * annotation (both dotted and slashed owners occur in the wild) and each entry
 * maps a <em>reference</em> - a member name, optionally followed by a descriptor
 * ({@code name(desc)}) or separated by one space ({@code name desc}) - to the
 * <em>production</em> member name. {@code data} holds per-namespace class
 * aliases.</p>
 *
 * <p>The class is immutable and de-duplicated so that repeated analysis of the
 * same class pool produces identical output.</p>
 */
public final class Refmap {

    public static final Refmap EMPTY = new Refmap(
            Collections.<String, Map<String, String>>emptyMap(),
            Collections.<String, String>emptyMap(),
            Collections.<String>emptyList());

    private final Map<String, Map<String, String>> members;
    private final Map<String, String> classAliases;
    private final List<String> files;
    private final int memberCount;

    /**
     * @param members      owner internal name (dots are normalized) -&gt; reference
     *                     key -&gt; production member name
     * @param classAliases {@code data} section aliases, owner internal name -&gt;
     *                     alias internal name
     * @param files        refmap resource paths that contributed to this instance
     */
    public Refmap(Map<String, Map<String, String>> members,
                  Map<String, String> classAliases,
                  List<String> files) {
        Map<String, Map<String, String>> owners = new LinkedHashMap<String, Map<String, String>>();
        int entries = 0;
        if (members != null) {
            for (Map.Entry<String, Map<String, String>> owner : members.entrySet()) {
                String ownerName = normalizeClassName(owner.getKey());
                Map<String, String> table = owner.getValue();
                if (ownerName == null || table == null || table.isEmpty()) {
                    continue;
                }
                Map<String, String> target = owners.get(ownerName);
                if (target == null) {
                    target = new LinkedHashMap<String, String>();
                    owners.put(ownerName, target);
                }
                for (Map.Entry<String, String> entry : table.entrySet()) {
                    String key = entry.getKey() == null ? null : entry.getKey().trim();
                    String value = sanitizeMemberName(entry.getValue());
                    if (key == null || key.isEmpty() || value == null || key.charAt(0) == '<') {
                        continue;
                    }
                    if (target.put(key, value) == null) {
                        entries++;
                    }
                }
            }
        }
        Map<String, String> aliases = new LinkedHashMap<String, String>();
        if (classAliases != null) {
            for (Map.Entry<String, String> alias : classAliases.entrySet()) {
                String from = normalizeClassName(alias.getKey());
                String to = normalizeClassName(alias.getValue());
                if (from == null || to == null || from.equals(to)) {
                    continue;
                }
                aliases.put(from, to);
            }
        }
        List<String> normalizedFiles = new ArrayList<String>();
        if (files != null) {
            for (String file : files) {
                if (file != null && !file.trim().isEmpty() && !normalizedFiles.contains(file.trim())) {
                    normalizedFiles.add(file.trim());
                }
            }
        }
        Collections.sort(normalizedFiles);
        this.members = Collections.unmodifiableMap(owners);
        this.classAliases = Collections.unmodifiableMap(aliases);
        this.files = Collections.unmodifiableList(normalizedFiles);
        this.memberCount = entries;
    }

    public boolean isEmpty() {
        return members.isEmpty() && classAliases.isEmpty() && files.isEmpty();
    }

    /** Number of {@code owner#member} entries across every parsed refmap. */
    public int memberCount() {
        return memberCount;
    }

    /** Number of target classes that carry member mappings. */
    public int ownerCount() {
        return members.size();
    }

    /** Refmap resource paths that were parsed, sorted. */
    public List<String> files() {
        return files;
    }

    /** True when this refmap has member entries for the class. */
    public boolean hasOwner(String owner) {
        String ownerName = normalizeClassName(owner);
        return ownerName != null && members.containsKey(ownerName);
    }

    /**
     * Class names to try for one annotated owner: the owner itself plus the
     * {@code data} section alias, when the two differ.
     */
    public List<String> ownersFor(String owner) {
        String ownerName = normalizeClassName(owner);
        if (ownerName == null) {
            return Collections.emptyList();
        }
        List<String> out = new ArrayList<String>(1);
        out.add(ownerName);
        String alias = classAliases.get(ownerName);
        if (alias != null && !alias.equals(ownerName)) {
            out.add(alias);
        }
        return out;
    }

    /**
     * Production names recorded for one member reference.
     *
     * <p>Accepts every key shape the annotation processor emits: {@code name},
     * {@code name(desc)} and {@code name desc}. When the caller passes a
     * descriptor, keys that spell a different descriptor are skipped; when it
     * does not, every overload recorded for that name is returned so that all of
     * them survive renaming.</p>
     *
     * @return production names, de-duplicated; empty when the refmap has no entry
     */
    public List<String> productionNames(String owner, String name, String desc) {
        if (owner == null || name == null || name.isEmpty() || members.isEmpty()) {
            return Collections.emptyList();
        }
        String ownerName = normalizeClassName(owner);
        Map<String, String> table = ownerName == null ? null : members.get(ownerName);
        if (table == null) {
            return Collections.emptyList();
        }
        LinkedHashSet<String> out = new LinkedHashSet<String>();
        for (Map.Entry<String, String> entry : table.entrySet()) {
            String key = entry.getKey();
            if (!key.startsWith(name)) {
                continue;
            }
            String tail = key.substring(name.length());
            if (!tail.isEmpty() && tail.charAt(0) != '(' && tail.charAt(0) != ' ') {
                continue;
            }
            if (!tail.isEmpty() && desc != null && !tail.trim().equals(desc)) {
                continue;
            }
            out.add(entry.getValue());
        }
        return new ArrayList<String>(out);
    }

    /** One-line summary for the analyzer notes. */
    public String describe() {
        return memberCount + " member mapping(s) for " + members.size()
                + " class(es) in " + files.size() + " refmap file(s)";
    }

    /** {@code data} section alias for the class, or {@code null}. */
    public String classAlias(String owner) {
        String ownerName = normalizeClassName(owner);
        return ownerName == null ? null : classAliases.get(ownerName);
    }

    private static String normalizeClassName(String raw) {
        if (raw == null) {
            return null;
        }
        String name = raw.trim();
        if (name.isEmpty()) {
            return null;
        }
        if (name.length() > 2 && name.charAt(0) == 'L' && name.charAt(name.length() - 1) == ';') {
            name = name.substring(1, name.length() - 1);
        }
        name = name.replace('.', '/');
        if (name.isEmpty() || name.indexOf(';') >= 0 || name.indexOf('(') >= 0) {
            return null;
        }
        return name;
    }

    private static String sanitizeMemberName(Object raw) {
        if (raw == null) {
            return null;
        }
        return sanitizeMemberName(raw instanceof String ? (String) raw : null);
    }

    private static String sanitizeMemberName(String raw) {
        if (raw == null) {
            return null;
        }
        String value = raw.trim();
        if (value.isEmpty()) {
            return null;
        }
        int space = value.indexOf(' ');
        if (space > 0) {
            value = value.substring(0, space).trim();
        }
        int paren = value.indexOf('(');
        if (paren > 0) {
            value = value.substring(0, paren).trim();
        }
        if (value.isEmpty() || value.charAt(0) == '<') {
            return null;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!Character.isJavaIdentifierPart(c) || c == '/') {
                return null;
            }
        }
        return value;
    }
}
