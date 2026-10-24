package io.umbra.core.model;

import org.objectweb.asm.tree.ClassNode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Mutable in-memory representation of the program being processed.
 *
 * <p>Classes are keyed by internal name. Resources keep their original entry
 * names so that manifests, service descriptors and assets survive a round-trip.
 * Multi-release class entries remember their {@code META-INF/versions/...}
 * prefix.</p>
 */
public final class ClassPool {

    private final Map<String, ClassNode> classes = new LinkedHashMap<String, ClassNode>();
    private final Set<String> generated = new LinkedHashSet<String>();
    private final Map<String, String> entryPrefixes = new LinkedHashMap<String, String>();
    private final Map<String, Long> classTimes = new LinkedHashMap<String, Long>();
    private final Map<String, byte[]> originalBytes = new LinkedHashMap<String, byte[]>();
    private final Map<String, Resource> resources = new LinkedHashMap<String, Resource>();
    private final Set<String> frozen = new LinkedHashSet<String>();
    private final Map<String, byte[]> rawOutput = new LinkedHashMap<String, byte[]>();

    private String mainClass;

    /** Freezes a class so that no pass renames or rewrites it. */
    public void freeze(String name) {
        frozen.add(name);
    }

    public boolean isFrozen(String name) {
        return frozen.contains(name);
    }

    public void putClass(String sourceEntry, byte[] bytes, ClassNode node) {
        classes.put(node.name, node);
        originalBytes.put(node.name, bytes);
        String suffix = node.name + ".class";
        String prefix = "";
        if (sourceEntry != null && sourceEntry.endsWith(suffix) && !sourceEntry.equals(suffix)) {
            prefix = sourceEntry.substring(0, sourceEntry.length() - suffix.length());
        }
        entryPrefixes.put(node.name, prefix);
        classTimes.put(node.name, Long.valueOf(0L));
    }

    public void setClassTime(String name, long time) {
        classTimes.put(name, Long.valueOf(time));
    }

    public void addGenerated(ClassNode node) {
        classes.put(node.name, node);
        generated.add(node.name);
        entryPrefixes.put(node.name, "");
        classTimes.put(node.name, Long.valueOf(315532800000L)); // 1980-01-01
    }

    /**
     * Atomically applies a batch of class renames.
     *
     * <p>Batch application avoids transient name collisions when class A is
     * renamed to the old name of class B.</p>
     *
     * @param oldToNew     original name to new name
     * @param remapped     remapped node for every original name
     */
    public void applyRenames(Map<String, String> oldToNew, Map<String, ClassNode> remapped) {
        Map<String, ClassNode> newClasses = new LinkedHashMap<String, ClassNode>();
        Map<String, String> newPrefixes = new LinkedHashMap<String, String>();
        Map<String, Long> newTimes = new LinkedHashMap<String, Long>();
        Map<String, byte[]> newOriginals = new LinkedHashMap<String, byte[]>();
        Set<String> newGenerated = new LinkedHashSet<String>();

        for (String oldName : new java.util.ArrayList<String>(classes.keySet())) {
            String newName = oldToNew.containsKey(oldName) ? oldToNew.get(oldName) : oldName;
            ClassNode node = remapped.get(oldName);
            if (node == null) {
                node = classes.get(oldName);
            }
            newClasses.put(newName, node);
            newPrefixes.put(newName, entryPrefixes.containsKey(oldName) ? entryPrefixes.get(oldName) : "");
            newTimes.put(newName, classTimes.containsKey(oldName) ? classTimes.get(oldName) : Long.valueOf(0L));
            if (originalBytes.containsKey(oldName)) {
                newOriginals.put(newName, originalBytes.get(oldName));
            }
            if (generated.contains(oldName)) {
                newGenerated.add(newName);
            }
        }

        classes.clear();
        classes.putAll(newClasses);
        entryPrefixes.clear();
        entryPrefixes.putAll(newPrefixes);
        classTimes.clear();
        classTimes.putAll(newTimes);
        originalBytes.clear();
        originalBytes.putAll(newOriginals);
        generated.clear();
        generated.addAll(newGenerated);
    }

    /** Replaces a class node under a new internal name, preserving entry metadata. */
    public void replaceClass(String oldName, String newName, ClassNode node) {
        String prefix = entryPrefixes.remove(oldName);
        Long time = classTimes.remove(oldName);
        byte[] original = originalBytes.remove(oldName);
        boolean wasGenerated = generated.remove(oldName);
        classes.remove(oldName);
        classes.put(newName, node);
        entryPrefixes.put(newName, prefix == null ? "" : prefix);
        classTimes.put(newName, time == null ? Long.valueOf(0L) : time);
        if (original != null) {
            originalBytes.put(newName, original);
        }
        if (wasGenerated) {
            generated.add(newName);
        }
    }

    public void removeClass(String name) {
        classes.remove(name);
        originalBytes.remove(name);
        entryPrefixes.remove(name);
        classTimes.remove(name);
        generated.remove(name);
    }

    public Map<String, ClassNode> classes() {
        return Collections.unmodifiableMap(classes);
    }

    public ClassNode getClass(String internalName) {
        return classes.get(internalName);
    }

    public boolean isGenerated(String name) {
        return generated.contains(name);
    }

    public String entryPrefix(String name) {
        String prefix = entryPrefixes.get(name);
        return prefix == null ? "" : prefix;
    }

    public long classTime(String name) {
        Long time = classTimes.get(name);
        return time == null ? 0L : time.longValue();
    }

    public byte[] originalBytes(String name) {
        return originalBytes.get(name);
    }

    /** Marks a class to be written from pre-existing bytes (incremental reuse). */
    public void putRawOutput(String name, byte[] bytes) {
        rawOutput.put(name, bytes);
    }

    public byte[] rawOutput(String name) {
        return rawOutput.get(name);
    }

    public void putResource(String name, byte[] bytes, long time, int method) {
        resources.put(name, new Resource(name, bytes, time, method));
    }

    public void removeResource(String name) {
        resources.remove(name);
    }

    public Map<String, Resource> resources() {
        return Collections.unmodifiableMap(resources);
    }

    public Resource resource(String name) {
        return resources.get(name);
    }

    public String mainClass() {
        return mainClass;
    }

    public void setMainClass(String mainClass) {
        this.mainClass = mainClass;
    }

    /** A non-class zip entry. */
    public static final class Resource {
        private final String name;
        private final byte[] bytes;
        private final long time;
        private final int method;

        public Resource(String name, byte[] bytes, long time, int method) {
            this.name = name;
            this.bytes = bytes;
            this.time = time;
            this.method = method;
        }

        public String name() { return name; }
        public byte[] bytes() { return bytes; }
        public long time() { return time; }
        public int method() { return method; }
    }
}
