package io.umbra.core.compat;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Mutable per-run layout state: detection result, options and the counters that
 * become the {@code layout.*} statistics.
 *
 * <p>One context is attached to each {@link io.umbra.core.model.ClassPool} by
 * {@code Jars.read} and consumed by {@code Jars.write}. It is confined to the
 * run that owns the pool, exactly like the pool itself.</p>
 */
public final class LayoutContext {

    private final JarLayout layout;
    private final LayoutOptions options;
    private final List<String> warnings = new ArrayList<String>();

    private final Map<String, VersionedClass> versionedClasses =
            new LinkedHashMap<String, VersionedClass>();
    private final List<String> moduleInfoEntries = new ArrayList<String>();
    private final Map<String, byte[]> moduleInfoBytes = new LinkedHashMap<String, byte[]>();

    private long springBootClasses;
    private long warClasses;
    private long multiReleaseClasses;
    private long preservedEntries;
    private long duplicateClasses;
    private long duplicateEntries;
    private long moduleInfoKept;
    private long servicesRewritten;
    private long manifestAttributesRewritten;
    private long versionedClassesRemapped;
    private String moduleInfoAction = "none";

    public LayoutContext(JarLayout layout, LayoutOptions options) {
        this.layout = layout == null ? JarLayout.flat() : layout;
        this.options = options == null ? LayoutOptions.defaults() : options;
    }

    public JarLayout layout() {
        return layout;
    }

    public LayoutOptions options() {
        return options;
    }

    /** Detected class prefix; empty for flat layouts. */
    public String classPrefix() {
        return layout.classPrefix();
    }

    public List<String> warnings() {
        return warnings;
    }

    public void addWarning(String warning) {
        if (warning != null && !warnings.contains(warning)) {
            warnings.add(warning);
        }
    }

    // ------------------------------------------------------------------
    // Read-side bookkeeping
    // ------------------------------------------------------------------

    public void addSpringBootClass() {
        springBootClasses++;
    }

    public void addWarClass() {
        warClasses++;
    }

    public void addPreservedEntry() {
        preservedEntries++;
    }

    public void addDuplicateClass() {
        duplicateClasses++;
    }

    public void addDuplicateEntry() {
        duplicateEntries++;
    }

    public void addVersionedClass(VersionedClass versionedClass) {
        if (versionedClass == null) {
            return;
        }
        versionedClasses.put(versionedClass.entryName(), versionedClass);
        multiReleaseClasses++;
    }

    /** Counts a versioned class that was flattened into a base path (flatten mode). */
    public void addFlattenedVersionedClass() {
        multiReleaseClasses++;
    }

    public Map<String, VersionedClass> versionedClasses() {
        return Collections.unmodifiableMap(versionedClasses);
    }

    public boolean hasVersionedClasses() {
        return !versionedClasses.isEmpty();
    }

    /** Records the base (non-versioned) {@code module-info.class} of the archive. */
    public void addModuleInfoEntry(String entryName, byte[] bytes) {
        if (entryName == null || moduleInfoEntries.contains(entryName)) {
            return;
        }
        moduleInfoEntries.add(entryName);
        moduleInfoBytes.put(entryName, bytes);
    }

    public List<String> moduleInfoEntries() {
        return Collections.unmodifiableList(moduleInfoEntries);
    }

    public byte[] moduleInfoBytes(String entryName) {
        return moduleInfoBytes.get(entryName);
    }

    // ------------------------------------------------------------------
    // Write-side bookkeeping
    // ------------------------------------------------------------------

    public void addModuleInfoKept(int count) {
        moduleInfoKept += count;
    }

    public void addModuleInfoAction(String action) {
        if (action != null && !"none".equals(action)) {
            moduleInfoAction = action;
        }
    }

    public void addServicesRewritten(int count) {
        servicesRewritten += count;
    }

    public void addManifestAttributesRewritten(int count) {
        manifestAttributesRewritten += count;
    }

    public void addVersionedClassRemapped() {
        versionedClassesRemapped++;
    }

    public long springBootClasses() {
        return springBootClasses;
    }

    public long warClasses() {
        return warClasses;
    }

    public long multiReleaseClasses() {
        return multiReleaseClasses;
    }

    public long preservedEntries() {
        return preservedEntries;
    }

    public long duplicateClasses() {
        return duplicateClasses;
    }

    public long moduleInfoKept() {
        return moduleInfoKept;
    }

    public long servicesRewritten() {
        return servicesRewritten;
    }

    public long manifestAttributesRewritten() {
        return manifestAttributesRewritten;
    }

    public long versionedClassesRemapped() {
        return versionedClassesRemapped;
    }

    /** Builds the statistics report consumed by the engine and audit reports. */
    public LayoutReport report() {
        return new LayoutReport(layout, buildCounts(), buildTexts());
    }

    private Map<String, Long> buildCounts() {
        Map<String, Long> counts = new LinkedHashMap<String, Long>();
        counts.put("layout.springBoot.classes", Long.valueOf(springBootClasses));
        counts.put("layout.war.classes", Long.valueOf(warClasses));
        counts.put("layout.multiRelease.classes", Long.valueOf(multiReleaseClasses));
        counts.put("layout.moduleInfo", Long.valueOf(moduleInfoKept));
        counts.put("layout.services", Long.valueOf(servicesRewritten));
        counts.put("layout.manifest.rewritten", Long.valueOf(manifestAttributesRewritten));
        counts.put("layout.duplicates", Long.valueOf(duplicateClasses + duplicateEntries));
        counts.put("layout.preserved.entries", Long.valueOf(preservedEntries));
        counts.put("layout.multiRelease.remapped", Long.valueOf(versionedClassesRemapped));
        return counts;
    }

    private Map<String, String> buildTexts() {
        Map<String, String> texts = new LinkedHashMap<String, String>();
        texts.put("layout.kind", layout.kindId());
        texts.put("layout.classPrefix", layout.classPrefix());
        texts.put("layout.multiRelease.mode",
                options.multiRelease() == LayoutOptions.MultiReleaseMode.PRESERVE ? "preserve" : "flatten");
        texts.put("layout.moduleInfo.action", moduleInfoAction);
        return texts;
    }
}
