package io.umbra.core.minecraft;

import java.util.Collections;
import java.util.List;

/**
 * Result of scanning Mixin annotations in the class pool.
 *
 * <p>Mixin classes are patched into target classes at runtime by name and by
 * bytecode shape. Their own class/member names and the referenced target
 * members must survive obfuscation, and both sides must keep their method
 * bodies intact (injection points are matched against transformed bytecode).</p>
 *
 * <p>{@link #refmapFiles()} lists the Mixin refmaps that contributed keep rules
 * and {@link #refmapHits()} lists the references that were translated from the
 * pre-obfuscation name written in the annotation to the production name that
 * exists in the archive, as {@code owner#reference->production}.</p>
 */
public final class MixinAnalysis {

    public static final MixinAnalysis EMPTY = new MixinAnalysis(
            Collections.<String>emptyList(), Collections.<String>emptyList(),
            Collections.<String>emptyList(), Collections.<String>emptyList(),
            Collections.<String>emptyList(), Collections.<String>emptyList(),
            Collections.<String>emptyList());

    private final List<String> mixinClasses;
    private final List<String> targetClasses;
    private final List<String> keepRules;
    private final List<String> bodySkipGlobs;
    private final List<String> notes;
    private final List<String> refmapFiles;
    private final List<String> refmapHits;

    public MixinAnalysis(List<String> mixinClasses, List<String> targetClasses,
                         List<String> keepRules, List<String> bodySkipGlobs,
                         List<String> notes, List<String> refmapFiles,
                         List<String> refmapHits) {
        this.mixinClasses = unmodifiable(mixinClasses);
        this.targetClasses = unmodifiable(targetClasses);
        this.keepRules = unmodifiable(keepRules);
        this.bodySkipGlobs = unmodifiable(bodySkipGlobs);
        this.notes = unmodifiable(notes);
        this.refmapFiles = unmodifiable(refmapFiles);
        this.refmapHits = unmodifiable(refmapHits);
    }

    private static List<String> unmodifiable(List<String> values) {
        return values == null ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new java.util.ArrayList<String>(values));
    }

    public List<String> mixinClasses() {
        return mixinClasses;
    }

    public List<String> targetClasses() {
        return targetClasses;
    }

    public List<String> keepRules() {
        return keepRules;
    }

    public List<String> bodySkipGlobs() {
        return bodySkipGlobs;
    }

    public List<String> notes() {
        return notes;
    }

    /** Refmap resources that were parsed and used, sorted. */
    public List<String> refmapFiles() {
        return refmapFiles;
    }

    /** References kept by their refmap production name, sorted. */
    public List<String> refmapHits() {
        return refmapHits;
    }
}
