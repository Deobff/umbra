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
 */
public final class MixinAnalysis {

    public static final MixinAnalysis EMPTY = new MixinAnalysis(
            Collections.<String>emptyList(), Collections.<String>emptyList(),
            Collections.<String>emptyList(), Collections.<String>emptyList(),
            Collections.<String>emptyList());

    private final List<String> mixinClasses;
    private final List<String> targetClasses;
    private final List<String> keepRules;
    private final List<String> bodySkipGlobs;
    private final List<String> notes;

    public MixinAnalysis(List<String> mixinClasses, List<String> targetClasses,
                         List<String> keepRules, List<String> bodySkipGlobs,
                         List<String> notes) {
        this.mixinClasses = unmodifiable(mixinClasses);
        this.targetClasses = unmodifiable(targetClasses);
        this.keepRules = unmodifiable(keepRules);
        this.bodySkipGlobs = unmodifiable(bodySkipGlobs);
        this.notes = unmodifiable(notes);
    }

    private static List<String> unmodifiable(List<String> values) {
        return values == null ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new java.util.ArrayList<String>(values));
    }

    /** Internal names of classes carrying {@code @Mixin}. */
    public List<String> mixinClasses() {
        return mixinClasses;
    }

    /** Internal names of classes referenced as mixin targets. */
    public List<String> targetClasses() {
        return targetClasses;
    }

    /** Keep rules (class globs or {@code owner#name(desc)}) for mixin/target members. */
    public List<String> keepRules() {
        return keepRules;
    }

    /** Class globs whose method bodies must not be rewritten. */
    public List<String> bodySkipGlobs() {
        return bodySkipGlobs;
    }

    public List<String> notes() {
        return notes;
    }
}
