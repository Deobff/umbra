package io.umbra.core.minecraft.mixin;

import io.umbra.core.minecraft.MixinAnalysis;

import java.util.ArrayList;
import java.util.TreeSet;

/**
 * Accumulates Mixin-derived keep information.
 *
 * <p>All sets are sorted and de-duplicated so that the produced
 * {@link MixinAnalysis} is deterministic for a given class pool: repeated runs
 * and differently ordered inputs yield identical lists. The collector is the
 * only place that formats keep rules, which keeps the {@code owner#name(desc)}
 * shape in one location.</p>
 *
 * <p>Refmap bookkeeping ({@link #refmapFile(String)} /
 * {@link #refmapHit(String, String, String)}) is collected the same way so the
 * report lists exactly which references were translated to a production name.</p>
 */
public final class MixinCollector {

    private final TreeSet<String> mixinClasses = new TreeSet<String>();
    private final TreeSet<String> targetClasses = new TreeSet<String>();
    private final TreeSet<String> keepRules = new TreeSet<String>();
    private final TreeSet<String> bodySkipGlobs = new TreeSet<String>();
    private final TreeSet<String> notes = new TreeSet<String>();
    private final TreeSet<String> refmapFiles = new TreeSet<String>();
    private final TreeSet<String> refmapHits = new TreeSet<String>();

    public void addMixin(String internalName) {
        if (internalName != null && !internalName.isEmpty()) {
            mixinClasses.add(internalName);
        }
    }

    public void addTarget(String internalName) {
        if (internalName != null && !internalName.isEmpty()) {
            targetClasses.add(internalName);
        }
    }

    public void keepClass(String internalName) {
        if (internalName != null && !internalName.isEmpty()) {
            keepRules.add(internalName);
        }
    }

    public void keepMember(String owner, String name, String desc) {
        if (owner == null || owner.isEmpty() || name == null || name.isEmpty()) {
            return;
        }
        StringBuilder rule = new StringBuilder(owner.length() + name.length() + 2);
        rule.append(owner).append('#').append(name);
        if (desc != null && !desc.isEmpty()) {
            rule.append(desc);
        }
        keepRules.add(rule.toString());
    }

    public void bodySkip(String internalName) {
        if (internalName != null && !internalName.isEmpty()) {
            bodySkipGlobs.add(internalName);
        }
    }

    public void note(String note) {
        if (note != null && !note.isEmpty()) {
            notes.add(note);
        }
    }

    /** Records a refmap resource that contributed mappings. */
    public void refmapFile(String path) {
        if (path != null && !path.isEmpty()) {
            refmapFiles.add(path);
        }
    }

    /** Records one reference translated by a refmap. */
    public void refmapHit(String owner, String reference, String production) {
        if (owner == null || owner.isEmpty() || reference == null || reference.isEmpty()
                || production == null || production.isEmpty()) {
            return;
        }
        refmapHits.add(owner + "#" + reference + "->" + production);
    }

    public int refmapHitCount() {
        return refmapHits.size();
    }

    public boolean isEmpty() {
        return mixinClasses.isEmpty() && targetClasses.isEmpty()
                && keepRules.isEmpty() && bodySkipGlobs.isEmpty() && notes.isEmpty()
                && refmapFiles.isEmpty() && refmapHits.isEmpty();
    }

    public MixinAnalysis build() {
        if (isEmpty()) {
            return MixinAnalysis.EMPTY;
        }
        return new MixinAnalysis(
                new ArrayList<String>(mixinClasses),
                new ArrayList<String>(targetClasses),
                new ArrayList<String>(keepRules),
                new ArrayList<String>(bodySkipGlobs),
                new ArrayList<String>(notes),
                new ArrayList<String>(refmapFiles),
                new ArrayList<String>(refmapHits));
    }
}
