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
 */
public final class MixinCollector {

    private final TreeSet<String> mixinClasses = new TreeSet<String>();
    private final TreeSet<String> targetClasses = new TreeSet<String>();
    private final TreeSet<String> keepRules = new TreeSet<String>();
    private final TreeSet<String> bodySkipGlobs = new TreeSet<String>();
    private final TreeSet<String> notes = new TreeSet<String>();

    /** Records a class carrying {@code @Mixin}. */
    public void addMixin(String internalName) {
        if (internalName != null && !internalName.isEmpty()) {
            mixinClasses.add(internalName);
        }
    }

    /** Records a class referenced as a {@code @Mixin} target. */
    public void addTarget(String internalName) {
        if (internalName != null && !internalName.isEmpty()) {
            targetClasses.add(internalName);
        }
    }

    /**
     * Adds a keep rule for a whole class. The internal name is an exact
     * (wildcard-free) Ant glob, so only that class is preserved.
     */
    public void keepClass(String internalName) {
        if (internalName != null && !internalName.isEmpty()) {
            keepRules.add(internalName);
        }
    }

    /**
     * Adds a member keep rule. {@code owner} is the internal class name,
     * {@code desc} may be {@code null} to keep every descriptor of
     * {@code name}.
     */
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

    /** Exempts a class from method-body rewriting. */
    public void bodySkip(String internalName) {
        if (internalName != null && !internalName.isEmpty()) {
            bodySkipGlobs.add(internalName);
        }
    }

    /** Adds a short diagnostic note; duplicates collapse. */
    public void note(String note) {
        if (note != null && !note.isEmpty()) {
            notes.add(note);
        }
    }

    /** True when nothing was found, so {@link MixinAnalysis#EMPTY} can be reused. */
    public boolean isEmpty() {
        return mixinClasses.isEmpty() && targetClasses.isEmpty()
                && keepRules.isEmpty() && bodySkipGlobs.isEmpty() && notes.isEmpty();
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
                new ArrayList<String>(notes));
    }
}
