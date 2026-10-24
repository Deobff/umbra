package io.umbra.core.minecraft;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.config.ConfigException;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Result of analysing a mod container (Minecraft Fabric/Forge/NeoForge/Quilt
 * metadata, mixin configurations and access wideners/transformers).
 *
 * <p>The profile drives three things:</p>
 * <ul>
 *   <li>extra keep rules (entry classes, mixin classes, targets, shadowed
 *       members, access-widened members);</li>
 *   <li>body-shape exemptions for classes whose bytecode is patched from
 *       outside (mixin classes and their targets);</li>
 *   <li>automatic downgrade of protection features that conflict with a mod
 *       loader (archive encryption, native code, resource rewriting, ...).</li>
 * </ul>
 *
 * <p>{@link #NONE} means "not a mod container"; it never changes anything.</p>
 */
public final class MinecraftProfile {

    /** Empty profile for ordinary jars. */
    public static final MinecraftProfile NONE = new MinecraftProfile(false, "",
            Collections.<String>emptyList(), Collections.<String>emptyList(),
            Collections.<String>emptyList(), Collections.<String>emptyList(),
            Collections.<String>emptyList(), Collections.<String>emptyList(),
            Collections.<String>emptyList(), Collections.<String>emptyList(),
            0, 0);

    private final boolean detected;
    private final String loader;
    private final List<String> modIds;
    private final List<String> evidence;
    private final List<String> keepRules;
    private final List<String> softKeepRules;
    private final List<String> bodySkipGlobs;
    private final List<String> frozenClasses;
    private final List<String> preservedResources;
    private final List<String> notes;
    private final int classCount;
    private final int targetCount;

    public MinecraftProfile(boolean detected, String loader,
                            List<String> modIds, List<String> evidence,
                            List<String> keepRules, List<String> softKeepRules,
                            List<String> bodySkipGlobs, List<String> frozenClasses,
                            List<String> preservedResources, List<String> notes,
                            int classCount, int targetCount) {
        this.detected = detected;
        this.loader = loader == null ? "" : loader;
        this.modIds = unmodifiable(modIds);
        this.evidence = unmodifiable(evidence);
        this.keepRules = unmodifiable(keepRules);
        this.softKeepRules = unmodifiable(softKeepRules);
        this.bodySkipGlobs = unmodifiable(bodySkipGlobs);
        this.frozenClasses = unmodifiable(frozenClasses);
        this.preservedResources = unmodifiable(preservedResources);
        this.notes = unmodifiable(notes);
        this.classCount = classCount;
        this.targetCount = targetCount;
    }

    private static List<String> unmodifiable(List<String> values) {
        return values == null ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new java.util.ArrayList<String>(values));
    }

    public boolean detected() {
        return detected;
    }

    /** Comma separated loader list, for example {@code "fabric,mixin"}. */
    public String loader() {
        return loader;
    }

    public List<String> modIds() {
        return modIds;
    }

    public List<String> evidence() {
        return evidence;
    }

    /** Keep rules in the format understood by {@code DefaultRuleSet}. */
    public List<String> keepRules() {
        return keepRules;
    }

    public List<String> softKeepRules() {
        return softKeepRules;
    }

    /** Ant-style class globs whose method bodies must not be rewritten. */
    public List<String> bodySkipGlobs() {
        return bodySkipGlobs;
    }

    public List<String> frozenClasses() {
        return frozenClasses;
    }

    /** Resource paths that must not be renamed or rewritten. */
    public List<String> preservedResources() {
        return preservedResources;
    }

    public List<String> notes() {
        return notes;
    }

    public int classCount() {
        return classCount;
    }

    public int targetCount() {
        return targetCount;
    }

    /**
     * Applies the mod-container downgrade policy.
     *
     * <p>A mod loader loads and patches a mod before (and independently of) the
     * protected program, so archive-level protections break it. The defaults
     * therefore disable class encryption, standalone integrity, native code,
     * resource path/content rewriting, reference hiding and member trimming,
     * and disable virtualization unless {@code minecraft.forceVmp} is true.
     * Renaming, string/integer encryption, control flow, anti-LLM and the
     * watermark stay enabled; classes that are externally visible (entry
     * points, mixin classes and targets, coremods) are exempted through the
     * keep/body-skip rules instead of through global switches.</p>
     *
     * <p>{@code minecraft.allowConflicts=true} skips the downgrade for users who
     * know exactly what they are doing.</p>
     */
    public UmbraConfig adjust(UmbraConfig base) {
        if (base == null || !detected || base.optionBool("minecraft.allowConflicts", false)) {
            return base;
        }
        UmbraConfig.Builder b = base.toBuilder();
        b.option("minecraft.detected", "true");
        b.option("minecraft.loader", loader);
        b.option("classEncryption.enabled", "false");
        b.option("classEncryption.integrity", "false");
        b.option("integrity.enabled", "false");
        b.option("native.enabled", "false");
        b.referenceObfuscation(new UmbraConfig.ReferenceOptions(false));
        b.resources(new UmbraConfig.ResourceOptions(false, false,
                Collections.<String>emptyList()));
        b.trim(new UmbraConfig.TrimOptions(false, false, false));
        boolean forceVmp = base.optionBool("minecraft.forceVmp", false);
        if (!forceVmp) {
            b.methodVirtualization(new UmbraConfig.VirtualizationOptions(false,
                    base.methodVirtualization().maxInstructions(),
                    base.methodVirtualization().maxMethods()));
            b.option("vm2.enabled", "false");
        }
        try {
            return b.build();
        } catch (ConfigException e) {
            // The base configuration is already valid; a rebuild cannot fail.
            return base;
        }
    }

    /** Summary map for logs, reports and the GUI state. */
    public Map<String, Object> asMap() {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("detected", Boolean.valueOf(detected));
        out.put("loader", loader);
        out.put("modIds", modIds);
        out.put("evidence", evidence);
        out.put("keepRules", Integer.valueOf(keepRules.size()));
        out.put("softKeepRules", Integer.valueOf(softKeepRules.size()));
        out.put("bodySkipGlobs", Integer.valueOf(bodySkipGlobs.size()));
        out.put("frozenClasses", Integer.valueOf(frozenClasses.size()));
        out.put("classCount", Integer.valueOf(classCount));
        out.put("targets", Integer.valueOf(targetCount));
        out.put("preservedResources", preservedResources);
        out.put("notes", notes);
        Map<String, Object> adjusted = new LinkedHashMap<String, Object>();
        adjusted.put("classEncryption", Boolean.FALSE);
        adjusted.put("integrity", Boolean.FALSE);
        adjusted.put("native", Boolean.FALSE);
        adjusted.put("referenceObfuscation", Boolean.FALSE);
        adjusted.put("resources", Boolean.FALSE);
        adjusted.put("trim", Boolean.FALSE);
        adjusted.put("virtualization", Boolean.FALSE);
        out.put("disabledFeatures", adjusted);
        return out;
    }
}
