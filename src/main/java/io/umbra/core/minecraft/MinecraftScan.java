package io.umbra.core.minecraft;

import io.umbra.core.util.Log;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Mutable accumulator for one mod-container detection run.
 *
 * <p>Keeps insertion order so the resulting profile is deterministic for a
 * given archive, deduplicates every rule category and resolves the container
 * loader list from a canonical priority (fabric, quilt, forge, neoforge,
 * mixin). Detectors only add facts; {@link #toProfile()} materialises the
 * immutable {@link MinecraftProfile}.</p>
 */
final class MinecraftScan {

    private static final int MAX_EVIDENCE = 64;
    private static final int MAX_NESTED_JAR_NAMES = 5;

    private final Log log;
    private final Map<String, String> evidence = new LinkedHashMap<String, String>();
    private final Set<String> modIds = new LinkedHashSet<String>();
    private final Set<String> keepRules = new LinkedHashSet<String>();
    private final Set<String> softKeepRules = new LinkedHashSet<String>();
    private final Set<String> bodySkipGlobs = new LinkedHashSet<String>();
    private final Set<String> frozenClasses = new LinkedHashSet<String>();
    private final Set<String> preservedResources = new LinkedHashSet<String>();
    private final List<String> notes = new ArrayList<String>();

    private final Set<String> keptClasses = new LinkedHashSet<String>();
    private final Set<String> targetClasses = new LinkedHashSet<String>();
    private final Set<String> parsedMixinConfigs = new LinkedHashSet<String>();
    private final Set<String> parsedAccessWideners = new LinkedHashSet<String>();
    private final Set<String> parsedAccessTransformers = new LinkedHashSet<String>();
    private final Set<String> pendingMixinConfigs = new LinkedHashSet<String>();
    private final Set<String> pendingAccessWideners = new LinkedHashSet<String>();
    private final Set<String> pendingAccessTransformers = new LinkedHashSet<String>();
    private final List<String> nestedJars = new ArrayList<String>();

    private boolean fabric;
    private boolean quilt;
    private boolean forge;
    private boolean neoforge;
    private boolean mixin;
    private boolean accessWidenerSeen;
    private boolean accessTransformerSeen;

    MinecraftScan(Log log) {
        this.log = log == null ? new Log(null, false) : log;
    }

    // ------------------------------------------------------------------
    // facts
    // ------------------------------------------------------------------

    void warn(String format, Object... args) {
        log.warn(format, args);
    }

    void debug(String format, Object... args) {
        log.debug(format, args);
    }

    void loaderFabric() {
        fabric = true;
    }

    void loaderQuilt() {
        quilt = true;
    }

    void loaderForge() {
        forge = true;
    }

    void loaderNeoForge() {
        neoforge = true;
    }

    void loaderMixin() {
        mixin = true;
    }

    void accessWidenerSeen() {
        accessWidenerSeen = true;
    }

    void accessTransformerSeen() {
        accessTransformerSeen = true;
    }

    void evidence(String key, String description) {
        if (key == null || key.isEmpty() || evidence.containsKey(key)) {
            return;
        }
        if (evidence.size() >= MAX_EVIDENCE) {
            return;
        }
        evidence.put(key, description == null ? key : description);
    }

    void modId(String id) {
        if (id == null) {
            return;
        }
        String trimmed = id.trim();
        if (!trimmed.isEmpty() && modIds.size() < 256) {
            modIds.add(trimmed);
        }
    }

    /** Hard-keeps a class: no renaming and no transformations. */
    void keepClass(String internalName) {
        String normalized = normalize(internalName);
        if (normalized == null) {
            return;
        }
        keepRules.add(normalized);
        keptClasses.add(normalized);
    }

    /** Keeps the name of a class member (any descriptor). */
    void keepMember(String owner, String member) {
        String normalizedOwner = normalize(owner);
        String normalizedMember = member == null ? "" : member.trim();
        if (normalizedOwner == null || normalizedMember.isEmpty()) {
            return;
        }
        keepRules.add(normalizedOwner + "#" + normalizedMember);
    }

    /** Keeps the name of a method including its descriptor. */
    void keepMethod(String owner, String method, String descriptor) {
        if (method == null || method.trim().isEmpty()) {
            return;
        }
        String rule = method.trim();
        if (descriptor != null && !descriptor.trim().isEmpty()
                && descriptor.trim().charAt(0) == '(') {
            rule += descriptor.trim();
        }
        keepMember(owner, rule);
    }

    /** Marks a class as body-rewrite exempt (control flow, strings, VM, ...). */
    void bodySkip(String internalName) {
        String normalized = normalize(internalName);
        if (normalized != null) {
            bodySkipGlobs.add(normalized);
        }
    }

    /** Keeps and freezes a loader plugin/coremod class. */
    void freezeClass(String internalName) {
        String normalized = normalize(internalName);
        if (normalized == null) {
            return;
        }
        keepClass(normalized);
        bodySkip(normalized);
        frozenClasses.add(normalized);
    }

    /** Keeps a mixin class name and preserves its method bodies. */
    void mixinClass(String internalName) {
        keepClass(internalName);
        bodySkip(internalName);
        mixin = true;
    }

    /** Keeps a mixin target class name and preserves its method bodies. */
    void targetClass(String internalName) {
        String normalized = normalize(internalName);
        if (normalized == null) {
            return;
        }
        keepClass(normalized);
        bodySkip(normalized);
        targetClasses.add(normalized);
        mixin = true;
    }

    /** Adds a raw rule discovered elsewhere (for example mixin analysis). */
    void rawKeepRule(String raw) {
        if (raw == null) {
            return;
        }
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) {
            return;
        }
        keepRules.add(trimmed);
        if (trimmed.indexOf('#') < 0) {
            keptClasses.add(normalize(trimmed));
        }
    }

    void rawSoftKeepRule(String raw) {
        if (raw == null) {
            return;
        }
        String trimmed = raw.trim();
        if (!trimmed.isEmpty()) {
            softKeepRules.add(trimmed);
        }
    }

    void rawBodySkipGlob(String glob) {
        if (glob == null) {
            return;
        }
        String trimmed = glob.trim();
        if (!trimmed.isEmpty()) {
            bodySkipGlobs.add(trimmed);
        }
    }

    void preserveResource(String path) {
        String normalized = normalizeResource(path);
        if (normalized != null) {
            preservedResources.add(normalized);
        }
    }

    void note(String text) {
        if (text == null) {
            return;
        }
        String trimmed = text.trim();
        if (!trimmed.isEmpty() && notes.size() < 64) {
            notes.add(trimmed);
        }
    }

    void nestedJar(String fileName) {
        if (fileName == null) {
            return;
        }
        String trimmed = fileName.trim();
        if (!trimmed.isEmpty() && nestedJars.size() < 64) {
            nestedJars.add(trimmed);
        }
    }

    // ------------------------------------------------------------------
    // pending mixin/access resources
    // ------------------------------------------------------------------

    void declareMixinConfig(String path) {
        String normalized = normalizeResource(path);
        if (normalized == null) {
            return;
        }
        preserveResource(normalized);
        if (!mixin) {
            mixin = true;
        }
        if (!parsedMixinConfigs.contains(normalized)) {
            pendingMixinConfigs.add(normalized);
        }
    }

    void declareAccessWidener(String path) {
        String normalized = normalizeResource(path);
        if (normalized == null) {
            return;
        }
        preserveResource(normalized);
        accessWidenerSeen = true;
        if (!parsedAccessWideners.contains(normalized)) {
            pendingAccessWideners.add(normalized);
        }
    }

    void declareAccessTransformer(String path) {
        String normalized = normalizeResource(path);
        if (normalized == null) {
            return;
        }
        preserveResource(normalized);
        accessTransformerSeen = true;
        if (!parsedAccessTransformers.contains(normalized)) {
            pendingAccessTransformers.add(normalized);
        }
    }

    /** Removes a pending path once it was consumed (present or not). */
    void consumedMixinConfig(String path) {
        parsedMixinConfigs.add(path);
        pendingMixinConfigs.remove(path);
    }

    void consumedAccessWidener(String path) {
        parsedAccessWideners.add(path);
        pendingAccessWideners.remove(path);
    }

    void consumedAccessTransformer(String path) {
        parsedAccessTransformers.add(path);
        pendingAccessTransformers.remove(path);
    }

    boolean isMixinConfigConsumed(String path) {
        return parsedMixinConfigs.contains(path);
    }

    boolean isAccessWidenerConsumed(String path) {
        return parsedAccessWideners.contains(path);
    }

    boolean isAccessTransformerConsumed(String path) {
        return parsedAccessTransformers.contains(path);
    }

    List<String> pendingMixinConfigs() {
        return new ArrayList<String>(pendingMixinConfigs);
    }

    List<String> pendingAccessWideners() {
        return new ArrayList<String>(pendingAccessWideners);
    }

    List<String> pendingAccessTransformers() {
        return new ArrayList<String>(pendingAccessTransformers);
    }

    // ------------------------------------------------------------------
    // result
    // ------------------------------------------------------------------

    boolean detected() {
        return fabric || quilt || forge || neoforge || mixin
                || accessWidenerSeen || accessTransformerSeen
                || !evidence.isEmpty() || !keepRules.isEmpty();
    }

    String loader() {
        List<String> parts = new ArrayList<String>();
        if (fabric) {
            parts.add("fabric");
        }
        if (quilt) {
            parts.add("quilt");
        }
        if (forge) {
            parts.add("forge");
        }
        if (neoforge) {
            parts.add("neoforge");
        }
        if (mixin) {
            parts.add("mixin");
        }
        if (parts.isEmpty() && accessWidenerSeen) {
            parts.add("fabric");
        }
        if (parts.isEmpty() && accessTransformerSeen) {
            parts.add("forge");
        }
        StringBuilder out = new StringBuilder();
        for (String part : parts) {
            if (out.length() > 0) {
                out.append(',');
            }
            out.append(part);
        }
        return out.toString();
    }

    private List<String> evidenceList() {
        List<String> out = new ArrayList<String>();
        for (Map.Entry<String, String> entry : evidence.entrySet()) {
            out.add(entry.getValue());
        }
        return out;
    }

    MinecraftProfile toProfile(io.umbra.core.config.UmbraConfig config) {
        List<String> policyNotes = new ArrayList<String>(notes);
        String loader = loader();
        policyNotes.add("detected " + (loader.isEmpty() ? "mod container" : loader + " mod container")
                + "; loader metadata, mixin configurations and access data are preserved verbatim");
        boolean allowConflicts = config != null && config.optionBool("minecraft.allowConflicts", false);
        boolean forceVmp = config != null && config.optionBool("minecraft.forceVmp", false);
        if (allowConflicts) {
            policyNotes.add("minecraft.allowConflicts=true: automatic protection downgrade is skipped, "
                    + "the protected archive may not load in the mod loader");
        } else {
            policyNotes.add("disabled class archive encryption, standalone integrity, native code, "
                    + "reference hiding, member trimming and resource rewriting");
            if (forceVmp) {
                policyNotes.add("virtualization kept because minecraft.forceVmp=true");
            } else {
                policyNotes.add("virtualization disabled because the mod loader patches bytecode at runtime "
                        + "(set minecraft.forceVmp=true to override)");
            }
        }
        if (accessWidenerSeen || accessTransformerSeen) {
            policyNotes.add("access widener/transformer entries kept by name; their resource files are "
                    + "preserved so the loader applies them after obfuscation");
        }
        if (!nestedJars.isEmpty()) {
            StringBuilder list = new StringBuilder();
            int shown = Math.min(nestedJars.size(), MAX_NESTED_JAR_NAMES);
            for (int i = 0; i < shown; i++) {
                if (list.length() > 0) {
                    list.append(", ");
                }
                list.append(nestedJars.get(i));
            }
            if (nestedJars.size() > shown) {
                list.append(", ...");
            }
            policyNotes.add(nestedJars.size() + " nested jar(s) are not processed recursively: " + list);
        }
        if (!targetClasses.isEmpty()) {
            policyNotes.add(targetClasses.size() + " mixin target class(es) keep their names and method bodies");
        }
        return new MinecraftProfile(true, loader,
                new ArrayList<String>(modIds), evidenceList(),
                new ArrayList<String>(keepRules), new ArrayList<String>(softKeepRules),
                new ArrayList<String>(bodySkipGlobs), new ArrayList<String>(frozenClasses),
                new ArrayList<String>(preservedResources), policyNotes,
                keptClasses.size(), targetClasses.size());
    }

    // ------------------------------------------------------------------
    // normalization
    // ------------------------------------------------------------------

    /** Normalizes a dotted or slash-separated class name to internal form. */
    static String normalize(String name) {
        if (name == null) {
            return null;
        }
        String trimmed = name.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        while (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        if (trimmed.isEmpty() || trimmed.indexOf(' ') >= 0) {
            return null;
        }
        return trimmed.replace('.', '/');
    }

    /** Normalizes a resource path (forward slashes, no leading slash). */
    static String normalizeResource(String path) {
        if (path == null) {
            return null;
        }
        String trimmed = path.trim().replace('\\', '/');
        while (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        if (trimmed.isEmpty()) {
            return null;
        }
        return trimmed;
    }
}
