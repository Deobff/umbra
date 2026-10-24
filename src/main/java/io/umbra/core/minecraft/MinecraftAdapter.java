package io.umbra.core.minecraft;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.model.ClassPool;
import io.umbra.core.util.Jars;
import io.umbra.core.util.Log;

import java.util.Map;

/**
 * Detects mod-container metadata (Minecraft Fabric/Forge/NeoForge/Quilt, mixin
 * configs, access wideners/transformers) and derives a {@link MinecraftProfile}.
 *
 * <p>The detector is read-only with respect to the class pool: it inspects
 * resources and annotations, then returns keep rules and body exemptions that
 * the engine installs before the pass pipeline runs. It never throws on a
 * malformed metadata file: a broken {@code fabric.mod.json} or {@code mods.toml}
 * only produces a warning and whatever keeps could still be derived.</p>
 *
 * <p>Detection sources, in processing order:</p>
 * <ol>
 *   <li>resources: {@code fabric.mod.json}, {@code quilt.mod.json},
 *       {@code META-INF/mods.toml}, {@code META-INF/neoforge.mods.toml},
 *       {@code mcmod.info}, {@code META-INF/MANIFEST.MF},
 *       {@code *.accesswidener}, {@code META-INF/accesstransformer.cfg};</li>
 *   <li>every JSON resource that looks like a mixin configuration;</li>
 *   <li>class-level loader/Mixin annotations and coremod interfaces;</li>
 *   <li>mixin configurations referenced from metadata;</li>
 *   <li>the {@link MixinAnalyzer} annotation analysis (merged).</li>
 * </ol>
 */
public final class MinecraftAdapter {

    private MinecraftAdapter() {
    }

    /**
     * Analyses the container. Never returns {@code null}.
     *
     * @param pool   loaded classes and resources
     * @param config effective configuration (reads {@code minecraft.*} options)
     * @param log    logger for detection/diagnostic lines
     */
    public static MinecraftProfile detect(ClassPool pool, UmbraConfig config, Log log) {
        Log safeLog = log == null ? new Log(null, false) : log;
        if (pool == null) {
            return MinecraftProfile.NONE;
        }
        MinecraftScan scan = new MinecraftScan(safeLog);
        for (Map.Entry<String, ClassPool.Resource> entry : pool.resources().entrySet()) {
            String resourceName = entry.getKey();
            ClassPool.Resource resource = entry.getValue();
            if (resourceName == null || resource == null) {
                continue;
            }
            try {
                scanResource(resourceName, resource.bytes(), pool, scan);
            } catch (RuntimeException e) {
                scan.warn("minecraft: failed to inspect resource %s: %s", resourceName, e.getMessage());
                scan.note("resource " + resourceName + " could not be inspected");
            }
        }
        try {
            ClassAnnotationDetector.scan(pool, scan);
        } catch (RuntimeException e) {
            scan.warn("minecraft: class annotation scan failed: %s", e.getMessage());
        }
        resolvePending(pool, scan);
        mergeMixinAnalysis(pool, scan);
        if (!scan.detected()) {
            safeLog.debug("minecraft: no mod container metadata detected");
            return MinecraftProfile.NONE;
        }
        MinecraftProfile profile = scan.toProfile(config);
        safeLog.debug("minecraft: detection finished loader=%s keepRules=%d bodySkip=%d targets=%d",
                profile.loader(), profile.keepRules().size(),
                profile.bodySkipGlobs().size(), profile.targetCount());
        return profile;
    }

    // ------------------------------------------------------------------
    // resource dispatch
    // ------------------------------------------------------------------

    private static void scanResource(String rawName, byte[] bytes, ClassPool pool,
                                     MinecraftScan scan) {
        String name = MinecraftScan.normalizeResource(rawName);
        if (name == null || bytes == null) {
            return;
        }
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        String base = lower.substring(lower.lastIndexOf('/') + 1);
        if ("fabric.mod.json".equals(base)) {
            ModMetadataDetector.scanFabric(name, bytes, scan);
            return;
        }
        if ("quilt.mod.json".equals(base)) {
            ModMetadataDetector.scanQuilt(name, bytes, scan);
            return;
        }
        if ("meta-inf/mods.toml".equals(lower)) {
            ForgeMetadataDetector.scan(name, bytes, false, scan);
            return;
        }
        if ("meta-inf/neoforge.mods.toml".equals(lower)) {
            ForgeMetadataDetector.scan(name, bytes, true, scan);
            return;
        }
        if ("mcmod.info".equals(base)) {
            ModMetadataDetector.scanLegacy(name, bytes, scan);
            return;
        }
        if ("meta-inf/manifest.mf".equals(lower)) {
            scanManifest(bytes, scan);
            return;
        }
        if ("meta-inf/accesstransformer.cfg".equals(lower)) {
            AccessDetector.scanTransformer(name, bytes, scan, pool);
            return;
        }
        if (lower.endsWith(".accesswidener")) {
            AccessDetector.scanWidener(name, bytes, scan, pool);
            return;
        }
        if (lower.endsWith(".json")) {
            MixinConfigDetector.maybeScan(name, bytes, scan);
        }
    }

    // ------------------------------------------------------------------
    // manifest
    // ------------------------------------------------------------------

    private static void scanManifest(byte[] bytes, MinecraftScan scan) {
        Map<String, String> attributes;
        try {
            attributes = Jars.parseManifest(bytes);
        } catch (RuntimeException e) {
            scan.warn("minecraft: malformed META-INF/MANIFEST.MF: %s", e.getMessage());
            return;
        }
        boolean found = false;
        String corePlugin = attribute(attributes, "FMLCorePlugin");
        if (corePlugin != null) {
            found = true;
            scan.loaderForge();
            scan.freezeClass(corePlugin);
            scan.evidence("manifest:FMLCorePlugin", "FMLCorePlugin " + corePlugin);
        }
        String containsFmlMod = attribute(attributes, "FMLCorePluginContainsFMLMod");
        if (containsFmlMod != null) {
            found = true;
            scan.loaderForge();
            if (parseBoolean(containsFmlMod)) {
                scan.evidence("manifest:FMLCorePluginContainsFMLMod",
                        "FMLCorePluginContainsFMLMod=true");
            }
        }
        String tweakClass = attribute(attributes, "TweakClass");
        if (tweakClass != null) {
            found = true;
            scan.loaderForge();
            scan.freezeClass(tweakClass);
            scan.evidence("manifest:TweakClass", "TweakClass " + tweakClass);
        }
        String mixinConfigs = attribute(attributes, "MixinConfigs");
        if (mixinConfigs != null) {
            found = true;
            for (String path : splitList(mixinConfigs)) {
                scan.declareMixinConfig(path);
            }
            scan.evidence("manifest:MixinConfigs", "MixinConfigs " + mixinConfigs);
        }
        String accessTransformers = attribute(attributes, "FMLAT");
        if (accessTransformers != null) {
            found = true;
            scan.loaderForge();
            for (String path : splitList(accessTransformers)) {
                scan.declareAccessTransformer(path);
            }
            scan.evidence("manifest:FMLAT", "FMLAT " + accessTransformers);
        }
        if (found) {
            scan.preserveResource("META-INF/MANIFEST.MF");
        }
    }

    private static String attribute(Map<String, String> attributes, String name) {
        String direct = attributes.get(name);
        if (direct != null) {
            String trimmed = direct.trim();
            return trimmed.isEmpty() ? null : trimmed;
        }
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                String value = entry.getValue() == null ? "" : entry.getValue().trim();
                return value.isEmpty() ? null : value;
            }
        }
        return null;
    }

    private static boolean parseBoolean(String value) {
        String lower = value == null ? "" : value.trim().toLowerCase(java.util.Locale.ROOT);
        return "true".equals(lower) || "yes".equals(lower) || "1".equals(lower) || "on".equals(lower);
    }

    private static String[] splitList(String value) {
        return value.trim().split("[,\\s]+");
    }

    // ------------------------------------------------------------------
    // deferred resource parsing
    // ------------------------------------------------------------------

    private static void resolvePending(ClassPool pool, MinecraftScan scan) {
        for (String path : scan.pendingMixinConfigs()) {
            try {
                MixinConfigDetector.parseDeclared(pool, path, scan);
            } catch (RuntimeException e) {
                scan.warn("minecraft: failed to parse mixin config %s: %s", path, e.getMessage());
            }
        }
        for (String path : scan.pendingAccessWideners()) {
            try {
                AccessDetector.parseDeclaredWidener(pool, path, scan);
            } catch (RuntimeException e) {
                scan.warn("minecraft: failed to parse access widener %s: %s", path, e.getMessage());
            }
        }
        for (String path : scan.pendingAccessTransformers()) {
            try {
                AccessDetector.parseDeclaredTransformer(pool, path, scan);
            } catch (RuntimeException e) {
                scan.warn("minecraft: failed to parse access transformer %s: %s", path, e.getMessage());
            }
        }
    }

    // ------------------------------------------------------------------
    // mixin annotation analysis (owned by the mixin analyzer)
    // ------------------------------------------------------------------

    private static void mergeMixinAnalysis(ClassPool pool, MinecraftScan scan) {
        MixinAnalysis analysis;
        try {
            analysis = MixinAnalyzer.analyze(pool);
        } catch (RuntimeException e) {
            scan.warn("minecraft: mixin annotation analysis failed: %s", e.getMessage());
            return;
        }
        if (analysis == null) {
            return;
        }
        for (String mixinClass : analysis.mixinClasses()) {
            if (mixinClass != null) {
                scan.mixinClass(mixinClass);
            }
        }
        for (String targetClass : analysis.targetClasses()) {
            if (targetClass != null) {
                scan.targetClass(targetClass);
            }
        }
        for (String rule : analysis.keepRules()) {
            scan.rawKeepRule(rule);
        }
        for (String glob : analysis.bodySkipGlobs()) {
            scan.rawBodySkipGlob(glob);
        }
        for (String note : analysis.notes()) {
            scan.note(note);
        }
    }
}
