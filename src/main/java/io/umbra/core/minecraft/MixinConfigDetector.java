package io.umbra.core.minecraft;

import io.umbra.core.model.ClassPool;

import java.util.List;
import java.util.Map;

/**
 * Parses Mixin configuration JSON ({@code *.mixins.json}, {@code mixins.*.json}
 * and any JSON document that looks like a mixin config).
 *
 * <p>For every config the class {@code package} is used to resolve relative
 * mixin names to internal names. Mixin classes are kept and exempted from
 * method-body rewrites (injection points are matched against the original
 * bytecode), the plugin class is kept by name and the config/refmap resources
 * are preserved verbatim. Malformed JSON is reported and only loses the class
 * list; the config resource is still marked as preserved.</p>
 */
final class MixinConfigDetector {

    private MixinConfigDetector() {
    }

    /** Examines a resource that may be a mixin configuration. */
    static void maybeScan(String resourceName, byte[] bytes, MinecraftScan scan) {
        if (resourceName == null || scan.isMixinConfigConsumed(resourceName)) {
            return;
        }
        String lower = resourceName.toLowerCase(java.util.Locale.ROOT);
        if (!lower.endsWith(".json")) {
            return;
        }
        boolean filenameHint = lower.contains("mixin");
        String text = MinecraftJson.text(bytes);
        if (!filenameHint
                && !(text.contains("\"mixins\"") && text.contains("\"package\""))) {
            return;
        }
        Map<String, Object> root = null;
        try {
            root = MinecraftJson.parseObject(text);
        } catch (RuntimeException e) {
            if (filenameHint) {
                scan.declareMixinConfig(resourceName);
                scan.consumedMixinConfig(resourceName);
                scan.preserveResource(resourceName);
                scan.evidence("mixin-config:" + resourceName, "mixin config " + resourceName);
                scan.warn("minecraft: malformed mixin config %s: %s", resourceName, e.getMessage());
                scan.note("malformed mixin config " + resourceName
                        + " ignored; the resource is preserved but its mixin classes could not be determined");
            }
            return;
        }
        if (root == null) {
            return;
        }
        boolean looksLikeConfig = looksLikeMixinConfig(root);
        if (filenameHint) {
            scan.declareMixinConfig(resourceName);
            scan.consumedMixinConfig(resourceName);
            scan.preserveResource(resourceName);
            scan.evidence("mixin-config:" + resourceName, "mixin config " + resourceName);
            if (looksLikeConfig) {
                apply(resourceName, root, scan);
            } else {
                scan.debug("minecraft: %s has a mixin file name but no mixin entries", resourceName);
            }
            return;
        }
        if (!looksLikeConfig || !root.containsKey("package")) {
            return;
        }
        scan.declareMixinConfig(resourceName);
        scan.consumedMixinConfig(resourceName);
        scan.preserveResource(resourceName);
        scan.evidence("mixin-config:" + resourceName, "mixin config " + resourceName);
        apply(resourceName, root, scan);
    }

    /** Parses a mixin config referenced by loader metadata but not named like one. */
    static void parseDeclared(ClassPool pool, String resourcePath, MinecraftScan scan) {
        if (resourcePath == null || scan.isMixinConfigConsumed(resourcePath)) {
            return;
        }
        scan.consumedMixinConfig(resourcePath);
        ClassPool.Resource resource = pool == null ? null : pool.resource(resourcePath);
        if (resource == null) {
            scan.debug("minecraft: declared mixin config %s is not present in the archive", resourcePath);
            return;
        }
        String text = MinecraftJson.text(resource.bytes());
        Map<String, Object> root;
        try {
            root = MinecraftJson.parseObject(text);
        } catch (RuntimeException e) {
            scan.warn("minecraft: malformed mixin config %s: %s", resourcePath, e.getMessage());
            scan.note("malformed mixin config " + resourcePath + " referenced by loader metadata");
            return;
        }
        if (!looksLikeMixinConfig(root)) {
            scan.debug("minecraft: %s does not look like a mixin config", resourcePath);
            return;
        }
        scan.preserveResource(resourcePath);
        scan.evidence("mixin-config:" + resourcePath, "mixin config " + resourcePath);
        apply(resourcePath, root, scan);
    }

    private static boolean looksLikeMixinConfig(Map<String, Object> root) {
        return root.containsKey("package")
                || root.containsKey("mixins")
                || root.containsKey("client")
                || root.containsKey("server")
                || root.containsKey("plugin")
                || root.containsKey("refmap");
    }

    private static void apply(String resourceName, Map<String, Object> root, MinecraftScan scan) {
        String packageName = MinecraftJson.asString(root.get("package"));
        if (packageName != null && packageName.endsWith(".")) {
            packageName = packageName.substring(0, packageName.length() - 1);
        }
        int mixins = 0;
        mixins += applyMixinArray(root.get("mixins"), packageName, scan);
        mixins += applyMixinArray(root.get("client"), packageName, scan);
        mixins += applyMixinArray(root.get("server"), packageName, scan);
        mixins += applyMixinArray(root.get("common"), packageName, scan);
        String pluginClass = MinecraftJson.asString(root.get("plugin"));
        if (pluginClass != null) {
            String internal = MinecraftScan.normalize(pluginClass);
            if (internal != null) {
                scan.keepClass(internal);
                scan.evidence("mixin-plugin:" + internal,
                        "mixin plugin " + pluginClass + " (" + resourceName + ")");
            }
        }
        String refmap = MinecraftJson.asString(root.get("refmap"));
        if (refmap != null) {
            scan.preserveResource(refmap);
            scan.evidence("mixin-refmap:" + refmap, "mixin refmap " + refmap + " (" + resourceName + ")");
        }
        scan.debug("minecraft: mixin config %s resolved %d mixin class(es)", resourceName, mixins);
    }

    private static int applyMixinArray(Object value, String packageName, MinecraftScan scan) {
        if (value == null) {
            return 0;
        }
        List<Object> list = MinecraftJson.asList(value);
        if (list == null) {
            return 0;
        }
        int count = 0;
        for (Object item : list) {
            String relative = null;
            if (item instanceof String) {
                relative = (String) item;
            } else {
                Map<String, Object> object = MinecraftJson.asMap(item);
                if (object != null) {
                    relative = MinecraftJson.asString(object.get("name"));
                }
            }
            if (relative == null || relative.trim().isEmpty()) {
                continue;
            }
            String internal = resolveMixinName(relative.trim(), packageName);
            if (internal != null) {
                scan.mixinClass(internal);
                count++;
                scan.evidence("mixin-class:" + internal, "mixin class " + internal);
            }
        }
        return count;
    }

    private static String resolveMixinName(String relative, String packageName) {
        String normalized = relative.replace('.', '/');
        String packageInternal = packageName == null ? "" : packageName.replace('.', '/');
        if (normalized.startsWith("/")) {
            return MinecraftScan.normalize(normalized);
        }
        if (packageInternal.isEmpty()) {
            return MinecraftScan.normalize(normalized);
        }
        if (normalized.startsWith(packageInternal + "/")) {
            return MinecraftScan.normalize(normalized);
        }
        return MinecraftScan.normalize(packageInternal + "/" + normalized);
    }
}
