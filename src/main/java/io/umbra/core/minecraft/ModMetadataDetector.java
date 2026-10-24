package io.umbra.core.minecraft;

import java.util.List;
import java.util.Map;

/**
 * Parses Fabric/Quilt mod JSON manifests and the legacy Forge
 * {@code mcmod.info} file.
 *
 * <p>Entry points are collected for every environment (main/client/server and
 * custom groups). A declared entry point is kept either as a class or as a
 * {@code owner#method} rule; mixin configurations and access wideners are
 * registered for later parsing. Malformed JSON only produces a warning and
 * still marks the container type from the file name so the feature downgrade
 * is applied.</p>
 */
final class ModMetadataDetector {

    private ModMetadataDetector() {
    }

    // ------------------------------------------------------------------
    // Fabric
    // ------------------------------------------------------------------

    static void scanFabric(String resourceName, byte[] bytes, MinecraftScan scan) {
        scan.loaderFabric();
        scan.preserveResource(resourceName);
        String id = null;
        try {
            Map<String, Object> root = MinecraftJson.parseObject(MinecraftJson.text(bytes));
            id = MinecraftJson.asString(root.get("id"));
            scan.modId(id);
            scanEntrypoints(root.get("entrypoints"), scan);
            collectMixinConfigs(root.get("mixins"), scan);
            declareAccessWidener(root.get("accessWidener"), scan);
            declareAccessWidener(root.get("access_widener"), scan);
            collectNestedJars(root.get("jars"), scan);
            Object custom = root.get("custom");
            if (custom != null) {
                scan.debug("minecraft: fabric custom metadata ignored for %s", resourceName);
            }
        } catch (RuntimeException e) {
            scan.warn("minecraft: malformed fabric.mod.json (%s): %s", resourceName, e.getMessage());
            scan.note("malformed fabric.mod.json ignored; loader kept and a conservative downgrade applied");
        }
        scan.evidence("fabric.mod.json",
                id == null ? "fabric.mod.json" : "fabric.mod.json id=" + id);
    }

    // ------------------------------------------------------------------
    // Quilt
    // ------------------------------------------------------------------

    static void scanQuilt(String resourceName, byte[] bytes, MinecraftScan scan) {
        scan.loaderQuilt();
        scan.preserveResource(resourceName);
        String id = null;
        try {
            Map<String, Object> root = MinecraftJson.parseObject(MinecraftJson.text(bytes));
            Map<String, Object> loader = MinecraftJson.asMap(root.get("quilt_loader"));
            Map<String, Object> source = loader == null ? root : loader;
            id = MinecraftJson.asString(source.get("id"));
            scan.modId(id);
            scanEntrypoints(source.get("entrypoints"), scan);
            if (loader != null) {
                scanEntrypoints(root.get("entrypoints"), scan);
            }
            collectMixinConfigs(root.get("mixin"), scan);
            collectMixinConfigs(root.get("mixins"), scan);
            declareAccessWidener(root.get("access_widener"), scan);
            declareAccessWidener(root.get("accessWidener"), scan);
            collectNestedJars(root.get("jars"), scan);
        } catch (RuntimeException e) {
            scan.warn("minecraft: malformed quilt.mod.json (%s): %s", resourceName, e.getMessage());
            scan.note("malformed quilt.mod.json ignored; loader kept and a conservative downgrade applied");
        }
        scan.evidence("quilt.mod.json",
                id == null ? "quilt.mod.json" : "quilt.mod.json id=" + id);
    }

    // ------------------------------------------------------------------
    // Legacy Forge mcmod.info
    // ------------------------------------------------------------------

    static void scanLegacy(String resourceName, byte[] bytes, MinecraftScan scan) {
        scan.loaderForge();
        scan.preserveResource(resourceName);
        String firstId = null;
        String mcVersion = null;
        try {
            Object root = MinecraftJson.parse(MinecraftJson.text(bytes));
            List<Object> entries;
            List<Object> modList = MinecraftJson.asList(mapValue(root, "modList"));
            if (modList != null) {
                entries = modList;
            } else if (root instanceof List) {
                entries = MinecraftJson.asList(root);
            } else {
                entries = null;
            }
            if (entries == null) {
                Map<String, Object> single = MinecraftJson.asMap(root);
                if (single != null) {
                    scanLegacyEntry(single, scan);
                    firstId = firstModId(single);
                }
            } else {
                for (Object entry : entries) {
                    Map<String, Object> table = MinecraftJson.asMap(entry);
                    if (table == null) {
                        continue;
                    }
                    scanLegacyEntry(table, scan);
                    String id = firstModId(table);
                    if (firstId == null) {
                        firstId = id;
                    }
                    if (mcVersion == null) {
                        mcVersion = MinecraftJson.asString(table.get("mcversion"));
                    }
                }
            }
        } catch (RuntimeException e) {
            scan.warn("minecraft: malformed mcmod.info (%s): %s", resourceName, e.getMessage());
            scan.note("malformed mcmod.info ignored; legacy Forge loader kept");
        }
        String description = "mcmod.info";
        if (firstId != null) {
            description += " id=" + firstId;
        }
        if (mcVersion != null) {
            description += " mcversion=" + mcVersion;
        }
        scan.evidence("mcmod.info", description);
    }

    private static void scanLegacyEntry(Map<String, Object> table, MinecraftScan scan) {
        scan.modId(MinecraftJson.asString(table.get("modid")));
        scan.modId(MinecraftJson.asString(table.get("modId")));
        String mcVersion = MinecraftJson.asString(table.get("mcversion"));
        if (mcVersion != null) {
            scan.evidence("mcmod.info:mcversion", "mcmod.info mcversion=" + mcVersion);
        }
    }

    private static String firstModId(Map<String, Object> table) {
        String id = MinecraftJson.asString(table.get("modid"));
        return id != null ? id : MinecraftJson.asString(table.get("modId"));
    }

    private static Object mapValue(Object root, String key) {
        Map<String, Object> map = MinecraftJson.asMap(root);
        return map == null ? null : map.get(key);
    }

    // ------------------------------------------------------------------
    // shared helpers
    // ------------------------------------------------------------------

    /**
     * Recursively handles an entrypoints value tree.
     *
     * <p>The top-level value is a map of environment groups
     * ({@code main}, {@code client}, {@code server}, {@code preLaunch}, ...);
     * each group value is a string, an array, a nested array or an entry
     * descriptor object such as
     * {@code {"value": "pkg.Class::method", "adapter": "default"}}. Descriptor
     * objects must only contribute their {@code value}/{@code class}, never
     * sibling keys like {@code adapter}.</p>
     */
    static void scanEntrypoints(Object value, MinecraftScan scan) {
        if (value == null) {
            return;
        }
        if (value instanceof String) {
            scanEntrypoint((String) value, scan);
            return;
        }
        List<Object> list = MinecraftJson.asList(value);
        if (list != null) {
            for (Object item : list) {
                scanEntrypoints(item, scan);
            }
            return;
        }
        Map<String, Object> object = MinecraftJson.asMap(value);
        if (object == null) {
            return;
        }
        Object descriptorValue = entrypointValue(object);
        if (descriptorValue != null) {
            scanEntrypoints(descriptorValue, scan);
            String method = MinecraftJson.asString(object.get("method"));
            String className = MinecraftJson.asString(descriptorValue);
            if (method != null && className != null) {
                String internal = MinecraftScan.normalize(className);
                if (internal != null) {
                    scan.keepMember(internal, method);
                }
            }
            return;
        }
        // Not a descriptor object: a group map (main/client/server/...) whose
        // values are entrypoint strings, arrays or descriptors. Iterate every
        // group instead of assuming a fixed set of names.
        for (Object groupValue : object.values()) {
            scanEntrypoints(groupValue, scan);
        }
    }

    /** Returns the class value of an entry descriptor object, if it is one. */
    private static Object entrypointValue(Map<String, Object> object) {
        if (object.containsKey("value")) {
            return object.get("value");
        }
        if (object.containsKey("class")) {
            return object.get("class");
        }
        return null;
    }

    private static void scanEntrypoint(String raw, MinecraftScan scan) {
        String entry = raw == null ? "" : raw.trim();
        if (entry.isEmpty()) {
            return;
        }
        String className = entry;
        String method = null;
        int separator = entry.indexOf("::");
        if (separator >= 0) {
            className = entry.substring(0, separator).trim();
            method = entry.substring(separator + 2).trim();
        }
        String internal = MinecraftScan.normalize(className);
        if (internal == null) {
            return;
        }
        scan.keepClass(internal);
        if (method != null && !method.isEmpty()) {
            scan.keepMember(internal, method);
        }
    }

    /** Handles {@code mixins}/{@code mixin}: strings or objects with a config. */
    static void collectMixinConfigs(Object value, MinecraftScan scan) {
        if (value == null) {
            return;
        }
        if (value instanceof String) {
            scan.declareMixinConfig((String) value);
            return;
        }
        List<Object> list = MinecraftJson.asList(value);
        if (list != null) {
            for (Object item : list) {
                collectMixinConfigs(item, scan);
            }
            return;
        }
        Map<String, Object> object = MinecraftJson.asMap(value);
        if (object != null) {
            String config = MinecraftJson.asString(object.get("config"));
            if (config != null) {
                scan.declareMixinConfig(config);
            }
            collectMixinConfigs(object.get("values"), scan);
            collectMixinConfigs(object.get("value"), scan);
        }
    }

    static void declareAccessWidener(Object value, MinecraftScan scan) {
        String path = MinecraftJson.asString(value);
        if (path != null) {
            scan.declareAccessWidener(path);
        }
    }

    static void collectNestedJars(Object value, MinecraftScan scan) {
        if (value == null) {
            return;
        }
        List<Object> list = MinecraftJson.asList(value);
        if (list == null) {
            return;
        }
        for (Object item : list) {
            if (item instanceof String) {
                scan.nestedJar((String) item);
                continue;
            }
            Map<String, Object> table = MinecraftJson.asMap(item);
            if (table != null) {
                String file = MinecraftJson.asString(table.get("file"));
                scan.nestedJar(file == null ? "unknown.jar" : file);
            }
        }
    }
}
