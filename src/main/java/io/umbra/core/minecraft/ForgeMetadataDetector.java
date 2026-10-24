package io.umbra.core.minecraft;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses modern Forge and NeoForge {@code mods.toml} metadata.
 *
 * <p>Collects {@code modId}s from {@code [[mods]]} tables, declared mixin
 * configurations from {@code [[mixins]]} (and root {@code mixins}/
 * {@code mixinConfigs} arrays) and access-transformer files. When the TOML is
 * malformed the detector falls back to a line-based extraction so at least the
 * mod ids, mixin configs and the loader downgrade survive.</p>
 */
final class ForgeMetadataDetector {

    private static final Pattern MOD_ID = Pattern.compile(
            "\\bmodId\\s*=\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern MIXIN_CONFIG = Pattern.compile(
            "\\bconfig\\s*=\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern MOD_LOADER = Pattern.compile(
            "\\bmodLoader\\s*=\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern AT_FILE = Pattern.compile(
            "\\b(?:file|path|config)\\s*=\\s*[\"']([^\"']+\\.cfg)[\"']", Pattern.CASE_INSENSITIVE);

    private ForgeMetadataDetector() {
    }

    static void scan(String resourceName, byte[] bytes, boolean neoForge, MinecraftScan scan) {
        if (neoForge) {
            scan.loaderNeoForge();
        } else {
            scan.loaderForge();
        }
        scan.preserveResource(resourceName);
        String text = MinecraftJson.text(bytes);
        Map<String, Object> root = null;
        try {
            root = MinecraftToml.parse(text);
        } catch (RuntimeException e) {
            scan.warn("minecraft: malformed %s: %s", resourceName, e.getMessage());
            scan.note("malformed " + resourceName + " parsed partially; loader kept");
        }
        int modCount = 0;
        if (root != null) {
            modCount = scanRoot(root, scan);
        } else {
            modCount = scanFallback(text, scan);
        }
        scan.evidence(resourceName, resourceName + (modCount > 0 ? " mods=" + modCount : ""));
    }

    private static int scanRoot(Map<String, Object> root, MinecraftScan scan) {
        int modCount = 0;
        List<Map<String, Object>> mods = MinecraftToml.tables(root.get("mods"));
        for (Map<String, Object> mod : mods) {
            String id = MinecraftJson.asString(mod.get("modId"));
            if (id == null) {
                id = MinecraftJson.asString(mod.get("modid"));
            }
            if (id != null) {
                scan.modId(id);
                modCount++;
            }
        }
        if (mods.isEmpty()) {
            String id = MinecraftJson.asString(root.get("modId"));
            if (id != null) {
                scan.modId(id);
                modCount++;
            }
        }
        String modLoader = MinecraftJson.asString(root.get("modLoader"));
        if (modLoader != null) {
            scan.evidence("mods.toml:modLoader", "modLoader=" + modLoader);
        }
        detectMixinConfigs(root.get("mixins"), scan);
        detectMixinConfigs(root.get("mixinConfigs"), scan);
        detectMixinConfigs(root.get("mixin"), scan);
        detectAccessTransformers(root.get("accessTransformers"), scan);
        detectAccessTransformers(root.get("accessTransformer"), scan);
        detectAccessTransformers(root.get("accessTransformerFiles"), scan);
        return modCount;
    }

    private static void detectMixinConfigs(Object value, MinecraftScan scan) {
        if (value == null) {
            return;
        }
        if (value instanceof String) {
            String config = MinecraftJson.asString(value);
            if (config != null) {
                scan.declareMixinConfig(config);
            }
            return;
        }
        List<Map<String, Object>> tables = MinecraftToml.tables(value);
        for (Map<String, Object> table : tables) {
            String config = MinecraftJson.asString(table.get("config"));
            if (config == null) {
                config = MinecraftJson.asString(table.get("value"));
            }
            if (config != null) {
                scan.declareMixinConfig(config);
            }
        }
    }

    private static void detectAccessTransformers(Object value, MinecraftScan scan) {
        if (value == null) {
            return;
        }
        if (value instanceof String) {
            String path = MinecraftJson.asString(value);
            if (path != null) {
                scan.declareAccessTransformer(path);
            }
            return;
        }
        List<Map<String, Object>> tables = MinecraftToml.tables(value);
        for (Map<String, Object> table : tables) {
            String file = MinecraftJson.asString(table.get("file"));
            if (file == null) {
                file = MinecraftJson.asString(table.get("path"));
            }
            if (file == null) {
                file = MinecraftJson.asString(table.get("config"));
            }
            if (file != null) {
                scan.declareAccessTransformer(file);
            }
        }
    }

    private static int scanFallback(String text, MinecraftScan scan) {
        int modCount = 0;
        Matcher ids = MOD_ID.matcher(text);
        while (ids.find()) {
            scan.modId(ids.group(1));
            modCount++;
        }
        Matcher loader = MOD_LOADER.matcher(text);
        if (loader.find()) {
            scan.evidence("mods.toml:modLoader", "modLoader=" + loader.group(1));
        }
        Matcher mixins = MIXIN_CONFIG.matcher(text);
        while (mixins.find()) {
            scan.declareMixinConfig(mixins.group(1));
        }
        Matcher accessTransformers = AT_FILE.matcher(text);
        while (accessTransformers.find()) {
            scan.declareAccessTransformer(accessTransformers.group(1));
        }
        if (modCount > 0) {
            scan.note("recovered " + modCount + " mod id(s) from malformed mods.toml");
        }
        return modCount;
    }
}
