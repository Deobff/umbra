package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.model.ClassPool;
import io.umbra.core.util.Jars;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Rewrites class names embedded in manifests, service descriptors and common
 * framework configuration files after renaming.
 */
public final class ResourceRewritePass implements Pass {

    private static final String SERVICES = "META-INF/services/";

    @Override
    public String name() {
        return "resource-rewrite";
    }

    @Override
    public int order() {
        return 120;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().renamer().enabled() && !context.mappings().classes().isEmpty();
    }

    @Override
    public void run(PassContext context) {
        Map<String, String> classMap = context.mappings().classes();
        if (classMap.isEmpty()) {
            return;
        }
        int rewritten = 0;
        ClassPool pool = context.classes();

        ClassPool.Resource manifest = pool.resource("META-INF/MANIFEST.MF");
        if (manifest != null) {
            Map<String, String> attributes = new LinkedHashMap<String, String>(Jars.parseManifest(manifest.bytes()));
            boolean changed = false;
            for (String key : new String[]{"Main-Class", "Premain-Class", "Agent-Class",
                    "Launcher-Agent-Class", "Rsrc-Main-Class", "Start-Class"}) {
                String value = attributes.get(key);
                if (value != null) {
                    String mapped = mapDotted(classMap, value.trim());
                    if (!mapped.equals(value.trim())) {
                        attributes.put(key, mapped);
                        changed = true;
                    }
                }
            }
            if (changed) {
                pool.putResource(manifest.name(), Jars.writeManifest(attributes), manifest.time(), manifest.method());
                rewritten++;
            }
        }

        List<String> names = new ArrayList<String>(pool.resources().keySet());
        for (String name : names) {
            ClassPool.Resource resource = pool.resource(name);
            if (resource == null) {
                continue;
            }
            if (name.startsWith(SERVICES)) {
                String service = name.substring(SERVICES.length());
                String mappedService = mapDotted(classMap, service);
                String content = rewriteServiceFile(resource.bytes(), classMap);
                if (!mappedService.equals(service)) {
                    pool.removeResource(name);
                    name = SERVICES + mappedService;
                }
                pool.putResource(name, content.getBytes(StandardCharsets.UTF_8), resource.time(), resource.method());
                rewritten++;
            } else if ("META-INF/spring.factories".equals(name)
                    || "META-INF/spring.handlers".equals(name)) {
                String content = rewriteKeyValueFile(resource.bytes(), classMap);
                pool.putResource(name, content.getBytes(StandardCharsets.UTF_8), resource.time(), resource.method());
                rewritten++;
            } else if (name.startsWith("META-INF/spring/") && name.endsWith(".imports")) {
                String content = rewriteLineFile(resource.bytes(), classMap);
                pool.putResource(name, content.getBytes(StandardCharsets.UTF_8), resource.time(), resource.method());
                rewritten++;
            } else if ("plugin.yml".equals(name) || "bungee.yml".equals(name)) {
                String content = rewriteYamlMain(resource.bytes(), classMap);
                pool.putResource(name, content.getBytes(StandardCharsets.UTF_8), resource.time(), resource.method());
                rewritten++;
            } else if (context.config().resources().rewriteContent() && isTextResource(name)) {
                String content = rewriteClassNames(resource.bytes(), classMap);
                if (content != null) {
                    pool.putResource(name, content.getBytes(StandardCharsets.UTF_8), resource.time(), resource.method());
                    rewritten++;
                }
            }
        }
        context.stats().add("resources.rewritten", rewritten);
        context.log().info("resource-rewrite: updated %d resource entries", rewritten);
    }

    private static String rewriteServiceFile(byte[] bytes, Map<String, String> classMap) {
        String text = new String(bytes, StandardCharsets.UTF_8);
        String[] lines = text.split("\n", -1);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                out.append(line);
            } else {
                out.append(mapDotted(classMap, trimmed));
            }
            if (i + 1 < lines.length) {
                out.append('\n');
            }
        }
        return out.toString();
    }

    private static String rewriteKeyValueFile(byte[] bytes, Map<String, String> classMap) {
        String text = new String(bytes, StandardCharsets.UTF_8);
        String[] lines = text.split("\n", -1);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            int equals = line.indexOf('=');
            if (equals < 0 || line.trim().startsWith("#")) {
                out.append(line);
            } else {
                String key = line.substring(0, equals);
                String value = line.substring(equals + 1);
                String[] parts = value.split(",");
                StringBuilder mapped = new StringBuilder();
                for (int j = 0; j < parts.length; j++) {
                    if (j > 0) {
                        mapped.append(',');
                    }
                    String part = parts[j];
                    String leading = leadingWhitespace(part);
                    String trailing = trailingWhitespace(part);
                    mapped.append(leading).append(mapDotted(classMap, part.trim())).append(trailing);
                }
                out.append(key).append('=').append(mapped);
            }
            if (i + 1 < lines.length) {
                out.append('\n');
            }
        }
        return out.toString();
    }

    private static String rewriteLineFile(byte[] bytes, Map<String, String> classMap) {
        String text = new String(bytes, StandardCharsets.UTF_8);
        String[] lines = text.split("\n", -1);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                out.append(line);
            } else {
                out.append(mapDotted(classMap, trimmed));
            }
            if (i + 1 < lines.length) {
                out.append('\n');
            }
        }
        return out.toString();
    }

    private static String rewriteYamlMain(byte[] bytes, Map<String, String> classMap) {
        String text = new String(bytes, StandardCharsets.UTF_8);
        String[] lines = text.split("\n", -1);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();
            if (trimmed.startsWith("main:") || trimmed.startsWith("main-class:")) {
                int colon = line.indexOf(':');
                String prefix = line.substring(0, colon + 1) + " ";
                out.append(prefix).append(mapDotted(classMap, line.substring(colon + 1).trim()));
            } else {
                out.append(line);
            }
            if (i + 1 < lines.length) {
                out.append('\n');
            }
        }
        return out.toString();
    }

    private static boolean isTextResource(String name) {
        if (name.startsWith("META-INF/")) {
            return false;
        }
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        return lower.endsWith(".xml") || lower.endsWith(".json")
                || lower.endsWith(".yml") || lower.endsWith(".yaml")
                || lower.endsWith(".properties");
    }

    private static String rewriteClassNames(byte[] bytes, Map<String, String> classMap) {
        if (bytes.length > 2 * 1024 * 1024) {
            return null;
        }
        String text = new String(bytes, StandardCharsets.UTF_8);
        String rewritten = text;
        for (Map.Entry<String, String> entry : classMap.entrySet()) {
            String original = entry.getKey().replace('/', '.');
            String mapped = entry.getValue().replace('/', '.');
            if (original.equals(mapped) || original.isEmpty()) {
                continue;
            }
            String pattern = "(?<![A-Za-z0-9_$./])" + java.util.regex.Pattern.quote(original)
                    + "(?![A-Za-z0-9_$])";
            rewritten = rewritten.replaceAll(pattern, java.util.regex.Matcher.quoteReplacement(mapped));
        }
        return rewritten.equals(text) ? null : rewritten;
    }

    private static String mapDotted(Map<String, String> classMap, String dotted) {
        String internal = dotted.replace('.', '/');
        String mapped = classMap.get(internal);
        return mapped == null ? dotted : mapped.replace('/', '.');
    }

    private static String leadingWhitespace(String value) {
        int i = 0;
        while (i < value.length() && Character.isWhitespace(value.charAt(i))) {
            i++;
        }
        return value.substring(0, i);
    }

    private static String trailingWhitespace(String value) {
        int i = value.length();
        while (i > 0 && Character.isWhitespace(value.charAt(i - 1))) {
            i--;
        }
        return value.substring(i);
    }
}
