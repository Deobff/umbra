package io.umbra.core.minecraft;

import io.umbra.core.model.ClassPool;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses access wideners ({@code .accesswidener}, v1/v2) and Forge access
 * transformers ({@code META-INF/accesstransformer.cfg}).
 *
 * <p>Both formats reference classes and members by their original names, so
 * every entry becomes a keep rule ({@code owner}, {@code owner#name},
 * {@code owner#name(desc)}). The resource files themselves are preserved by the
 * mod-container downgrade. Invalid lines are skipped with a debug line; a
 * completely malformed file only produces a warning.</p>
 */
final class AccessDetector {

    private static final Pattern DESCRIPTOR_TYPE = Pattern.compile("L([A-Za-z0-9_$/]+);");

    private AccessDetector() {
    }

    // ------------------------------------------------------------------
    // access widener
    // ------------------------------------------------------------------

    static void scanWidener(String resourceName, byte[] bytes, MinecraftScan scan, ClassPool pool) {
        if (resourceName == null || scan.isAccessWidenerConsumed(resourceName)) {
            return;
        }
        scan.consumedAccessWidener(resourceName);
        scan.accessWidenerSeen();
        scan.preserveResource(resourceName);
        scan.evidence("accesswidener:" + resourceName, "access widener " + resourceName);
        String text = MinecraftJson.text(bytes);
        String[] lines = text.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        int entries = 0;
        int skipped = 0;
        for (int i = 0; i < lines.length; i++) {
            String line = stripComment(lines[i]).trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] tokens = line.split("\\s+");
            if (tokens.length > 0 && "accessWidener".equalsIgnoreCase(tokens[0])) {
                String header = "accessWidener";
                for (int t = 1; t < tokens.length; t++) {
                    header += " " + tokens[t];
                }
                scan.evidence("accesswidener-header:" + resourceName, header + " (" + resourceName + ")");
                continue;
            }
            int kindIndex = -1;
            for (int t = 0; t < tokens.length; t++) {
                String token = tokens[t];
                if ("class".equals(token) || "method".equals(token) || "field".equals(token)) {
                    kindIndex = t;
                    break;
                }
            }
            if (kindIndex < 0 || kindIndex + 1 >= tokens.length) {
                skipped++;
                continue;
            }
            String kind = tokens[kindIndex];
            String owner = tokens[kindIndex + 1];
            if ("class".equals(kind)) {
                scan.keepClass(owner);
                entries++;
                continue;
            }
            if (kindIndex + 2 >= tokens.length) {
                skipped++;
                continue;
            }
            String member = tokens[kindIndex + 2];
            String descriptor = kindIndex + 3 < tokens.length ? tokens[kindIndex + 3] : null;
            scan.keepClass(owner);
            if ("method".equals(kind)) {
                scan.keepMethod(owner, member, descriptor);
            } else {
                scan.keepMember(owner, member);
            }
            keepDescriptorTypes(descriptor, scan, pool);
            entries++;
        }
        if (skipped > 0) {
            scan.debug("minecraft: skipped %d unparseable access widener line(s) in %s", skipped, resourceName);
        }
        scan.debug("minecraft: access widener %s contributed %d keep entr(ies)", resourceName, entries);
    }

    static void parseDeclaredWidener(ClassPool pool, String resourcePath, MinecraftScan scan) {
        if (resourcePath == null || scan.isAccessWidenerConsumed(resourcePath)) {
            return;
        }
        ClassPool.Resource resource = pool == null ? null : pool.resource(resourcePath);
        if (resource == null) {
            scan.consumedAccessWidener(resourcePath);
            scan.preserveResource(resourcePath);
            scan.accessWidenerSeen();
            scan.debug("minecraft: declared access widener %s is not present in the archive", resourcePath);
            return;
        }
        // scanWidener marks the resource consumed itself when it starts.
        scanWidener(resourcePath, resource.bytes(), scan, pool);
    }

    // ------------------------------------------------------------------
    // access transformer
    // ------------------------------------------------------------------

    static void scanTransformer(String resourceName, byte[] bytes, MinecraftScan scan, ClassPool pool) {
        if (resourceName == null || scan.isAccessTransformerConsumed(resourceName)) {
            return;
        }
        scan.consumedAccessTransformer(resourceName);
        scan.accessTransformerSeen();
        scan.preserveResource(resourceName);
        scan.evidence("accesstransformer:" + resourceName, "access transformer " + resourceName);
        String text = MinecraftJson.text(bytes);
        String[] lines = text.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        int entries = 0;
        int skipped = 0;
        for (int i = 0; i < lines.length; i++) {
            String line = stripComment(lines[i]).trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] tokens = line.split("\\s+");
            if (tokens.length < 2) {
                skipped++;
                continue;
            }
            String owner = tokens[1];
            String ownerInternal = MinecraftScan.normalize(owner);
            if (ownerInternal == null) {
                skipped++;
                continue;
            }
            scan.keepClass(ownerInternal);
            if (tokens.length >= 3) {
                String member = tokens[2];
                String descriptor = tokens.length >= 4 ? tokens[3] : null;
                if (descriptor != null && descriptor.startsWith("(")) {
                    scan.keepMethod(ownerInternal, member, descriptor);
                } else {
                    scan.keepMember(ownerInternal, member);
                }
                keepDescriptorTypes(descriptor, scan, pool);
            }
            entries++;
        }
        if (skipped > 0) {
            scan.debug("minecraft: skipped %d unparseable access transformer line(s) in %s",
                    skipped, resourceName);
        }
        scan.debug("minecraft: access transformer %s contributed %d keep entr(ies)", resourceName, entries);
    }

    static void parseDeclaredTransformer(ClassPool pool, String resourcePath, MinecraftScan scan) {
        if (resourcePath == null || scan.isAccessTransformerConsumed(resourcePath)) {
            return;
        }
        ClassPool.Resource resource = pool == null ? null : pool.resource(resourcePath);
        if (resource == null) {
            scan.consumedAccessTransformer(resourcePath);
            scan.preserveResource(resourcePath);
            scan.accessTransformerSeen();
            scan.debug("minecraft: declared access transformer %s is not present in the archive", resourcePath);
            return;
        }
        // scanTransformer marks the resource consumed itself when it starts.
        scanTransformer(resourcePath, resource.bytes(), scan, pool);
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /** Keeps in-archive classes referenced from a member descriptor. */
    static void keepDescriptorTypes(String descriptor, MinecraftScan scan, ClassPool pool) {
        if (descriptor == null || pool == null) {
            return;
        }
        Matcher matcher = DESCRIPTOR_TYPE.matcher(descriptor);
        while (matcher.find()) {
            String internal = matcher.group(1);
            if (pool.getClass(internal) != null) {
                scan.keepClass(internal);
            }
        }
    }

    /** Removes a {@code #} comment outside quotes (neither format quotes paths). */
    private static String stripComment(String line) {
        int hash = line.indexOf('#');
        if (hash < 0) {
            return line;
        }
        return line.substring(0, hash);
    }
}
