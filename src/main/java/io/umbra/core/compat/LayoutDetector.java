package io.umbra.core.compat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Detects the archive layout without transforming anything.
 *
 * <p>Detection is intentionally conservative: a Spring Boot or WAR layout is
 * only claimed when the corresponding container prefixes are present (the
 * manifest {@code Main-Class} alone is not enough). The {@code layout.enabled},
 * {@code layout.springBoot} and {@code layout.war} options disable detection,
 * which restores the legacy flat handling as an escape hatch.</p>
 */
public final class LayoutDetector {

    private LayoutDetector() {
    }

    /** Scans an open ZIP archive and returns the detected layout. */
    public static JarLayout detect(ZipFile zip, LayoutOptions options, List<String> warnings)
            throws IOException {
        LayoutOptions effective = options == null ? LayoutOptions.defaults() : options;
        boolean enabled = effective.enabled();
        boolean hasBootClasses = false;
        boolean hasBootLib = false;
        boolean hasWebClasses = false;
        boolean hasWebLib = false;
        boolean hasRootBootLoader = false;
        boolean hasWebXml = false;
        boolean multiReleaseAttribute = false;
        String mainClass = null;
        String startClass = null;
        int maxVersion = 0;
        int nestedLibraries = 0;
        boolean moduleInfo = false;
        boolean versions = false;

        byte[] manifest = null;
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            if (entry.isDirectory()) {
                continue;
            }
            String name = entry.getName();
            String upper = name.toUpperCase(Locale.ROOT);
            if (upper.startsWith("BOOT-INF/CLASSES/")) {
                hasBootClasses = true;
            } else if (upper.startsWith(JarLayout.BOOT_LIB.toUpperCase(Locale.ROOT))) {
                hasBootLib = true;
                if (upper.endsWith(".JAR")) {
                    nestedLibraries++;
                }
            } else if (upper.startsWith("WEB-INF/CLASSES/")) {
                hasWebClasses = true;
            } else if (upper.startsWith(JarLayout.WAR_LIB.toUpperCase(Locale.ROOT))) {
                hasWebLib = true;
                if (upper.endsWith(".JAR")) {
                    nestedLibraries++;
                }
            } else if ("WEB-INF/WEB.XML".equals(upper)) {
                hasWebXml = true;
            } else if (upper.startsWith("ORG/SPRINGFRAMEWORK/BOOT/LOADER/")) {
                hasRootBootLoader = true;
            }
            if (upper.startsWith("META-INF/VERSIONS/")) {
                versions = true;
                int version = versionOf(name);
                if (version > maxVersion) {
                    maxVersion = version;
                }
            }
            if (upper.endsWith("/MODULE-INFO.CLASS") || "MODULE-INFO.CLASS".equals(upper)) {
                moduleInfo = true;
            }
            if ("META-INF/MANIFEST.MF".equalsIgnoreCase(name)) {
                manifest = readAll(zip.getInputStream(entry));
            }
        }
        if (manifest != null) {
            Map<String, String> attributes = ManifestRewriter.parseMainAttributes(manifest);
            mainClass = attributes.get("Main-Class");
            startClass = attributes.get("Start-Class");
            String multiRelease = attributes.get("Multi-Release");
            multiReleaseAttribute = "true".equalsIgnoreCase(multiRelease == null ? "" : multiRelease.trim());
        }
        if (moduleInfo) {
            // Detected through the case-insensitive scan above; cheap re-check for
            // versioned-only module descriptors.
            moduleInfo = true;
        }

        String lowerMain = mainClass == null ? "" : mainClass.toLowerCase(Locale.ROOT);
        boolean bootLauncher = lowerMain.contains("org.springframework.boot.loader")
                || lowerMain.endsWith("jarlauncher") || lowerMain.endsWith("warlauncher")
                || lowerMain.endsWith("propertieslauncher");
        boolean bootSignals = hasBootClasses || hasBootLib || bootLauncher || hasRootBootLoader;
        boolean boot = enabled && effective.springBoot() && bootSignals
                && (hasBootClasses || hasWebClasses);
        boolean bootWar = boot && hasWebClasses;
        boolean war = !boot && enabled && effective.war() && hasWebClasses;

        JarLayout.Kind kind;
        String classPrefix;
        if (boot) {
            kind = bootWar ? JarLayout.Kind.SPRING_BOOT_WAR : JarLayout.Kind.SPRING_BOOT;
            classPrefix = bootWar ? JarLayout.WAR_CLASSES : JarLayout.BOOT_CLASSES;
        } else if (war) {
            kind = JarLayout.Kind.WAR;
            classPrefix = JarLayout.WAR_CLASSES;
        } else {
            kind = JarLayout.Kind.FLAT;
            classPrefix = "";
        }

        if (warnings != null) {
            if (!enabled && bootSignals) {
                warnings.add("layout.enabled=false: Spring Boot/WAR archive handled with legacy flat rules");
            } else if (enabled && !effective.springBoot() && bootSignals) {
                warnings.add("layout.springBoot=false: Spring Boot archive handled with legacy flat rules");
            } else if (enabled && !effective.war() && !boot && hasWebClasses) {
                warnings.add("layout.war=false: WAR archive handled with legacy flat rules");
            }
            if (kind == JarLayout.Kind.FLAT && bootLauncher && !hasBootClasses) {
                warnings.add("manifest declares a Spring Boot loader but BOOT-INF/classes is missing; "
                        + "treating the archive as flat");
            }
            if (boot && hasWebXml && bootWar) {
                // Expected for executable WARs; nothing to report.
            } else if (hasWebClasses && !boot) {
                warnings.add("WEB-INF/classes detected (WAR layout)");
            }
            if (hasWebLib) {
                warnings.add("WAR nested libraries are preserved byte-identically");
            }
        }

        return JarLayout.of(kind, classPrefix, versions || multiReleaseAttribute,
                multiReleaseAttribute, moduleInfo, maxVersion, mainClass, startClass,
                nestedLibraries);
    }

    /** Best-effort detection for pools assembled without {@code Jars.read}. */
    public static JarLayout detectFromPool(io.umbra.core.model.ClassPool pool, LayoutOptions options) {
        LayoutOptions effective = options == null ? LayoutOptions.defaults() : options;
        if (pool == null || !effective.enabled()) {
            return JarLayout.flat();
        }
        boolean bootClasses = false;
        boolean warClasses = false;
        int bootLibs = 0;
        int warLibs = 0;
        boolean versions = false;
        for (String className : pool.classes().keySet()) {
            String prefix = pool.entryPrefix(className);
            if (JarLayout.BOOT_CLASSES.equals(prefix)) {
                bootClasses = true;
            } else if (JarLayout.WAR_CLASSES.equals(prefix)) {
                warClasses = true;
            }
        }
        for (String resource : pool.resources().keySet()) {
            if (resource.startsWith(JarLayout.BOOT_LIB) && resource.toLowerCase(Locale.ROOT).endsWith(".jar")) {
                bootLibs++;
            } else if (resource.startsWith(JarLayout.WAR_LIB)
                    && resource.toLowerCase(Locale.ROOT).endsWith(".jar")) {
                warLibs++;
            } else if (resource.startsWith("META-INF/versions/")) {
                versions = true;
            }
        }
        String mainClass = null;
        String startClass = null;
        Map<String, String> attributes = pool.resources().containsKey(ManifestRewriter.MANIFEST_ENTRY)
                ? ManifestRewriter.parseMainAttributes(pool.resource(ManifestRewriter.MANIFEST_ENTRY).bytes())
                : new java.util.LinkedHashMap<String, String>();
        mainClass = attributes.get("Main-Class");
        startClass = attributes.get("Start-Class");
        boolean multiReleaseAttribute = "true".equalsIgnoreCase(
                attributes.get("Multi-Release") == null ? "" : attributes.get("Multi-Release").trim());
        JarLayout.Kind kind;
        String prefix;
        boolean boot = effective.springBoot() && (bootClasses || (bootLibs > 0
                && mainClass != null && mainClass.toLowerCase(Locale.ROOT).contains("org.springframework.boot.loader")));
        boolean war = !boot && effective.war() && warClasses;
        if (boot) {
            kind = warClasses ? JarLayout.Kind.SPRING_BOOT_WAR : JarLayout.Kind.SPRING_BOOT;
            prefix = warClasses ? JarLayout.WAR_CLASSES : JarLayout.BOOT_CLASSES;
        } else if (war) {
            kind = JarLayout.Kind.WAR;
            prefix = JarLayout.WAR_CLASSES;
        } else {
            kind = JarLayout.Kind.FLAT;
            prefix = "";
        }
        return JarLayout.of(kind, prefix, versions || multiReleaseAttribute, multiReleaseAttribute,
                false, 0, mainClass, startClass, bootLibs + warLibs);
    }

    private static int versionOf(String entryName) {
        int start = "META-INF/versions/".length();
        int slash = entryName.indexOf('/', start);
        if (slash < 0) {
            return 0;
        }
        try {
            return Integer.parseInt(entryName.substring(start, slash));
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    /** Reads the manifest text of an archive for inspection helpers. */
    public static String manifestText(byte[] manifest) {
        return manifest == null ? "" : new String(manifest, StandardCharsets.UTF_8);
    }
}
