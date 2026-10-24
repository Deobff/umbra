package io.umbra.core.engine;

import io.umbra.core.compat.JarLayout;
import io.umbra.core.compat.LayoutDetector;
import io.umbra.core.compat.LayoutOptions;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * Loads every class from an output archive without initializing it, forcing the
 * JVM to link (and therefore verify) the bytecode, and performs layout-aware
 * structural checks on the produced archive.
 *
 * <p>The verifier understands the layouts Umbra can write:</p>
 *
 * <ul>
 *   <li>flat JARs: classes at the root;</li>
 *   <li>Spring Boot fat JARs: classes under {@code BOOT-INF/classes/}, nested
 *       libraries under {@code BOOT-INF/lib/} (extracted to a temporary
 *       classpath so application classes can link their dependencies);</li>
 *   <li>WARs: classes under {@code WEB-INF/classes/}, libraries under
 *       {@code WEB-INF/lib/};</li>
 *   <li>multi-release entries: every {@code META-INF/versions/N/} class is
 *       parsed and checked for a consistent entry path/binary name, a matching
 *       {@code Multi-Release: true} attribute and a class-file version that the
 *       JVM will accept for that directory;</li>
 *   <li>module descriptors: base and versioned {@code module-info.class} files
 *       are parsed as module attributes and must declare one consistent module
 *       name.</li>
 * </ul>
 *
 * <p>Layout-destroying post-processors are caught structurally: a manifest that
 * declares a Spring Boot loader while no {@code BOOT-INF/classes/} entries
 * remain is an error, and manifest entry points that reference missing classes
 * are errors.</p>
 */
public final class UmbraVerifier {

    /** Directory prefixes whose contents are class-path roots for non-flat layouts. */
    private static final String BOOT_CLASSES = "BOOT-INF/classes/";
    private static final String WAR_CLASSES = "WEB-INF/classes/";
    private static final String BOOT_LIB = "BOOT-INF/lib/";
    private static final String WAR_LIB = "WEB-INF/lib/";
    private static final String VERSIONS_PREFIX = "META-INF/versions/";

    /** Class-file major version supported by the JVM running Umbra. */
    private static final int RUNTIME_CLASS_MAJOR = runtimeClassMajor();

    private UmbraVerifier() {
    }

    /**
     * @param jar output archive
     * @return human-readable verification failures; empty when the archive links
     *         and its layout is structurally intact
     * @throws IOException if the archive cannot be read
     */
    public static List<String> verify(Path jar) throws IOException {
        return verify(jar, Collections.<Path>emptyList());
    }

    /**
     * @param jar       output archive
     * @param libraries library JARs/directories added to the verification class path
     * @return human-readable verification failures; empty on success
     * @throws IOException if the archive cannot be read
     */
    public static List<String> verify(Path jar, List<Path> libraries) throws IOException {
        return verifyDetailed(jar, libraries).errors();
    }

    /** Full verification result, including per-layout reporting. */
    public static Report verifyDetailed(Path jar, List<Path> libraries) throws IOException {
        Report report = new Report();
        List<String> warnings = new ArrayList<String>();
        Map<String, byte[]> classBytes = new LinkedHashMap<String, byte[]>();
        Map<String, Integer> entryCounts = new LinkedHashMap<String, Integer>();
        List<String> classEntryNames = new ArrayList<String>();
        List<String> versionedEntries = new ArrayList<String>();
        List<String> moduleInfoEntries = new ArrayList<String>();
        List<String> nestedLibraries = new ArrayList<String>();
        Map<String, byte[]> nestedLibraryBytes = new LinkedHashMap<String, byte[]>();
        Map<String, byte[]> smallText = new LinkedHashMap<String, byte[]>();
        List<ZipEntry> entries = new ArrayList<ZipEntry>();

        try (ZipFile zip = new ZipFile(jar.toFile())) {
            JarLayout layout = LayoutDetector.detect(zip, LayoutOptions.defaults(), warnings);
            report.layout = layout;
            Enumeration<? extends ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                entries.add(enumeration.nextElement());
            }
            Collections.sort(entries, new Comparator<ZipEntry>() {
                @Override
                public int compare(ZipEntry a, ZipEntry b) {
                    return a.getName().compareTo(b.getName());
                }
            });
            for (ZipEntry entry : entries) {
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                Integer previous = entryCounts.get(name);
                entryCounts.put(name, Integer.valueOf(previous == null ? 1 : previous.intValue() + 1));
                if (previous != null && previous.intValue() == 1) {
                    report.notes.add("duplicate entry name: " + name + " (first occurrence used)");
                }
                String upper = name.toUpperCase(Locale.ROOT);
                if (name.startsWith(VERSIONS_PREFIX)) {
                    if (upper.endsWith(".CLASS")) {
                        versionedEntries.add(name);
                        classBytes.put(name, readAll(zip.getInputStream(entry)));
                    }
                    continue;
                }
                if (upper.startsWith("META-INF/") && isSignatureFile(upper)) {
                    report.errors.add("signed archive: signature entry " + name
                            + " must not be present in a protected output");
                    continue;
                }
                if ("META-INF/MANIFEST.MF".equalsIgnoreCase(name)) {
                    smallText.put(name, readAll(zip.getInputStream(entry)));
                    continue;
                }
                if ("META-INF/INDEX.LIST".equalsIgnoreCase(name)) {
                    report.notes.add("stale META-INF/INDEX.LIST present; it is ignored by the JVM");
                    continue;
                }
                if (upper.endsWith("/MODULE-INFO.CLASS") || "MODULE-INFO.CLASS".equals(upper)) {
                    moduleInfoEntries.add(name);
                    classBytes.put(name, readAll(zip.getInputStream(entry)));
                    continue;
                }
                if (upper.endsWith(".CLASS")) {
                    classEntryNames.add(name);
                    classBytes.put(name, readAll(zip.getInputStream(entry)));
                    continue;
                }
                if (name.startsWith(BOOT_LIB) && upper.endsWith(".JAR")) {
                    nestedLibraries.add(name);
                    byte[] libraryBytes = readAll(zip.getInputStream(entry));
                    nestedLibraryBytes.put(name, libraryBytes);
                    validateNestedLibrary(report, name, libraryBytes);
                    continue;
                }
                if (name.startsWith(WAR_LIB) && upper.endsWith(".JAR")) {
                    nestedLibraries.add(name);
                    byte[] libraryBytes = readAll(zip.getInputStream(entry));
                    nestedLibraryBytes.put(name, libraryBytes);
                    validateNestedLibrary(report, name, libraryBytes);
                }
            }
        }

        report.layoutKind = report.layout.kindId();
        report.classPrefix = report.layout.classPrefix();
        report.nestedLibraries = nestedLibraries.size();
        report.versionedClasses = versionedEntries.size();
        report.moduleDescriptors = moduleInfoEntries.size();
        report.notes.add("layout: " + report.layout.describe());

        byte[] manifest = smallText.get("META-INF/MANIFEST.MF");
        Map<String, String> attributes = manifest == null
                ? Collections.<String, String>emptyMap()
                : io.umbra.core.util.Jars.parseManifest(manifest);
        String mainClass = attributes.get("Main-Class");
        String startClass = attributes.get("Start-Class");
        boolean bootLoaderMain = mainClass != null
                && mainClass.toLowerCase(Locale.ROOT).contains("org.springframework.boot.loader");

        Set<String> entryNames = new LinkedHashSet<String>(entryCounts.keySet());
        boolean hasBootClasses = hasPrefix(entryNames, BOOT_CLASSES);
        boolean hasWarClasses = hasPrefix(entryNames, WAR_CLASSES);

        // Layout-destroying post-processors: the container root vanished.
        if (bootLoaderMain && !hasBootClasses && !hasWarClasses) {
            report.errors.add("layout: manifest Main-Class is a Spring Boot loader (" + mainClass
                    + ") but the nested class root (BOOT-INF/classes/ or WEB-INF/classes/) is missing; "
                    + "an archive post-processor destroyed the Spring Boot layout");
        }
        if (!nestedLibraries.isEmpty() && !hasBootClasses && !hasWarClasses) {
            report.errors.add("layout: " + nestedLibraries.size() + " nested library archive(s) are "
                    + "still present but the container class root (BOOT-INF/classes/ or "
                    + "WEB-INF/classes/) is missing; an archive post-processor destroyed the layout");
        }
        if (attributes.get("Spring-Boot-Version") != null && !hasBootClasses && !hasWarClasses) {
            report.errors.add("layout: manifest declares a Spring Boot application but no "
                    + "BOOT-INF/classes/ or WEB-INF/classes/ entries remain");
        }
        String springBootClasses = attributes.get("Spring-Boot-Classes");
        if (springBootClasses != null && !springBootClasses.trim().isEmpty()) {
            String prefix = springBootClasses.trim();
            if (!prefix.endsWith("/")) {
                prefix = prefix + "/";
            }
            if (!hasPrefix(entryNames, prefix)) {
                report.errors.add("layout: manifest Spring-Boot-Classes=" + springBootClasses
                        + " but no entries exist under that prefix");
            }
        }
        String springBootLib = attributes.get("Spring-Boot-Lib");
        if (springBootLib != null && !springBootLib.trim().isEmpty() && nestedLibraries.isEmpty()) {
            report.notes.add("manifest Spring-Boot-Lib=" + springBootLib + " is present but no nested "
                    + "library archives were found (application without dependencies)");
        }

        checkEntryPoint(report, entryNames, "Main-Class", mainClass, report.layout);
        checkEntryPoint(report, entryNames, "Start-Class", startClass, report.layout);
        checkEntryPoint(report, entryNames, "Premain-Class", attributes.get("Premain-Class"), report.layout);
        checkEntryPoint(report, entryNames, "Agent-Class", attributes.get("Agent-Class"), report.layout);
        checkEntryPoint(report, entryNames, "Launcher-Agent-Class",
                attributes.get("Launcher-Agent-Class"), report.layout);

        // Multi-release structural checks.
        checkMultiRelease(report, entryNames, attributes, versionedEntries, classBytes);
        // Module descriptors.
        checkModuleInfo(report, moduleInfoEntries, classBytes);
        if (report.layout.kind() == JarLayout.Kind.WAR && !entryNames.contains("WEB-INF/web.xml")) {
            report.notes.add("WAR layout without WEB-INF/web.xml (allowed for annotation-only web apps)");
        }

        // Verify that archive class entries sit at their expected paths.
        for (String entryName : classEntryNames) {
            byte[] bytes = classBytes.get(entryName);
            if (bytes == null) {
                continue;
            }
            String expectedName;
            try {
                expectedName = new ClassReader(bytes).getClassName();
            } catch (RuntimeException malformed) {
                report.errors.add(entryName + ": unparseable class file ("
                        + malformed.getMessage() + ')');
                continue;
            }
            String expectedPath = expectedEntryPath(expectedName, entryName, report.layout);
            if (!expectedPath.equals(entryName)) {
                report.errors.add(entryName + ": class file declares internal name " + expectedName
                        + " but lives at the wrong entry path (expected " + expectedPath + ')');
            }
            report.expectedClassEntries.add(expectedPath);
        }

        // Load classes: root classes through the archive URL, nested-layout
        // classes through a child-first map; nested libraries are extracted so
        // application classes can link their dependencies.
        Path extraction = null;
        try {
            List<URL> urls = new ArrayList<URL>();
            urls.add(jar.toUri().toURL());
            if (!nestedLibraries.isEmpty()) {
                extraction = Files.createTempDirectory("umbra-verify-libs-");
                int index = 0;
                for (String name : nestedLibraries) {
                    byte[] libraryBytes = nestedLibraryBytes.get(name);
                    if (libraryBytes == null) {
                        continue;
                    }
                    Path nested = extraction.resolve("lib" + (index++) + ".jar");
                    Files.write(nested, libraryBytes);
                    urls.add(nested.toUri().toURL());
                }
            }
            if (libraries != null) {
                for (Path library : libraries) {
                    if (library != null && Files.exists(library)) {
                        urls.add(library.toUri().toURL());
                    }
                }
            }
            final Map<String, byte[]> prefixed = new LinkedHashMap<String, byte[]>();
            for (String entryName : classEntryNames) {
                byte[] bytes = classBytes.get(entryName);
                if (bytes == null) {
                    continue;
                }
                String binaryName;
                try {
                    binaryName = new ClassReader(bytes).getClassName().replace('/', '.');
                } catch (RuntimeException malformed) {
                    continue;
                }
                String rootRelativePath = binaryName.replace('.', '/') + ".class";
                if (!rootRelativePath.equals(entryName)) {
                    // Container-prefixed class: a plain URLClassLoader cannot
                    // find it, so define the bytes through the child-first hook.
                    prefixed.put(binaryName, bytes);
                }
            }
            URLClassLoader loader = new URLClassLoader(urls.toArray(new URL[0]),
                    UmbraVerifier.class.getClassLoader()) {
                @Override
                protected Class<?> findClass(String className) throws ClassNotFoundException {
                    byte[] bytes = prefixed.get(className);
                    if (bytes != null) {
                        return defineClass(className, bytes, 0, bytes.length);
                    }
                    return super.findClass(className);
                }
            };
            try {
                Set<String> verified = new LinkedHashSet<String>();
                for (String entryName : classEntryNames) {
                    byte[] bytes = classBytes.get(entryName);
                    if (bytes == null) {
                        continue;
                    }
                    String className;
                    try {
                        className = new ClassReader(bytes).getClassName().replace('/', '.');
                    } catch (RuntimeException malformed) {
                        continue;
                    }
                    if (!verified.add(className)) {
                        report.errors.add(entryName + ": duplicate binary class name " + className);
                        continue;
                    }
                    int major = classMajorVersion(bytes);
                    if (major > RUNTIME_CLASS_MAJOR) {
                        // The tool may run on an older JDK than the protected
                        // artifact targets; structural checks still apply but
                        // the JVM cannot link these classes here.
                        report.notes.add(entryName + ": not linked, class file version " + major
                                + " requires a newer JVM than " + RUNTIME_CLASS_MAJOR);
                        report.skippedByVersion++;
                        continue;
                    }
                    try {
                        Class<?> type = Class.forName(className, false, loader);
                        type.getDeclaredMethods();
                        type.getDeclaredFields();
                        report.classesVerified++;
                    } catch (Throwable failure) {
                        report.errors.add(entryName + " (" + className + "): "
                                + failure.getClass().getName() + ": " + failure.getMessage());
                    }
                }
            } finally {
                loader.close();
            }
        } finally {
            deleteDirectory(extraction);
        }

        for (String warning : warnings) {
            report.notes.add(warning);
        }
        report.notes.add("verified " + report.classesVerified + " classes, "
                + report.versionedClasses + " multi-release variants, "
                + report.moduleDescriptors + " module descriptor(s), "
                + report.nestedLibraries + " nested library archive(s)");
        return report;
    }

    // ------------------------------------------------------------------
    // Structural checks
    // ------------------------------------------------------------------

    private static void checkEntryPoint(Report report, Set<String> entryNames, String attribute,
                                        String value, JarLayout layout) {
        if (value == null || value.trim().isEmpty()) {
            return;
        }
        String internal = value.trim().replace('.', '/');
        String flatPath = internal + ".class";
        String nestedPath = (layout.isFlat() ? "" : layout.classPrefix()) + flatPath;
        if (entryNames.contains(nestedPath) || entryNames.contains(flatPath)) {
            return;
        }
        // A versioned-only class is a valid multi-release layout: the JVM
        // selects it from META-INF/versions/N on the matching runtime even
        // though no base entry exists.
        String suffix = "/" + flatPath;
        for (String candidate : entryNames) {
            if (candidate.startsWith(VERSIONS_PREFIX) && candidate.endsWith(suffix)) {
                report.notes.add("manifest " + attribute + "=" + value.trim()
                        + " resolves only in META-INF/versions (multi-release)");
                return;
            }
        }
        report.errors.add("manifest " + attribute + "=" + value.trim()
                + " does not resolve to a class entry in the archive");
    }

    private static void checkMultiRelease(Report report, Set<String> entryNames,
                                          Map<String, String> attributes,
                                          List<String> versionedEntries, Map<String, byte[]> classBytes) {
        if (versionedEntries.isEmpty()) {
            String attribute = attributes.get("Multi-Release");
            if (attribute != null && "true".equalsIgnoreCase(attribute.trim())) {
                report.notes.add("manifest declares Multi-Release: true but no META-INF/versions entries exist");
            }
            return;
        }
        String attribute = attributes.get("Multi-Release");
        if (attribute == null || !"true".equalsIgnoreCase(attribute.trim())) {
            report.errors.add("META-INF/versions entries exist but the manifest lacks "
                    + "Multi-Release: true (the JVM ignores the versioned entries)");
        }
        Set<String> seen = new LinkedHashSet<String>();
        for (String entryName : versionedEntries) {
            String relative = entryName.substring(VERSIONS_PREFIX.length());
            int slash = relative.indexOf('/');
            if (slash <= 0) {
                report.errors.add(entryName + ": versioned entry has no class path after the version directory");
                continue;
            }
            int version;
            try {
                version = Integer.parseInt(relative.substring(0, slash));
            } catch (NumberFormatException invalid) {
                report.errors.add(entryName + ": version directory is not a number");
                continue;
            }
            String inner = relative.substring(slash + 1);
            if (!seen.add(version + "|" + inner)) {
                report.errors.add(entryName + ": duplicate multi-release entry for version " + version
                        + " and path " + inner);
            }
            byte[] bytes = classBytes.get(entryName);
            if (bytes == null) {
                continue;
            }
            if (inner.equals("module-info.class")) {
                continue; // validated by checkModuleInfo
            }
            String internalName;
            int major;
            try {
                internalName = new ClassReader(bytes).getClassName();
                major = classMajorVersion(bytes);
            } catch (RuntimeException malformed) {
                report.errors.add(entryName + ": unparseable versioned class ("
                        + malformed.getMessage() + ')');
                continue;
            }
            String expectedInner = internalName + ".class";
            if (!inner.equals(expectedInner)) {
                report.errors.add(entryName + ": versioned class declares internal name " + internalName
                        + " but its path should be " + expectedInner);
            }
            if (major > 0 && major < version + 44) {
                report.notes.add(entryName + ": class file version " + major
                        + " is below the minimum for META-INF/versions/" + version
                        + " (the JVM ignores this copy)");
            }
        }
    }

    private static void checkModuleInfo(Report report, List<String> moduleEntries,
                                        Map<String, byte[]> classBytes) {
        String expectedModuleName = null;
        String expectedEntry = null;
        for (String entryName : moduleEntries) {
            byte[] bytes = classBytes.get(entryName);
            if (bytes == null) {
                continue;
            }
            final String[] moduleName = new String[1];
            boolean[] sawModule = new boolean[1];
            try {
                new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
                    @Override
                    public ModuleVisitor visitModule(String name, int access, String version) {
                        sawModule[0] = true;
                        moduleName[0] = name;
                        return null;
                    }
                }, 0);
            } catch (RuntimeException malformed) {
                report.errors.add(entryName + ": unparseable module descriptor ("
                        + malformed.getMessage() + ')');
                continue;
            }
            if (!sawModule[0] || moduleName[0] == null) {
                report.errors.add(entryName + ": not a module descriptor");
                continue;
            }
            if (expectedModuleName == null) {
                expectedModuleName = moduleName[0];
                expectedEntry = entryName;
            } else if (!expectedModuleName.equals(moduleName[0])) {
                report.errors.add(entryName + ": module name " + moduleName[0]
                        + " differs from " + expectedModuleName + " declared by " + expectedEntry);
            }
        }
    }

    private static void validateNestedLibrary(Report report, String entryName, byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            report.errors.add(entryName + ": nested library archive is empty");
            return;
        }
        // ZipInputStream silently stops at the first invalid signature, so a
        // corrupt/garbage "nested jar" would otherwise be reported as an empty
        // archive. Validate the ZIP structure explicitly first.
        if (bytes.length < 4 || !hasSignature(bytes, 0, 0x04034b50)) {
            report.errors.add(entryName + ": nested library is not a valid ZIP archive "
                    + "(missing local file header signature)");
            return;
        }
        if (!hasEndOfCentralDirectory(bytes)) {
            report.errors.add(entryName + ": nested library is truncated "
                    + "(missing end-of-central-directory record)");
            return;
        }
        int entries = 0;
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                entries++;
                byte[] buffer = new byte[4096];
                while (in.read(buffer) >= 0) {
                    // Drain the entry so the next header is read correctly.
                }
            }
        } catch (ZipException malformed) {
            report.errors.add(entryName + ": nested library is not a valid ZIP archive ("
                    + malformed.getMessage() + ')');
            return;
        } catch (IOException failure) {
            report.errors.add(entryName + ": nested library could not be read ("
                    + failure.getMessage() + ')');
            return;
        }
        if (entries == 0) {
            report.notes.add(entryName + ": nested library contains no entries");
        }
    }

    private static boolean hasSignature(byte[] bytes, int offset, int signature) {
        return offset + 4 <= bytes.length
                && (bytes[offset] & 0xFF) == (signature & 0xFF)
                && (bytes[offset + 1] & 0xFF) == ((signature >>> 8) & 0xFF)
                && (bytes[offset + 2] & 0xFF) == ((signature >>> 16) & 0xFF)
                && (bytes[offset + 3] & 0xFF) == ((signature >>> 24) & 0xFF);
    }

    /** Scans the trailing comment window for the ZIP end-of-central-directory record. */
    private static boolean hasEndOfCentralDirectory(byte[] bytes) {
        int start = Math.max(0, bytes.length - (0xFFFF + 22));
        for (int offset = bytes.length - 22; offset >= start; offset--) {
            if (hasSignature(bytes, offset, 0x06054b50)) {
                return true;
            }
        }
        return false;
    }

    /** Class-file major version supported by the JVM running Umbra (52 for Java 8). */
    private static int runtimeClassMajor() {
        String property = System.getProperty("java.class.version", "");
        int dot = property.indexOf('.');
        try {
            return Integer.parseInt(dot < 0 ? property : property.substring(0, dot));
        } catch (NumberFormatException ignored) {
            return 52;
        }
    }

    private static int classMajorVersion(byte[] bytes) {
        if (bytes.length < 8) {
            return -1;
        }
        if ((bytes[0] & 0xFF) != 0xCA || (bytes[1] & 0xFF) != 0xFE
                || (bytes[2] & 0xFF) != 0xBA || (bytes[3] & 0xFF) != 0xBE) {
            return -1;
        }
        return ((bytes[6] & 0xFF) << 8) | (bytes[7] & 0xFF);
    }

    /**
     * Expected entry path for a class: classes under the container class root
     * live at {@code prefix + internalName.class}; preserved root classes (for
     * example Spring Boot loader classes) stay at the archive root.
     */
    private static String expectedEntryPath(String internalName, String actualEntry, JarLayout layout) {
        if (!layout.isFlat() && !actualEntry.startsWith(layout.classPrefix())) {
            return internalName + ".class";
        }
        return layout.classPrefix() + internalName + ".class";
    }

    private static boolean hasPrefix(Set<String> names, String prefix) {
        for (String name : names) {
            if (name.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSignatureFile(String upperName) {
        return upperName.endsWith(".SF") || upperName.endsWith(".RSA")
                || upperName.endsWith(".DSA") || upperName.endsWith(".EC");
    }

    private static void deleteDirectory(Path directory) {
        if (directory == null || !Files.exists(directory)) {
            return;
        }
        try {
            Files.walk(directory)
                    .sorted(Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (IOException ignored) {
                            // Best-effort temporary cleanup.
                        }
                    });
        } catch (IOException ignored) {
            // Best-effort temporary cleanup.
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

    /** Per-layout verification result. */
    public static final class Report {
        private JarLayout layout = JarLayout.flat();
        private String layoutKind = "flat";
        private String classPrefix = "";
        private int classesVerified;
        private int skippedByVersion;
        private int versionedClasses;
        private int moduleDescriptors;
        private int nestedLibraries;
        private final List<String> errors = new ArrayList<String>();
        private final List<String> notes = new ArrayList<String>();
        private final List<String> expectedClassEntries = new ArrayList<String>();

        public JarLayout layout() {
            return layout;
        }

        /** Layout id: flat, spring-boot, spring-boot-war, war or multi-release. */
        public String layoutKind() {
            return layoutKind;
        }

        public String classPrefix() {
            return classPrefix;
        }

        public int classesVerified() {
            return classesVerified;
        }

        /** Classes with a class-file version newer than the running JVM (not linked). */
        public int skippedByVersion() {
            return skippedByVersion;
        }

        public int versionedClasses() {
            return versionedClasses;
        }

        public int moduleDescriptors() {
            return moduleDescriptors;
        }

        public int nestedLibraries() {
            return nestedLibraries;
        }

        /** Verification failures; empty when the archive is acceptable. */
        public List<String> errors() {
            return Collections.unmodifiableList(errors);
        }

        /** Informational notes (layout summary, preserved entries, ignored versions). */
        public List<String> notes() {
            return Collections.unmodifiableList(notes);
        }

        public boolean ok() {
            return errors.isEmpty();
        }

        /** Expected class entry paths observed in the archive (layout-aware). */
        public List<String> expectedClassEntries() {
            return Collections.unmodifiableList(expectedClassEntries);
        }

        /** One-line summary used by CLI inspection/reporting. */
        public String summary() {
            return "layout=" + layoutKind + (classPrefix.isEmpty() ? "" : " classes=" + classPrefix)
                    + " classes=" + classesVerified
                    + (skippedByVersion > 0 ? " skipped-newer=" + skippedByVersion : "")
                    + " versioned=" + versionedClasses
                    + " module-info=" + moduleDescriptors + " nested-libs=" + nestedLibraries
                    + " errors=" + errors.size();
        }
    }
}
