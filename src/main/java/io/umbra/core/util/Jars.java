package io.umbra.core.util;

import io.umbra.core.compat.ClassRenameMap;
import io.umbra.core.compat.JarLayout;
import io.umbra.core.compat.LayoutContext;
import io.umbra.core.compat.LayoutDetector;
import io.umbra.core.compat.LayoutOptions;
import io.umbra.core.compat.LayoutRegistry;
import io.umbra.core.compat.LayoutReport;
import io.umbra.core.compat.ManifestRewriter;
import io.umbra.core.compat.ModuleInfoRewriter;
import io.umbra.core.compat.TextResourceRewriter;
import io.umbra.core.compat.VersionedClass;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * JAR input/output helpers with full archive-layout compatibility.
 *
 * <p>The reader normalises an archive into the {@link ClassPool} while keeping
 * the physical layout in a {@link LayoutContext}: classes are keyed by internal
 * name and remember their entry prefix, while nested libraries, loader classes,
 * multi-release variants, module descriptors and opaque resources are preserved
 * for the writer. The writer reproduces the same layout: classes are written
 * back under their original prefix, multi-release variants are remapped with the
 * same naming mapping as the base classes, manifests/service descriptors are
 * rewritten, and everything the protector must not touch is copied
 * byte-identically.</p>
 *
 * <p>The flat-JAR path keeps the previous behaviour: one class per internal
 * name, classes at the root, resources untouched, deterministic ordering and
 * timestamps.</p>
 */
public final class Jars {

    private static final long FIXED_TIME = 315532800000L;
    private static final String VERSIONS_PREFIX = "META-INF/versions/";
    private static final String MANIFEST_ENTRY = "META-INF/MANIFEST.MF";

    private Jars() {
    }

    public static void read(Path input, ClassPool pool, Log log) throws IOException {
        readInternal(input, pool, log, LayoutOptions.defaults(), null);
    }

    public static JarLayout read(Path input, ClassPool pool, Log log, LayoutOptions options)
            throws IOException {
        return readInternal(input, pool, log,
                options == null ? LayoutOptions.defaults() : options, null);
    }

    public static JarLayout read(Path input, ClassPool pool, Log log, Map<String, String> options)
            throws IOException {
        LayoutOptions parsed = LayoutOptions.from(options);
        return readInternal(input, pool, log, parsed, options);
    }

    private static JarLayout readInternal(Path input, ClassPool pool, Log log,
                                          LayoutOptions options, Map<String, String> rawOptions)
            throws IOException {
        if (pool == null) {
            throw new IllegalArgumentException("class pool is null");
        }
        boolean signedInput = false;
        boolean multiReleaseInput = false;
        boolean flattenMode = options.multiRelease() == LayoutOptions.MultiReleaseMode.FLATTEN;
        int versionedEntries = 0;
        int payloadClasses = 0;
        List<FlattenedClass> flattened = new ArrayList<FlattenedClass>();

        try (ZipFile zip = new ZipFile(input.toFile())) {
            List<String> layoutWarnings = new ArrayList<String>();
            JarLayout layout = LayoutDetector.detect(zip, options, layoutWarnings);
            LayoutContext context = new LayoutContext(layout, options);
            for (String warning : options.warnings()) {
                log.warn("layout: %s", warning);
                context.addWarning(warning);
            }
            for (String warning : layoutWarnings) {
                log.warn("layout: %s", warning);
                context.addWarning(warning);
            }
            LayoutRegistry.attach(pool, context);
            log.info("layout: %s", layout.describe());

            if (options.multiRelease() == LayoutOptions.MultiReleaseMode.PRESERVE
                    && (layout.multiRelease() || layout.maxVersion() > 0)) {
                log.info("multi-release input: preserving META-INF/versions with consistent remapping "
                        + "(layout.multiRelease=flatten flattens the input)");
            }
            warnIncompatibleOptions(layout, options, rawOptions, log, context);

            List<ZipEntry> entries = new ArrayList<ZipEntry>();
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
                String upper = name.toUpperCase(Locale.ROOT);
                if (isSignatureEntry(upper)) {
                    signedInput = true;
                    continue;
                }
                if ("META-INF/INDEX.LIST".equalsIgnoreCase(name)) {

                    continue;
                }
                if (upper.startsWith("META-INF/VERSIONS/")) {
                    versionedEntries++;
                    multiReleaseInput = true;
                    byte[] bytes = readAll(zip.getInputStream(entry));
                    if (flattenMode) {
                        handleFlattenedVersionedEntry(name, bytes, entry, layout, flattened,
                                context, log);
                    } else {
                        handlePreservedVersionedEntry(name, bytes, entry, layout, context, pool, log);
                    }
                    continue;
                }
                byte[] bytes = readAll(zip.getInputStream(entry));
                if (MANIFEST_ENTRY.equalsIgnoreCase(name)) {
                    bytes = stripUtf8Bom(bytes);
                    byte[] cleaned = stripSignatureAttributes(bytes);
                    if (cleaned != null) {
                        signedInput = true;
                        bytes = cleaned;
                    }
                    if (options.multiRelease() == LayoutOptions.MultiReleaseMode.FLATTEN) {
                        byte[] plain = stripMultiReleaseAttribute(bytes);
                        if (plain != null) {
                            multiReleaseInput = true;
                            bytes = plain;
                        }
                    }
                    putResource(context, pool, name, bytes, entry, log);
                    String main = parseMainClass(bytes);
                    if (main != null) {
                        pool.setMainClass(main.replace('.', '/'));
                    }
                    continue;
                }
                if (isModuleInfoEntry(name, layout)) {
                    putResource(context, pool, name, bytes, entry, log);
                    context.addModuleInfoEntry(name, bytes);
                    continue;
                }
                if (isTransformableClass(name, layout)) {
                    try {
                        ClassNode node = parseClassFile(bytes);
                        if (!isLoadableEntry(name, node.name, layout)) {
                            // The path does not name the class inside the file, so the JVM
                            // can never load it from here: it is payload data (code
                            // generator templates, embedded class files). Rewriting it would
                            // edit data the tool that shipped it still reads, and ASM can
                            // refuse a class this size outright - keep the bytes verbatim.
                            payloadClasses++;
                            pool.putOpaque(name, bytes, entry.getTime());
                            context.addPreservedEntry();
                            continue;
                        }
                        ClassNode existing = pool.getClass(node.name);
                        if (existing != null) {
                            handleDuplicateClass(context, pool, log, name, node.name, bytes);
                            continue;
                        }
                        pool.putClass(name, bytes, node);
                        pool.setClassTime(node.name, entry.getTime());
                        countClass(layout, name, context);
                        continue;
                    } catch (RuntimeException unparseable) {
                        log.warn("Unparseable class entry %s preserved as resource: %s",
                                name, unparseable.getMessage());
                    }
                }
                putResource(context, pool, name, bytes, entry, log);
            }
        }

        if (payloadClasses > 0 && log != null) {
            log.info("layout: kept %d class file(s) byte-identical as payload data "
                    + "(their entry path does not name the class they contain; the JVM cannot "
                    + "load them from there)", Integer.valueOf(payloadClasses));
        }
        int promoted = 0;
        if (!flattened.isEmpty()) {
            Collections.sort(flattened, new Comparator<FlattenedClass>() {
                @Override
                public int compare(FlattenedClass a, FlattenedClass b) {
                    return a.internalName.compareTo(b.internalName);
                }
            });
            for (FlattenedClass candidate : flattened) {
                if (pool.getClass(candidate.internalName) != null) {
                    continue;
                }
                try {
                    ClassReader reader = new ClassReader(candidate.bytes);
                    ClassNode node = new ClassNode();
                    reader.accept(node, 0);
                    String source = candidate.classPrefix + candidate.internalName + ".class";
                    pool.putClass(source, candidate.bytes, node);
                    promoted++;
                } catch (RuntimeException ignored) {

                }
            }
        }
        if (multiReleaseInput && log != null) {
            if (flattenMode) {
                log.warn("multi-release input: flattened %d versioned entries "
                        + "(%d versioned-only classes kept, base classes preferred); "
                        + "the protected JAR is a plain JAR", Integer.valueOf(versionedEntries),
                        Integer.valueOf(promoted));
            }
        }
        if (signedInput && log != null) {
            log.warn("signed input: removed JAR signature entries/attributes; "
                    + "the protected JAR is unsigned and must be re-signed by the publisher");
        }
        return LayoutRegistry.layout(pool);
    }

    private static void warnIncompatibleOptions(JarLayout layout, LayoutOptions options,
                                                Map<String, String> rawOptions, Log log,
                                                LayoutContext context) {
        boolean classEncryption = rawOptions != null
                && "true".equalsIgnoreCase(String.valueOf(rawOptions.get("classEncryption.enabled")).trim());
        if (classEncryption) {
            if (layout.multiRelease() && options.multiRelease() == LayoutOptions.MultiReleaseMode.PRESERVE) {
                log.warn("layout: classEncryption.enabled drops META-INF/versions entries; "
                        + "the protected archive loses its multi-release layout");
                context.addWarning("class encryption incompatible with multi-release preserve mode");
            }
            if (!layout.isFlat()) {
                log.warn("layout: classEncryption is not nested-layout aware and will move %s classes "
                        + "out of the container root", layout.classPrefix());
                context.addWarning("class encryption incompatible with " + layout.kindId() + " layout");
            }
        }
    }

    private static void handleDuplicateClass(LayoutContext context, ClassPool pool, Log log,
                                             String entryName, String internalName, byte[] bytes) {
        context.addDuplicateClass();
        byte[] chosen = pool.originalBytes(internalName);
        if (chosen != null && Arrays.equals(chosen, bytes)) {
            log.warn("duplicate class entry %s for internal name %s (identical bytes); "
                    + "keeping the first occurrence", entryName, internalName);
        } else {
            log.warn("duplicate class entry %s for internal name %s with different bytes; "
                    + "keeping the first occurrence (deterministic resolution)", entryName, internalName);
        }
    }

    private static void putResource(LayoutContext context, ClassPool pool, String name, byte[] bytes,
                                    ZipEntry entry, Log log) {
        if (pool.resource(name) != null) {
            context.addDuplicateEntry();
            log.warn("duplicate archive entry %s ignored (first occurrence wins)", name);
            return;
        }
        pool.putResource(name, bytes, entry.getTime(), entry.getMethod());
        if (!context.layout().isFlat() && !MANIFEST_ENTRY.equalsIgnoreCase(name)) {
            context.addPreservedEntry();
        }
    }

    /**
     * Whether the entry path is a path the JVM could load the class from, that is
     * "&lt;class prefix&gt;/&lt;internal name&gt;.class". Anything else under a .class suffix is
     * payload data that merely looks like a class file.
     */
    private static boolean isLoadableEntry(String entryName, String internalName, JarLayout layout) {
        String expected = internalName + ".class";
        if (entryName.equals(expected)) {
            return true;
        }
        String prefix = layout == null ? "" : layout.classPrefix();
        return prefix != null && prefix.length() > 0 && entryName.equals(prefix + expected);
    }

    /**
     * Class-file header major version this build of ASM understands. A newer
     * class file is parsed with its major version temporarily masked down to
     * this value; ClassNode.version is restored to the original value
     * afterwards so the emitted class keeps the input version instead of being
     * silently downgraded or skipped as an opaque resource.
     */
    private static final int SUPPORTED_MAJOR = 69;

    private static ClassNode parseClassFile(byte[] bytes) {
        try {
            ClassReader reader = new ClassReader(bytes);
            ClassNode node = new ClassNode();
            reader.accept(node, 0);
            return node;
        } catch (RuntimeException tooNew) {
            if (bytes == null || bytes.length < 8) {
                throw tooNew;
            }
            int originalMajor = ((bytes[6] & 0xFF) << 8) | (bytes[7] & 0xFF);
            if (originalMajor <= SUPPORTED_MAJOR) {
                throw tooNew;
            }
            byte[] masked = bytes.clone();
            masked[6] = (byte) (SUPPORTED_MAJOR >> 8);
            masked[7] = (byte) SUPPORTED_MAJOR;
            ClassReader reader = new ClassReader(masked);
            ClassNode node = new ClassNode();
            reader.accept(node, 0);
            node.version = originalMajor;
            return node;
        }
    }

    private static boolean isTransformableClass(String name, JarLayout layout) {
        if (!name.toLowerCase(Locale.ROOT).endsWith(".class")) {
            return false;
        }
        if (layout.isFlat()) {

            return !name.startsWith("META-INF/");
        }
        return name.startsWith(layout.classPrefix());
    }

    private static boolean isModuleInfoEntry(String name, JarLayout layout) {
        String logical = logicalName(name, layout);
        return "module-info.class".equals(logical) || logical.endsWith("/module-info.class");
    }

    private static void countClass(JarLayout layout, String name, LayoutContext context) {
        if (name.startsWith(JarLayout.BOOT_CLASSES)) {
            context.addSpringBootClass();
        } else if (name.startsWith(JarLayout.WAR_CLASSES)) {
            context.addWarClass();
        }
    }

    static String logicalName(String entryName, JarLayout layout) {
        String prefix = layout.classPrefix();
        if (prefix.length() > 0 && entryName.startsWith(prefix)) {
            return entryName.substring(prefix.length());
        }
        return entryName;
    }

    private static void handleFlattenedVersionedEntry(String name, byte[] bytes, ZipEntry entry,
                                                      JarLayout layout,
                                                      List<FlattenedClass> flattened,
                                                      LayoutContext context, Log log) {
        if (!name.toLowerCase(Locale.ROOT).endsWith(".class")) {

            return;
        }
        String relative = name.substring(VERSIONS_PREFIX.length());
        int slash = relative.indexOf('/');
        if (slash <= 0) {
            return;
        }
        int version;
        try {
            version = Integer.parseInt(relative.substring(0, slash));
        } catch (NumberFormatException invalidVersion) {
            return;
        }
        try {
            ClassReader reader = new ClassReader(bytes);
            ClassNode node = new ClassNode();
            reader.accept(node, 0);
            context.addFlattenedVersionedClass();
            int existing = indexOfFlattened(flattened, node.name);
            if (existing >= 0) {
                FlattenedClass previous = flattened.get(existing);
                if (version > previous.version) {
                    flattened.set(existing, new FlattenedClass(node.name, version, bytes,
                            layout.classPrefix()));
                }
            } else {
                flattened.add(new FlattenedClass(node.name, version, bytes,
                        layout.classPrefix()));
            }
            log.debug("multi-release flatten: %s (version %d, class %s)", name,
                    Integer.valueOf(version), node.name);
        } catch (RuntimeException unparseable) {
            log.debug("multi-release flatten: skipping unparseable versioned class %s", name);
        }
    }

    private static int indexOfFlattened(List<FlattenedClass> flattened, String internalName) {
        for (int i = 0; i < flattened.size(); i++) {
            if (flattened.get(i).internalName.equals(internalName)) {
                return i;
            }
        }
        return -1;
    }

    private static void handlePreservedVersionedEntry(String name, byte[] bytes, ZipEntry entry,
                                                      JarLayout layout, LayoutContext context,
                                                      ClassPool pool, Log log) {
        String relative = name.substring(VERSIONS_PREFIX.length());
        int slash = relative.indexOf('/');
        if (slash <= 0) {
            putResource(context, pool, name, bytes, entry, log);
            return;
        }
        int version;
        try {
            version = Integer.parseInt(relative.substring(0, slash));
        } catch (NumberFormatException invalidVersion) {
            putResource(context, pool, name, bytes, entry, log);
            return;
        }
        String versionDirectory = VERSIONS_PREFIX + relative.substring(0, slash + 1);
        String entryPath = relative.substring(slash + 1);
        boolean moduleInfo = isModuleInfoEntry(entryPath, layout);
        boolean classUnderRoot = false;
        if (!moduleInfo && entryPath.toLowerCase(Locale.ROOT).endsWith(".class")) {
            if (layout.isFlat()) {
                classUnderRoot = !entryPath.startsWith("META-INF/");
            } else {
                classUnderRoot = entryPath.startsWith(layout.classPrefix());
            }
        }
        if (moduleInfo || classUnderRoot) {
            String internalName = null;
            if (!moduleInfo) {
                try {
                    internalName = new ClassReader(bytes).getClassName();
                } catch (RuntimeException unparseable) {
                    log.warn("multi-release: unparseable versioned class %s preserved as resource", name);
                }
            }
            if (moduleInfo || internalName != null) {
                VersionedClass versioned = new VersionedClass(name, versionDirectory, entryPath,
                        classPrefixOf(entryPath, layout), internalName, version, moduleInfo,
                        entry.getTime(), entry.getMethod());
                context.addVersionedClass(versioned);
                putResource(context, pool, name, bytes, entry, log);
                return;
            }
        }
        putResource(context, pool, name, bytes, entry, log);
    }

    private static String classPrefixOf(String entryPath, JarLayout layout) {
        if (layout.isFlat()) {
            return "";
        }
        if (entryPath.startsWith(layout.classPrefix())) {
            return layout.classPrefix();
        }
        return "";
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    public static void write(Path output, ClassPool pool, Hierarchy hierarchy,
                             boolean preserveTimestamps, Log log) throws IOException {
        writeInternal(output, pool, hierarchy, preserveTimestamps, log, null,
                null, null, null);
    }

    public static LayoutReport write(Path output, ClassPool pool, Hierarchy hierarchy,
                                     boolean preserveTimestamps, Log log, LayoutOptions options,
                                     Map<String, String> classMap, Map<String, String> methodMap,
                                     Map<String, String> fieldMap) throws IOException {
        return writeInternal(output, pool, hierarchy, preserveTimestamps, log,
                options == null ? LayoutOptions.defaults() : options,
                classMap, methodMap, fieldMap);
    }

    public static LayoutReport write(Path output, ClassPool pool, Hierarchy hierarchy,
                                     boolean preserveTimestamps, Log log, Map<String, String> options,
                                     Map<String, String> classMap, Map<String, String> methodMap,
                                     Map<String, String> fieldMap) throws IOException {
        return writeInternal(output, pool, hierarchy, preserveTimestamps, log,
                LayoutOptions.from(options), classMap, methodMap, fieldMap);
    }

    private static LayoutReport writeInternal(Path output, ClassPool pool, Hierarchy hierarchy,
                                              boolean preserveTimestamps, Log log,
                                              LayoutOptions requestedOptions,
                                              Map<String, String> classMap,
                                              Map<String, String> methodMap,
                                              Map<String, String> fieldMap) throws IOException {
        LayoutContext context = LayoutRegistry.getContext(pool);
        LayoutOptions options;
        if (context == null) {
            options = requestedOptions == null ? LayoutOptions.defaults() : requestedOptions;
            JarLayout detected = LayoutDetector.detectFromPool(pool, options);
            context = new LayoutContext(detected, options);
            LayoutRegistry.attach(pool, context);
            log.debug("layout: no read-time context for this pool; inferred %s", detected.describe());
        } else {
            options = context.options();
            if (requestedOptions != null && requestedOptions.multiRelease() != options.multiRelease()) {
                log.warn("layout: multiRelease mode is fixed when the input is read; using %s",
                        options.multiRelease());
            }
        }
        JarLayout layout = context.layout();
        ClassRenameMap rename = ClassRenameMap.of(classMap, methodMap, fieldMap);
        boolean preserveMultiRelease = options.multiRelease() == LayoutOptions.MultiReleaseMode.PRESERVE;
        boolean versionedEntries = context.hasVersionedClasses();

        Path absoluteOutput = output.toAbsolutePath();
        Path parent = absoluteOutput.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        List<PlannedEntry> classEntries = planClasses(pool, hierarchy, layout, preserveTimestamps, context,
                rename, log);
        List<PlannedEntry> moduleEntries = planModuleInfo(pool, layout, rename, context, preserveTimestamps, log);
        List<PlannedEntry> resourceEntries = planResources(pool, layout, rename, context,
                preserveTimestamps, preserveMultiRelease, versionedEntries, log);
        List<PlannedEntry> versionEntries = planVersionedClasses(pool, rename, context,
                preserveTimestamps, log);

        Path temp = SafeArchive.temporary(absoluteOutput);
        try {
            try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(temp))) {
                Set<String> directories = new HashSet<String>();
                for (PlannedEntry entry : classEntries) {
                    writeEntry(zos, entry, directories);
                }
                for (PlannedEntry entry : moduleEntries) {
                    writeEntry(zos, entry, directories);
                }
                for (PlannedEntry entry : resourceEntries) {
                    writeEntry(zos, entry, directories);
                }
                for (PlannedEntry entry : versionEntries) {
                    writeEntry(zos, entry, directories);
                }
            }
            SafeArchive.publish(temp, absoluteOutput);
        } finally {
            SafeArchive.deleteQuietly(temp);
        }

        LayoutReport report = context.report();
        if (log != null) {
            log.info("layout: wrote %s archive (%d classes, %d multi-release variants, "
                            + "%d module-info kept, %d manifest attributes rewritten, "
                            + "%d services/framework resources, %d duplicates resolved)",
                    layout.kindId(), Integer.valueOf(classEntries.size()),
                    Integer.valueOf(versionEntries.size()),
                    Long.valueOf(context.moduleInfoKept()),
                    Long.valueOf(context.manifestAttributesRewritten()),
                    Long.valueOf(context.servicesRewritten()),
                    Long.valueOf(context.duplicateClasses()));
            for (String warning : context.warnings()) {
                log.debug("layout: %s", warning);
            }
        }
        return report;
    }

    private static List<PlannedEntry> planClasses(ClassPool pool, Hierarchy hierarchy, JarLayout layout,
                                                  boolean preserveTimestamps, LayoutContext context,
                                                  ClassRenameMap rename, Log log)
            throws IOException {
        List<PlannedEntry> entries = new ArrayList<PlannedEntry>();
        Set<String> names = new LinkedHashSet<String>();
        List<String> classNames = new ArrayList<String>(pool.classes().keySet());
        Collections.sort(classNames);
        for (String className : classNames) {
            ClassNode node = pool.getClass(className);
            if (node == null) {
                continue;
            }

            String prefix = pool.entryPrefix(className);
            String entryName = prefix + node.name + ".class";
            byte[] bytes = pool.rawOutput(className);
            if (bytes == null) {
                try {
                    bytes = io.umbra.core.model.UmbraMethodGuard.toBytes(node, pool, rename,
                            hierarchy, log);
                } catch (RuntimeException failure) {
                    throw new IOException("Failed to serialize " + className + ": "
                            + failure.getMessage() + " (the class has a method whose bytecode "
                            + "exceeds the JVM's 64 KB limit and restoring its original body did "
                            + "not fit either; lower flow/exception strength for this archive)",
                            failure);
                }
            }
            long time = preserveTimestamps ? pool.classTime(className) : FIXED_TIME;
            time = time <= 0L ? FIXED_TIME : time;
            if (!names.add(entryName)) {
                context.addDuplicateEntry();
                continue;
            }
            entries.add(new PlannedEntry(entryName, bytes, time, ZipEntry.DEFLATED));
        }
        return entries;
    }

    private static List<PlannedEntry> planModuleInfo(ClassPool pool, JarLayout layout,
                                                     ClassRenameMap rename, LayoutContext context,
                                                     boolean preserveTimestamps, Log log) {
        List<PlannedEntry> entries = new ArrayList<PlannedEntry>();
        Set<String> modulePackages = modulePackages(pool);
        Set<String> candidateNames = new LinkedHashSet<String>(context.moduleInfoEntries());
        List<String> resourceNames = new ArrayList<String>(pool.resources().keySet());
        Collections.sort(resourceNames);
        for (String name : resourceNames) {
            if (isModuleInfoEntry(name, layout) && !name.startsWith(VERSIONS_PREFIX)) {
                candidateNames.add(name);
            }
        }
        for (String entryName : candidateNames) {
            ClassPool.Resource resource = pool.resource(entryName);
            if (resource == null) {
                continue;
            }
            ModuleInfoRewriter.Result result = ModuleInfoRewriter.rewrite(resource.bytes(), rename,
                    context.options().moduleInfo(), entryName);
            byte[] bytes = result.bytes();
            if (result.action() == ModuleInfoRewriter.Action.DROPPED) {
                log.warn("layout: dropped %s: %s", entryName, result.detail());
                context.addModuleInfoAction("dropped");
                continue;
            }
            if (bytes != null
                    && context.options().moduleInfo() != LayoutOptions.ModuleInfoMode.KEEP) {

                bytes = withModulePackages(bytes, modulePackages);
            }
            context.addModuleInfoKept(1);
            context.addModuleInfoAction(result.action() == ModuleInfoRewriter.Action.REWRITTEN
                    ? "rewritten" : "kept");
            long time = preserveTimestamps ? resource.time() : FIXED_TIME;
            time = time <= 0L ? FIXED_TIME : time;
            entries.add(new PlannedEntry(entryName, bytes == null ? resource.bytes() : bytes, time,
                    resource.method()));
        }
        return entries;
    }

    private static Set<String> modulePackages(ClassPool pool) {
        Set<String> packages = new java.util.TreeSet<String>();
        for (String className : pool.classes().keySet()) {
            int slash = className.lastIndexOf('/');
            if (slash > 0) {
                packages.add(className.substring(0, slash));
            }
        }
        return packages;
    }

    private static byte[] withModulePackages(byte[] moduleBytes, Set<String> packages) {
        try {
            ClassReader reader = new ClassReader(moduleBytes);
            ClassNode node = new ClassNode();
            reader.accept(node, 0);
            if (node.module == null) {
                return moduleBytes;
            }
            Set<String> merged = new java.util.TreeSet<String>(packages);
            if (node.module.packages != null) {
                for (String existing : node.module.packages) {
                    if (existing != null && !existing.isEmpty()) {
                        merged.add(existing);
                    }
                }
            }
            node.module.packages = new ArrayList<String>(merged);
            org.objectweb.asm.ClassWriter writer = new org.objectweb.asm.ClassWriter(0);
            node.accept(writer);
            return writer.toByteArray();
        } catch (RuntimeException failure) {
            return moduleBytes;
        }
    }

    private static List<PlannedEntry> planResources(ClassPool pool, JarLayout layout,
                                                    ClassRenameMap rename, LayoutContext context,
                                                    boolean preserveTimestamps,
                                                    boolean preserveMultiRelease,
                                                    boolean versionedEntries, Log log) {
        List<String> resourceNames = new ArrayList<String>(pool.resources().keySet());
        Collections.sort(resourceNames);

        String manifestName = null;
        for (String name : resourceNames) {
            if (MANIFEST_ENTRY.equalsIgnoreCase(name)) {
                manifestName = name;
                break;
            }
        }
        if (manifestName != null) {
            resourceNames.remove(manifestName);
            resourceNames.add(0, manifestName);
        }
        Set<String> claimed = new LinkedHashSet<String>(context.versionedClasses().keySet());
        List<PlannedEntry> entries = new ArrayList<PlannedEntry>();
        Set<String> usedNames = new LinkedHashSet<String>();
        for (String name : resourceNames) {
            ClassPool.Resource resource = pool.resource(name);
            if (resource == null) {
                continue;
            }
            String upper = name.toUpperCase(Locale.ROOT);
            if (claimed.contains(name) || isSignatureEntry(upper)
                    || "META-INF/INDEX.LIST".equalsIgnoreCase(name)) {
                continue;
            }
            if (isModuleInfoEntry(name, layout) && !name.startsWith(VERSIONS_PREFIX)) {
                continue;
            }
            byte[] bytes = resource.bytes();
            long time = preserveTimestamps ? resource.time() : FIXED_TIME;
            time = time <= 0L ? FIXED_TIME : time;
            if (MANIFEST_ENTRY.equalsIgnoreCase(name)) {
                ManifestRewriter.Result rewritten = ManifestRewriter.rewrite(bytes, rename,
                        preserveMultiRelease, versionedEntries);
                bytes = rewritten.bytes();
                context.addManifestAttributesRewritten(rewritten.attributesRewritten());
                for (String warning : rewritten.warnings()) {
                    log.warn("layout: manifest: %s", warning);
                }
                bytes = applyEntryPointFallback(bytes, pool, layout, context, log);
                byte[] unsignedManifest = stripSignatureAttributes(bytes);
                if (unsignedManifest != null) {
                    bytes = unsignedManifest;
                }
                usedNames.add(name);
                entries.add(new PlannedEntry(name, bytes, time, resource.method()));
                continue;
            }
            String logicalName = logicalName(name, layout);
            String newName = name;
            if (!rename.isEmpty() && TextResourceRewriter.handles(logicalName)) {
                TextResourceRewriter.Result rewritten = TextResourceRewriter.rewrite(logicalName,
                        bytes, rename);
                if (rewritten.changed()) {
                    bytes = rewritten.bytes();
                    context.addServicesRewritten(1);
                    if (!rewritten.logicalName().equals(logicalName)) {
                        newName = physicalName(name, logicalName, rewritten.logicalName(), layout);
                    }
                }
            }
            if (!usedNames.add(newName)) {
                log.warn("layout: duplicate output entry %s generated by resource rewriting; "
                        + "keeping the first occurrence", newName);
                context.addDuplicateEntry();
                continue;
            }
            entries.add(new PlannedEntry(newName, bytes, time, resource.method()));
        }
        List<String> opaqueNames = new ArrayList<String>(pool.opaqueEntries().keySet());
        Collections.sort(opaqueNames);
        for (String name : opaqueNames) {
            if (!usedNames.add(name)) {
                continue;
            }
            byte[] bytes = pool.opaqueEntries().get(name);
            long time = preserveTimestamps ? pool.opaqueTime(name) : FIXED_TIME;
            time = time <= 0L ? FIXED_TIME : time;
            entries.add(new PlannedEntry(name, bytes, time, ZipEntry.DEFLATED));
        }
        return entries;
    }

    private static byte[] applyEntryPointFallback(byte[] manifestBytes, ClassPool pool,
                                                  JarLayout layout, LayoutContext context, Log log) {
        if (pool.mainClass() == null || pool.mainClass().isEmpty()) {
            return manifestBytes;
        }
        Map<String, String> attributes = new LinkedHashMap<String, String>(parseManifest(manifestBytes));
        String current = attributes.get("Main-Class");
        String desired = pool.mainClass().replace('/', '.');
        if (layout.isFlat()) {
            boolean currentResolves = current != null
                    && pool.getClass(current.trim().replace('.', '/')) != null;
            if (!currentResolves && pool.getClass(pool.mainClass()) != null && !desired.equals(current)) {
                attributes.put("Main-Class", desired);
                context.addManifestAttributesRewritten(1);
                return writeManifest(attributes);
            }
            return manifestBytes;
        }
        if (current != null && !current.trim().replace('.', '/').equals(pool.mainClass())
                && pool.getClass(pool.mainClass()) != null) {
            String warning = "entry-point class " + desired + " installed by a pass is not wired into the "
                    + layout.kindId() + " loader; keeping Main-Class " + current.trim();
            log.warn("layout: %s", warning);
            context.addWarning(warning);
        }
        return manifestBytes;
    }

    private static String physicalName(String originalName, String logicalName, String newLogicalName,
                                       JarLayout layout) {
        if (newLogicalName.equals(logicalName)) {
            return originalName;
        }
        String prefix = layout.classPrefix();
        if (prefix.length() > 0 && originalName.startsWith(prefix)) {
            return prefix + newLogicalName;
        }
        return newLogicalName;
    }

    private static List<PlannedEntry> planVersionedClasses(ClassPool pool, ClassRenameMap rename,
                                                           LayoutContext context,
                                                           boolean preserveTimestamps, Log log) {
        List<PlannedEntry> entries = new ArrayList<PlannedEntry>();
        List<String> entryNames = new ArrayList<String>(context.versionedClasses().keySet());
        Collections.sort(entryNames);
        Set<String> usedNames = new LinkedHashSet<String>();
        for (String entryName : entryNames) {
            VersionedClass versioned = context.versionedClasses().get(entryName);
            ClassPool.Resource resource = pool.resource(entryName);
            if (resource == null) {
                log.debug("layout: versioned entry %s was removed by a pass", entryName);
                continue;
            }
            byte[] bytes = resource.bytes();
            String newName = entryName;
            if (!rename.isEmpty()) {
                if (versioned.moduleInfo()) {
                    ModuleInfoRewriter.Result result = ModuleInfoRewriter.rewrite(bytes, rename,
                            context.options().moduleInfo(), entryName);
                    if (result.action() == ModuleInfoRewriter.Action.DROPPED) {
                        log.warn("layout: dropped versioned %s: %s", entryName, result.detail());
                        context.addModuleInfoAction("dropped");
                        continue;
                    }
                    bytes = result.bytes();
                    context.addModuleInfoKept(1);
                    context.addModuleInfoAction(result.action() == ModuleInfoRewriter.Action.REWRITTEN
                            ? "rewritten" : "kept");
                } else {
                    String mappedName = rename.mapClass(versioned.internalName());
                    try {
                        bytes = remapClassBytes(bytes, rename);
                        context.addVersionedClassRemapped();
                        newName = versioned.outputEntryName(mappedName);
                    } catch (RuntimeException failure) {
                        log.warn("layout: could not remap versioned class %s (%s); keeping original bytes",
                                entryName, failure.getMessage());
                        context.addWarning("unremapped multi-release variant " + entryName);
                    }
                }
            }
            if (!usedNames.add(newName)) {
                log.warn("layout: duplicate output entry %s generated by multi-release remapping; "
                        + "keeping the first occurrence", newName);
                context.addDuplicateEntry();
                continue;
            }
            long time = preserveTimestamps ? resource.time()
                    : (versioned.time() <= 0L ? FIXED_TIME : versioned.time());
            entries.add(new PlannedEntry(newName, bytes, time <= 0L ? FIXED_TIME : time,
                    resource.method()));
        }
        return entries;
    }

    private static byte[] remapClassBytes(byte[] bytes, ClassRenameMap rename) {
        ClassReader reader = new ClassReader(bytes);
        ClassWriter writer = new ClassWriter(0);
        reader.accept(new ClassRemapper(writer, rename.remapper()), 0);
        return writer.toByteArray();
    }

    private static void writeEntry(ZipOutputStream zos, PlannedEntry entry, Set<String> directories)
            throws IOException {
        ensureDirectories(zos, entry.name, directories, entry.time);
        ZipEntry zipEntry = new ZipEntry(entry.name);
        zipEntry.setTime(entry.time);
        if (entry.method == ZipEntry.STORED) {
            zipEntry.setMethod(ZipEntry.STORED);
            zipEntry.setSize(entry.bytes.length);
            zipEntry.setCompressedSize(entry.bytes.length);
            java.util.zip.CRC32 crc = new java.util.zip.CRC32();
            crc.update(entry.bytes);
            zipEntry.setCrc(crc.getValue());
        } else if (entry.method == ZipEntry.DEFLATED) {
            zipEntry.setMethod(ZipEntry.DEFLATED);
        }
        zos.putNextEntry(zipEntry);
        zos.write(entry.bytes);
        zos.closeEntry();
    }

    private static void ensureDirectories(ZipOutputStream zos, String entryName,
                                          Set<String> directories, long time) throws IOException {
        int slash = entryName.lastIndexOf('/');
        while (slash > 0) {
            String directory = entryName.substring(0, slash + 1);
            if (directories.add(directory)) {
                ZipEntry entry = new ZipEntry(directory);
                entry.setTime(time);
                zos.putNextEntry(entry);
                zos.closeEntry();
            }
            slash = entryName.lastIndexOf('/', slash - 1);
        }
    }

    private static byte[] stripMultiReleaseAttribute(byte[] manifestBytes) {
        Map<String, String> attributes = parseManifest(manifestBytes);
        boolean changed = false;
        java.util.Iterator<String> keys = attributes.keySet().iterator();
        while (keys.hasNext()) {
            if ("multi-release".equalsIgnoreCase(keys.next())) {
                keys.remove();
                changed = true;
            }
        }
        return changed ? writeManifest(attributes) : null;
    }

    private static byte[] stripSignatureAttributes(byte[] manifestBytes) {
        Map<String, String> attributes = parseManifest(manifestBytes);
        boolean changed = false;
        java.util.Iterator<String> keys = attributes.keySet().iterator();
        while (keys.hasNext()) {
            String key = keys.next();
            String lower = key.toLowerCase(Locale.ROOT);
            if ("signature-version".equals(lower) || "magic".equals(lower)
                    || lower.endsWith("-digest") || lower.contains("-digest-")) {
                keys.remove();
                changed = true;
            }
        }
        if (!changed) {
            return null;
        }
        return writeManifest(attributes);
    }

    private static boolean isSignatureEntry(String upperName) {
        if (!upperName.startsWith("META-INF/")) {
            return false;
        }
        return upperName.endsWith(".SF") || upperName.endsWith(".RSA") || upperName.endsWith(".DSA")
                || upperName.endsWith(".EC") || upperName.endsWith(".SIG");
    }

    private static byte[] stripUtf8Bom(byte[] bytes) {
        if (bytes == null || bytes.length < 3) {
            return bytes;
        }
        if ((bytes[0] & 0xFF) == 0xEF && (bytes[1] & 0xFF) == 0xBB && (bytes[2] & 0xFF) == 0xBF) {
            byte[] stripped = new byte[bytes.length - 3];
            System.arraycopy(bytes, 3, stripped, 0, stripped.length);
            return stripped;
        }
        return bytes;
    }

    public static String parseMainClass(byte[] manifest) {
        Map<String, String> attributes = parseManifest(manifest);
        return attributes.get("Main-Class");
    }

    public static Map<String, String> parseManifest(byte[] manifest) {
        Map<String, String> attributes = new LinkedHashMap<String, String>();
        String text = new String(manifest, StandardCharsets.UTF_8);
        if (!text.isEmpty() && text.charAt(0) == '\uFEFF') {
            text = text.substring(1);
        }
        String[] lines = text.replace("\r\n", "\n").replace('\r', '\n').split("\n");
        String currentKey = null;
        StringBuilder currentValue = new StringBuilder();
        for (String line : lines) {
            if (line.isEmpty()) {
                continue;
            }
            if (line.charAt(0) == ' ') {
                if (currentKey != null) {
                    currentValue.append(line.substring(1));
                }
                continue;
            }
            if (currentKey != null) {
                attributes.put(currentKey, currentValue.toString());
            }
            int colon = line.indexOf(':');
            if (colon < 0) {
                currentKey = null;
                currentValue.setLength(0);
                continue;
            }
            currentKey = line.substring(0, colon).trim();
            currentValue.setLength(0);
            currentValue.append(line.substring(colon + 1).trim());
        }
        if (currentKey != null) {
            attributes.put(currentKey, currentValue.toString());
        }
        return attributes;
    }

    public static byte[] writeManifest(Map<String, String> attributes) {
        java.util.jar.Manifest manifest = new java.util.jar.Manifest();
        if (!attributes.containsKey("Manifest-Version")) {
            manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        }
        for (Map.Entry<String, String> e : attributes.entrySet()) {
            manifest.getMainAttributes().putValue(e.getKey(), e.getValue());
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            manifest.write(out);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to serialize manifest", e);
        }
        return out.toByteArray();
    }

    private static final class PlannedEntry {
        final String name;
        final byte[] bytes;
        final long time;

        final int method;

        PlannedEntry(String name, byte[] bytes, long time, int method) {
            this.name = name;
            this.bytes = bytes;
            this.time = time;
            this.method = method;
        }
    }

    private static final class FlattenedClass {
        final String internalName;
        final int version;
        final byte[] bytes;
        final String classPrefix;

        FlattenedClass(String internalName, int version, byte[] bytes, String classPrefix) {
            this.internalName = internalName;
            this.version = version;
            this.bytes = bytes;
            this.classPrefix = classPrefix;
        }
    }
}
