package io.umbra.cli;

import io.umbra.core.engine.EngineResult;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Read-only compatibility inspection of an input archive.
 *
 * <p>The inspector never loads or transforms classes. It detects the archive
 * layout (flat, Spring Boot fat JAR, WAR, multi-release, modular), counts what
 * the protection pipeline will see, and reports compatibility risks before a
 * run. The same report is embedded in {@code --compat-report} output.</p>
 */
public final class InspectTool {

    /** Detected archive layout families. */
    public static final String LAYOUT_FLAT = "flat";
    public static final String LAYOUT_SPRING_BOOT = "spring-boot";
    public static final String LAYOUT_WAR = "war";
    public static final String LAYOUT_MULTI_RELEASE = "multi-release";

    private InspectTool() {
    }

    /** Immutable analysis result for one archive. */
    public static final class Report {
        public Path input;
        public long bytes;
        public String layout = LAYOUT_FLAT;
        public boolean springBoot;
        public boolean war;
        public boolean multiRelease;
        public boolean moduleInfo;
        public boolean signed;
        public boolean javaAgent;
        public boolean executable;
        public boolean osgi;
        public boolean multiReleaseAttribute;
        public int transformableClasses;
        public int versionedClasses;
        public int resources;
        public int nestedLibraries;
        public int signatureFiles;
        public int serviceFiles;
        public int duplicateEntries;
        public int versionedResourceEntries;
        public long nestedLibraryBytes;
        public String mainClass;
        public String startClass;
        public String premainClass;
        public String agentClass;
        public String launcherAgentClass;
        public String automaticModuleName;
        public String bundleSymbolicName;
        public final Map<String, Integer> classFileVersions = new TreeMap<String, Integer>();
        public final List<String> frameworks = new ArrayList<String>();
        public final List<String> services = new ArrayList<String>();
        public final List<String> moduleDetails = new ArrayList<String>();
        public final List<String> warnings = new ArrayList<String>();
        public final List<String> duplicateNames = new ArrayList<String>();
    }

    /** Analyzes {@code input}; throws IOException when the archive cannot be read. */
    public static Report analyze(Path input) throws IOException {
        Report report = new Report();
        report.input = input.toAbsolutePath();
        report.bytes = Files.size(input);
        Map<String, byte[]> smallFiles = new LinkedHashMap<String, byte[]>();
        Map<String, Integer> entryCounts = new LinkedHashMap<String, Integer>();
        List<String> classNames = new ArrayList<String>();
        List<String> versionedClassNames = new ArrayList<String>();
        try (ZipFile zip = new ZipFile(input.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory()) {
                    continue;
                }
                Integer previous = entryCounts.get(name);
                entryCounts.put(name, Integer.valueOf(previous == null ? 1 : previous.intValue() + 1));
                if (previous != null && previous.intValue() == 1) {
                    report.duplicateEntries++;
                    if (report.duplicateNames.size() < 25) {
                        report.duplicateNames.add(name);
                    }
                }
                String lower = name.toLowerCase(Locale.ROOT);
                String upper = name.toUpperCase(Locale.ROOT);
                boolean classEntry = lower.endsWith(".class");
                boolean versioned = upper.startsWith("META-INF/VERSIONS/");
                if (!versioned) {
                    if (upper.startsWith("META-INF/") && (upper.endsWith(".SF")
                            || upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC"))) {
                        report.signatureFiles++;
                        continue;
                    }
                    if (upper.startsWith("META-INF/MANIFEST.MF")) {
                        smallFiles.put(name, readAll(zip.getInputStream(entry)));
                        continue;
                    }
                    if ("META-INF/INDEX.LIST".equalsIgnoreCase(name)) {
                        continue;
                    }
                }
                if (versioned) {
                    report.multiRelease = true;
                    if (classEntry) {
                        report.versionedClasses++;
                        versionedClassNames.add(name);
                    } else {
                        report.versionedResourceEntries++;
                    }
                    continue;
                }
                if (classEntry) {
                    if ("module-info.class".equals(lower) || lower.endsWith("/module-info.class")) {
                        report.moduleInfo = true;
                        report.moduleDetails.add(name);
                        continue;
                    }
                    if (isTransformableClass(name)) {
                        report.transformableClasses++;
                        classNames.add(name);
                        addMajor(report, zip, entry);
                    } else {
                        // Class outside every known container: keep as a resource.
                        report.resources++;
                    }
                    continue;
                }
                report.resources++;
                if (upper.startsWith("BOOT-INF/LIB/") && lower.endsWith(".jar")) {
                    report.springBoot = true;
                    report.nestedLibraries++;
                    report.nestedLibraryBytes += entry.getSize() > 0 ? entry.getSize() : 0L;
                } else if (upper.startsWith("WEB-INF/LIB/") && lower.endsWith(".jar")) {
                    report.war = true;
                    report.nestedLibraries++;
                    report.nestedLibraryBytes += entry.getSize() > 0 ? entry.getSize() : 0L;
                }
                if (upper.startsWith("META-INF/SERVICES/")
                        && !name.substring("META-INF/services/".length()).contains("/")) {
                    report.serviceFiles++;
                    if (report.services.size() < 60) {
                        report.services.add(name.substring("META-INF/services/".length()));
                    }
                }
            }
            // A directory-only marker of the layouts is not enough: look for
            // container prefixes in all entry names after the first pass.
            if (!report.springBoot) {
                report.springBoot = hasPrefix(entryCounts.keySet(), "BOOT-INF/classes/")
                        || hasPrefix(entryCounts.keySet(), "BOOT-INF/lib/");
            }
            if (!report.war) {
                report.war = hasPrefix(entryCounts.keySet(), "WEB-INF/classes/")
                        || hasEntry(entryCounts.keySet(), "WEB-INF/web.xml");
            }
        }

        for (Map.Entry<String, byte[]> entry : smallFiles.entrySet()) {
            applyManifest(report, entry.getValue());
        }
        report.signed = report.signatureFiles > 0;
        if (report.transformableClasses == 0 && report.versionedClasses == 0) {
            report.warnings.add("no transformable class entries were found");
        }
        if (report.springBoot) {
            report.layout = LAYOUT_SPRING_BOOT;
        } else if (report.war) {
            report.layout = LAYOUT_WAR;
        } else if (report.multiRelease) {
            report.layout = LAYOUT_MULTI_RELEASE;
        } else {
            report.layout = LAYOUT_FLAT;
        }
        collectFrameworks(report, entryCounts.keySet());
        buildWarnings(report);
        return report;
    }

    private static boolean isTransformableClass(String name) {
        if (name.startsWith("BOOT-INF/classes/") || name.startsWith("WEB-INF/classes/")) {
            return true;
        }
        if (name.startsWith("BOOT-INF/") || name.startsWith("WEB-INF/")) {
            return false;
        }
        if (name.startsWith("META-INF/")) {
            return false;
        }
        return true;
    }

    private static boolean hasPrefix(Set<String> names, String prefix) {
        for (String name : names) {
            if (name.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasEntry(Set<String> names, String entry) {
        for (String name : names) {
            if (name.equalsIgnoreCase(entry)) {
                return true;
            }
        }
        return false;
    }

    private static void addMajor(Report report, ZipFile zip, ZipEntry entry) {
        try (InputStream in = zip.getInputStream(entry)) {
            byte[] header = new byte[8];
            int read = 0;
            while (read < header.length) {
                int n = in.read(header, read, header.length - read);
                if (n < 0) {
                    break;
                }
                read += n;
            }
            if (read >= 8 && (header[0] & 0xFF) == 0xCA && (header[1] & 0xFF) == 0xFE
                    && (header[2] & 0xFF) == 0xBA && (header[3] & 0xFF) == 0xBE) {
                int major = ((header[6] & 0xFF) << 8) | (header[7] & 0xFF);
                String key = String.valueOf(major);
                Integer count = report.classFileVersions.get(key);
                report.classFileVersions.put(key, Integer.valueOf(count == null ? 1 : count.intValue() + 1));
            }
        } catch (IOException ignored) {
            // A damaged entry does not abort inspection.
        }
    }

    private static void applyManifest(Report report, byte[] manifestBytes) {
        try {
            Manifest manifest = new Manifest(new ByteArrayInputStream(manifestBytes));
            java.util.jar.Attributes main = manifest.getMainAttributes();
            report.mainClass = main.getValue("Main-Class");
            report.startClass = main.getValue("Start-Class");
            report.premainClass = main.getValue("Premain-Class");
            report.agentClass = main.getValue("Agent-Class");
            report.launcherAgentClass = main.getValue("Launcher-Agent-Class");
            report.automaticModuleName = main.getValue("Automatic-Module-Name");
            report.bundleSymbolicName = main.getValue("Bundle-SymbolicName");
            String multiRelease = main.getValue("Multi-Release");
            if ("true".equalsIgnoreCase(multiRelease)) {
                report.multiReleaseAttribute = true;
                report.multiRelease = true;
            }
            if (report.premainClass != null || report.agentClass != null
                    || report.launcherAgentClass != null) {
                report.javaAgent = true;
            }
            if (report.bundleSymbolicName != null || main.getValue("Export-Package") != null
                    || main.getValue("Import-Package") != null) {
                report.osgi = true;
            }
            if (report.mainClass != null) {
                report.executable = true;
            }
            String loader = report.mainClass == null ? "" : report.mainClass;
            if (loader.contains("org.springframework.boot.loader")) {
                report.springBoot = true;
            }
        } catch (IOException ignored) {
            report.warnings.add("manifest could not be parsed");
        }
    }

    private static void collectFrameworks(Report report, Set<String> names) {
        Set<String> frameworks = new LinkedHashSet<String>();
        boolean springClasses = false;
        boolean kotlin = false;
        boolean scala = false;
        boolean groovy = false;
        boolean micronaut = false;
        boolean quarkus = false;
        for (String name : names) {
            if (!springClasses && name.startsWith("org/springframework/")) {
                springClasses = true;
            }
            if (!kotlin && (name.endsWith(".kotlin_module") || name.startsWith("kotlin/"))) {
                kotlin = true;
            }
            if (!scala && name.startsWith("scala/")) {
                scala = true;
            }
            if (!groovy && name.startsWith("groovy/")) {
                groovy = true;
            }
            if (!micronaut && (name.startsWith("io/micronaut/")
                    || name.startsWith("META-INF/services/io.micronaut"))) {
                micronaut = true;
            }
            if (!quarkus && (name.startsWith("META-INF/quarkus") || name.startsWith("io/quarkus/"))) {
                quarkus = true;
            }
        }
        if (report.springBoot || report.startClass != null || springClasses
                || hasEntry(names, "META-INF/spring.factories")
                || hasEntry(names, "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports")) {
            frameworks.add("spring");
        }
        if (report.springBoot) {
            frameworks.add("spring-boot");
        }
        if (kotlin) {
            frameworks.add("kotlin");
        }
        if (scala) {
            frameworks.add("scala");
        }
        if (groovy) {
            frameworks.add("groovy");
        }
        if (micronaut) {
            frameworks.add("micronaut");
        }
        if (quarkus) {
            frameworks.add("quarkus");
        }
        if (report.osgi) {
            frameworks.add("osgi");
        }
        if (report.javaAgent) {
            frameworks.add("java-agent");
        }
        if (report.moduleInfo) {
            frameworks.add("jpms");
        }
        if (report.multiRelease) {
            frameworks.add("multi-release");
        }
        report.frameworks.addAll(frameworks);
    }

    private static void buildWarnings(Report report) {
        if (report.springBoot) {
            report.warnings.add("Spring Boot fat JAR: classes under BOOT-INF/classes are transformed; "
                    + "nested BOOT-INF/lib archives are preserved byte-identically (their classes are not protected)");
        }
        if (report.war) {
            report.warnings.add("WAR layout: classes under WEB-INF/classes are transformed; "
                    + "WEB-INF/lib archives and static resources are preserved");
        }
        if (report.multiRelease) {
            report.warnings.add("multi-release JAR: versioned classes are processed with one consistent mapping "
                    + "in preserve mode (layout.multiRelease=flatten produces a plain JAR)");
        }
        if (report.moduleInfo) {
            report.warnings.add("module-info.class present: exports/opens/uses/provides are remapped "
                    + "(layout.moduleInfo=auto|keep|drop)");
        }
        if (report.signatureFiles > 0) {
            report.warnings.add("signed JAR: signature files/manifest digests will be removed; "
                    + "re-sign the protected artifact before publishing");
        }
        if (report.duplicateEntries > 0) {
            report.warnings.add("duplicate archive entries: " + report.duplicateEntries
                    + " duplicate name(s); the first occurrence wins and the rest are dropped");
        }
        if (report.javaAgent) {
            report.warnings.add("java agent attributes present: Premain-Class/Agent-Class are remapped "
                    + "so attach keeps working");
        }
        if (report.nestedLibraries > 0) {
            report.warnings.add(report.nestedLibraries + " nested library archive(s) preserved ("
                    + humanBytes(report.nestedLibraryBytes) + "); protect them separately if they are yours");
        }
        if (!report.classFileVersions.isEmpty()) {
            String max = null;
            for (String major : report.classFileVersions.keySet()) {
                if (max == null || Integer.parseInt(major) > Integer.parseInt(max)) {
                    max = major;
                }
            }
            report.warnings.add("class file versions: " + describeMajors(report.classFileVersions)
                    + (max == null ? "" : " (highest major " + max + ")"));
        }
        if (report.transformableClasses == 0) {
            report.warnings.add("nothing to transform: only resources/libraries were found");
        }
    }

    private static String describeMajors(Map<String, Integer> majors) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Integer> entry : majors.entrySet()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            int major = Integer.parseInt(entry.getKey());
            sb.append("major ").append(major);
            if (major >= 45) {
                sb.append(" / Java ").append(major - 44);
            }
            sb.append(" x").append(entry.getValue());
        }
        return sb.toString();
    }

    /** Human-readable rendering used by {@code --inspect}. */
    public static String format(Report report, String version) {
        StringBuilder sb = new StringBuilder();
        sb.append("Umbra ").append(version).append(" - input compatibility inspection\n");
        sb.append("Input:   ").append(report.input).append('\n');
        sb.append("Size:    ").append(humanBytes(report.bytes)).append('\n');
        sb.append("Layout:  ").append(report.layout).append('\n');
        sb.append("Classes: ").append(report.transformableClasses).append(" transformable");
        if (report.versionedClasses > 0) {
            sb.append(", ").append(report.versionedClasses).append(" versioned");
        }
        sb.append('\n');
        sb.append("Resources: ").append(report.resources);
        if (report.nestedLibraries > 0) {
            sb.append(" + ").append(report.nestedLibraries).append(" nested libraries");
        }
        sb.append('\n');
        if (report.transformableClasses > 0) {
            sb.append("Class file versions: ").append(describeMajors(report.classFileVersions)).append('\n');
        }
        if (report.mainClass != null) {
            sb.append("Main-Class:   ").append(report.mainClass).append('\n');
        }
        if (report.startClass != null) {
            sb.append("Start-Class:  ").append(report.startClass).append('\n');
        }
        if (report.premainClass != null) {
            sb.append("Premain-Class: ").append(report.premainClass).append('\n');
        }
        if (report.agentClass != null) {
            sb.append("Agent-Class:  ").append(report.agentClass).append('\n');
        }
        if (report.automaticModuleName != null) {
            sb.append("Automatic-Module-Name: ").append(report.automaticModuleName).append('\n');
        }
        if (report.bundleSymbolicName != null) {
            sb.append("Bundle-SymbolicName: ").append(report.bundleSymbolicName).append('\n');
        }
        sb.append("Flags:   ");
        List<String> flags = new ArrayList<String>();
        if (report.executable) {
            flags.add("executable");
        }
        if (report.javaAgent) {
            flags.add("java-agent");
        }
        if (report.signed) {
            flags.add("signed");
        }
        if (report.multiRelease) {
            flags.add("multi-release");
        }
        if (report.moduleInfo) {
            flags.add("module-info");
        }
        if (report.osgi) {
            flags.add("osgi");
        }
        sb.append(flags.isEmpty() ? "-" : join(flags)).append('\n');
        sb.append("Frameworks: ").append(report.frameworks.isEmpty() ? "-" : join(report.frameworks)).append('\n');
        sb.append("Services:   ").append(report.serviceFiles).append('\n');
        if (report.signatureFiles > 0) {
            sb.append("Signatures: ").append(report.signatureFiles).append(" file(s) will be removed\n");
        }
        sb.append('\n');
        if (report.warnings.isEmpty()) {
            sb.append("Warnings: none\n");
        } else {
            sb.append("Warnings:\n");
            for (String warning : report.warnings) {
                sb.append("  - ").append(warning).append('\n');
            }
        }
        sb.append('\n');
        sb.append("This was a read-only inspection; no output was written.\n");
        return sb.toString();
    }

    private static String join(List<String> values) {
        StringBuilder sb = new StringBuilder();
        for (String value : values) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(value);
        }
        return sb.toString();
    }

    /** Writes the machine-readable inspection report ({@code --inspect-json}). */
    public static void writeJson(Report report, Path target, String version) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        field(sb, "tool", "Umbra", true);
        field(sb, "version", version, true);
        field(sb, "kind", "inspect", true);
        field(sb, "input", report.input == null ? null : report.input.toString(), true);
        field(sb, "bytes", String.valueOf(report.bytes), true);
        field(sb, "layout", report.layout, true);
        field(sb, "transformableClasses", String.valueOf(report.transformableClasses), true);
        field(sb, "versionedClasses", String.valueOf(report.versionedClasses), true);
        field(sb, "resources", String.valueOf(report.resources), true);
        field(sb, "nestedLibraries", String.valueOf(report.nestedLibraries), true);
        field(sb, "serviceFiles", String.valueOf(report.serviceFiles), true);
        field(sb, "signatureFiles", String.valueOf(report.signatureFiles), true);
        field(sb, "duplicateEntries", String.valueOf(report.duplicateEntries), true);
        field(sb, "springBoot", String.valueOf(report.springBoot), true);
        field(sb, "war", String.valueOf(report.war), true);
        field(sb, "multiRelease", String.valueOf(report.multiRelease), true);
        field(sb, "moduleInfo", String.valueOf(report.moduleInfo), true);
        field(sb, "signed", String.valueOf(report.signed), true);
        field(sb, "javaAgent", String.valueOf(report.javaAgent), true);
        field(sb, "executable", String.valueOf(report.executable), true);
        field(sb, "osgi", String.valueOf(report.osgi), true);
        field(sb, "mainClass", report.mainClass, true);
        field(sb, "startClass", report.startClass, true);
        field(sb, "premainClass", report.premainClass, true);
        field(sb, "agentClass", report.agentClass, true);
        field(sb, "automaticModuleName", report.automaticModuleName, true);
        sb.append("  \"classFileVersions\": {");
        boolean first = true;
        for (Map.Entry<String, Integer> entry : report.classFileVersions.entrySet()) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append('"').append(entry.getKey()).append("\": ").append(entry.getValue());
        }
        sb.append("},\n");
        array(sb, "frameworks", report.frameworks, true);
        array(sb, "services", report.services, true);
        array(sb, "warnings", report.warnings, false);
        sb.append("}\n");
        writeFile(target, sb.toString());
    }

    /** Writes the combined compatibility report after a protection run. */
    public static void writeCompatReport(Path target, Report inspection, EngineResult result,
                                         String version) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        field(sb, "tool", "Umbra", true);
        field(sb, "version", version, true);
        field(sb, "kind", "compat-report", true);
        field(sb, "input", inspection.input == null ? null : inspection.input.toString(), true);
        field(sb, "output", result.output() == null ? null : result.output().toString(), true);
        field(sb, "layout", inspection.layout, true);
        field(sb, "dryRun", String.valueOf(result.dryRun()), true);
        field(sb, "classes", String.valueOf(result.classes()), true);
        field(sb, "resources", String.valueOf(result.resources()), true);
        field(sb, "millis", String.valueOf(result.millis()), true);
        field(sb, "inputTransformableClasses", String.valueOf(inspection.transformableClasses), true);
        field(sb, "inputVersionedClasses", String.valueOf(inspection.versionedClasses), true);
        field(sb, "inputNestedLibraries", String.valueOf(inspection.nestedLibraries), true);
        field(sb, "inputServiceFiles", String.valueOf(inspection.serviceFiles), true);
        field(sb, "inputSigned", String.valueOf(inspection.signatureFiles > 0), true);
        field(sb, "inputModuleInfo", String.valueOf(inspection.moduleInfo), true);
        field(sb, "inputMultiRelease", String.valueOf(inspection.multiRelease), true);
        sb.append("  \"frameworks\": [");
        boolean first = true;
        for (String framework : inspection.frameworks) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append('"').append(escape(framework)).append('"');
        }
        sb.append("],\n");
        sb.append("  \"passTimesMs\": {");
        first = true;
        for (Map.Entry<String, Long> entry : result.passTimes().entrySet()) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append('"').append(escape(entry.getKey())).append("\": ").append(entry.getValue());
        }
        sb.append("},\n");
        sb.append("  \"stats\": {");
        first = true;
        for (Map.Entry<String, Long> entry : result.stats().snapshot().entrySet()) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append('"').append(escape(entry.getKey())).append("\": ").append(entry.getValue());
        }
        sb.append("},\n");
        sb.append("  \"statsText\": {");
        first = true;
        for (Map.Entry<String, String> entry : new TreeMap<String, String>(
                result.stats().textSnapshot()).entrySet()) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append('"').append(escape(entry.getKey())).append("\": \"")
                    .append(escape(entry.getValue())).append('"');
        }
        sb.append("},\n");
        sb.append("  \"warnings\": [");
        first = true;
        for (String warning : inspection.warnings) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append('"').append(escape(warning)).append('"');
        }
        sb.append("]\n");
        sb.append("}\n");
        writeFile(target, sb.toString());
    }

    private static void field(StringBuilder sb, String name, String value, boolean comma) {
        sb.append("  \"").append(escape(name)).append("\": ");
        if (value == null) {
            sb.append("null");
        } else if (isNumber(value)) {
            sb.append(value);
        } else if ("true".equals(value) || "false".equals(value)) {
            sb.append(value);
        } else {
            sb.append('"').append(escape(value)).append('"');
        }
        if (comma) {
            sb.append(',');
        }
        sb.append('\n');
    }

    private static void array(StringBuilder sb, String name, List<String> values, boolean comma) {
        sb.append("  \"").append(name).append("\": [");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append('"').append(escape(values.get(i))).append('"');
        }
        sb.append(']');
        if (comma) {
            sb.append(',');
        }
        sb.append('\n');
    }

    private static boolean isNumber(String value) {
        if (value.isEmpty()) {
            return false;
        }
        int dots = 0;
        boolean digit = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '-' && i == 0) {
                continue;
            }
            if (c == '.') {
                dots++;
                if (dots > 1) {
                    return false;
                }
                continue;
            }
            if (c < '0' || c > '9') {
                return false;
            }
            digit = true;
        }
        return digit;
    }

    private static String escape(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private static void writeFile(Path target, String content) throws IOException {
        Path parent = target.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try (OutputStream out = Files.newOutputStream(target, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            out.write(content.getBytes(StandardCharsets.UTF_8));
        }
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

    private static String humanBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double value = bytes;
        String[] units = {"KB", "MB", "GB", "TB"};
        int unit = -1;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024.0;
            unit++;
        }
        return String.format(Locale.ROOT, "%.1f %s", Double.valueOf(value), units[unit]);
    }

    /** Prints the inspection to stdout (used by {@code --inspect}). */
    public static void print(Report report, String version, PrintStream out) {
        out.print(format(report, version));
    }

    /** Utility for callers that need the stable set of layout names. */
    public static List<String> layouts() {
        return Collections.unmodifiableList(java.util.Arrays.asList(
                LAYOUT_FLAT, LAYOUT_SPRING_BOOT, LAYOUT_WAR, LAYOUT_MULTI_RELEASE));
    }
}
