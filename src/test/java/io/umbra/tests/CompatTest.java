package io.umbra.tests;

import io.umbra.core.compat.ClassRenameMap;
import io.umbra.core.compat.JarLayout;
import io.umbra.core.compat.LayoutRegistry;
import io.umbra.core.compat.LayoutOptions;
import io.umbra.core.compat.LayoutReport;
import io.umbra.core.engine.UmbraVerifier;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.util.Jars;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Synthetic compatibility matrix for the archive-layout engine.
 *
 * <p>Each case builds a fixture in-test (Spring Boot fat JAR, WAR, multi-release,
 * modular, agent/OSGi, services/framework resources, duplicate entries, unicode,
 * Zip64, signed input), protects it through {@code Jars.read}/{@code Jars.write}
 * with a simulated naming mapping, and asserts the produced archive at byte
 * level, with {@link UmbraVerifier}, and by executing the protected application
 * where the layout allows it.</p>
 */
public final class CompatTest {

    private static int checks;
    private static Path root;

    private CompatTest() {
    }

    public static void main(String[] args) throws Exception {
        root = Files.createTempDirectory("umbra-compat-test-");
        try {
            testFlatRoundTrip();
            testSpringBootFatJar();
            testWarLayout();
            testMultiReleaseLayouts();
            testModuleInfo();
            testAgentAndOsgiManifest();
            testServiceAndFrameworkResources();
            testDuplicateEntries();
            testZip64AndUnicode();
            testSignedJar();
            testDeterministicOutput();
            testArchiveEdgeRegressions();
        } finally {
            delete(root);
        }
        System.out.println("CompatTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------------
    // 1. Flat JAR: unchanged behaviour + executable output
    // ------------------------------------------------------------------

    private static void testFlatRoundTrip() throws Exception {
        Path jar = root.resolve("flat.jar");
        Map<String, byte[]> fixture = new LinkedHashMap<String, byte[]>();
        fixture.put("META-INF/MANIFEST.MF", manifest("Manifest-Version: 1.0", "Main-Class: flat.Main"));
        fixture.put("flat/Main.class", mainClass("flat/Main", "FLAT-OK"));
        fixture.put("flat/Helper.class", classBytes("flat/Helper", 7, Opcodes.V1_8));
        fixture.put("data.txt", "hello flat".getBytes(StandardCharsets.UTF_8));
        writeJar(jar, fixture);

        ClassPool pool = new ClassPool();
        JarLayout layout = Jars.read(jar, pool, log(), LayoutOptions.defaults());
        check(layout.isFlat(), "flat: layout detected as flat");
        check("flat".equals(layout.kindId()), "flat: kind id");
        check(pool.classes().size() == 2, "flat: both classes loaded");

        Path out = root.resolve("flat-out.jar");
        LayoutReport report = write(pool, out, null, null, null, null);
        assertStatsKeys(report, "flat");
        check(report.counts().get("layout.springBoot.classes").longValue() == 0, "flat: no boot classes");
        check(report.counts().get("layout.war.classes").longValue() == 0, "flat: no war classes");
        check(report.counts().get("layout.multiRelease.classes").longValue() == 0, "flat: no versioned classes");

        Map<String, byte[]> entries = readEntries(out);
        check(entries.keySet().containsAll(Arrays.asList(
                "flat/Main.class", "flat/Helper.class", "data.txt", "META-INF/MANIFEST.MF")),
                "flat: entry set preserved");
        check(Arrays.equals(entries.get("data.txt"),
                "hello flat".getBytes(StandardCharsets.UTF_8)), "flat: resource bytes unchanged");
        Map<String, String> attributes = Jars.parseManifest(entries.get("META-INF/MANIFEST.MF"));
        check("flat.Main".equals(attributes.get("Main-Class")), "flat: Main-Class unchanged");

        String output = runJar(out);
        check(output.contains("FLAT-OK"), "flat: protected JAR executes (stdout=" + output.trim() + ")");
        List<String> errors = UmbraVerifier.verify(out);
        check(errors.isEmpty(), "flat: verifier clean (" + errors + ")");
        UmbraVerifier.Report detailed = UmbraVerifier.verifyDetailed(out, null);
        check(detailed.ok() && "flat".equals(detailed.layoutKind()), "flat: verifier reports flat layout");
        check(detailed.classesVerified() == 2, "flat: verifier loaded 2 classes");
    }

    // ------------------------------------------------------------------
    // 2. Spring Boot fat JAR
    // ------------------------------------------------------------------

    private static void testSpringBootFatJar() throws Exception {
        Path jar = root.resolve("boot.jar");
        byte[] nestedLib = jarBytes(bytesMap(
                "lib/Dep.class", classBytes("lib/Dep", 3, Opcodes.V1_8),
                "lib/data.txt", "nested".getBytes(StandardCharsets.UTF_8)));
        byte[] loaderClass = classBytes("org/springframework/boot/loader/JarLauncher", 1, Opcodes.V1_8);
        Map<String, byte[]> fixture = new LinkedHashMap<String, byte[]>();
        fixture.put("META-INF/MANIFEST.MF", manifest(
                "Manifest-Version: 1.0",
                "Main-Class: org.springframework.boot.loader.JarLauncher",
                "Start-Class: app.Main",
                "Spring-Boot-Version: 3.2.0",
                "Spring-Boot-Classes: BOOT-INF/classes/",
                "Spring-Boot-Lib: BOOT-INF/lib/",
                "Class-Path: \"\""));
        fixture.put("BOOT-INF/classes/app/Main.class", mainClass("app/Main", "BOOT-OK"));
        fixture.put("BOOT-INF/classes/app/Helper.class", classBytes("app/Helper", 5, Opcodes.V1_8));
        fixture.put("BOOT-INF/classes/app/Impl.class", classBytes("app/Impl", 0, Opcodes.V1_8));
        fixture.put("BOOT-INF/classes/app/Service.class", classBytes("app/Service", 0, Opcodes.V1_8));
        fixture.put("BOOT-INF/classes/META-INF/services/app.Service",
                "app.Impl\n".getBytes(StandardCharsets.UTF_8));
        fixture.put("BOOT-INF/classes/application.properties",
                "app.name=demo\n".getBytes(StandardCharsets.UTF_8));
        fixture.put("BOOT-INF/lib/nested.jar", nestedLib);
        fixture.put("org/springframework/boot/loader/JarLauncher.class", loaderClass);
        writeJar(jar, fixture, java.util.Collections.singleton("BOOT-INF/lib/nested.jar"));

        ClassPool pool = new ClassPool();
        JarLayout layout = Jars.read(jar, pool, log(), LayoutOptions.defaults());
        check("spring-boot".equals(layout.kindId()), "boot: layout detected (" + layout.kindId() + ")");
        check("BOOT-INF/classes/".equals(layout.classPrefix()), "boot: class prefix");
        check(pool.classes().size() == 4, "boot: application classes only (" + pool.classes().keySet() + ")");
        check(pool.getClass("org/springframework/boot/loader/JarLauncher") == null,
                "boot: loader class kept out of the transformable pool");
        check(pool.resource("BOOT-INF/lib/nested.jar") != null, "boot: nested library retained as resource");
        check(pool.resource("org/springframework/boot/loader/JarLauncher.class") != null,
                "boot: loader class preserved as resource");

        Map<String, String> classes = map("app/Main", "a/Main", "app/Helper", "a/H",
                "app/Impl", "a/Impl", "app/Service", "a/Service");
        simulateRename(pool, classes, null, null);
        Path out = root.resolve("boot-out.jar");
        LayoutReport report = write(pool, out, null, classes, null, null);
        assertStatsKeys(report, "spring-boot");
        check(report.counts().get("layout.springBoot.classes").longValue() == 4,
                "boot: layout.springBoot.classes counts transformed classes");
        check(report.counts().get("layout.services").longValue() == 1,
                "boot: layout.services counts rewritten service descriptor");
        check(report.counts().get("layout.manifest.rewritten").longValue() >= 1,
                "boot: layout.manifest.rewritten counts Start-Class");

        Map<String, byte[]> entries = readEntries(out);
        check(entries.containsKey("BOOT-INF/classes/a/Main.class"), "boot: renamed class under BOOT-INF/classes");
        check(entries.containsKey("BOOT-INF/classes/a/H.class"), "boot: renamed helper under BOOT-INF/classes");
        check(entries.containsKey("BOOT-INF/classes/a/Impl.class"), "boot: renamed impl under BOOT-INF/classes");
        check(!entries.containsKey("BOOT-INF/classes/app/Main.class"), "boot: old class entry removed");
        check(entries.containsKey("BOOT-INF/lib/nested.jar"), "boot: nested library entry kept");
        check(Arrays.equals(nestedLib, entries.get("BOOT-INF/lib/nested.jar")),
                "boot: nested library byte-identical");
        check(Arrays.equals(loaderClass, entries.get("org/springframework/boot/loader/JarLauncher.class")),
                "boot: loader class byte-identical");
        check(entries.containsKey("org/springframework/boot/loader/JarLauncher.class"),
                "boot: loader class name unchanged at the archive root");
        check(entryMethod(out, "BOOT-INF/lib/nested.jar") == ZipEntry.STORED,
                "boot: nested library entry preserved as STORED (not recompressed)");
        check(entryMethod(out, "BOOT-INF/classes/a/Main.class") == ZipEntry.DEFLATED,
                "boot: class entries stay DEFLATED");
        check(Arrays.equals("app.name=demo\n".getBytes(StandardCharsets.UTF_8),
                entries.get("BOOT-INF/classes/application.properties")),
                "boot: class-root resource byte-identical");
        check(entries.containsKey("BOOT-INF/classes/META-INF/services/a.Service"),
                "boot: service descriptor renamed inside the container root");
        check("a.Impl\n".equals(text(entries.get("BOOT-INF/classes/META-INF/services/a.Service"))),
                "boot: service descriptor content rewritten");

        Map<String, String> attributes = Jars.parseManifest(entries.get("META-INF/MANIFEST.MF"));
        check("org.springframework.boot.loader.JarLauncher".equals(attributes.get("Main-Class")),
                "boot: Main-Class kept as the Spring Boot loader");
        check("a.Main".equals(attributes.get("Start-Class")), "boot: Start-Class remapped");
        check("BOOT-INF/classes/".equals(attributes.get("Spring-Boot-Classes")),
                "boot: Spring-Boot-Classes kept");
        check("BOOT-INF/lib/".equals(attributes.get("Spring-Boot-Lib")), "boot: Spring-Boot-Lib kept");
        check(attributes.get("Multi-Release") == null, "boot: no Multi-Release attribute added");

        String output = runPrefixedMain(out, "BOOT-INF/classes/", "a.Main");
        check(output.contains("BOOT-OK"), "boot: protected application classes execute (stdout="
                + output.trim() + ")");

        UmbraVerifier.Report verified = UmbraVerifier.verifyDetailed(out, null);
        check(verified.ok(), "boot: verifier clean (" + verified.errors() + ")");
        check("spring-boot".equals(verified.layoutKind()), "boot: verifier reports spring-boot layout");
        check(verified.nestedLibraries() == 1, "boot: verifier saw the nested library");
        check(verified.classesVerified() >= 5, "boot: verifier loaded application + loader classes");
    }

    // ------------------------------------------------------------------
    // 3. WAR
    // ------------------------------------------------------------------

    private static void testWarLayout() throws Exception {
        Path jar = root.resolve("app.war");
        byte[] nestedLib = jarBytes(bytesMap("lib/Dep.class", classBytes("lib/Dep", 2, Opcodes.V1_8)));
        Map<String, byte[]> fixture = new LinkedHashMap<String, byte[]>();
        fixture.put("META-INF/MANIFEST.MF", manifest("Manifest-Version: 1.0", "Main-Class: web.Main"));
        fixture.put("WEB-INF/classes/web/Main.class", mainClass("web/Main", "WAR-OK"));
        fixture.put("WEB-INF/classes/web/Helper.class", classBytes("web/Helper", 4, Opcodes.V1_8));
        fixture.put("WEB-INF/lib/lib.jar", nestedLib);
        fixture.put("WEB-INF/web.xml", "<web-app/>".getBytes(StandardCharsets.UTF_8));
        fixture.put("index.html", "<html/>".getBytes(StandardCharsets.UTF_8));
        writeJar(jar, fixture);

        ClassPool pool = new ClassPool();
        JarLayout layout = Jars.read(jar, pool, log(), LayoutOptions.defaults());
        check("war".equals(layout.kindId()), "war: layout detected (" + layout.kindId() + ")");
        check("WEB-INF/classes/".equals(layout.classPrefix()), "war: class prefix");
        check(pool.classes().size() == 2, "war: WEB-INF/classes classes loaded");

        Map<String, String> classes = map("web/Main", "w/M");
        simulateRename(pool, classes, null, null);
        Path out = root.resolve("app-out.war");
        LayoutReport report = write(pool, out, null, classes, null, null);
        assertStatsKeys(report, "war");
        check(report.counts().get("layout.war.classes").longValue() == 2,
                "war: layout.war.classes counts transformed classes");

        Map<String, byte[]> entries = readEntries(out);
        check(entries.containsKey("WEB-INF/classes/w/M.class"), "war: renamed class under WEB-INF/classes");
        check(entries.containsKey("WEB-INF/classes/web/Helper.class"), "war: untouched class kept");
        check(Arrays.equals(nestedLib, entries.get("WEB-INF/lib/lib.jar")), "war: nested library byte-identical");
        check(Arrays.equals("<web-app/>".getBytes(StandardCharsets.UTF_8),
                entries.get("WEB-INF/web.xml")), "war: web.xml byte-identical");
        check(Arrays.equals("<html/>".getBytes(StandardCharsets.UTF_8),
                entries.get("index.html")), "war: static resource byte-identical");
        Map<String, String> attributes = Jars.parseManifest(entries.get("META-INF/MANIFEST.MF"));
        check("w.M".equals(attributes.get("Main-Class")), "war: Main-Class remapped");
        check(runPrefixedMain(out, "WEB-INF/classes/", "w.M").contains("WAR-OK"),
                "war: protected application classes execute");
        check(UmbraVerifier.verify(out).isEmpty(), "war: verifier clean");
    }

    // ------------------------------------------------------------------
    // 4. Multi-release layout (preserve + flatten, consistent mapping)
    // ------------------------------------------------------------------

    private static void testMultiReleaseLayouts() throws Exception {
        Path jar = root.resolve("mr.jar");
        Map<String, byte[]> fixture = new LinkedHashMap<String, byte[]>();
        fixture.put("META-INF/versions/9/mr/C.class", classBytes("mr/C", 9, Opcodes.V9));
        fixture.put("mr/C.class", classBytes("mr/C", 8, Opcodes.V1_8));
        fixture.put("data.txt", "base".getBytes(StandardCharsets.UTF_8));
        fixture.put("META-INF/MANIFEST.MF", manifest("Manifest-Version: 1.0",
                "Main-Class: mr.C", "Multi-Release: true"));
        writeJar(jar, fixture);

        ClassPool pool = new ClassPool();
        JarLayout layout = Jars.read(jar, pool, log(), LayoutOptions.defaults());
        check(layout.multiRelease(), "mr: preserve detection");
        check(pool.resource("META-INF/versions/9/mr/C.class") != null, "mr: versioned entry retained");

        Map<String, String> classes = map("mr/C", "x/C");
        simulateRename(pool, classes, null, null);
        Path out = root.resolve("mr-out.jar");
        LayoutReport report = write(pool, out, null, classes, null, null);
        assertStatsKeys(report, "multi-release");
        check(report.counts().get("layout.multiRelease.classes").longValue() == 1,
                "mr: layout.multiRelease.classes counts versioned classes");
        check(report.counts().get("layout.multiRelease.remapped").longValue() == 1,
                "mr: layout.multiRelease.remapped counts remapped variants");
        Map<String, byte[]> entries = readEntries(out);
        check(entries.containsKey("META-INF/versions/9/x/C.class"), "mr: versioned copy renamed at its path");
        check(entries.containsKey("x/C.class"), "mr: base class renamed");
        Map<String, String> attributes = Jars.parseManifest(entries.get("META-INF/MANIFEST.MF"));
        check("true".equals(attributes.get("Multi-Release")), "mr: attribute preserved");
        check("x.C".equals(attributes.get("Main-Class")), "mr: Main-Class remapped");
        List<String> mrErrors = UmbraVerifier.verify(out);
        check(mrErrors.isEmpty(), "mr: verifier clean (" + mrErrors + ")");


        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("layout.multiRelease", "flatten");
        ClassPool flatPool = new ClassPool();
        Jars.read(jar, flatPool, log(), options);
        check(flatPool.getClass("mr/C") != null, "mr flatten: base class loaded");
        Path flatOut = root.resolve("mr-flat.jar");
        LayoutReport flatReport = write(flatPool, flatOut, options, null, null, null);
        Map<String, byte[]> flatEntries = readEntries(flatOut);
        boolean versioned = false;
        for (String name : flatEntries.keySet()) {
            if (name.startsWith("META-INF/versions/")) {
                versioned = true;
            }
        }
        check(!versioned, "mr flatten: plain JAR output");
        check(flatEntries.containsKey("mr/C.class"), "mr flatten: class at base path");
        check(Jars.parseManifest(flatEntries.get("META-INF/MANIFEST.MF")).get("Multi-Release") == null,
                "mr flatten: Multi-Release attribute removed");
        check(flatReport.texts().get("layout.multiRelease.mode").equals("flatten"),
                "mr flatten: mode reported");
    }

    // ------------------------------------------------------------------
    // 5. module-info.class
    // ------------------------------------------------------------------

    private static void testModuleInfo() throws Exception {
        byte[] moduleInfo = moduleInfoBytes();
        Path jar = root.resolve("mod.jar");
        Map<String, byte[]> fixture = new LinkedHashMap<String, byte[]>();
        fixture.put("module-info.class", moduleInfo);
        fixture.put("META-INF/MANIFEST.MF", manifest("Manifest-Version: 1.0"));
        fixture.put("app/pkg/Service.class", classBytes("app/pkg/Service", 0, Opcodes.V9));
        fixture.put("app/pkg/ServiceImpl.class", classBytes("app/pkg/ServiceImpl", 1, Opcodes.V9));
        fixture.put("app/opens/Opened.class", classBytes("app/opens/Opened", 2, Opcodes.V9));
        writeJar(jar, fixture);

        ClassPool pool = new ClassPool();
        JarLayout layout = Jars.read(jar, pool, log(), LayoutOptions.defaults());
        check(layout.moduleInfo(), "module: module-info detected");
        check(pool.getClass("module-info") == null, "module: descriptor is not treated as a class");
        check(pool.resource("module-info.class") != null, "module: descriptor kept as a resource");

        Map<String, String> classes = map(
                "app/pkg/Service", "mod/svc/S", "app/pkg/ServiceImpl", "mod/svc/Impl");
        simulateRename(pool, classes, null, null);
        Path out = root.resolve("mod-out.jar");
        LayoutReport report = write(pool, out, null, classes, null, null);
        assertStatsKeys(report, "flat");
        check(report.counts().get("layout.moduleInfo").longValue() == 1, "module: kept descriptor counted");
        check("rewritten".equals(report.texts().get("layout.moduleInfo.action")),
                "module: action rewritten");

        Map<String, byte[]> entries = readEntries(out);
        byte[] rewritten = entries.get("module-info.class");
        check(rewritten != null, "module: descriptor present in output");
        ModuleDescription description = describeModule(rewritten);
        check("com.example.mod".equals(description.name), "module: module name unchanged");
        check(description.exports.contains("mod/svc"), "module: exports remapped (" + description.exports + ")");
        check(description.opens.contains("app/opens"), "module: opens of unmoved package kept");
        check(description.uses.contains("mod/svc/S"), "module: uses remapped");
        check(description.provides.contains("mod/svc/Impl"), "module: provides remapped");
        List<String> moduleErrors = UmbraVerifier.verify(out);
        check(moduleErrors.isEmpty(), "module: verifier clean (" + moduleErrors + ")");

        check(!Jars.parseManifest(entries.get("META-INF/MANIFEST.MF")).containsKey("Automatic-Module-Name"),
                "module: no Automatic-Module-Name invented");

        // drop mode
        Map<String, String> dropOptions = new LinkedHashMap<String, String>();
        dropOptions.put("layout.moduleInfo", "drop");
        ClassPool dropPool = new ClassPool();
        Jars.read(jar, dropPool, log(), dropOptions);
        Path dropOut = root.resolve("mod-drop.jar");
        LayoutReport dropReport = write(dropPool, dropOut, dropOptions, null, null, null);
        check(!readEntries(dropOut).containsKey("module-info.class"), "module drop: descriptor removed");
        check(dropReport.counts().get("layout.moduleInfo").longValue() == 0,
                "module drop: kept count is zero");
        check("dropped".equals(dropReport.texts().get("layout.moduleInfo.action")),
                "module drop: action reported");

        // auto mode with an inconsistent package mapping drops the descriptor
        ClassPool conflictPool = new ClassPool();
        Jars.read(jar, conflictPool, log());
        Map<String, String> conflicting = map(
                "app/pkg/Service", "x/A", "app/pkg/ServiceImpl", "y/B");
        simulateRename(conflictPool, conflicting, null, null);
        Path conflictOut = root.resolve("mod-conflict.jar");
        LayoutReport conflictReport = write(conflictPool, conflictOut, null, conflicting, null, null);
        check(!readEntries(conflictOut).containsKey("module-info.class"),
                "module auto: inconsistent package mapping drops the descriptor");
        check("dropped".equals(conflictReport.texts().get("layout.moduleInfo.action")),
                "module auto: drop reason recorded");

        // keep mode keeps the original descriptor bytes
        Map<String, String> keepOptions = new LinkedHashMap<String, String>();
        keepOptions.put("layout.moduleInfo", "keep");
        ClassPool keepPool = new ClassPool();
        Jars.read(jar, keepPool, log(), keepOptions);
        Map<String, String> keepConflicting = map(
                "app/pkg/Service", "x/A", "app/pkg/ServiceImpl", "y/B");
        simulateRename(keepPool, keepConflicting, null, null);
        Path keepOut = root.resolve("mod-keep.jar");
        LayoutReport keepReport = write(keepPool, keepOut, keepOptions, keepConflicting, null, null);
        byte[] kept = readEntries(keepOut).get("module-info.class");
        check(kept != null && Arrays.equals(moduleInfo, kept),
                "module keep: original descriptor bytes retained");
        check("kept".equals(keepReport.texts().get("layout.moduleInfo.action")),
                "module keep: action reported");
    }

    // ------------------------------------------------------------------
    // 6. Agent / OSGi manifest attributes
    // ------------------------------------------------------------------

    private static void testAgentAndOsgiManifest() throws Exception {
        Path jar = root.resolve("agent.jar");
        Map<String, byte[]> fixture = new LinkedHashMap<String, byte[]>();
        fixture.put("META-INF/MANIFEST.MF", manifest(
                "Manifest-Version: 1.0",
                "Main-Class: agent.M",
                "Premain-Class: agent.Premain",
                "Agent-Class: agent.A",
                "Launcher-Agent-Class: agent.L",
                "Bundle-Activator: app.Act",
                "Export-Package: app.pkg;version=\"1.0\"",
                "Import-Package: app.pkg;resolution:=optional",
                "Add-Opens: app.pkg",
                "Add-Exports: app.pkg",
                "Provide-Capability: osgi.service;objectClass:List<String>=\"app.pkg.Service\"",
                "Automatic-Module-Name: com.keep.name",
                "Class-Path: lib/dep.jar"));
        fixture.put("agent/M.class", mainClass("agent/M", "AGENT"));
        fixture.put("agent/Premain.class", classBytes("agent/Premain", 0, Opcodes.V1_8));
        fixture.put("agent/A.class", classBytes("agent/A", 0, Opcodes.V1_8));
        fixture.put("agent/L.class", classBytes("agent/L", 0, Opcodes.V1_8));
        fixture.put("app/Act.class", classBytes("app/Act", 0, Opcodes.V1_8));
        fixture.put("app/pkg/Service.class", classBytes("app/pkg/Service", 0, Opcodes.V1_8));
        fixture.put("app/pkg/Impl.class", classBytes("app/pkg/Impl", 0, Opcodes.V1_8));
        writeJar(jar, fixture);

        ClassPool pool = new ClassPool();
        Jars.read(jar, pool, log());
        Map<String, String> classes = map(
                "agent/M", "ag/M", "agent/Premain", "ag/P", "agent/A", "ag/A", "agent/L", "ag/L",
                "app/Act", "newpkg/Act", "app/pkg/Service", "newpkg/S", "app/pkg/Impl", "newpkg/I");
        simulateRename(pool, classes, null, null);
        Path out = root.resolve("agent-out.jar");
        LayoutReport report = write(pool, out, null, classes, null, null);
        assertStatsKeys(report, "flat");
        check(report.counts().get("layout.manifest.rewritten").longValue() >= 8,
                "agent: manifest attributes rewritten count (" + report.counts().get("layout.manifest.rewritten") + ")");

        Map<String, String> attributes = Jars.parseManifest(readEntries(out).get("META-INF/MANIFEST.MF"));
        check("ag.M".equals(attributes.get("Main-Class")), "agent: Main-Class remapped");
        check("ag.P".equals(attributes.get("Premain-Class")), "agent: Premain-Class remapped");
        check("ag.A".equals(attributes.get("Agent-Class")), "agent: Agent-Class remapped");
        check("ag.L".equals(attributes.get("Launcher-Agent-Class")), "agent: Launcher-Agent-Class remapped");
        check("newpkg.Act".equals(attributes.get("Bundle-Activator")), "agent: Bundle-Activator remapped");
        check(attributes.get("Export-Package").contains("newpkg"), "agent: Export-Package package remapped");
        check(attributes.get("Export-Package").contains("version=\"1.0\""),
                "agent: Export-Package attributes preserved");
        check(attributes.get("Import-Package").contains("newpkg"), "agent: Import-Package remapped");
        check("newpkg".equals(attributes.get("Add-Opens")), "agent: Add-Opens remapped");
        check("newpkg".equals(attributes.get("Add-Exports")), "agent: Add-Exports remapped");
        check(attributes.get("Provide-Capability").contains("newpkg.S"),
                "agent: Provide-Capability class remapped");
        check("com.keep.name".equals(attributes.get("Automatic-Module-Name")),
                "agent: Automatic-Module-Name untouched");
        check("lib/dep.jar".equals(attributes.get("Class-Path")), "agent: Class-Path untouched");
        check(UmbraVerifier.verify(out).isEmpty(), "agent: verifier clean");
    }

    // ------------------------------------------------------------------
    // 7. Services / spring.factories / AutoConfiguration.imports / native-image
    // ------------------------------------------------------------------

    private static void testServiceAndFrameworkResources() throws Exception {
        Path jar = root.resolve("resources.jar");
        Map<String, byte[]> fixture = new LinkedHashMap<String, byte[]>();
        fixture.put("META-INF/MANIFEST.MF", manifest("Manifest-Version: 1.0"));
        fixture.put("META-INF/services/com.example.Service",
                "com.example.Impl\n".getBytes(StandardCharsets.UTF_8));
        fixture.put("META-INF/spring.factories",
                "com.example.Service=com.example.Impl\norg.other=com.example.Impl\n"
                        .getBytes(StandardCharsets.UTF_8));
        fixture.put("META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports",
                "com.example.Impl\n".getBytes(StandardCharsets.UTF_8));
        fixture.put("META-INF/native-image/com.example/native-image.properties",
                "Args = --initialize-at-build-time=com.example.Impl\n".getBytes(StandardCharsets.UTF_8));
        fixture.put("com/example/Service.class", classBytes("com/example/Service", 0, Opcodes.V1_8));
        fixture.put("com/example/Impl.class", classBytes("com/example/Impl", 1, Opcodes.V1_8));
        writeJar(jar, fixture);

        ClassPool pool = new ClassPool();
        Jars.read(jar, pool, log());
        Map<String, String> classes = map(
                "com/example/Service", "svc/S", "com/example/Impl", "svc/I");
        simulateRename(pool, classes, null, null);
        Path out = root.resolve("resources-out.jar");
        LayoutReport report = write(pool, out, null, classes, null, null);
        check(report.counts().get("layout.services").longValue() == 4,
                "resources: layout.services counts services/spring/native-image rewrites ("
                        + report.counts().get("layout.services") + ")");

        Map<String, byte[]> entries = readEntries(out);
        check("svc.I\n".equals(text(entries.get("META-INF/services/svc.S"))),
                "resources: service file renamed and content rewritten");
        String factories = text(entries.get("META-INF/spring.factories"));
        check(factories.contains("svc.S=svc.I"), "resources: spring.factories key+value rewritten");
        check(factories.contains("org.other=svc.I"), "resources: spring.factories unrelated key kept");
        check("svc.I\n".equals(text(entries.get(
                "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports"))),
                "resources: AutoConfiguration.imports rewritten");
        check(text(entries.get("META-INF/native-image/com.example/native-image.properties"))
                .contains("svc.I"), "resources: native-image config rewritten");
        check(UmbraVerifier.verify(out).isEmpty(), "resources: verifier clean");
    }

    // ------------------------------------------------------------------
    // 8. Duplicate entries: warn + deterministic first-wins
    // ------------------------------------------------------------------

    private static void testDuplicateEntries() throws Exception {
        Path jar = root.resolve("duplicates.jar");
        byte[] first = classBytes("dup/Foo", 1, Opcodes.V1_8);
        byte[] second = classBytes("dup/Foo", 2, Opcodes.V1_8);
        Map<String, byte[]> fixture = new LinkedHashMap<String, byte[]>();
        fixture.put("META-INF/MANIFEST.MF", manifest("Manifest-Version: 1.0"));
        fixture.put("dup/Foo.class", first);
        fixture.put("dup2/Foo.class", second);
        fixture.put("dup/Bar.class", classBytes("dup/Bar", 3, Opcodes.V1_8));
        writeJar(jar, fixture);

        ClassPool pool = new ClassPool();
        JarLayout layout = Jars.read(jar, pool, log(), LayoutOptions.defaults());
        check(layout.isFlat(), "duplicates: read does not fail and reports flat layout");
        check(pool.getClass("dup/Foo") != null, "duplicates: class resolved");
        check(Arrays.equals(first, pool.originalBytes("dup/Foo")),
                "duplicates: first occurrence in sorted order wins deterministically");
        ClassPool secondRead = new ClassPool();
        Jars.read(jar, secondRead, log());
        check(Arrays.equals(pool.originalBytes("dup/Foo"), secondRead.originalBytes("dup/Foo")),
                "duplicates: resolution is deterministic across reads");

        Path out = root.resolve("duplicates-out.jar");
        LayoutReport report = write(pool, out, null, null, null, null);
        check(report.counts().get("layout.duplicates").longValue() >= 1,
                "duplicates: layout.duplicates counted (" + report.counts().get("layout.duplicates") + ")");
        Map<String, byte[]> entries = readEntries(out);
        int fooEntries = 0;
        for (String name : entries.keySet()) {
            if (name.equals("dup/Foo.class")) {
                fooEntries++;
            }
        }
        check(fooEntries == 1, "duplicates: exactly one output entry for the duplicated class");
        check(report.counts().get("layout.preserved.entries") != null,
                "duplicates: preserved-entry stat present");
        check(UmbraVerifier.verify(out).isEmpty(), "duplicates: verifier clean");
    }

    // ------------------------------------------------------------------
    // 9. Zip64 + unicode entry names
    // ------------------------------------------------------------------

    private static void testZip64AndUnicode() throws Exception {
        Path jar = root.resolve("unicode.jar");
        Map<String, byte[]> fixture = new LinkedHashMap<String, byte[]>();
        fixture.put("META-INF/MANIFEST.MF", manifest("Manifest-Version: 1.0", "Main-Class: uni.Ünïcode"));
        fixture.put("uni/Ünïcode.class", mainClass("uni/Ünïcode", "UNICODE"));
        fixture.put("资源/说明.txt", "你好，世界".getBytes(StandardCharsets.UTF_8));
        fixture.put("emoji/😀.txt", "smile".getBytes(StandardCharsets.UTF_8));
        writeJar(jar, fixture);

        ClassPool pool = new ClassPool();
        Jars.read(jar, pool, log());
        check(pool.getClass("uni/Ünïcode") != null, "unicode: unicode class name loaded");
        Path out = root.resolve("unicode-out.jar");
        write(pool, out, null, null, null, null);
        Map<String, byte[]> entries = readEntries(out);
        check(Arrays.equals("你好，世界".getBytes(StandardCharsets.UTF_8),
                entries.get("资源/说明.txt")), "unicode: unicode resource name and bytes round-trip");
        check(entries.containsKey("emoji/😀.txt"), "unicode: supplementary-plane entry name round-trips");
        check(Jars.parseManifest(entries.get("META-INF/MANIFEST.MF")).get("Main-Class")
                .equals("uni.Ünïcode"), "unicode: unicode Main-Class preserved");
        check(runJar(out).contains("UNICODE"), "unicode: protected unicode-named class executes");

        // Zip64: more than 65535 entries forces the ZIP64 central directory.
        Path bulkIn = root.resolve("bulk-in.jar");
        Map<String, byte[]> bulkFixture = new LinkedHashMap<String, byte[]>();
        bulkFixture.put("META-INF/MANIFEST.MF", manifest("Manifest-Version: 1.0"));
        bulkFixture.put("bulk/Keep.class", classBytes("bulk/Keep", 0, Opcodes.V1_8));
        writeJar(bulkIn, bulkFixture);
        ClassPool bulkPool = new ClassPool();
        Jars.read(bulkIn, bulkPool, log());
        int total = 66000;
        byte[] one = "x".getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < total; i++) {
            bulkPool.putResource("bulk/f" + i + ".txt", one, 315532800000L, 8);
        }
        Path bulkOut = root.resolve("bulk-out.jar");
        Jars.write(bulkOut, bulkPool, new Hierarchy(), false, log());
        int readBack = 0;
        try (ZipFile zip = new ZipFile(bulkOut.toFile())) {
            java.util.Enumeration<? extends ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                if (!entry.isDirectory()) {
                    readBack++;
                }
            }
        }
        check(readBack > 65535, "zip64: " + readBack + " entries written and read back");
        check(Files.size(bulkOut) > 0L, "zip64: archive written");
    }

    // ------------------------------------------------------------------
    // 10. Signed JAR: strip cleanly, never emit half-signed archives
    // ------------------------------------------------------------------

    private static void testSignedJar() throws Exception {
        Path jar = root.resolve("signed.jar");
        String signedManifest = "Manifest-Version: 1.0\r\n"
                + "Main-Class: sig.Main\r\n"
                + "Signature-Version: 1.0\r\n"
                + "SHA-256-Digest-Manifest: abcdef\r\n"
                + "\r\n"
                + "Name: sig/Main.class\r\n"
                + "SHA-256-Digest: 123456\r\n"
                + "\r\n";
        Map<String, byte[]> fixture = new LinkedHashMap<String, byte[]>();
        fixture.put("META-INF/MANIFEST.MF", signedManifest.getBytes(StandardCharsets.UTF_8));
        fixture.put("META-INF/CERT.SF", "signature".getBytes(StandardCharsets.UTF_8));
        fixture.put("META-INF/CERT.RSA", "signature".getBytes(StandardCharsets.UTF_8));
        fixture.put("sig/Main.class", mainClass("sig/Main", "SIGNED"));
        writeJar(jar, fixture);

        ClassPool pool = new ClassPool();
        Jars.read(jar, pool, log());
        check(pool.resource("META-INF/CERT.SF") == null, "signed: signature file stripped at read");
        check(pool.resource("META-INF/CERT.RSA") == null, "signed: signature block stripped at read");
        check(pool.resource("META-INF/MANIFEST.MF") != null, "signed: manifest kept");
        Map<String, String> afterRead = Jars.parseManifest(pool.resource("META-INF/MANIFEST.MF").bytes());
        check(afterRead.get("Signature-Version") == null, "signed: Signature-Version stripped");
        check(afterRead.get("SHA-256-Digest-Manifest") == null, "signed: manifest digest stripped");

        Path out = root.resolve("signed-out.jar");
        write(pool, out, null, null, null, null);
        Map<String, byte[]> entries = readEntries(out);
        for (String name : entries.keySet()) {
            check(!name.toUpperCase(java.util.Locale.ROOT).endsWith(".SF")
                    && !name.toUpperCase(java.util.Locale.ROOT).endsWith(".RSA"),
                    "signed: no signature entries in output (" + name + ")");
        }
        Map<String, String> attributes = Jars.parseManifest(entries.get("META-INF/MANIFEST.MF"));
        check(attributes.get("Signature-Version") == null, "signed: output manifest unsigned");
        check("sig.Main".equals(attributes.get("Main-Class")), "signed: Main-Class kept");
        check(UmbraVerifier.verify(out).isEmpty(), "signed: verifier clean");
        check(runJar(out).contains("SIGNED"), "signed: unsigned protected JAR executes");
    }

    // ------------------------------------------------------------------
    // 11. Deterministic output
    // ------------------------------------------------------------------

    private static void testDeterministicOutput() throws Exception {
        Path jar = root.resolve("deterministic.jar");
        byte[] nestedLib = jarBytes(bytesMap("lib/Dep.class", classBytes("lib/Dep", 3, Opcodes.V1_8)));
        Map<String, byte[]> fixture = new LinkedHashMap<String, byte[]>();
        fixture.put("META-INF/MANIFEST.MF", manifest(
                "Manifest-Version: 1.0",
                "Main-Class: org.springframework.boot.loader.JarLauncher",
                "Start-Class: app.Main",
                "Spring-Boot-Classes: BOOT-INF/classes/",
                "Spring-Boot-Lib: BOOT-INF/lib/"));
        fixture.put("BOOT-INF/classes/app/Main.class", mainClass("app/Main", "DET"));
        fixture.put("BOOT-INF/classes/app/Helper.class", classBytes("app/Helper", 0, Opcodes.V1_8));
        fixture.put("BOOT-INF/lib/nested.jar", nestedLib);
        fixture.put("org/springframework/boot/loader/JarLauncher.class",
                classBytes("org/springframework/boot/loader/JarLauncher", 0, Opcodes.V1_8));
        writeJar(jar, fixture, java.util.Collections.singleton("BOOT-INF/lib/nested.jar"));

        Map<String, String> classes = map("app/Main", "d/Main", "app/Helper", "d/H");
        Path first = root.resolve("det-1.jar");
        Path second = root.resolve("det-2.jar");
        for (Path target : new Path[]{first, second}) {
            ClassPool pool = new ClassPool();
            Jars.read(jar, pool, log());
            simulateRename(pool, classes, null, null);
            write(pool, target, null, classes, null, null);
        }
        check(Arrays.equals(Files.readAllBytes(first), Files.readAllBytes(second)),
                "determinism: byte-identical output for identical input+mapping");
        check(UmbraVerifier.verify(first).isEmpty(), "determinism: verifier clean");
    }

    // ------------------------------------------------------------------
    // 12. WS11 edge-case regressions (3.1 bug hunt)
    // ------------------------------------------------------------------

    private static void testArchiveEdgeRegressions() throws Exception {
        // 12a. Malformed manifest (continuation without key, garbage line,
        //      over-long value): output must stay a readable JAR manifest.
        Path malformed = root.resolve("edge-malformed-manifest.jar");
        Map<String, byte[]> f1 = new LinkedHashMap<String, byte[]>();
        String badManifest = "Manifest-Version: 1.0\r\n"
                + "Main-Class: edge.Main\r\n"
                + "X-Long: " + repeat('A', 400) + "\r\n"
                + " continuation-without-key\r\n"
                + "GarbageLineWithoutColon\r\n\r\n";
        f1.put("META-INF/MANIFEST.MF", badManifest.getBytes(StandardCharsets.UTF_8));
        f1.put("edge/Main.class", mainClass("edge/Main", "EDGE"));
        writeJar(malformed, f1);
        ClassPool pool1 = new ClassPool();
        Jars.read(malformed, pool1, log());
        check("edge: malformed manifest Main-Class still parsed",
                "edge.Main".equals(Jars.parseManifest(
                        pool1.resource("META-INF/MANIFEST.MF").bytes()).get("Main-Class")));
        Path out1 = root.resolve("edge-malformed-out.jar");
        write(pool1, out1, null, null, null, null);
        check("edge: sanitized manifest is readable by java.util.jar.JarFile",
                jarFileReadable(out1));
        check("edge: sanitized manifest keeps Main-Class", "edge.Main".equals(
                Jars.parseManifest(readEntries(out1).get("META-INF/MANIFEST.MF")).get("Main-Class")));
        check("edge: malformed manifest verifier clean", UmbraVerifier.verify(out1).isEmpty());

        // 12b. UTF-8 BOM before the first manifest header must be stripped.
        Path bom = root.resolve("edge-bom-manifest.jar");
        Map<String, byte[]> f2 = new LinkedHashMap<String, byte[]>();
        byte[] valid = manifest("Manifest-Version: 1.0", "Main-Class: edge.Main");
        byte[] bomBytes = new byte[valid.length + 3];
        bomBytes[0] = (byte) 0xEF;
        bomBytes[1] = (byte) 0xBB;
        bomBytes[2] = (byte) 0xBF;
        System.arraycopy(valid, 0, bomBytes, 3, valid.length);
        f2.put("META-INF/MANIFEST.MF", bomBytes);
        f2.put("edge/Main.class", mainClass("edge/Main", "BOM"));
        writeJar(bom, f2);
        ClassPool pool2 = new ClassPool();
        Jars.read(bom, pool2, log());
        check("edge: BOM manifest Main-Class parsed", "edge.Main".equals(
                Jars.parseManifest(pool2.resource("META-INF/MANIFEST.MF").bytes()).get("Main-Class")));
        Path out2 = root.resolve("edge-bom-out.jar");
        write(pool2, out2, null, null, null, null);
        byte[] outputManifest = readEntries(out2).get("META-INF/MANIFEST.MF");
        check("edge: BOM removed from output manifest", outputManifest.length < 3
                || !((outputManifest[0] & 0xFF) == 0xEF && (outputManifest[1] & 0xFF) == 0xBB
                && (outputManifest[2] & 0xFF) == 0xBF));
        check("edge: BOM output readable by JarFile", jarFileReadable(out2));
        check("edge: BOM verifier clean", UmbraVerifier.verify(out2).isEmpty());

        // 12c. Invalid module-info must be dropped in AUTO mode even when no
        //      class was renamed (previously kept because mapping was empty).
        Path badModule = root.resolve("edge-invalid-module.jar");
        Map<String, byte[]> f3 = new LinkedHashMap<String, byte[]>();
        f3.put("module-info.class", "not a class file".getBytes(StandardCharsets.UTF_8));
        f3.put("mod/api/Api.class", classBytes("mod/api/Api", 0, Opcodes.V1_8));
        writeJar(badModule, f3);
        ClassPool pool3 = new ClassPool();
        Jars.read(badModule, pool3, log());
        Path out3 = root.resolve("edge-invalid-module-out.jar");
        LayoutReport report3 = write(pool3, out3, null, null, null, null);
        check("edge: invalid module-info dropped without renames",
                !readEntries(out3).containsKey("module-info.class"));
        check("edge: moduleInfo kept count is zero",
                report3.counts().get("layout.moduleInfo").longValue() == 0L);
        check("edge: invalid module-info verifier clean", UmbraVerifier.verify(out3).isEmpty());

        // 12d. Versioned-only Main-Class is valid for multi-release: the
        //      verifier must report a note, not an error.
        Path versionedOnly = root.resolve("edge-mr-versioned-only.jar");
        Map<String, byte[]> f4 = new LinkedHashMap<String, byte[]>();
        f4.put("META-INF/MANIFEST.MF", manifest("Manifest-Version: 1.0",
                "Main-Class: mr.Only", "Multi-Release: true"));
        f4.put("META-INF/versions/11/mr/Only.class", mainClass("mr/Only", "ONLY"));
        writeJar(versionedOnly, f4);
        ClassPool pool4 = new ClassPool();
        Jars.read(versionedOnly, pool4, log());
        Path out4 = root.resolve("edge-mr-versioned-only-out.jar");
        write(pool4, out4, null, null, null, null);
        UmbraVerifier.Report ver4 = UmbraVerifier.verifyDetailed(out4, null);
        check("edge: versioned-only entry point is not an error", ver4.ok());
        boolean versionedNote = false;
        for (String note : ver4.notes()) {
            if (note.contains("META-INF/versions")) {
                versionedNote = true;
            }
        }
        check("edge: versioned-only entry point reported as a note", versionedNote);
        check("edge: versioned entry preserved",
                readEntries(out4).containsKey("META-INF/versions/11/mr/Only.class"));

        // 12e. Corrupt nested library must be reported by the verifier.
        Path corruptBoot = root.resolve("edge-corrupt-nested-lib.jar");
        Map<String, byte[]> f5 = new LinkedHashMap<String, byte[]>();
        f5.put("META-INF/MANIFEST.MF", manifest("Manifest-Version: 1.0",
                "Main-Class: org.springframework.boot.loader.JarLauncher",
                "Start-Class: app.Main",
                "Spring-Boot-Classes: BOOT-INF/classes/",
                "Spring-Boot-Lib: BOOT-INF/lib/"));
        f5.put("BOOT-INF/classes/app/Main.class", mainClass("app/Main", "CORRUPT"));
        f5.put("org/springframework/boot/loader/JarLauncher.class",
                classBytes("org/springframework/boot/loader/JarLauncher", 0, Opcodes.V1_8));
        f5.put("BOOT-INF/lib/broken.jar", "not a zip archive".getBytes(StandardCharsets.UTF_8));
        writeJar(corruptBoot, f5);
        ClassPool pool5 = new ClassPool();
        Jars.read(corruptBoot, pool5, log());
        Path out5 = root.resolve("edge-corrupt-nested-lib-out.jar");
        write(pool5, out5, null, null, null, null);
        List<String> errors5 = UmbraVerifier.verify(out5);
        boolean nestedReported = false;
        for (String error : errors5) {
            if (error.contains("nested library") && error.contains("not a valid ZIP")) {
                nestedReported = true;
            }
        }
        check("edge: corrupt nested library reported", nestedReported);
        check("edge: corrupt nested bytes preserved",
                Arrays.equals("not a zip archive".getBytes(StandardCharsets.UTF_8),
                        readEntries(out5).get("BOOT-INF/lib/broken.jar")));

        // 12f. Newer class-file version: structural checks only (skipped link).
        Path newer = root.resolve("edge-newer-class.jar");
        Map<String, byte[]> f6 = new LinkedHashMap<String, byte[]>();
        f6.put("META-INF/MANIFEST.MF", manifest("Manifest-Version: 1.0",
                "Main-Class: edge.Future"));
        ClassWriter futureWriter = new ClassWriter(0);
        futureWriter.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "edge/Future", null, "java/lang/Object", null);
        futureWriter.visitEnd();
        f6.put("edge/Future.class", futureWriter.toByteArray());
        writeJar(newer, f6);
        ClassPool pool6 = new ClassPool();
        Jars.read(newer, pool6, log());
        Path out6 = root.resolve("edge-newer-class-out.jar");
        write(pool6, out6, null, null, null, null);
        UmbraVerifier.Report ver6 = UmbraVerifier.verifyDetailed(out6, null);
        check("edge: newer class version is not an error", ver6.ok());
        check("edge: newer class version counted as skipped", ver6.skippedByVersion() >= 1);

        // 12g. Atomic publication: a failed replace must keep the previous
        //      output and leave no temporary archive behind.
        Path atomicTarget = root.resolve("edge-atomic-out.jar");
        ClassPool atomicPool = new ClassPool();
        Jars.read(root.resolve("flat.jar"), atomicPool, log());
        write(atomicPool, atomicTarget, null, null, null, null);
        byte[] before = Files.readAllBytes(atomicTarget);
        boolean readOnlySupported = true;
        try {
            Files.setAttribute(atomicTarget, "dos:readonly", Boolean.TRUE);
        } catch (Exception unsupported) {
            // Platform without the DOS read-only attribute: skip this half.
            readOnlySupported = false;
        }
        if (readOnlySupported) {
            boolean readOnlyFailed = false;
            try {
                write(atomicPool, atomicTarget, null, null, null, null);
            } catch (IOException expected) {
                readOnlyFailed = true;
            } finally {
                try {
                    Files.setAttribute(atomicTarget, "dos:readonly", Boolean.FALSE);
                } catch (Exception ignored) {
                    // The attribute may already be gone on some file systems.
                }
            }
            if (readOnlyFailed) {
                check("edge: failed replace keeps previous output",
                        Arrays.equals(before, Files.readAllBytes(atomicTarget)));
            }
        }
        boolean tempLeft = false;
        try (java.util.stream.Stream<Path> stream = Files.list(root)) {
            tempLeft = stream.anyMatch(path -> path.getFileName().toString().endsWith(".umbra-tmp"));
        }
        check("edge: no temporary archive left after failed write", !tempLeft);
        check("edge: output still readable after atomic test", jarFileReadable(atomicTarget));
    }

    private static String repeat(char value, int count) {
        StringBuilder sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            sb.append(value);
        }
        return sb.toString();
    }

    private static boolean jarFileReadable(Path jar) {
        try (java.util.jar.JarFile file = new java.util.jar.JarFile(jar.toFile())) {
            file.getManifest();
            java.util.Enumeration<java.util.jar.JarEntry> entries = file.entries();
            while (entries.hasMoreElements()) {
                entries.nextElement();
            }
            return true;
        } catch (IOException failure) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Fixture helpers
    // ------------------------------------------------------------------

    private static byte[] manifest(String... lines) {
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            sb.append(line).append("\r\n");
        }
        sb.append("\r\n");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static Map<String, String> map(String... pairs) {
        Map<String, String> result = new LinkedHashMap<String, String>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            result.put(pairs[i], pairs[i + 1]);
        }
        return result;
    }

    private static Map<String, byte[]> bytesMap(Object... pairs) {
        Map<String, byte[]> result = new LinkedHashMap<String, byte[]>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            result.put((String) pairs[i], (byte[]) pairs[i + 1]);
        }
        return result;
    }

    private static byte[] classBytes(String internalName, int marker, int version) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(version, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, internalName, null,
                "java/lang/Object", null);
        MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
        MethodVisitor markerMethod = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "marker", "()I", null, null);
        markerMethod.visitCode();
        markerMethod.visitLdcInsn(Integer.valueOf(marker));
        markerMethod.visitInsn(Opcodes.IRETURN);
        markerMethod.visitMaxs(1, 0);
        markerMethod.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] mainClass(String internalName, String text) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, internalName, null,
                "java/lang/Object", null);
        MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
        MethodVisitor main = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "main", "([Ljava/lang/String;)V", null, null);
        main.visitCode();
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out",
                "Ljava/io/PrintStream;");
        main.visitLdcInsn(text);
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "print",
                "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitMaxs(2, 1);
        main.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] moduleInfoBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V9, Opcodes.ACC_MODULE, "module-info", null, null, null);
        ModuleVisitor module = writer.visitModule("com.example.mod", 0, "1.0");
        module.visitRequire("java.base", Opcodes.ACC_MANDATED, null);
        module.visitExport("app/pkg", 0);
        module.visitOpen("app/opens", 0);
        module.visitUse("app/pkg/Service");
        module.visitProvide("app/pkg/Service", "app/pkg/ServiceImpl");
        module.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void writeJar(Path jar, Map<String, byte[]> entries) throws Exception {
        writeJar(jar, entries, java.util.Collections.<String>emptySet());
    }

    /**
     * Writes a fixture, storing the named entries without compression (nested
     * JARs in Spring Boot {@code BOOT-INF/lib/} must be STORED).
     */
    private static void writeJar(Path jar, Map<String, byte[]> entries,
                                 java.util.Set<String> storedEntries) throws Exception {
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                ZipEntry zipEntry = new ZipEntry(entry.getKey());
                zipEntry.setTime(315532800000L);
                if (storedEntries.contains(entry.getKey())) {
                    zipEntry.setMethod(ZipEntry.STORED);
                    zipEntry.setSize(entry.getValue().length);
                    zipEntry.setCompressedSize(entry.getValue().length);
                    java.util.zip.CRC32 crc = new java.util.zip.CRC32();
                    crc.update(entry.getValue());
                    zipEntry.setCrc(crc.getValue());
                }
                out.putNextEntry(zipEntry);
                out.write(entry.getValue());
                out.closeEntry();
            }
        }
    }

    private static int entryMethod(Path jar, String name) throws Exception {
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            ZipEntry entry = zip.getEntry(name);
            check(entry != null, "entryMethod: missing entry " + name);
            return entry.getMethod();
        }
    }

    private static byte[] jarBytes(Map<String, byte[]> entries) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (ZipOutputStream out = new ZipOutputStream(buffer)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                ZipEntry zipEntry = new ZipEntry(entry.getKey());
                zipEntry.setTime(315532800000L);
                out.putNextEntry(zipEntry);
                out.write(entry.getValue());
                out.closeEntry();
            }
        }
        return buffer.toByteArray();
    }

    private static LayoutReport write(ClassPool pool, Path output, Map<String, String> options,
                                      Map<String, String> classes, Map<String, String> methods,
                                      Map<String, String> fields) throws Exception {
        if (options == null) {
            return Jars.write(output, pool, new Hierarchy(), false, log(),
                    (Map<String, String>) null, classes, methods, fields);
        }
        return Jars.write(output, pool, new Hierarchy(), false, log(), options, classes, methods, fields);
    }

    /**
     * Simulates the renamer: remaps every class through a
     * {@link ClassRenameMap} and applies the batch rename to the pool.
     */
    private static void simulateRename(ClassPool pool, Map<String, String> classes,
                                       Map<String, String> methods, Map<String, String> fields) {
        ClassRenameMap rename = ClassRenameMap.of(classes, methods, fields);
        Map<String, ClassNode> remapped = new LinkedHashMap<String, ClassNode>();
        Map<String, String> oldToNew = new LinkedHashMap<String, String>();
        for (String name : pool.classes().keySet()) {
            byte[] original = pool.originalBytes(name);
            if (original == null) {
                continue;
            }
            ClassReader reader = new ClassReader(original);
            ClassWriter writer = new ClassWriter(0);
            reader.accept(new ClassRemapper(writer, rename.remapper()), 0);
            ClassNode node = new ClassNode();
            new ClassReader(writer.toByteArray()).accept(node, 0);
            remapped.put(name, node);
            String mapped = rename.mapClass(name);
            if (!mapped.equals(name)) {
                oldToNew.put(name, mapped);
            }
        }
        if (!oldToNew.isEmpty()) {
            pool.applyRenames(oldToNew, remapped);
        }
    }

    private static Map<String, byte[]> readEntries(Path jar) throws Exception {
        Map<String, byte[]> entries = new TreeMap<String, byte[]>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            java.util.Enumeration<? extends ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                entries.put(entry.getName(), readAll(zip.getInputStream(entry)));
            }
        }
        return entries;
    }

    private static byte[] readAll(InputStream in) throws Exception {
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

    private static String text(byte[] bytes) {
        return bytes == null ? null : new String(bytes, StandardCharsets.UTF_8);
    }

    private static Log log() {
        return Log.console(false);
    }

    /** Runs the protected flat JAR and returns its stdout. */
    private static String runJar(Path jar) throws Exception {
        String javaExe = System.getProperty("java.home") + java.io.File.separator + "bin"
                + java.io.File.separator + "java.exe";
        ProcessBuilder builder = new ProcessBuilder(javaExe, "-jar", jar.toAbsolutePath().toString());
        builder.redirectErrorStream(true);
        Process process = builder.start();
        byte[] stdout;
        try (InputStream in = process.getInputStream()) {
            stdout = readAll(in);
        }
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new AssertionError("timeout running " + jar);
        }
        check(process.exitValue() == 0, "runJar: exit code " + process.exitValue()
                + " for " + jar + " (stdout=" + new String(stdout, StandardCharsets.UTF_8) + ")");
        return new String(stdout, StandardCharsets.UTF_8);
    }

    /**
     * Loads classes under a container prefix from the protected archive and
     * invokes the main class, emulating what the Spring Boot/WAR loader does.
     */
    private static String runPrefixedMain(Path jar, String prefix, String mainClass) throws Exception {
        final Map<String, byte[]> classes = new TreeMap<String, byte[]>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            java.util.Enumeration<? extends ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                String name = entry.getName();
                if (entry.isDirectory() || !name.startsWith(prefix) || !name.endsWith(".class")) {
                    continue;
                }
                byte[] bytes = readAll(zip.getInputStream(entry));
                classes.put(new ClassReader(bytes).getClassName().replace('/', '.'), bytes);
            }
        }
        ClassLoader loader = new ClassLoader(CompatTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] bytes = classes.get(name);
                if (bytes != null) {
                    return defineClass(name, bytes, 0, bytes.length);
                }
                throw new ClassNotFoundException(name);
            }
        };
        PrintStream previous = System.out;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(captured, true, "UTF-8"));
            Class<?> type = Class.forName(mainClass, true, loader);
            type.getMethod("main", String[].class).invoke(null, (Object) new String[0]);
        } finally {
            System.setOut(previous);
        }
        return new String(captured.toByteArray(), StandardCharsets.UTF_8);
    }

    private static ModuleDescription describeModule(byte[] moduleInfo) {
        final ModuleDescription description = new ModuleDescription();
        new ClassReader(moduleInfo).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public ModuleVisitor visitModule(String name, int access, String version) {
                description.name = name;
                return new ModuleVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitExport(String packaze, int access, String... modules) {
                        description.exports.add(packaze);
                    }

                    @Override
                    public void visitOpen(String packaze, int access, String... modules) {
                        description.opens.add(packaze);
                    }

                    @Override
                    public void visitUse(String service) {
                        description.uses.add(service);
                    }

                    @Override
                    public void visitProvide(String service, String... providers) {
                        for (String provider : providers) {
                            description.provides.add(provider);
                        }
                    }
                };
            }
        }, 0);
        return description;
    }

    private static void assertStatsKeys(LayoutReport report, String expectedKind) {
        String[] required = {
                "layout.springBoot.classes", "layout.war.classes", "layout.multiRelease.classes",
                "layout.moduleInfo", "layout.services", "layout.manifest.rewritten"
        };
        for (String key : required) {
            check(report.counts().containsKey(key), "stats: missing " + key);
        }
        check(expectedKind.equals(report.texts().get("layout.kind")),
                "stats: layout.kind=" + report.texts().get("layout.kind") + " expected " + expectedKind);
        check(report.texts().get("layout.multiRelease.mode") != null, "stats: multiRelease mode reported");
    }

    private static final class ModuleDescription {
        String name;
        final List<String> exports = new ArrayList<String>();
        final List<String> opens = new ArrayList<String>();
        final List<String> uses = new ArrayList<String>();
        final List<String> provides = new ArrayList<String>();
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }

    /** Message-first alias used by the newer edge-case groups. */
    private static void check(String message, boolean condition) {
        check(condition, message);
    }

    private static void delete(Path directory) {
        try {
            if (!Files.exists(directory)) {
                return;
            }
            Files.walk(directory)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (Exception ignored) {
                            // Best-effort temporary cleanup.
                        }
                    });
        } catch (Exception ignored) {
            // Best-effort temporary cleanup.
        }
    }
}
