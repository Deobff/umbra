package io.umbra.tests;

import io.umbra.core.compat.JarLayout;
import io.umbra.core.compat.LayoutOptions;
import io.umbra.core.compat.LayoutReport;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.util.Jars;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * Checks multi-release handling in both supported modes:
 *
 * <ul>
 *   <li>{@code layout.multiRelease=preserve} (default): {@code META-INF/versions/N/}
 *       layout, entries and the {@code Multi-Release} attribute are preserved;</li>
 *   <li>{@code layout.multiRelease=flatten}: versioned classes are promoted to
 *       base paths, versioned resources are dropped and the attribute is removed
 *       (the historic Umbra behaviour).</li>
 * </ul>
 */
public final class MultiReleaseTest {

    private static int checks;

    private MultiReleaseTest() {
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("umbra-mr-test-");
        try {
            Path jar = dir.resolve("multi-release.jar");
            buildFixture(jar);
            testPreserveMode(dir, jar);
            testFlattenMode(dir, jar);
            testPreserveRename(dir, jar);
        } finally {
            delete(dir);
        }
        System.out.println("MultiReleaseTest: " + checks + " checks passed");
    }

    private static void buildFixture(Path jar) throws Exception {
        JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar));
        // Versioned entries deliberately come first so the reader cannot rely
        // on the base class being seen first.
        add(out, "META-INF/versions/11/mr/Base.class", classBytes("mr/Base", 11, Opcodes.V11));
        add(out, "META-INF/versions/9/mr/Base.class", classBytes("mr/Base", 9, Opcodes.V9));
        add(out, "META-INF/versions/9/mr/Only.class", classBytes("mr/Only", 9, Opcodes.V9));
        add(out, "META-INF/versions/9/data.txt", "versioned-data".getBytes(StandardCharsets.UTF_8));
        add(out, "mr/Base.class", classBytes("mr/Base", 8, Opcodes.V1_8));
        add(out, "data.txt", "base-data".getBytes(StandardCharsets.UTF_8));
        String manifest = "Manifest-Version: 1.0\r\nMain-Class: mr.Base\r\n"
                + "Multi-Release: true\r\n\r\n";
        add(out, "META-INF/MANIFEST.MF", manifest.getBytes(StandardCharsets.UTF_8));
        out.close();
    }

    private static void testPreserveMode(Path dir, Path jar) throws Exception {
        ClassPool pool = new ClassPool();
        JarLayout layout = Jars.read(jar, pool, Log.console(false), LayoutOptions.defaults());
        check(layout.multiRelease(), "preserve: layout reported as multi-release");
        check(layout.maxVersion() == 11, "preserve: highest version detected");
        check(pool.getClass("mr/Base") != null, "preserve: base class kept");
        check(pool.getClass("mr/Only") == null, "preserve: versioned-only class is not flattened into the pool");
        check(pool.resource("META-INF/versions/9/mr/Only.class") != null,
                "preserve: versioned-only class kept as a versioned entry");
        check(pool.resource("META-INF/versions/9/data.txt") != null,
                "preserve: versioned resource kept");
        check(pool.resource("mr/Base.class") == null, "preserve: versioned class is not a base resource");

        Path out = dir.resolve("preserved.jar");
        LayoutReport report = Jars.write(out, pool, new Hierarchy(), false, Log.console(false),
                LayoutOptions.defaults(), null, null, null);
        Map<String, byte[]> entries = readEntries(out);
        check(entries.containsKey("META-INF/versions/9/mr/Base.class"), "preserve: 9/Base entry kept");
        check(entries.containsKey("META-INF/versions/11/mr/Base.class"), "preserve: 11/Base entry kept");
        check(entries.containsKey("META-INF/versions/9/mr/Only.class"), "preserve: 9/Only entry kept");
        check(entries.containsKey("META-INF/versions/9/data.txt"), "preserve: versioned resource kept in output");
        check(entries.containsKey("mr/Base.class"), "preserve: base class written at base path");
        Map<String, String> manifest = Jars.parseManifest(entries.get("META-INF/MANIFEST.MF"));
        check("true".equals(manifest.get("Multi-Release")), "preserve: Multi-Release attribute kept");
        check("mr.Base".equals(manifest.get("Main-Class")), "preserve: main class preserved");
        check(report.counts().get("layout.multiRelease.classes").longValue() == 3,
                "preserve: layout.multiRelease.classes counts all versioned classes");
        check("multi-release".equals(report.texts().get("layout.kind")),
                "preserve: layout.kind is multi-release");
        check(report.texts().get("layout.multiRelease.mode").equals("preserve"),
                "preserve: mode reported");
    }

    private static void testFlattenMode(Path dir, Path jar) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("layout.multiRelease", "flatten");
        ClassPool pool = new ClassPool();
        JarLayout layout = Jars.read(jar, pool, Log.console(false), options);
        check(pool.getClass("mr/Base") != null, "flatten: base class kept");
        check(pool.getClass("mr/Only") != null, "flatten: versioned-only class promoted to base path");
        check(pool.resource("META-INF/versions/9/mr/Only.class") == null,
                "flatten: versioned entries dropped from the pool");
        boolean versionedResource = false;
        for (String name : pool.resources().keySet()) {
            if (name.startsWith("META-INF/versions/")) {
                versionedResource = true;
            }
        }
        check(!versionedResource, "flatten: versioned resources dropped");
        Map<String, String> attributes = Jars.parseManifest(
                pool.resource("META-INF/MANIFEST.MF").bytes());
        check(attributes.get("Multi-Release") == null, "flatten: Multi-Release attribute removed at read");
        check("mr.Base".equals(attributes.get("Main-Class")), "flatten: main class preserved");
        check(layout.multiRelease(), "flatten: detector still reports the input was multi-release");

        Path out = dir.resolve("flattened.jar");
        Jars.write(out, pool, new Hierarchy(), false, Log.console(false), options, null, null, null);
        Map<String, byte[]> entries = readEntries(out);
        check(entries.containsKey("mr/Base.class"), "flatten: base class written at base path");
        check(entries.containsKey("mr/Only.class"), "flatten: promoted versioned-only class written at base path");
        boolean versioned = false;
        for (String name : entries.keySet()) {
            if (name.startsWith("META-INF/versions/")) {
                versioned = true;
            }
        }
        check(!versioned, "flatten: no versioned entries in the flat output");
        Map<String, String> manifest = Jars.parseManifest(entries.get("META-INF/MANIFEST.MF"));
        check(manifest.get("Multi-Release") == null, "flatten: Multi-Release attribute absent");
    }

    private static void testPreserveRename(Path dir, Path jar) throws Exception {
        ClassPool pool = new ClassPool();
        Jars.read(jar, pool, Log.console(false), LayoutOptions.defaults());
        // Simulate the renamer: rename the base class and its member (global
        // method map) so every versioned copy must follow the same mapping.
        Map<String, String> classes = new LinkedHashMap<String, String>();
        classes.put("mr/Base", "pkg/R");
        Map<String, String> methods = new LinkedHashMap<String, String>();
        methods.put("marker()I", "m");
        io.umbra.core.compat.ClassRenameMap rename = io.umbra.core.compat.ClassRenameMap.of(
                classes, methods, null);
        Map<String, org.objectweb.asm.tree.ClassNode> remapped =
                new LinkedHashMap<String, org.objectweb.asm.tree.ClassNode>();
        for (String name : pool.classes().keySet()) {
            byte[] original = pool.originalBytes(name);
            if (original == null) {
                continue;
            }
            org.objectweb.asm.ClassReader reader = new org.objectweb.asm.ClassReader(original);
            org.objectweb.asm.ClassWriter writer = new org.objectweb.asm.ClassWriter(0);
            reader.accept(new org.objectweb.asm.commons.ClassRemapper(writer, rename.remapper()), 0);
            org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
            new org.objectweb.asm.ClassReader(writer.toByteArray()).accept(node, 0);
            remapped.put(name, node);
        }
        Map<String, String> oldToNew = new LinkedHashMap<String, String>();
        oldToNew.put("mr/Base", "pkg/R");
        pool.applyRenames(oldToNew, remapped);

        Path out = dir.resolve("preserved-renamed.jar");
        Jars.write(out, pool, new Hierarchy(), false, Log.console(false), LayoutOptions.defaults(),
                classes, methods, null);
        Map<String, byte[]> entries = readEntries(out);
        check(entries.containsKey("pkg/R.class"), "rename: base class renamed");
        check(entries.containsKey("META-INF/versions/9/pkg/R.class"), "rename: version 9 copy renamed at path");
        check(entries.containsKey("META-INF/versions/11/pkg/R.class"), "rename: version 11 copy renamed at path");
        check(entries.containsKey("META-INF/versions/9/mr/Only.class"),
                "rename: versioned-only class path kept (no base mapping)");
        byte[] version9 = entries.get("META-INF/versions/9/pkg/R.class");
        check(version9 != null && containsAscii(version9, "pkg/R"), "rename: versioned class internal name remapped");
        check(version9 != null && methodNamed(version9, "m") && !methodNamed(version9, "marker"),
                "rename: versioned class member name remapped");
        byte[] only = entries.get("META-INF/versions/9/mr/Only.class");
        check(only != null, "rename: versioned-only entry present");
        Map<String, String> manifest = Jars.parseManifest(entries.get("META-INF/MANIFEST.MF"));
        check("true".equals(manifest.get("Multi-Release")), "rename: Multi-Release kept");
        check("pkg.R".equals(manifest.get("Main-Class")), "rename: Main-Class remapped");
    }

    private static byte[] classBytes(String name, int marker, int version) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(version, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null,
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

    private static void add(JarOutputStream out, String name, byte[] bytes) throws Exception {
        JarEntry entry = new JarEntry(name);
        entry.setTime(315532800000L);
        out.putNextEntry(entry);
        out.write(bytes);
        out.closeEntry();
    }

    private static Map<String, byte[]> readEntries(Path jar) throws Exception {
        Map<String, byte[]> entries = new TreeMap<String, byte[]>();
        try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(jar.toFile())) {
            java.util.Enumeration<? extends java.util.zip.ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                java.util.zip.ZipEntry entry = enumeration.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                java.io.InputStream in = zip.getInputStream(entry);
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) >= 0) {
                    out.write(buffer, 0, read);
                }
                in.close();
                entries.put(entry.getName(), out.toByteArray());
            }
        }
        return entries;
    }

    private static boolean methodNamed(byte[] classBytes, String methodName) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new org.objectweb.asm.ClassReader(classBytes).accept(node, 0);
        for (org.objectweb.asm.tree.MethodNode method : node.methods) {
            if (method.name.equals(methodName)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsAscii(byte[] bytes, String text) {
        byte[] needle = text.getBytes(StandardCharsets.ISO_8859_1);
        outer:
        for (int i = 0; i + needle.length <= bytes.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (bytes[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }

    private static void delete(Path directory) {
        try {
            if (!Files.exists(directory)) {
                return;
            }
            Files.walk(directory)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (Exception ignored) {
                            // Best effort temp cleanup.
                        }
                    });
        } catch (Exception ignored) {
            // Best effort temp cleanup.
        }
    }
}
