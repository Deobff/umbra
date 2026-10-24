package io.umbra.core.enterprise;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Extracts Umbra watermark payloads from a protected JAR. */
public final class WatermarkTracer {

    private static final String PREFIX = "UMBRA|";

    private WatermarkTracer() {
    }

    public static List<String> trace(Path jar) throws IOException {
        Set<String> marks = new LinkedHashSet<String>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            ZipEntry manifest = zip.getEntry("META-INF/MANIFEST.MF");
            if (manifest != null) {
                try (InputStream in = zip.getInputStream(manifest)) {
                    Map<String, String> attributes = io.umbra.core.util.Jars.parseManifest(readAll(in));
                    String value = attributes.get("Umbra-Watermark");
                    if (value != null && !value.isEmpty()) {
                        marks.add("manifest: " + value);
                    }
                }
            }
            java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }
                final String entryName = entry.getName();
                try (InputStream in = zip.getInputStream(entry)) {
                    byte[] bytes = readAll(in);
                    ClassReader reader = new ClassReader(bytes);
                    final String className = reader.getClassName();
                    reader.accept(new ClassVisitor(Opcodes.ASM9) {
                        @Override
                        public FieldVisitor visitField(int access, String name, String descriptor,
                                                       String signature, Object value) {
                            if (value instanceof String && ((String) value).startsWith(PREFIX)) {
                                marks.add(entryName + " " + className + "." + name + " = " + value);
                            }
                            return null;
                        }
                    }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                } catch (RuntimeException ignored) {
                    // Ignore unparseable entries; the manifest mark is still reported.
                }
            }
        }
        return new ArrayList<String>(marks);
    }

    private static byte[] readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
}
