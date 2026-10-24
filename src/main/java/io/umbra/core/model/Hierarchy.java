package io.umbra.core.model;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Lightweight class hierarchy over the input jar, user libraries and JDK
 * classes. It is used by the renamer (override/field resolution) and by the
 * frame-computing {@code ClassWriter}.
 */
public final class Hierarchy {

    private final Map<String, ClassInfo> infos = new LinkedHashMap<String, ClassInfo>();

    /** Registers an input class. */
    public ClassInfo addInput(ClassNode node) {
        ClassInfo info = new ClassInfo(node.name, node.superName, node.interfaces.toArray(new String[0]),
                node.access, ClassInfo.Source.INPUT, node.version);
        addMembers(info, node);
        infos.put(node.name, info);
        return info;
    }

    /** Registers a library class from raw bytes. */
    public ClassInfo addLibrary(byte[] bytes) {
        ClassReader reader = new ClassReader(bytes);
        ClassNode node = new ClassNode();
        reader.accept(node, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        ClassInfo info = new ClassInfo(node.name, node.superName, node.interfaces.toArray(new String[0]),
                node.access, ClassInfo.Source.LIBRARY, node.version);
        addMembers(info, node);
        infos.put(node.name, info);
        return info;
    }

    /** Loads all class entries from a jar/zip/jmod. */
    public void addLibraryJar(Path path) throws IOException {
        try (ZipFile zip = new ZipFile(path.toFile())) {
            java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }
                try (InputStream in = zip.getInputStream(entry)) {
                    byte[] bytes = readAll(in);
                    try {
                        addLibrary(bytes);
                    } catch (RuntimeException ignored) {
                        // Malformed or unsupported class file: ignore library entry.
                    }
                }
            }
        }
    }

    /** Returns hierarchy information, loading JDK classes on demand. */
    public ClassInfo resolve(String name) {
        ClassInfo info = infos.get(name);
        if (info != null) {
            return info;
        }
        info = loadFromSystem(name);
        if (info == null) {
            info = new ClassInfo(name, "java/lang/Object", new String[0], 0, ClassInfo.Source.UNKNOWN, 52);
        }
        infos.put(name, info);
        return info;
    }

    public boolean isInput(String name) {
        ClassInfo info = infos.get(name);
        return info != null && info.isInput();
    }

    public boolean isKnown(String name) {
        ClassInfo info = infos.get(name);
        return info != null && info.source() != ClassInfo.Source.UNKNOWN;
    }

    /** True when {@code a} is {@code b}, a superclass of {@code b}, or an interface of {@code b}. */
    public boolean isAssignableFrom(String a, String b) {
        if (a.equals(b)) {
            return true;
        }
        Deque<String> queue = new ArrayDeque<String>();
        Set<String> seen = new HashSet<String>();
        queue.add(b);
        while (!queue.isEmpty()) {
            String current = queue.poll();
            if (current == null || !seen.add(current)) {
                continue;
            }
            if (current.equals(a)) {
                return true;
            }
            ClassInfo info = resolve(current);
            if (info.superName() != null) {
                queue.add(info.superName());
            }
            for (String itf : info.interfaces()) {
                queue.add(itf);
            }
        }
        return false;
    }

    /** ASM-compatible common-superclass computation. */
    public String getCommonSuperClass(String a, String b) {
        if (a.equals(b)) {
            return a;
        }
        if (isAssignableFrom(a, b)) {
            return a;
        }
        if (isAssignableFrom(b, a)) {
            return b;
        }
        if (resolve(a).isInterface() || resolve(b).isInterface()) {
            return "java/lang/Object";
        }
        String current = a;
        Set<String> seen = new HashSet<String>();
        while (current != null && seen.add(current)) {
            current = resolve(current).superName();
            if (current != null && isAssignableFrom(current, b)) {
                return current;
            }
        }
        return "java/lang/Object";
    }

    /**
     * Resolves a method declaration starting at {@code owner}.
     *
     * @return declaring class info, or {@code null} when it cannot be resolved
     */
    public ClassInfo resolveMethod(String owner, String name, String desc) {
        return resolveMember(owner, name + desc, true, new HashSet<String>());
    }

    /**
     * Resolves a field declaration starting at {@code owner}.
     *
     * @return declaring class info, or {@code null} when it cannot be resolved
     */
    public ClassInfo resolveField(String owner, String name, String desc) {
        return resolveMember(owner, name + ":" + desc, false, new HashSet<String>());
    }

    private ClassInfo resolveMember(String owner, String key, boolean method, Set<String> seen) {
        if (owner == null || !seen.add(owner)) {
            return null;
        }
        ClassInfo info = resolve(owner);
        boolean declared = method ? info.methods().contains(key) : info.fields().contains(key);
        if (declared) {
            return info;
        }
        ClassInfo fromSuper = resolveMember(info.superName(), key, method, seen);
        if (fromSuper != null) {
            return fromSuper;
        }
        for (String itf : info.interfaces()) {
            ClassInfo fromInterface = resolveMember(itf, key, method, seen);
            if (fromInterface != null) {
                return fromInterface;
            }
        }
        return null;
    }

    private ClassInfo loadFromSystem(String name) {
        String resource = name + ".class";
        ClassLoader loader = ClassLoader.getSystemClassLoader();
        try (InputStream in = loader.getResourceAsStream(resource)) {
            if (in == null) {
                return null;
            }
            byte[] bytes = readAll(in);
            ClassReader reader = new ClassReader(bytes);
            ClassNode node = new ClassNode();
            reader.accept(node, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            ClassInfo info = new ClassInfo(node.name, node.superName, node.interfaces.toArray(new String[0]),
                    node.access, ClassInfo.Source.JDK, node.version);
            addMembers(info, node);
            return info;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static void addMembers(ClassInfo info, ClassNode node) {
        for (MethodNode method : node.methods) {
            info.addMethod(method.name, method.desc, method.access);
        }
        for (FieldNode field : node.fields) {
            info.addField(field.name, field.desc, field.access);
        }
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

    /** Snapshot of all known input class names, in insertion order. */
    public List<String> inputClassNames() {
        List<String> out = new ArrayList<String>();
        for (Map.Entry<String, ClassInfo> e : infos.entrySet()) {
            if (e.getValue().isInput()) {
                out.add(e.getKey());
            }
        }
        return out;
    }

    /** Test/debug helper. */
    public Map<String, ClassInfo> snapshot() {
        return new HashMap<String, ClassInfo>(infos);
    }
}
