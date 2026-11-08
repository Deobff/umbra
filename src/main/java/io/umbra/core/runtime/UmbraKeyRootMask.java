package io.umbra.core.runtime;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.CodeSource;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import io.umbra.core.runtime.crypto.UmbraCrypto;

/**
 * Runtime mask derived from the native key root (injected template).
 *
 * <p>Tables emitted by the flow layer store <code>C ^ mask(slot)</code> instead of
 * a literal constant, and the patch that links two entries uses the same mask. An
 * attacker who reads the class sees a literal ciphertext and a call to
 * {@link #mask(int)}; without the native key root the mask cannot be evaluated
 * statically, so the constant stays hidden.</p>
 *
 * <p>The template is self-contained (JDK only). At run time it locates the
 * injected native loader by scanning the archive for the helper prefix, calls
 * <code>deriveKey(1, 0)</code> reflectively and caches the resulting 32-byte
 * root. The build side computes the same root and the same {@link #mix(byte[],
 * int)} function, so both sides bind to identical masks.</p>
 *
 * <p>A build that ships the native guard fails closed: if the root cannot be
 * resolved at run time the class initializer throws instead of silently
 * computing a different table. Builds without the native guard never inject this
 * class at all (they are reported as the static tier).</p>
 */
public final class UmbraKeyRootMask {

    private static final String PREFIX = "@@PREFIX@@";

    private static volatile byte[] root;
    private static volatile boolean resolved;

    private UmbraKeyRootMask() {
    }

    public static int mask(int slot) {
        return mix(root(), slot);
    }

    public static int mix(byte[] key, int slot) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException();
        }
        int value = 0x811C9DC5;
        for (int i = 0; i < key.length; i++) {
            value ^= key[i] & 0xFF;
            value *= 0x01000193;
        }
        value ^= slot;
        value *= 0x9E3779B1;
        value ^= value >>> 15;
        value *= 0x85EBCA77;
        value ^= value >>> 13;
        return value;
    }

    public static byte[] rootOrNull() {
        try {
            byte[] value = root();
            if (value != null) {

                UmbraCrypto.installKeyRoot(value);
            }
            return value;
        } catch (RuntimeException unavailable) {
            return null;
        }
    }

    private static byte[] root() {
        if (!resolved) {
            synchronized (UmbraKeyRootMask.class) {
                if (!resolved) {
                    byte[] value = nativeRoot();
                    if (value == null) {
                        throw new IllegalStateException();
                    }
                    root = value;
                    resolved = true;
                }
            }
        }
        byte[] value = root;
        if (value == null) {
            throw new IllegalStateException();
        }
        return value;
    }

    private static byte[] nativeRoot() {
        try {
            CodeSource source = UmbraKeyRootMask.class.getProtectionDomain().getCodeSource();
            if (source == null) {
                return null;
            }
            URL location = source.getLocation();
            if (location == null || !"file".equals(location.getProtocol())) {
                return null;
            }
            File file = new File(location.toURI());
            if (!file.isFile()) {
                return null;
            }
            ClassLoader loader = UmbraKeyRootMask.class.getClassLoader();
            if (loader == null) {
                loader = ClassLoader.getSystemClassLoader();
            }
            JarFile jar = new JarFile(file);
            try {
                Enumeration<JarEntry> entries = jar.entries();
                String self = UmbraKeyRootMask.class.getName();
                while (entries.hasMoreElements()) {
                    String name = entries.nextElement().getName();
                    if (!name.startsWith(PREFIX) || !name.endsWith(".class")) {
                        continue;
                    }
                    String binary = name.substring(0, name.length() - 6).replace('/', '.');
                    if (binary.equals(self)) {
                        continue;
                    }
                    byte[] value = derive(jar, loader, name, binary);
                    if (value != null) {
                        return value;
                    }
                }
            } finally {
                jar.close();
            }
        } catch (Throwable unavailable) {
            return null;
        }
        return null;
    }

    private static byte[] derive(JarFile jar, ClassLoader loader, String entry, String binary) {
        try {
            JarEntry data = jar.getJarEntry(entry);
            if (data == null) {
                return null;
            }
            byte[] bytes = new byte[(int) data.getSize()];
            java.io.InputStream in = jar.getInputStream(data);
            try {
                int offset = 0;
                while (offset < bytes.length) {
                    int read = in.read(bytes, offset, bytes.length - offset);
                    if (read < 0) {
                        break;
                    }
                    offset += read;
                }
            } finally {
                in.close();
            }
            if (!contains(bytes, "deriveKey")) {
                return null;
            }
            Class<?> type = Class.forName(binary, false, loader);
            Method derive = type.getMethod("deriveKey", int.class, int.class);
            Object value = derive.invoke(null, Integer.valueOf(1), Integer.valueOf(0));
            if (value instanceof byte[] && ((byte[]) value).length == 32) {
                return (byte[]) value;
            }
        } catch (Throwable ignored) {

        }
        return null;
    }

    private static boolean contains(byte[] data, String text) {
        byte[] needle = text.getBytes();
        outer:
        for (int i = 0; i + needle.length <= data.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
