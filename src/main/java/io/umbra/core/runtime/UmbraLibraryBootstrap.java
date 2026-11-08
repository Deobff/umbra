package io.umbra.core.runtime;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * Plaintext entry point of a <em>sealed library</em> archive (library mode).
 *
 * <p>A library jar has no {@code main}, so the regular class-encryption mode - which
 * injects a loader trampoline behind {@code Main-Class} - cannot start it. In
 * library mode the archive keeps <strong>exactly one plaintext class</strong> (this
 * one, self-contained and JDK-only); the host application calls</p>
 *
 * <pre>
 *   ClassLoader lib = UmbraLibraryBootstrap.open(new File("lib-sealed.jar"));
 *   Class&lt;?&gt; type = lib.loadClass("com.example.Library");
 * </pre>
 *
 * <p>This class only reads the manifest, instantiates the sealed loader and returns
 * it. It holds <strong>no key material</strong>: the index key is derived from the
 * native key root inside the loader, so "this class + the sealed ciphertext" is not
 * enough to decrypt anything offline.</p>
 *
 * <p><b>Security boundary (do not oversell).</b> The host explicitly hands control
 * to this method, and the host runs in the host's process: an attacker who controls
 * the host can hook the returned {@link ClassLoader}, instrument {@code loadClass}
 * or read the process memory of the host. That is inherent to library mode and is
 * independent of the strength of the sealed archive itself. Library mode protects
 * the archive at rest and on disk; it does not defend against a compromised host.</p>
 *
 * <p>Runtime template: single top-level class, JDK-only, no nested/anonymous
 * classes, no reference to any program class (classes are resolved by name at run
 * time). The build asserts that last property when the class is injected.</p>
 */
public final class UmbraLibraryBootstrap {

    private static final String ENTRY_ATTRIBUTE = "Main-Class";

    private static final int ROOT_BYTES = 32;

    private UmbraLibraryBootstrap() {
    }

    public static ClassLoader open(File jar, byte[] root) throws IOException {
        if (root == null || root.length != ROOT_BYTES) {
            throw new IOException("sealed library key root must be " + ROOT_BYTES + " bytes");
        }
        return open(jar, root, true);
    }

    public static ClassLoader open(File jar) throws IOException {
        return open(jar, null, false);
    }

    private static ClassLoader open(File jar, byte[] root, boolean withRoot) throws IOException {
        if (jar == null || !jar.isFile()) {
            throw new IOException("sealed library is missing");
        }
        String entry = loaderEntry(jar);
        if (entry == null || entry.isEmpty()) {
            throw new IOException("sealed library has no bootstrap entry");
        }
        try {
            URL location = jar.toURI().toURL();
            URLClassLoader host = new URLClassLoader(new URL[] { location },
                    UmbraLibraryBootstrap.class.getClassLoader());
            Class<?> loaderType = Class.forName(entry, true, host);
            if (withRoot) {

                java.lang.reflect.Method install =
                        loaderType.getMethod("installHostRoot", byte[].class);
                install.invoke(null, (Object) root.clone());
            }
            Object instance = loaderType.getDeclaredConstructor().newInstance();
            if (instance instanceof ClassLoader) {
                return (ClassLoader) instance;
            }
        } catch (IOException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw new IOException("sealed library could not be opened");
        }
        throw new IOException("sealed library loader is not a ClassLoader");
    }

    private static String loaderEntry(File jar) {
        try {
            JarFile file = new JarFile(jar);
            try {
                Manifest manifest = file.getManifest();
                if (manifest == null) {
                    return null;
                }
                return manifest.getMainAttributes().getValue(ENTRY_ATTRIBUTE);
            } finally {
                file.close();
            }
        } catch (Throwable unreadable) {
            return null;
        }
    }
}
