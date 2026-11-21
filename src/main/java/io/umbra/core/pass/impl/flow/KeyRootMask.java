package io.umbra.core.pass.impl.flow;

import io.umbra.core.api.PassContext;
import io.umbra.core.compat.JarLayout;
import io.umbra.core.compat.LayoutRegistry;
import io.umbra.core.runtime.UmbraKeyRootMask;
import io.umbra.core.runtime.crypto.UmbraCrypto;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodInsnNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Build-side view of the native-key-root table mask (P1 / V4).
 *
 * <p>When the build ships the native guard, every masked constant written into a
 * runtime table is stored as {@code C ^ mask(slot)} and the patch that links two
 * entries carries the same mask. The mask is derived from the native key root,
 * so the class file contains only a literal ciphertext; recovering {@code C}
 * requires evaluating {@link UmbraKeyRootMask#mask(int)} at run time, i.e. the
 * key root inside the native library.</p>
 *
 * <h3>Ordering contract</h3>
 *
 * <p>The string-encryption pass ({@code order() == 70}) decides whether its v4
 * payloads bind to the native root by checking whether a root was <em>published</em>
 * ({@code PassContext.NATIVE_KEY_ROOT}). Nothing may publish before it, or the
 * string keys would bind to a root the runtime never installs (the runtime root
 * is only reachable through the native loader). The VM2 pass runs at 60, so it
 * creates the mask with {@code publish == false}: it uses the root from the
 * private cache without touching the secret map. The flow-layer passes (85..95)
 * create the mask with {@code publish == true}, which publishes the same bytes
 * before {@code NativeGuardPass} (114) compiles the bridge. Every user therefore
 * sees one identical root and the injected helper's
 * {@code deriveKey(1, 0)} matches the build-side mask.</p>
 *
 * <p>The root is derived deterministically from the build seed, so the same seed
 * still produces a byte-identical archive.</p>
 */
public final class KeyRootMask {

    private static final int ROOT_BYTES = 32;

    private static final String ROOT_LABEL = "umbra.flow.mask.v1";

    private static byte[] cachedRawRoot;
    private static long cachedSeed = Long.MIN_VALUE;

    private final String helper;
    private final byte[] root;

    private KeyRootMask(String helper, byte[] root) {
        this.helper = helper;
        this.root = root;
    }

    public static KeyRootMask create(PassContext context, boolean publish) {
        if (context == null || !context.config().optionBool(RuntimeTable.OPTION_ENABLED, true)) {
            return null;
        }
        if (context.config().optionBool("classEncryption.libraryMode", false)) {

            context.stats().text("flow.tableMode", "static");
            context.log().info("flow: library mode keeps the static table tier "
                    + "(the host key root is not visible to the runtime mask)");
            return null;
        }
        try {
            if (!nativeGuardActive(context)) {
                return null;
            }
            if (!publish && !publisherEnabled(context)) {

                return null;
            }
            byte[] raw = context.secret(PassContext.NATIVE_KEY_ROOT);
            if (raw == null) {
                raw = derivedRawRoot(context);
                if (publish) {
                    context.putSecret(PassContext.NATIVE_KEY_ROOT, raw);
                }
            }
            byte[] root = UmbraCrypto.nativeKeyRoot(raw, UmbraCrypto.ROOT_SLOT,
                    UmbraCrypto.ROOT_SUB);
            if (root == null || root.length != ROOT_BYTES) {
                return null;
            }
            String helper = context.runtime().ensureKeyRootMask(context.classes(),
                    context.config().seed());
            if (helper == null || context.classes().getClass(helper) == null) {

                context.log().debug("key-root mask: injected helper is missing; keeping the "
                        + "static table tier");
                return null;
            }
            return new KeyRootMask(helper, root);
        } catch (RuntimeException failure) {
            context.log().debug("key-root mask: unavailable (%s); keeping the static table tier",
                    failure.toString());
            return null;
        }
    }

    private static boolean publisherEnabled(PassContext context) {
        return context.config().flow().enabled()
                || context.config().exceptionObfuscation().enabled()
                || context.config().optionBool("mba.enabled", false);
    }

    private static boolean nativeGuardActive(PassContext context) {
        boolean requested = context.config().optionInt("antiDebug.level", 0) > 0
                || context.config().antiDebug()
                || context.config().optionBool("antiDebug.enabled", false);
        if (!requested || !context.config().optionBool("antiDebug.nativeGuard", true)) {
            return false;
        }
        if (isEclipseRunnableJar(context)) {
            // The Rsrc loader boots the nested libraries first and the guard is routed
            // through Rsrc-Main-Class, which never installs the key root the mask needs;
            // a masked table would throw at class-init time. Static tier instead.
            context.stats().text("flow.tableMode", "static");
            if (context.stats().text("flow.tableTier.note") == null) {
                context.stats().text("flow.tableTier.note", "eclipse-runnable-jar=static");
                context.log().info("flow: Eclipse runnable jar keeps the static table tier "
                        + "(the Rsrc loader cannot install the native key root)");
            }
            return false;
        }
        JarLayout layout = LayoutRegistry.layout(context.classes());
        return (layout.isFlat() && !layout.moduleInfo())
                || context.config().optionBool("layout.forceEntryProtection", false);
    }

    /** True when the manifest declares an Eclipse runnable jar ({@code Rsrc-Main-Class}). */
    private static boolean isEclipseRunnableJar(PassContext context) {
        try {
            io.umbra.core.model.ClassPool.Resource manifest =
                    context.classes().resource("META-INF/MANIFEST.MF");
            if (manifest == null) {
                return false;
            }
            return io.umbra.core.util.Jars.parseManifest(manifest.bytes())
                    .get("Rsrc-Main-Class") != null;
        } catch (RuntimeException unreadable) {
            return false;
        }
    }

    private static synchronized byte[] derivedRawRoot(PassContext context) {
        long seed = context.config().seed();
        if (cachedRawRoot != null && cachedSeed == seed) {
            return cachedRawRoot;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] label = ROOT_LABEL.getBytes(StandardCharsets.UTF_8);
            digest.update(label);
            byte[] material = new byte[label.length + 8];
            System.arraycopy(label, 0, material, 0, label.length);
            for (int i = 0; i < 8; i++) {
                material[label.length + i] = (byte) (seed >>> (i * 8));
            }
            byte[] root = digest.digest(material);
            cachedRawRoot = root;
            cachedSeed = seed;
            return root;
        } catch (java.security.NoSuchAlgorithmException missing) {
            throw new IllegalStateException("SHA-256 unavailable", missing);
        }
    }

    public int value(int slot) {
        return UmbraKeyRootMask.mix(root, slot);
    }

    public void emit(InsnList out, int slot) {
        AsmUtil.pushInt(out, slot);
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, helper, "mask", "(I)I", false));
    }

    public String helper() {
        return helper;
    }
}
