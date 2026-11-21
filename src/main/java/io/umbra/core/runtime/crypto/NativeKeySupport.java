package io.umbra.core.runtime.crypto;

import io.umbra.core.api.PassContext;
import io.umbra.core.model.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Build-time bridge to the per-build native key root (analysis finding P0).
 *
 * <p>The root is the single secret every protection layer derives from. It is
 * compiled into the native library only; the Java side never stores it in a
 * constant, so recovering it means reversing the native image instead of reading
 * a loader method (weakness W1).</p>
 *
 * <p>Passes exchange the root through
 * {@link PassContext#putSecret}/{@link PassContext#secret} under
 * {@link PassContext#NATIVE_KEY_ROOT}: the native pass publishes it when it
 * embeds it into the library, every later pass consumes it. This class adds the
 * two lookups the crypto passes need on top of that slot:</p>
 *
 * <ul>
 *   <li>{@link #root(PassContext)} - the published root, or {@code null};</li>
 *   <li>{@link #ensureRoot(PassContext)} - publish-once helper for a producer;</li>
 *   <li>{@link #nativeLoader(ClassPool)} - internal name of the injected native
 *       loader (the class declaring {@code native int register(int, Class)}),
 *       or {@code null} when the build has no native library;</li>
 *   <li>{@link #nativeLibrary(ClassPool, String)} - the JAR entry of the native
 *       library that loader extracts, or {@code null}.</li>
 * </ul>
 *
 * <p>Every lookup is defensive: an absent library, a renamed loader or a failed
 * compilation simply returns {@code null} and the caller falls back to its
 * embedded key. Nothing here throws.</p>
 */
public final class NativeKeySupport {

    public static final String DETERMINISTIC_ROOT_LABEL = "umbra.flow.mask.v1";

    public static final int ROOT_BYTES = 32;

    private static final String REGISTER_DESC = "(ILjava/lang/Class;)I";
    private static final String REGISTER_NAME = "register";

    private static final String RESOURCE_FIELD = "RESOURCE";

    private static final String KEY_ROOT_NAME = "keyRoot";

    private static final String KEY_ROOT_DESC = "(II[B)I";

    public static final String KEY_ROOT2_NAME = "keyRoot2";

    public static final String KEY_ROOT2_DESC = "(II[B[B)I";

    public static final String GATE_SECRET_NAME = "native.gateSecret";

    private static final String GATE_CHALLENGE_NAME = "gateChallenge";
    private static final String GATE_CHALLENGE_DESC = "([J)I";
    private static final String GATE_ATTEST_NAME = "gateAttest";
    private static final String GATE_ATTEST_DESC = "(J[B)I";

    private static final String GUARD_ATTEST_NAME = "attest";
    private static final String GUARD_ATTEST_DESC = "(J)[B";

    private static final String GATE_TICK_NAME = "gateTick";
    private static final String GATE_TICK_DESC = "(I[B)I";

    private static final String NATIVE_CHECK_NAME = "nativeCheck";
    private static final String NATIVE_CHECK_DESC = "()I";

    private NativeKeySupport() {
    }

    public static byte[] root(PassContext context) {
        if (context == null) {
            return null;
        }
        try {
            byte[] value = context.secret(PassContext.NATIVE_KEY_ROOT);
            if (value == null || value.length != ROOT_BYTES) {
                return null;
            }

            return UmbraCrypto.nativeKeyRoot(value, UmbraCrypto.ROOT_SLOT, UmbraCrypto.ROOT_SUB);
        } catch (RuntimeException unavailable) {
            return null;
        }
    }

    public static byte[] ensureBuildRoot(PassContext context) {
        if (context == null) {
            return null;
        }
        byte[] existing = context.secret(PassContext.NATIVE_KEY_ROOT);
        if (existing != null && existing.length == ROOT_BYTES) {
            return existing;
        }
        // One implementation only: BuildRoot.derive is the same
        // SHA-256(label || LE64(seed)) with the same label, and the pass side
        // (PassContext.keyRoot) already derives from it. Keeping a second copy
        // here is exactly the split that DeterminismTest pins together.
        byte[] root = io.umbra.core.util.BuildRoot.derive(context.config().seed(),
                DETERMINISTIC_ROOT_LABEL);
        context.putSecret(PassContext.NATIVE_KEY_ROOT, root);
        return root;
    }

    public static byte[] keyRoot(PassContext context) {
        if (context == null) {
            return null;
        }
        try {
            byte[] value = context.keyRoot();
            if (value == null || value.length != ROOT_BYTES) {
                return null;
            }

            return UmbraCrypto.nativeKeyRoot(value, UmbraCrypto.ROOT_SLOT, UmbraCrypto.ROOT_SUB);
        } catch (RuntimeException unavailable) {
            return null;
        }
    }

    public static byte[] rawRoot(PassContext context) {
        if (context == null) {
            return null;
        }
        try {
            byte[] value = context.keyRoot();
            return value == null || value.length != ROOT_BYTES ? null : value;
        } catch (RuntimeException unavailable) {
            return null;
        }
    }

    public static byte[] ensureRoot(PassContext context) {
        return keyRoot(context);
    }

    public static String nativeLoader(ClassPool pool) {
        if (pool == null) {
            return null;
        }
        for (ClassNode node : pool.classes().values()) {
            if (node == null || node.methods == null) {
                continue;
            }
            if (!pool.isGenerated(node.name)) {
                continue;
            }
            for (MethodNode method : node.methods) {
                if ((method.access & Opcodes.ACC_NATIVE) != 0
                        && REGISTER_NAME.equals(method.name)
                        && REGISTER_DESC.equals(method.desc)) {
                    return node.name;
                }
            }
        }
        return null;
    }

    public static byte[] gateSecret(PassContext context) {
        if (context == null) {
            return null;
        }
        try {
            byte[] value = context.secret(GATE_SECRET_NAME);
            return value == null || value.length != ROOT_BYTES ? null : value;
        } catch (RuntimeException unavailable) {
            return null;
        }
    }

    public static boolean declaresGate(ClassNode loader) {
        return declares(loader, GATE_CHALLENGE_NAME, GATE_CHALLENGE_DESC)
                && declares(loader, GATE_ATTEST_NAME, GATE_ATTEST_DESC);
    }

    public static boolean declaresGateTick(ClassNode loader) {
        return declares(loader, GATE_TICK_NAME, GATE_TICK_DESC);
    }

    public static boolean declaresAttest(ClassNode guard) {
        return declares(guard, GUARD_ATTEST_NAME, GUARD_ATTEST_DESC);
    }

    public static String nativeGuard(ClassPool pool) {
        if (pool == null) {
            return null;
        }
        for (ClassNode node : pool.classes().values()) {
            if (node == null || node.methods == null || !pool.isGenerated(node.name)) {
                continue;
            }
            if (declares(node, NATIVE_CHECK_NAME, NATIVE_CHECK_DESC)) {
                return node.name;
            }
        }
        return null;
    }

    public static boolean declaresNativeCheck(ClassNode guard) {
        return declares(guard, NATIVE_CHECK_NAME, NATIVE_CHECK_DESC);
    }

    private static boolean declares(ClassNode node, String name, String desc) {
        if (node == null || node.methods == null) {
            return false;
        }
        for (MethodNode method : node.methods) {
            if (name.equals(method.name) && desc.equals(method.desc)) {
                return true;
            }
        }
        return false;
    }

    public static String keyRootLoader(ClassPool pool) {
        String fallback = null;
        if (pool == null) {
            return null;
        }
        for (ClassNode node : pool.classes().values()) {
            if (node == null || node.methods == null || !pool.isGenerated(node.name)) {
                continue;
            }
            boolean registers = false;
            for (MethodNode method : node.methods) {
                if ((method.access & Opcodes.ACC_NATIVE) == 0) {
                    continue;
                }
                if (REGISTER_NAME.equals(method.name) && REGISTER_DESC.equals(method.desc)) {
                    registers = true;
                }
            }
            if (!registers) {
                continue;
            }
            if (declaresKeyRoot(node)) {
                return node.name;
            }
            if (fallback == null) {
                fallback = node.name;
            }
        }
        return fallback;
    }

    public static String nativeLibrary(ClassPool pool, String loaderName) {
        if (pool == null || loaderName == null) {
            return null;
        }
        ClassNode node = pool.getClass(loaderName);
        if (node == null || node.fields == null) {
            return null;
        }
        for (FieldNode field : node.fields) {
            if (!RESOURCE_FIELD.equals(field.name) || !(field.value instanceof String)) {
                continue;
            }
            String entry = (String) field.value;
            if (entry.isEmpty() || entry.charAt(0) == '@') {
                return null;
            }
            return pool.resource(entry) == null ? null : entry;
        }
        return null;
    }

    public static boolean declaresKeyRoot(ClassNode loader) {
        if (loader == null || loader.methods == null) {
            return false;
        }
        for (MethodNode method : loader.methods) {
            if (KEY_ROOT_NAME.equals(method.name) && KEY_ROOT_DESC.equals(method.desc)) {
                return true;
            }
        }
        return false;
    }

    public static boolean declaresKeyRoot2(ClassNode loader) {
        if (loader == null || loader.methods == null) {
            return false;
        }
        for (MethodNode method : loader.methods) {
            if (KEY_ROOT2_NAME.equals(method.name) && KEY_ROOT2_DESC.equals(method.desc)) {
                return true;
            }
        }
        return false;
    }

    public static boolean declaresVerifyLoaderSha(ClassNode bridge) {
        if (bridge == null || bridge.methods == null) {
            return false;
        }
        for (MethodNode method : bridge.methods) {
            if ("verifyLoader".equals(method.name)
                    && "(Ljava/lang/String;Ljava/lang/String;)I".equals(method.desc)) {
                return true;
            }
        }
        return false;
    }

    public static String nativeLoaderBinaryName(ClassPool pool) {
        String internal = nativeLoader(pool);
        return internal == null ? null : internal.replace('/', '.');
    }
}
