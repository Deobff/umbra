package io.umbra.core.runtime.crypto;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

/**
 * Invokedynamic bootstrap for encrypted string constants (engine-v2).
 *
 * <p>This is a runtime template: its bytecode is copied into the output JAR
 * under a randomized name together with the injected string decryptor
 * ({@link UmbraStringCipher}) and the shared crypto helper ({@link UmbraCrypto});
 * both references are remapped at injection time, so this class itself is
 * self-contained.</p>
 *
 * <p>The indy instruction has descriptor {@code ()Ljava/lang/String;} and its
 * bootstrap arguments are the packed Base64 payload, the name of the per-class
 * synthetic key field (or {@code ""} for per-site keys), the 64-bit site seed,
 * the call-site index and the per-site engine code. The bootstrap decrypts the
 * value once while the call site is being linked and returns a constant
 * {@code CallSite}, so later calls are a plain constant load.</p>
 *
 * <p>The decrypted value is interned (inside the decryptor), preserving string
 * identity semantics of the original literals.</p>
 */
public final class UmbraStringIndy {

    private UmbraStringIndy() {
    }

    /** String literal call site. */
    public static CallSite bootstrapString(MethodHandles.Lookup caller, String name, MethodType type,
                                           String packed, String classKeySpec, long siteSeed,
                                           int siteId, int engine) throws Throwable {
        String classKeyBase64 = null;
        if (classKeySpec != null && classKeySpec.length() > 0) {
            // The lookup class is the class that contains this indy instruction,
            // so it may read its own private synthetic key field.
            MethodHandle getter = caller.findStaticGetter(caller.lookupClass(), classKeySpec,
                    String.class);
            classKeyBase64 = (String) getter.invoke();
        }
        String value = UmbraStringCipher.decode(packed, classKeyBase64, siteSeed, siteId, engine);
        MethodHandle constant = MethodHandles.constant(String.class, value);
        return new ConstantCallSite(constant.asType(type));
    }
}
