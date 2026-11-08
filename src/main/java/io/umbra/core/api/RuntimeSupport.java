package io.umbra.core.api;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.model.ClassPool;

/**
 * Injects runtime helpers into the program being protected.
 *
 * <p>Implementations may add classes (for example a string decryptor), embed
 * watermarks, or register manifest attributes.</p>
 */
public interface RuntimeSupport {

    String ensureStringDecryptor(ClassPool pool, long seed);

    String ensureIndyBootstrap(ClassPool pool, long seed);

    String ensureVirtualMachine(ClassPool pool, long seed);

    default String ensureOtp(ClassPool pool, long seed) {
        return null;
    }

    default String ensureKeyRootMask(ClassPool pool, long seed) {
        return null;
    }

    default String ensureAuthGate(ClassPool pool, long seed, UmbraConfig.AuthGateOptions options) {
        return null;
    }

    String embedWatermark(ClassPool pool, String watermark);
}
