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

    /**
     * Ensures a string decryptor class exists in the pool.
     *
     * @param pool program pool
     * @param seed deterministic seed
     * @return internal name of the decryptor class
     */
    String ensureStringDecryptor(ClassPool pool, long seed);

    /**
     * Ensures an invokedynamic bootstrap helper exists in the pool.
     *
     * @param pool program pool
     * @param seed deterministic seed
     * @return internal name of the bootstrap class
     */
    String ensureIndyBootstrap(ClassPool pool, long seed);

    /**
     * Ensures the bytecode interpreter used by virtualized methods exists.
     *
     * @param pool program pool
     * @param seed deterministic seed
     * @return internal name of the interpreter class
     */
    String ensureVirtualMachine(ClassPool pool, long seed);

    /**
     * Ensures the server-backed authorization gate class exists in the pool.
     *
     * <p>The generated gate exposes {@code public static void guard()}; the
     * {@code AuthGatePass} calls it at the start of entry points. The returned
     * class is a renamed copy of the runtime template with the configured server,
     * software, title, cache file, registration flag, timeout and entry points
     * substituted in.</p>
     *
     * @param pool    program pool
     * @param seed    deterministic seed
     * @param options authorization gate configuration
     * @return internal name of the gate class, or {@code null} when the runtime
     *         support does not provide one
     */
    default String ensureAuthGate(ClassPool pool, long seed, UmbraConfig.AuthGateOptions options) {
        return null;
    }

    /**
     * Embeds a watermark in the program.
     *
     * @param pool       program pool
     * @param watermark  watermark payload
     * @return description of where the mark was written, or {@code null}
     */
    String embedWatermark(ClassPool pool, String watermark);
}
