package io.umbra.core.api;

import java.util.Set;

/**
 * Optional integration point for a native / J2C protection backend.
 *
 * <p>The open-source pipeline does not ship a native compiler. Enterprise
 * deployments can provide an implementation that translates the selected
 * methods and injects the required loader classes. Bridges are responsible for
 * their own platform matrix, compiler toolchain and runtime verification.</p>
 */
public interface NativeBridge {

    /** True when the backend and its toolchain are available on this machine. */
    boolean isAvailable();

    /**
     * Translates the selected methods.
     *
     * @param context    current pass context
     * @param methodKeys method keys in {@code owner#name#desc} form
     * @throws Exception when translation or compilation fails
     */
    void transform(PassContext context, Set<String> methodKeys) throws Exception;
}
