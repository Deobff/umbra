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

    boolean isAvailable();

    void transform(PassContext context, Set<String> methodKeys) throws Exception;
}
