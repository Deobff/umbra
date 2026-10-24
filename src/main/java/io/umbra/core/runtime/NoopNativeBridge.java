package io.umbra.core.runtime;

import io.umbra.core.api.NativeBridge;
import io.umbra.core.api.PassContext;

import java.util.Set;

/**
 * Default {@link NativeBridge}: reports that no native toolchain is installed.
 *
 * <p>Enterprise integrations can replace this class at the composition root
 * without changing the core pipeline.</p>
 */
public final class NoopNativeBridge implements NativeBridge {

    @Override
    public boolean isAvailable() {
        return false;
    }

    @Override
    public void transform(PassContext context, Set<String> methodKeys) {
        throw new UnsupportedOperationException(
                "No native bridge is configured. Provide an enterprise NativeBridge implementation "
                        + "and a platform compiler toolchain.");
    }
}
