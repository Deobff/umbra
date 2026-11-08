package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.runtime.crypto.NativeKeySupport;

/**
 * Publishes the per-build key root <strong>before any consumer runs</strong>.
 *
 * <p>The root has to exist before the first layer binds a payload to it. When it
 * was created lazily, the layers disagreed: VM2 (order 60) compiled its payloads
 * against "no root" while the string layer (order 70) and everything after it
 * bound to a root, and at run time {@code UmbraKeyRootMask} supplied yet another
 * value - so VM2 rejected its own payloads ("Umbra VM2 payload rejected
 * (header)").</p>
 *
 * <p>This pass runs at order 5, publishes the <em>deterministic</em> root
 * ({@code SHA-256(label || LE64(seed))}, see
 * {@link NativeKeySupport#ensureBuildRoot(PassContext)}) once, and every later
 * layer - VM2, strings, flow tables, the native guard, the class layer - reads the
 * same secret. The compiled bridge embeds derivations of that root, so the runtime
 * mask resolves exactly the same bytes.</p>
 */
public final class KeyRootPublishPass implements Pass {

    @Override
    public String name() {
        return "key-root-publish";
    }

    @Override
    public int order() {
        return 5;
    }

    @Override
    public boolean enabled(PassContext context) {

        boolean bridgeExpected = context.config().optionBool("classEncryption.nativeKey", true)
                && context.config().optionBool("antiDebug.nativeGuard", true)
                && context.config().optionInt("antiDebug.level", 0) > 0;
        if (!bridgeExpected) {
            return false;
        }
        return context.config().optionBool("classEncryption.enabled", false)
                || context.config().optionBool("integrity.enabled", false)
                || context.config().stringEncryption().enabled();
    }

    @Override
    public void run(PassContext context) {
        byte[] root = NativeKeySupport.ensureBuildRoot(context);
        if (root == null) {
            context.stats().text("keyRoot.published", "none");
            return;
        }
        context.stats().text("keyRoot.published", "early");
        context.stats().add("keyRoot.bytes", root.length);
        context.log().debug("key-root-publish: deterministic build root published at order 5");
    }
}
