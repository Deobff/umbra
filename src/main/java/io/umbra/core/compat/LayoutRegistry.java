package io.umbra.core.compat;

import io.umbra.core.model.ClassPool;

import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * Associates the detected layout with the {@link ClassPool} being processed.
 *
 * <p>{@code Jars.read} attaches the context before any pass runs, so owner code
 * (passes, post-processors, CLI tooling) can query the layout without receiving
 * new engine state:</p>
 *
 * <pre>
 * JarLayout layout = LayoutRegistry.layout(ctx.classes());
 * if (!layout.isFlat()) {
 *     // nested layout: do not install a root-level launcher / archive post-processor
 * }
 * </pre>
 *
 * <p>The map is keyed by pool identity and holds the pool weakly, so a finished
 * run leaves no global state behind.</p>
 */
public final class LayoutRegistry {

    private static final Map<ClassPool, LayoutContext> CONTEXTS =
            Collections.synchronizedMap(new WeakHashMap<ClassPool, LayoutContext>());

    private LayoutRegistry() {
    }

    /** Attaches a context (called by {@code Jars.read}). */
    public static void attach(ClassPool pool, LayoutContext context) {
        if (pool != null && context != null) {
            CONTEXTS.put(pool, context);
        }
    }

    /**
     * Attaches a layout detected elsewhere, using default options.
     *
     * <p>Useful for tooling that assembles a pool without going through
     * {@code Jars.read}; {@code Jars.write} then writes according to this
     * layout.</p>
     */
    public static void put(ClassPool pool, JarLayout layout) {
        if (pool != null && layout != null) {
            CONTEXTS.put(pool, new LayoutContext(layout, LayoutOptions.defaults()));
        }
    }

    /** Returns the context attached to the pool, or {@code null}. */
    public static LayoutContext getContext(ClassPool pool) {
        return pool == null ? null : CONTEXTS.get(pool);
    }

    /** Returns the detected layout attached to the pool, or {@code null}. */
    public static JarLayout get(ClassPool pool) {
        LayoutContext context = getContext(pool);
        return context == null ? null : context.layout();
    }

    /**
     * Returns the layout attached to the pool, or a flat layout when nothing was
     * attached. Never returns {@code null}, so callers do not need null checks.
     */
    public static JarLayout layout(ClassPool pool) {
        JarLayout layout = get(pool);
        return layout == null ? JarLayout.flat() : layout;
    }

    /** Removes the association (best-effort cleanup for long-lived pools). */
    public static void detach(ClassPool pool) {
        if (pool != null) {
            CONTEXTS.remove(pool);
        }
    }
}
