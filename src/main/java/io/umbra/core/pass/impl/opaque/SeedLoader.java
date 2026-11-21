package io.umbra.core.pass.impl.opaque;

import org.objectweb.asm.tree.InsnList;

/**
 * The value shape of the rolling state local.
 *
 * <p>A seed loader decides <em>how</em> the rolling local is rewritten, never
 * <em>what</em> it becomes: every implementation has to push an expression that
 * evaluates to {@link SeedSite#outcome}. That is the whole contract the
 * predicates rely on, so a loader can be swapped without touching the guard or
 * the edge setter.</p>
 */
public interface SeedLoader {

    /** Option value this loader answers to ({@code static}, {@code enhanced}, ...). */
    String name();

    /** True when the shape needs a per-class helper method installed up front. */
    boolean needsHelper();

    /** Installs the helper body (called once per class, before any method runs). */
    void install(ClassState state);

    /** Pushes the expression that produces {@code site.outcome}. */
    void pushValue(InsnList out, ClassState state, int local, SeedSite site);

    /** Writes the fields this loader needs; called only when the class is kept. */
    void materialize(ClassState state);
}
