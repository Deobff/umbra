package io.umbra.core.api;

/**
 * A single transformation stage in the Umbra pipeline.
 *
 * <p>Passes are stateless with respect to a run: all mutable state lives in
 * {@link PassContext}. The engine sorts passes by {@link #order()} and invokes
 * {@link #run(PassContext)} once per run.</p>
 */
public interface Pass {

    /** Stable identifier used in logs and configuration. */
    String name();

    /** Lower values run first. */
    int order();

    /** Whether the pass should run for the current configuration. */
    boolean enabled(PassContext context);

    /** Executes the pass. */
    void run(PassContext context) throws Exception;
}
