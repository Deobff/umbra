package io.umbra.core.api;

/**
 * A single transformation stage in the Umbra pipeline.
 *
 * <p>Passes are stateless with respect to a run: all mutable state lives in
 * {@link PassContext}. The engine sorts passes by {@link #order()} and invokes
 * {@link #run(PassContext)} once per run.</p>
 */
public interface Pass {

    String name();

    int order();

    boolean enabled(PassContext context);

    void run(PassContext context) throws Exception;
}
