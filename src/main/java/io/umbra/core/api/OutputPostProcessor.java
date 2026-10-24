package io.umbra.core.api;

import java.nio.file.Path;

/**
 * A transformation that can only run after the output JAR has been written.
 *
 * <p>True archive-level protections (class-file encryption with a bootstrap
 * loader, whole-archive integrity manifests, resource encryption) need the
 * final byte image and the final entry list. Passes register an
 * implementation on {@link PassContext#postProcessors()} and the engine invokes
 * it right after the writer produced the archive. Implementations must rewrite
 * the archive atomically (write a sibling file, then move it over the target).</p>
 */
public interface OutputPostProcessor {

    /** Stable identifier used in logs. */
    String name();

    /**
     * Rewrites {@code output} in place.
     *
     * @param output  the archive produced by the writer
     * @param context the pass context of the running job
     * @throws Exception when the archive cannot be processed
     */
    void process(Path output, PassContext context) throws Exception;
}
