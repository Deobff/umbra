package io.umbra.core.api;

/** Receives coarse progress updates from the engine. */
public interface ProgressListener {

    /**
     * @param percent 0..100
     * @param message human-readable stage description
     */
    void onProgress(int percent, String message);

    /** Polled by the engine between passes. */
    default boolean isCancelled() {
        return false;
    }

    ProgressListener NONE = new ProgressListener() {
        @Override
        public void onProgress(int percent, String message) {
            // no-op
        }
    };
}
