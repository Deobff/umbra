package io.umbra.core.api;

/** Receives coarse progress updates from the engine. */
public interface ProgressListener {

    void onProgress(int percent, String message);

    default boolean isCancelled() {
        return false;
    }

    ProgressListener NONE = new ProgressListener() {
        @Override
        public void onProgress(int percent, String message) {

        }
    };
}
