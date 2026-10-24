package io.umbra.core.engine;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Thread-safe counter bag populated by passes and consumed by audit reports. */
public final class Stats {

    private final Map<String, Long> values = new LinkedHashMap<String, Long>();
    private final Map<String, String> texts = new LinkedHashMap<String, String>();

    public synchronized void add(String key, long delta) {
        Long current = values.get(key);
        values.put(key, Long.valueOf((current == null ? 0L : current.longValue()) + delta));
    }

    public void inc(String key) {
        add(key, 1L);
    }

    /** Stores a small textual result (loader name, detected mod id, ...). */
    public synchronized void text(String key, String value) {
        if (key != null && value != null) {
            texts.put(key, value);
        }
    }

    public synchronized String text(String key) {
        return texts.get(key);
    }

    public synchronized Map<String, String> textSnapshot() {
        return Collections.unmodifiableMap(new LinkedHashMap<String, String>(texts));
    }

    public synchronized Map<String, Long> snapshot() {
        return Collections.unmodifiableMap(new LinkedHashMap<String, Long>(values));
    }
}
