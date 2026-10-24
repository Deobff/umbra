package io.umbra.core.compat;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Layout statistics produced by {@code Jars.write}.
 *
 * <p>The engine adds {@link #counts()} with {@code Stats.add} and
 * {@link #texts()} with {@code Stats.text} after writing, so every run reports
 * the archive layout it actually produced.</p>
 */
public final class LayoutReport {

    private final JarLayout layout;
    private final Map<String, Long> counts;
    private final Map<String, String> texts;

    public LayoutReport(JarLayout layout, Map<String, Long> counts, Map<String, String> texts) {
        this.layout = layout == null ? JarLayout.flat() : layout;
        this.counts = Collections.unmodifiableMap(counts == null
                ? new LinkedHashMap<String, Long>() : new LinkedHashMap<String, Long>(counts));
        this.texts = Collections.unmodifiableMap(texts == null
                ? new LinkedHashMap<String, String>() : new LinkedHashMap<String, String>(texts));
    }

    public JarLayout layout() {
        return layout;
    }

    /** Numeric stats, already namespaced under {@code layout.}. */
    public Map<String, Long> counts() {
        return counts;
    }

    /** Textual stats such as {@code layout.kind}. */
    public Map<String, String> texts() {
        return texts;
    }

    @Override
    public String toString() {
        return "LayoutReport{" + layout.kindId() + ", counts=" + counts + '}';
    }
}
