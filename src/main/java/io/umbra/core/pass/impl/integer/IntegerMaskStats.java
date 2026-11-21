package io.umbra.core.pass.impl.integer;

import io.umbra.core.api.PassContext;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Running counters for the polymorphic int mask layer.
 *
 * <p>One instance lives inside each {@link IntMaskCodec}; the pass reports it
 * once with {@link #report(PassContext)}. The counters mirror CONTRACT §6: the
 * number of encoded sites, the total number of mask stages materialised for
 * them, and a mixed text line of the families that were emitted.</p>
 */
public final class IntegerMaskStats {

    /** Sites that received a mask chain. */
    public static final String SITES = "integer.masks.sites";
    /** Total mask stages across all sites. */
    public static final String TOTAL = "integer.masks.total";
    /** Family mix, e.g. {@code "xor=140,add=122,sub=118"}. */
    public static final String FAMILIES = "integer.masks.families";
    /** Chains that had to be rebuilt because a non-invertible family was drawn. */
    public static final String SWAPPED = "integer.masks.swapped";

    private long sites;
    private long total;
    private long swapped;
    private final Map<String, Long> families = new LinkedHashMap<String, Long>();

    /** Records one site chain: one site, its stage count and its families. */
    public synchronized void record(IntMaskStack stack) {
        if (stack == null) {
            return;
        }
        sites++;
        total += stack.size();
        for (int i = 0; i < stack.size(); i++) {
            bump(stack.masks().get(i).family());
        }
    }

    private void bump(String family) {
        Long current = families.get(family);
        families.put(family, Long.valueOf(current == null ? 1L : current.longValue() + 1L));
    }

    /** One chain was drawn non-invertible and rebuilt from reversible families. */
    public synchronized void swapped() {
        swapped++;
    }

    public synchronized long sites() {
        return sites;
    }

    public synchronized long total() {
        return total;
    }

    public synchronized long swappedCount() {
        return swapped;
    }

    /** The family mix as {@code "family=count"} pairs, in first-seen order. */
    public synchronized String familiesText() {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, Long> entry : families.entrySet()) {
            if (out.length() > 0) {
                out.append(',');
            }
            out.append(entry.getKey()).append('=').append(entry.getValue().longValue());
        }
        return out.toString();
    }

    /** Folds another accumulator into this one. */
    public void merge(IntegerMaskStats other) {
        if (other == null) {
            return;
        }
        synchronized (other) {
            synchronized (this) {
                this.sites += other.sites;
                this.total += other.total;
                this.swapped += other.swapped;
                for (Map.Entry<String, Long> entry : other.families.entrySet()) {
                    Long current = this.families.get(entry.getKey());
                    this.families.put(entry.getKey(), Long.valueOf(
                            (current == null ? 0L : current.longValue()) + entry.getValue().longValue()));
                }
            }
        }
    }

    /** Writes the counters into the run statistics. */
    public void report(PassContext context) {
        if (context == null) {
            return;
        }
        long siteCount;
        long stageCount;
        long swapCount;
        String mix;
        synchronized (this) {
            siteCount = sites;
            stageCount = total;
            swapCount = swapped;
            mix = familiesText();
        }
        context.stats().add(SITES, siteCount);
        context.stats().add(TOTAL, stageCount);
        context.stats().add(SWAPPED, swapCount);
        if (!mix.isEmpty()) {
            context.stats().text(FAMILIES, mix);
        }
    }

    @Override
    public synchronized String toString() {
        return "sites=" + sites + " masks=" + total + " swapped=" + swapped
                + " families=[" + familiesText() + "]";
    }
}
