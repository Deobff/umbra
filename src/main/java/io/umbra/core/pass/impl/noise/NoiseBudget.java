package io.umbra.core.pass.impl.noise;

/**
 * Byte budget shared by one decompiler-noise run.
 *
 * <p>Noise is bounded twice: a per-class limit keeps a single class from
 * ballooning and a global limit keeps the whole protected archive within a
 * predictable growth. Both are counted in attribute payload bytes (plus a small
 * per-attribute header estimate), which is what dominates the file size
 * increase. Once the global budget is exhausted the remaining classes are left
 * untouched, deterministically, so output stays reproducible for a seed.</p>
 */
public final class NoiseBudget {

    private final int perClassLimit;
    private final int globalLimit;
    private int used;

    public NoiseBudget(int perClassLimit, int globalLimit) {
        this.perClassLimit = Math.max(0, perClassLimit);
        this.globalLimit = Math.max(0, globalLimit);
    }

    public int perClassLimit() {
        return perClassLimit;
    }

    public int globalLimit() {
        return globalLimit;
    }

    public int remaining() {
        return Math.max(0, globalLimit - used);
    }

    public int used() {
        return used;
    }

    /**
     * Reserves {@code bytes}; returns false when either the global limit would
     * be exceeded.
     */
    public boolean charge(int bytes) {
        if (bytes < 0) {
            return false;
        }
        if (used + bytes > globalLimit) {
            return false;
        }
        used += bytes;
        return true;
    }
}
