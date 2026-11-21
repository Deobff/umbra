package io.umbra.core.api;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.rules.RuleSet;
import io.umbra.core.util.BuildRoot;
import io.umbra.core.util.Log;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/** Shared, mutable state for one Umbra run. */
public final class PassContext {

    private final UmbraConfig config;
    private final ClassPool classes;
    private final Hierarchy hierarchy;
    private final RuleSet rules;
    private final RuntimeSupport runtime;
    private final MappingSet mappings;
    private final Stats stats;
    private final Log log;
    private final Random random;
    private final ProgressListener progress;
    private final List<OutputPostProcessor> postProcessors = new ArrayList<OutputPostProcessor>();

    public PassContext(UmbraConfig config, ClassPool classes, Hierarchy hierarchy, RuleSet rules,
                       RuntimeSupport runtime, MappingSet mappings, Stats stats, Log log, Random random,
                       ProgressListener progress) {
        this.config = config;
        this.classes = classes;
        this.hierarchy = hierarchy;
        this.rules = rules;
        this.runtime = runtime;
        this.mappings = mappings;
        this.stats = stats;
        this.log = log;
        this.random = random;
        this.progress = progress;
    }

    public UmbraConfig config() { return config; }
    public ClassPool classes() { return classes; }
    public Hierarchy hierarchy() { return hierarchy; }
    public RuleSet rules() { return rules; }
    public RuntimeSupport runtime() { return runtime; }
    public MappingSet mappings() { return mappings; }
    public Stats stats() { return stats; }
    public Log log() { return log; }
    public Random random() { return random; }
    public ProgressListener progress() { return progress; }

    public List<OutputPostProcessor> postProcessors() { return postProcessors; }

    private final java.util.Map<String, byte[]> secrets =
            new java.util.LinkedHashMap<String, byte[]>();

    public static final String NATIVE_KEY_ROOT = "native.keyRoot";

    public void putSecret(String name, byte[] value) {
        if (name != null && value != null) {
            secrets.put(name, value.clone());
        }
    }

    public byte[] secret(String name) {
        byte[] value = secrets.get(name);
        return value == null ? null : value.clone();
    }

    public boolean hasSecret(String name) {
        return secrets.containsKey(name);
    }

    /**
     * The per-build root every protection layer derives from.
     *
     * <p>Derived from {@code config.seed()} through {@link BuildRoot}, so a run is
     * reproducible for a given seed (see ARCHITECTURE.md). It used to be drawn from
     * an <em>unseeded</em> {@code SecureRandom}: two runs with the same seed then
     * agreed only on the generated entry names, every payload byte differed, and
     * the archives landed a few bytes apart, which made {@code --seed} promise the
     * opposite of what it delivered.</p>
     *
     * <p>Reproducibility is safe because the root reaches the archive either way -
     * the native library embeds derivations of it and the seed-bound fallback keeps
     * its half in the loader - so keep the deployment seed private: two archives
     * built from the same seed carry the same root.</p>
     */
    public byte[] keyRoot() {
        byte[] existing = secret(NATIVE_KEY_ROOT);
        if (existing != null) {
            return existing;
        }
        byte[] root = BuildRoot.derive(config.seed());
        putSecret(NATIVE_KEY_ROOT, root);
        byte[] copy = root.clone();
        java.util.Arrays.fill(root, (byte) 0);
        return copy;
    }
}
