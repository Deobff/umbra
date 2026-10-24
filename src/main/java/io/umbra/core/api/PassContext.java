package io.umbra.core.api;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.rules.RuleSet;
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

    /** Post-write archive processors registered by passes (mutable, order of registration). */
    public List<OutputPostProcessor> postProcessors() { return postProcessors; }
}
