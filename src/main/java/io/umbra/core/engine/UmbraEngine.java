package io.umbra.core.engine;


import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.api.OutputPostProcessor;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.api.RuntimeSupport;
import io.umbra.core.compat.JarLayout;
import io.umbra.core.compat.LayoutReport;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.enterprise.AuditReport;
import io.umbra.core.enterprise.LicenseException;
import io.umbra.core.enterprise.LicenseInfo;
import io.umbra.core.enterprise.LicenseOnlineValidator;
import io.umbra.core.enterprise.LicenseValidator;
import io.umbra.core.enterprise.RiskReport;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.minecraft.MinecraftAdapter;
import io.umbra.core.minecraft.MinecraftProfile;
import io.umbra.core.pass.impl.AntiLlmPass;
import io.umbra.core.pass.impl.AuthGatePass;
import io.umbra.core.pass.impl.ClassEncryptionPass;
import io.umbra.core.pass.impl.ControlFlowFlatteningPass;
import io.umbra.core.pass.impl.AntiDebugPass;
import io.umbra.core.pass.impl.DecompilerNoisePass;
import io.umbra.core.pass.impl.DebugInfoPass;
import io.umbra.core.pass.impl.ExceptionObfuscationPass;
import io.umbra.core.pass.impl.FieldInitializationPass;
import io.umbra.core.pass.impl.FlowObfuscationPass;
import io.umbra.core.pass.impl.IntegrityPass;
import io.umbra.core.pass.impl.IntegerEncryptionPass;
import io.umbra.core.pass.impl.InvokeWrapperPass;
import io.umbra.core.pass.impl.JunkMemberPass;
import io.umbra.core.pass.impl.MbaPass;
import io.umbra.core.pass.impl.MemberShufflePass;
import io.umbra.core.pass.impl.MemberTrimPass;
import io.umbra.core.pass.impl.NativeCodePass;
import io.umbra.core.pass.impl.NativeGuardPass;
import io.umbra.core.pass.impl.NocturnePass;
import io.umbra.core.pass.impl.ParameterObfuscationPass;
import io.umbra.core.pass.impl.ReferenceObfuscationPass;
import io.umbra.core.pass.impl.ReflectionAnalysisPass;
import io.umbra.core.pass.impl.ReflectionGatePass;
import io.umbra.core.pass.impl.RenamePass;
import io.umbra.core.pass.impl.ResourcePathObfuscationPass;
import io.umbra.core.pass.impl.ResourceRewritePass;
import io.umbra.core.pass.impl.StringEncryptionPass;
import io.umbra.core.pass.impl.TypeConfusionPass;
import io.umbra.core.pass.impl.VirtualizationPass;
import io.umbra.core.pass.impl.WatermarkPass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.rules.RuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.DomainTags;
import io.umbra.core.util.Jars;
import io.umbra.core.util.Log;
import org.objectweb.asm.tree.ClassNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import io.umbra.core.util.RuntimeNames;

/** Orchestrates loading, transforming and writing a program. */
public final class UmbraEngine {

    private final Log log;

    public UmbraEngine(Log log) {
        this.log = log;
    }

    /**
     * Runs the complete pipeline.
     *
     * @param config   validated configuration
     * @param progress progress callback, never {@code null}
     * @return run statistics
     * @throws Exception when loading, transforming or writing fails
     */
    public EngineResult run(UmbraConfig config, ProgressListener progress) throws Exception {
        long start = System.currentTimeMillis();
        ProgressListener listener = progress == null ? ProgressListener.NONE : progress;

        listener.onProgress(2, "Loading input " + config.input());
        ClassPool pool = new ClassPool();
        JarLayout layout = Jars.read(config.input(), pool, log, config.options());
        log.info("Loaded %d classes and %d resources from %s (%s layout)",
                pool.classes().size(), pool.resources().size(), config.input(),
                layout == null ? "flat" : layout.describe());

        listener.onProgress(8, "Building hierarchy");
        // The generated runtime helpers must not carry the vendor name; the
        // package comes from runtime.package (default: derived from the seed).
        RuntimeNames.configure(config, pool);
        if (!RuntimeNames.DEFAULT.equals(RuntimeNames.base())) {
            log.info("runtime helpers live in %s (runtime.package=pinned or seed-derived)",
                    RuntimeNames.base());
        }
        Hierarchy hierarchy = new Hierarchy();
        for (ClassNode node : pool.classes().values()) {
            hierarchy.addInput(node);
        }
        for (Path library : config.libraries()) {
            loadLibrary(library, hierarchy);
        }

        listener.onProgress(9, "Inspecting mod container");
        MinecraftProfile minecraft = config.optionBool("minecraft.enabled", true)
                ? MinecraftAdapter.detect(pool, config, log) : MinecraftProfile.NONE;
        if (minecraft.detected()) {
            config = minecraft.adjust(config);
            log.info("minecraft: detected %s (%d keep rules, %d body-skip classes, %d targets)",
                    minecraft.loader(), minecraft.keepRules().size(),
                    minecraft.bodySkipGlobs().size(), minecraft.targetCount());
            for (String note : minecraft.notes()) {
                log.info("minecraft: %s", note);
            }
        } else {
            log.debug("minecraft: no mod container metadata detected");
        }

        // Whole-archive class encryption installs a root-level bootstrap loader
        // and moves every class into encrypted payloads. On nested layouts
        // (Spring Boot fat JAR/WAR) and preserved multi-release archives that
        // would destroy the container or the versioned entries, so it is
        // disabled explicitly instead of producing a broken archive.
        boolean preservedMultiRelease = layout.multiRelease()
                && !"flatten".equalsIgnoreCase(config.option("layout.multiRelease", "preserve"));
        boolean classEncryptionBlocked = false;
        if (config.optionBool("classEncryption.enabled", false)
                && !config.optionBool("layout.forceEntryProtection", false)
                && (!layout.isFlat() || preservedMultiRelease || layout.moduleInfo())) {
            config = config.toBuilder()
                    .option("classEncryption.enabled", "false")
                    .option("layout.classEncryptionSkipped", "true")
                    .build();
            classEncryptionBlocked = true;
            log.warn("layout: class encryption is a flat-JAR archive protection and cannot run on %s layout%s; "
                            + "it has been disabled for this run (set layout.forceEntryProtection=true to override)",
                    layout.kindId(), (preservedMultiRelease ? " with preserved multi-release entries"
                            : (layout.moduleInfo() ? " with module-info" : "")));
        }

        // Nocturne can either be the only body engine (default) or run as the
        // final body wrapper after the classic passes. Compatible mode is
        // opt-in: it wraps the output of flow/VM/MBA/... and leaves them
        // enabled; exclusive mode keeps the original isolated design.
        if (config.optionBool("nocturne.enabled", false)) {
            boolean compatible = config.optionBool("nocturne.compatible", false)
                    || !config.optionBool("nocturne.exclusive", true);
            if (compatible) {
                log.info("nocturne: compatible mode - classic body passes run first "
                        + "and Nocturne shadows their output");
            } else {
                config = nocturneExclusive(config, log);
            }
        }

        Stats stats = new Stats();
        stats.add("input.classes", pool.classes().size());
        stats.add("input.resources", pool.resources().size());
        stats.add("minecraft.detected", minecraft.detected() ? 1 : 0);
        stats.add("minecraft.keepRules", minecraft.keepRules().size());
        stats.add("minecraft.frozenClasses", minecraft.frozenClasses().size());
        stats.add("minecraft.bodySkipClasses", minecraft.bodySkipGlobs().size());
        stats.add("minecraft.targets", minecraft.targetCount());
        if (minecraft.detected()) {
            stats.text("minecraft.loader", minecraft.loader());
            stats.text("minecraft.modIds", join(minecraft.modIds()));
            stats.text("minecraft.evidence", join(minecraft.evidence()));
        }
        if (classEncryptionBlocked) {
            stats.add("classEncryption.skipped.layout", 1);
            stats.text("classEncryption.skipReason", layout.kindId()
                    + (preservedMultiRelease ? "+multi-release" : "")
                    + (layout.moduleInfo() ? "+module-info" : ""));
        }
        RiskReport risk = RiskReport.scan(pool, hierarchy);
        LicenseInfo license = validateLicense(config, log, stats);

        Map<String, String> inputHashes = new LinkedHashMap<String, String>();
        for (Map.Entry<String, ClassNode> entry : pool.classes().entrySet()) {
            byte[] bytes = pool.originalBytes(entry.getKey());
            if (bytes != null) {
                inputHashes.put(entry.getKey(), IncrementalCache.hash(bytes));
            }
        }
        IncrementalCache.Plan incremental = IncrementalCache.load(config, inputHashes, log);

        if (config.dryRun()) {
            stats.add("duration.ms", System.currentTimeMillis() - start);
            Path html = reportPath(config, config.report().htmlFile());
            Path json = reportPath(config, config.report().jsonFile());
            EngineResult result = new EngineResult(config.output(), pool.classes().size(), pool.resources().size(),
                    System.currentTimeMillis() - start, true, new LinkedHashMap<String, Long>(),
                    stats, risk, license, html, json);
            if (reportEnabled(config)) {
                AuditReport.write(html, json, config, result, stats, risk, license);
            }
            listener.onProgress(100, "Dry run complete");
            return result;
        }

        DefaultRuleSet rules = new DefaultRuleSet(config.keep(), config.softKeep(),
                config.keepPublicApi(), config.softKeepPublicApi());
        for (String rule : minecraft.keepRules()) {
            rules.addKeepRule(rule);
        }
        // The Eclipse jar-in-jar loader stays completely untouched: its
        // createURLStreamHandler is reached from javax.crypto's own <clinit>, so
        // any injected decryption there deadlocks JceSecurity.
        if (isEclipseRunnableJar(pool)) {
            rules.addKeepRule("org.eclipse.jdt.internal.jarinjarloader.**");
            rules.addBodySkipGlob("org.eclipse.jdt.internal.jarinjarloader.**");
            log.info("layout: Eclipse loader kept verbatim (names and bodies)");
        }
        for (String rule : minecraft.softKeepRules()) {
            rules.addKeepRule(rule);
        }
        for (String glob : minecraft.bodySkipGlobs()) {
            rules.addBodySkipGlob(glob);
        }
        // Per-build KDF domain separators: the build side (Cipher and the runtime
        // templates the passes call directly) must agree with every injected copy, so
        // this runs once before any pass (see DomainTags).
        DomainTags.install(config.seed());
        RuntimeSupport runtime = new DefaultRuntimeSupport();
        MappingSet mappings = new MappingSet();
        Random random = new Random(config.seed());
        PassContext context = new PassContext(config, pool, hierarchy, rules, runtime,
                mappings, stats, log, random, listener);

        List<Pass> passes = passes();
        Collections.sort(passes, new Comparator<Pass>() {
            @Override
            public int compare(Pass a, Pass b) {
                return Integer.compare(a.order(), b.order());
            }
        });

        Map<String, Long> timings = new LinkedHashMap<String, Long>();
        int index = 0;
        for (Pass pass : passes) {
            index++;
            if (listener.isCancelled()) {
                throw new java.util.concurrent.CancellationException("Umbra run cancelled");
            }
            if (!pass.enabled(context)) {
                log.debug("Pass %s is disabled", pass.name());
                continue;
            }
            int percent = 10 + (int) (80.0 * (index - 1) / Math.max(1, passes.size()));
            listener.onProgress(percent, "Running " + pass.name());
            long passStart = System.currentTimeMillis();
            log.info("Pass %s started", pass.name());
            pass.run(context);
            long elapsed = System.currentTimeMillis() - passStart;
            timings.put(pass.name(), Long.valueOf(elapsed));
            stats.add("pass." + pass.name() + ".ms", elapsed);
            log.info("Pass %s finished in %d ms", pass.name(), elapsed);
        }

        if (incremental != null) {
            incremental.apply(pool, mappings, stats);
        }
        // Safety net: no class may be written with MethodHandle/MethodType/
        // InvokeDynamic (major >= 51) or ConstantDynamic (major >= 55) constants
        // while declaring an older class file version.
        int versionBumped = AsmUtil.ensureConstantCompatibleVersions(pool, log);
        if (versionBumped > 0) {
            stats.add("output.version.bumped", versionBumped);
            log.info("version-safety: upgraded %d class(es) to a class file version that supports their constants",
                    versionBumped);
        }
        listener.onProgress(92, "Writing " + config.output());
        LayoutReport layoutReport = Jars.write(config.output(), pool, hierarchy,
                config.preserveTimestamps(), log, config.options(),
                mappings.classes(), mappings.globalMethods(), mappings.globalFields());
        if (layoutReport != null) {
            for (Map.Entry<String, Long> entry : layoutReport.counts().entrySet()) {
                stats.add(entry.getKey(), entry.getValue().longValue());
            }
            for (Map.Entry<String, String> entry : layoutReport.texts().entrySet()) {
                stats.text(entry.getKey(), entry.getValue());
            }
        }
        // Archive-level transformations (class encryption, integrity manifests)
        // run on the final byte image produced by the writer.
        int postIndex = 0;
        for (OutputPostProcessor processor : new ArrayList<OutputPostProcessor>(context.postProcessors())) {
            postIndex++;
            listener.onProgress(93 + (int) (5.0 * postIndex / Math.max(1, context.postProcessors().size())),
                    "Post-processing " + processor.name());
            long postStart = System.currentTimeMillis();
            log.info("Post-processor %s started", processor.name());
            processor.process(config.output(), context);
            long postElapsed = System.currentTimeMillis() - postStart;
            timings.put("post." + processor.name(), Long.valueOf(postElapsed));
            stats.add("post." + processor.name() + ".ms", postElapsed);
            log.info("Post-processor %s finished in %d ms", processor.name(), postElapsed);
        }
        // Incremental metadata and audit reports are auxiliary artifacts: a
        // failure to write them must never turn a successfully written output
        // into a failed run.
        try {
            IncrementalCache.write(config, inputHashes, mappings, log);
        } catch (Exception cacheFailure) {
            log.warn("incremental metadata could not be written: %s", cacheFailure.getMessage());
            stats.add("incremental.writeFailed", 1);
        }
        listener.onProgress(100, "Done");

        stats.add("output.classes", pool.classes().size());
        stats.add("output.resources", pool.resources().size());
        stats.add("duration.ms", System.currentTimeMillis() - start);
        Path html = reportPath(config, config.report().htmlFile());
        Path json = reportPath(config, config.report().jsonFile());
        EngineResult result = new EngineResult(config.output(), pool.classes().size(), pool.resources().size(),
                System.currentTimeMillis() - start, false, timings, stats, risk, license, html, json);
        if (reportEnabled(config)) {
            try {
                AuditReport.write(html, json, config, result, stats, risk, license);
                log.info("Audit report written (%s, %s)", html, json);
            } catch (Exception reportFailure) {
                log.warn("audit report could not be written: %s", reportFailure.getMessage());
                stats.add("report.writeFailed", 1);
            }
        }
        log.info("Output written to %s (%d classes, %d resources, %d ms)",
                config.output(), result.classes(), result.resources(), result.millis());
        return result;
    }

    private static List<Pass> passes() {
        List<Pass> passes = new ArrayList<Pass>();
        passes.add(new ReflectionAnalysisPass());
        passes.add(new MemberTrimPass());
        passes.add(new FieldInitializationPass());
        passes.add(new DebugInfoPass());
        passes.add(new MemberShufflePass());
        passes.add(new InvokeWrapperPass());
        passes.add(new ParameterObfuscationPass());
        passes.add(new RenamePass());
        passes.add(new AntiLlmPass());
        passes.add(new TypeConfusionPass());
        passes.add(new VirtualizationPass());
        passes.add(new ResourcePathObfuscationPass());
        passes.add(new ReferenceObfuscationPass());
        passes.add(new StringEncryptionPass());
        passes.add(new IntegerEncryptionPass());
        passes.add(new FlowObfuscationPass());
        passes.add(new ControlFlowFlatteningPass());
        passes.add(new ExceptionObfuscationPass());
        passes.add(new JunkMemberPass());
        passes.add(new WatermarkPass());
        passes.add(new AntiDebugPass());
        passes.add(new AuthGatePass());
        passes.add(new ReflectionGatePass());
        passes.add(new MbaPass());
        passes.add(new NocturnePass());
        passes.add(new DecompilerNoisePass());
        passes.add(new NativeCodePass());
        passes.add(new NativeGuardPass());
        passes.add(new IntegrityPass());
        passes.add(new ClassEncryptionPass());
        passes.add(new ResourceRewritePass());
        return passes;
    }

    /**
     * Enforces Nocturne's exclusivity: all existing method-body rewrites are
     * switched off, leaving Nocturne as the only body transformation. Data/name
     * layers (rename, string/integer encryption, metadata cleanup, watermark)
     * are not method-body techniques and remain available.
     */
    private static UmbraConfig nocturneExclusive(UmbraConfig base, Log log) {
        UmbraConfig.Builder b = base.toBuilder();
        b.flow(new UmbraConfig.FlowOptions(false, base.flow().level(),
                base.flow().maxInstructions(), false));
        b.exceptionObfuscation(new UmbraConfig.ExceptionOptions(false));
        b.methodVirtualization(new UmbraConfig.VirtualizationOptions(false,
                base.methodVirtualization().maxInstructions(),
                base.methodVirtualization().maxMethods()));
        b.antiLlm(new UmbraConfig.AntiLlmOptions(false,
                base.antiLlm().decoyMethodsPerClass(), base.antiLlm().decoyCallSitesPerClass(),
                base.antiLlm().wrapperLayers(), base.antiLlm().maxWrappedMethodsPerClass(),
                false));
        b.invokeWrapper(new UmbraConfig.WrapperOptions(false, base.invokeWrapper().maxPerClass()));
        b.parameterObfuscation(new UmbraConfig.ParameterOptions(false));
        b.referenceObfuscation(new UmbraConfig.ReferenceOptions(false));
        b.trim(new UmbraConfig.TrimOptions(false, false, false));
        b.junk(new UmbraConfig.JunkOptions(false, 0, 0));
        b.option("mba.enabled", "false");
        b.option("typeConfusion.enabled", "false");
        b.option("vm2.enabled", "false");
        b.option("native.enabled", "false");
        b.option("nocturne.exclusive", "true");
        log.info("nocturne: exclusive mode — flow/flattening/exception/MBA/VM/native/"
                + "reference-hiding/anti-LLM/parameter/junk passes disabled");
        try {
            return b.build();
        } catch (io.umbra.core.config.ConfigException e) {
            return base;
        }
    }

    private static String join(java.util.List<String> values) {
        if (values == null || values.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (String value : values) {
            if (out.length() > 0) {
                out.append(',');
            }
            out.append(value);
        }
        return out.toString();
    }

    private static LicenseInfo validateLicense(UmbraConfig config, Log log, Stats stats) {
        UmbraConfig.LicenseOptions options = config.license();
        if (options.file().trim().isEmpty()) {
            if (options.require()) {
                throw new LicenseException("Enterprise license required but license.file is empty");
            }
            return null;
        }
        Path licensePath = resolveRelative(config, options.file());
        Path keyPath = options.publicKey().trim().isEmpty()
                ? null : resolveRelative(config, options.publicKey());
        LicenseInfo license;
        try {
            license = LicenseValidator.validate(licensePath, keyPath);
        } catch (IOException e) {
            throw new LicenseException("Unable to read license: " + e.getMessage(), e);
        }
        if (!license.isValid()) {
            if (options.require()) {
                throw new LicenseException("License invalid: " + license.error());
            }
            log.warn("License problem: %s", license.error());
            return license;
        }
        for (String feature : options.requiredFeatures()) {
            if (!license.hasFeature(feature)) {
                if (options.require()) {
                    throw new LicenseException("License does not include required feature: " + feature);
                }
                log.warn("License does not include feature: %s", feature);
            }
        }
        if (!options.server().trim().isEmpty()) {
            long started = System.currentTimeMillis();
            LicenseOnlineValidator.Result online;
            try {
                online = LicenseOnlineValidator.check(licensePath, options.server());
            } catch (IOException e) {
                online = new LicenseOnlineValidator.Result(false, e.getMessage());
            }
            stats.add("license.online.ms", System.currentTimeMillis() - started);
            stats.add("license.online.valid", online.isValid() ? 1 : 0);
            if (!online.isValid()) {
                if (options.require()) {
                    throw new LicenseException("Online license validation failed: " + online.reason());
                }
                log.warn("Online license validation failed: %s", online.reason());
            } else {
                log.info("Online license check: OK (%s)", options.server());
            }
        }
        log.info("License: %s", license);
        return license;
    }

    private static Path resolveRelative(UmbraConfig config, String value) {
        Path path = java.nio.file.Paths.get(value.trim());
        if (path.isAbsolute()) {
            return path;
        }
        Path parent = config.output().toAbsolutePath().getParent();
        return parent == null ? path : parent.resolve(path);
    }

    private static boolean reportEnabled(UmbraConfig config) {
        return config.report().enabled();
    }

    private static Path reportPath(UmbraConfig config, String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        Path path = java.nio.file.Paths.get(value.trim());
        if (path.isAbsolute()) {
            return path;
        }
        Path parent = config.output().toAbsolutePath().getParent();
        return parent == null ? path : parent.resolve(path);
    }

    private void loadLibrary(Path path, Hierarchy hierarchy) throws IOException {
        if (!Files.exists(path)) {
            log.warn("Library not found: %s", path);
            return;
        }
        if (Files.isDirectory(path)) {
            List<Path> files = new ArrayList<Path>();
            try (java.util.stream.Stream<Path> stream = Files.walk(path)) {
                stream.filter(p -> Files.isRegularFile(p) && p.toString().endsWith(".class"))
                        .forEach(files::add);
            }
            for (Path file : files) {
                try {
                    hierarchy.addLibrary(Files.readAllBytes(file));
                } catch (RuntimeException e) {
                    log.debug("Skipping library class %s: %s", file, e.getMessage());
                }
            }
            log.info("Loaded library directory %s (%d classes)", path, files.size());
        } else {
            hierarchy.addLibraryJar(path);
            log.info("Loaded library %s", path);
        }
    }
    /**
     * Freezes the Eclipse jar-in-jar loader when the archive is an Eclipse
     * "Runnable JAR".
     *
     * <p>That loader's {@code createURLStreamHandler} is invoked from
     * {@code java.net.URL} construction, which the JDK itself performs while
     * initializing {@code javax.crypto.JceSecurity}. Instrumenting it re-enters
     * the injected string decryptor before crypto is ready ("AES-256-CTR
     * unavailable"), so the loader package is frozen and never transformed.</p>
     */
    private static void freezeEclipseLoader(ClassPool pool, Log log) {
        ClassPool.Resource manifest = pool.resource("META-INF/MANIFEST.MF");
        if (manifest == null) {
            return;
        }
        java.util.Map<String, String> attributes =
                io.umbra.core.util.Jars.parseManifest(manifest.bytes());
        if (attributes.get("Rsrc-Main-Class") == null) {
            return;
        }
        int frozen = 0;
        for (String name : new java.util.ArrayList<String>(pool.classes().keySet())) {
            if (name.startsWith("org/eclipse/jdt/internal/jarinjarloader/")) {
                pool.freeze(name);
                frozen++;
            }
        }
        log.info("layout: Eclipse runnable jar detected, %d loader class(es) frozen", frozen);
        log.info("layout: archive sealing is skipped for this layout (loader needs plain classes)");
    }
    /** True when the archive is an Eclipse "Runnable JAR" (JarRsrcLoader layout). */
    private static boolean isEclipseRunnableJar(ClassPool pool) {
        ClassPool.Resource manifest = pool.resource("META-INF/MANIFEST.MF");
        if (manifest == null) {
            return false;
        }
        return io.umbra.core.util.Jars.parseManifest(manifest.bytes()).get("Rsrc-Main-Class") != null;
    }
}
