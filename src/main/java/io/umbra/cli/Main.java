package io.umbra.cli;

import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.ConfigException;
import io.umbra.core.config.ConfigLoader;
import io.umbra.core.config.Presets;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.enterprise.LicenseException;
import io.umbra.core.enterprise.LicenseInfo;
import io.umbra.core.enterprise.LicenseValidator;
import io.umbra.core.enterprise.MappingDiff;
import io.umbra.core.enterprise.WatermarkTracer;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.engine.UmbraVerifier;
import io.umbra.core.util.Log;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Command-line entry point. */
public final class Main {

    private static final String VERSION = "3.2.2";

    private Main() {
    }

    public static void main(String[] args) {
        // No arguments opens the desktop console. The console is a separate JavaFX
        // jar (the engine jar must stay JavaFX-free so it runs on any JDK 8), so it
        // is launched as a child process when it sits next to this jar; otherwise the
        // command line help is printed instead of failing silently.
        if (args.length == 0 || "gui".equals(args[0]) || "--gui".equals(args[0])) {
            if (!launchConsole()) {
                System.exit(1);
            }
            return;
        }
        try {
            Args parsed = Args.parse(args);
            if (parsed.help) {
                usage();
                return;
            }
            if (parsed.version) {
                System.out.println("Umbra " + VERSION);
                return;
            }
            if (parsed.diffOld != null) {
                System.out.println(MappingDiff.compare(Paths.get(parsed.diffOld), Paths.get(parsed.diffNew)));
                return;
            }
            if (parsed.traceWatermark != null) {
                List<String> marks = WatermarkTracer.trace(Paths.get(parsed.traceWatermark));
                if (marks.isEmpty()) {
                    System.out.println("No Umbra watermark found");
                } else {
                    for (String mark : marks) {
                        System.out.println(mark);
                    }
                }
                return;
            }

            if (parsed.dumpPreset != null) {
                UmbraConfig base = new UmbraConfig.Builder()
                        .input(Paths.get("in.jar"))
                        .output(Paths.get("out.jar"))
                        .build();
                System.out.print(io.umbra.core.config.PresetValues.dump(parsed.dumpPreset, base));
                return;
            }
            if (parsed.inspect) {
                Path target = null;
                if (parsed.input != null) {
                    target = Paths.get(parsed.input);
                } else if (parsed.config != null) {
                    target = ConfigLoader.load(Paths.get(parsed.config), false).input();
                }
                if (target == null) {
                    throw new ConfigException("--inspect requires -i <jar> (or a config file with an input path)");
                }
                if (!Files.exists(target)) {
                    throw new ConfigException("Input does not exist: " + target);
                }
                if (!Files.isRegularFile(target)) {
                    throw new ConfigException("Input is not a regular file: " + target);
                }
                InspectTool.Report inspection = InspectTool.analyze(target);
                InspectTool.print(inspection, VERSION, System.out);
                if (parsed.inspectJson != null) {
                    Path json = Paths.get(parsed.inspectJson);
                    InspectTool.writeJson(inspection, json, VERSION);
                    System.out.println("Inspection JSON: " + json.toAbsolutePath());
                }
                return;
            }
            final boolean quiet = parsed.quiet;
            Log log = new Log(new Log.Sink() {
                @Override
                public void line(String level, String message) {
                    if (quiet && !"ERROR".equals(level) && !"WARN".equals(level)) {
                        return;
                    }
                    if ("ERROR".equals(level)) {
                        System.err.println("[" + level + "] " + message);
                    } else {
                        System.out.println("[" + level + "] " + message);
                    }
                }
            }, parsed.verbose);

            // Validate the command-line license early only when no configuration
            // file can supply one: with -c the effective license (file, public
            // key, require flag) is assembled from the YAML and the CLI
            // overrides first and then enforced by the engine. Checking only
            // --license here would reject a valid config-supplied license.
            if (parsed.config == null && (parsed.license != null || parsed.requireLicense)) {
                if (parsed.license == null) {
                    System.err.println("Enterprise license required but --license was not provided");
                    System.exit(3);
                }
                validateCliLicense(parsed.license, parsed.licenseKey, parsed.requireLicense, log);
            }

            UmbraConfig config = buildConfig(parsed, log);
            if (!Files.exists(config.input())) {
                throw new ConfigException("Input does not exist: " + config.input());
            }
            if (!Files.isRegularFile(config.input())) {
                throw new ConfigException("Input is not a regular file: " + config.input());
            }
            validateRunConfiguration(config, parsed);

            ProgressListener progress = new ProgressListener() {
                @Override
                public void onProgress(int percent, String message) {
                    if (!quiet) {
                        System.out.println(String.format("[%3d%%] %s", percent, message));
                    }
                }
            };

            UmbraEngine engine = new UmbraEngine(log);
            EngineResult result = engine.run(config, progress);

            if (!result.dryRun()) {
                System.out.println("Umbra finished: " + result.classes() + " classes, "
                        + result.resources() + " resources in " + result.millis() + " ms");
                if (parsed.verify) {
                    List<String> errors = UmbraVerifier.verify(config.output(), config.libraries());
                    if (errors.isEmpty()) {
                        System.out.println("Verification: OK");
                    } else {
                        System.err.println("Verification failed for " + errors.size() + " class(es):");
                        for (String error : errors) {
                            System.err.println("  " + error);
                        }
                        System.exit(2);
                    }
                }
            }
            if (parsed.compatReport != null) {
                Path compatPath = Paths.get(parsed.compatReport);
                // A report path problem must not turn a successful protection
                // run into a failure; the output JAR is already written.
                try {
                    InspectTool.writeCompatReport(compatPath, InspectTool.analyze(config.input()),
                            result, VERSION);
                    System.out.println("Compatibility report: " + compatPath.toAbsolutePath());
                } catch (java.io.IOException reportFailure) {
                    System.err.println("Warning: compatibility report not written: "
                            + reportFailure.getMessage());
                }
            }
        } catch (ConfigException e) {
            System.err.println("Configuration error: " + e.getMessage());
            usage();
            System.exit(1);
        } catch (LicenseException e) {
            System.err.println("License error: " + e.getMessage());
            System.exit(3);
        } catch (java.util.concurrent.CancellationException e) {
            System.err.println("Umbra cancelled");
            System.exit(130);
        } catch (java.util.zip.ZipException e) {
            System.err.println("Input is not a readable JAR: " + e.getMessage());
            System.exit(1);
        } catch (java.nio.file.NoSuchFileException e) {
            System.err.println("File not found: " + e.getFile());
            System.exit(1);
        } catch (java.io.FileNotFoundException e) {
            System.err.println("File not found: " + e.getMessage());
            System.exit(1);
        } catch (java.io.IOException e) {
            System.err.println("Umbra failed: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Umbra failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Validates a command-line license and reports problems with the documented
     * exit code 3 for license errors (an unreadable license file is a license
     * error, not a generic failure).
     */
    private static void validateCliLicense(String licenseFile, String keyFile, boolean require, Log log) {
        LicenseInfo license;
        try {
            license = LicenseValidator.validate(Paths.get(licenseFile),
                    keyFile == null ? null : Paths.get(keyFile));
        } catch (java.io.IOException e) {
            System.err.println("License error: " + e.getMessage());
            System.exit(3);
            return;
        }
        if (license.isValid()) {
            log.info("License: %s", license);
        } else {
            log.warn("License problem: %s", license.error());
            if (require) {
                System.exit(3);
            }
        }
    }

    /** Cross-cutting validation that is independent of how the config was built. */
    private static void validateRunConfiguration(UmbraConfig config, Args args) throws ConfigException {
        if (!args.allowInPlace) {
            try {
                if (Files.exists(config.output()) && Files.isSameFile(config.input(), config.output())) {
                    throw new ConfigException("Output must be different from the input (add --allow-in-place to overwrite it)");
                }
            } catch (java.io.IOException ignored) {
                // Non-existent output cannot alias the input.
            }
        }
        if (config.methodVirtualization().maxInstructions() < 0) {
            throw new ConfigException("--virtualize-max-instructions must be >= 0");
        }
        if (config.methodVirtualization().maxMethods() < 0) {
            throw new ConfigException("--virtualize-max-methods must be >= 0");
        }
        if (config.antiLlm().decoyMethodsPerClass() < 0 || config.antiLlm().decoyCallSitesPerClass() < 0
                || config.antiLlm().wrapperLayers() < 0) {
            throw new ConfigException("--anti-llm counts/layers must be >= 0");
        }
        if (config.authGate().timeoutMs() < 0) {
            throw new ConfigException("--auth-timeout must be >= 0");
        }
        if (config.renamer().minimumNameLength() < 0) {
            throw new ConfigException("--min-name-length must be >= 0");
        }
    }

    private static UmbraConfig buildConfig(Args args, Log log) throws Exception {
        UmbraConfig base;
        if (args.config != null) {
            // Lenient load: -i/-o (and other flags) are applied as overrides below,
            // so a config file without input/output must not fail here. The final
            // strict build() at the end still reports missing paths clearly.
            Path configPath = Paths.get(args.config);
            if (!Files.isRegularFile(configPath)) {
                throw new ConfigException("Configuration file not found: " + configPath);
            }
            base = ConfigLoader.load(configPath, false);
        } else {
            UmbraConfig.Builder builder = new UmbraConfig.Builder();
            if (args.input == null || (args.output == null && !args.dryRun)) {
                throw new ConfigException("Either -c <config> or both -i <input> and -o <output> are required"
                        + (args.input != null ? " (use --dry-run to analyze without -o)" : ""));
            }
            Path input = Paths.get(args.input);
            String inputName = input.getFileName() == null ? "input" : input.getFileName().toString();
            Path output = args.output == null
                    ? input.resolveSibling(inputName + ".dry-run")
                    : Paths.get(args.output);
            builder.input(input);
            builder.output(output);
            base = builder.build();
        }

        UmbraConfig.Builder b = base.toBuilder();
        if (args.preset != null) {
            // Apply the preset BEFORE the explicit CLI overrides so that
            // --set/--no-* options always win over preset defaults.
            base = Presets.apply(base.toBuilder().preset(args.preset).build(), args.preset, false);
            b = base.toBuilder();
        }
        if (args.input != null) {
            b.input(Paths.get(args.input));
        }
        if (args.output != null) {
            b.output(Paths.get(args.output));
        } else if (args.dryRun && base.output() == null && base.input() != null) {
            // --dry-run never writes the output, so an output path from the CLI
            // is optional. Use a harmless sibling placeholder for the config.
            Path input = base.input();
            String name = input.getFileName() == null ? "dry-run" : input.getFileName().toString();
            b.output(input.resolveSibling(name + ".dry-run"));
        }
        for (String library : args.libraries) {
            b.addLibrary(Paths.get(library));
        }
        if (!args.keep.isEmpty()) {
            List<String> keep = new ArrayList<String>(base.keep());
            keep.addAll(args.keep);
            b.keep(keep);
        }
        if (args.seed != null) {
            b.seed(args.seed);
        }
        Map<String, String> typedSets = new LinkedHashMap<String, String>();
        for (String assignment : args.sets) {
            int split = assignment.indexOf('=');
            if (split <= 0) {
                throw new ConfigException("--set expects key=value, got: " + assignment);
            }
            String key = assignment.substring(0, split).trim();
            String value = assignment.substring(split + 1).trim();
            b.option(key, value);
            typedSets.put(key, value);
        }
        if (!typedSets.isEmpty()) {
            // A --set key may name a typed section (`renamer.enabled=false`,
            // `flowObfuscation.level=aggressive`); the engine reads the typed
            // sections, so translate them here. This is the only front end that
            // does it, and only for --set: a derived configuration (preset,
            // nocturne exclusive mode) must still be able to tighten a section.
            UmbraConfig.applyTypedOverrides(b, typedSets);
            // The explicit switches below start from the typed values, so refresh
            // the snapshot they read: preset < --set < --no-* / --flatten.
            base = b.build(false);
        }
        if (args.dryRun) {
            b.dryRun(true);
        }
        if (args.fixedTime) {
            b.preserveTimestamps(false);
        }

        UmbraConfig.RenamerOptions r = base.renamer();
        if (args.noRename || args.dictionary != null || args.minNameLength != null
                || args.mappingFile != null) {
            r = new UmbraConfig.RenamerOptions(!args.noRename && r.enabled(), r.prefix(), r.repackage(),
                    r.repackagePackage(), r.renameClasses(), r.renameMethods(), r.renameFields(),
                    args.mappingFile == null ? r.mappingFile() : args.mappingFile,
                    args.dictionary == null ? r.dictionary() : args.dictionary,
                    args.minNameLength == null ? r.minimumNameLength() : args.minNameLength.intValue());
        }
        b.renamer(r);

        UmbraConfig.StringEncryptionOptions s = base.stringEncryption();
        if (args.noString) {
            s = new UmbraConfig.StringEncryptionOptions(false, s.minLength());
        }
        b.stringEncryption(s);

        UmbraConfig.IntegerEncryptionOptions i = base.integerEncryption();
        if (args.noInteger) {
            i = new UmbraConfig.IntegerEncryptionOptions(false, i.includeLong());
        }
        b.integerEncryption(i);

        UmbraConfig.FlowOptions f = base.flow();
        if (args.noFlow) {
            f = new UmbraConfig.FlowOptions(false, f.level(), f.maxInstructions(), f.flattening());
        } else if (args.flatten) {
            f = new UmbraConfig.FlowOptions(f.enabled(), f.level(), f.maxInstructions(), true);
        }
        b.flow(f);

        UmbraConfig.VirtualizationOptions virtualization = base.methodVirtualization();
        if (args.virtualize || args.virtualizeMaxInstructions != null || args.virtualizeMaxMethods != null) {
            virtualization = new UmbraConfig.VirtualizationOptions(
                    args.virtualize || args.virtualizeMaxInstructions != null
                            || args.virtualizeMaxMethods != null || virtualization.enabled(),
                    args.virtualizeMaxInstructions == null
                            ? virtualization.maxInstructions() : args.virtualizeMaxInstructions.intValue(),
                    args.virtualizeMaxMethods == null
                            ? virtualization.maxMethods() : args.virtualizeMaxMethods.intValue());
        }
        b.methodVirtualization(virtualization);

        UmbraConfig.AntiLlmOptions antiLlm = base.antiLlm();
        if (args.antiLlm || args.antiLlmDecoys != null || args.antiLlmLayers != null) {
            antiLlm = new UmbraConfig.AntiLlmOptions(
                    true,
                    args.antiLlmDecoys == null
                            ? antiLlm.decoyMethodsPerClass() : args.antiLlmDecoys.intValue(),
                    antiLlm.decoyCallSitesPerClass(),
                    args.antiLlmLayers == null
                            ? antiLlm.wrapperLayers() : args.antiLlmLayers.intValue(),
                    antiLlm.maxWrappedMethodsPerClass(),
                    antiLlm.shieldVirtualization());
        }
        b.antiLlm(antiLlm);

        UmbraConfig.ShuffleOptions sh = base.shuffle();
        if (args.noShuffle) {
            sh = new UmbraConfig.ShuffleOptions(false);
        }
        b.shuffle(sh);

        UmbraConfig.JunkOptions j = base.junk();
        if (args.noJunk) {
            j = new UmbraConfig.JunkOptions(false, j.methods(), j.fields());
        }
        b.junk(j);

        UmbraConfig.WatermarkOptions w = base.watermark();
        if (args.noWatermark) {
            w = new UmbraConfig.WatermarkOptions(false, w.id());
        }
        b.watermark(w);

        UmbraConfig.MappingOptions mapping = base.mapping();
        if (args.inputMapping != null) {
            mapping = new UmbraConfig.MappingOptions(mapping.enabled(), mapping.file(), args.inputMapping);
        }
        b.mapping(mapping);

        if (args.reportHtml != null || args.reportJson != null) {
            String html = args.reportHtml == null ? base.report().htmlFile() : args.reportHtml;
            String json = args.reportJson == null ? base.report().jsonFile() : args.reportJson;
            b.report(new UmbraConfig.ReportOptions(true, html, json));
        }
        if (args.keepPublicApi) {
            b.keepPublicApi(true);
        }
        if (args.softKeepPublicApi) {
            b.softKeepPublicApi(true);
        }
        if (args.noReflection) {
            b.reflection(new UmbraConfig.ReflectionOptions(false));
        }
        if (args.trim) {
            b.trim(new UmbraConfig.TrimOptions(true, true, true));
        }
        if (args.parameterObfuscation) {
            b.parameterObfuscation(new UmbraConfig.ParameterOptions(true));
        }
        if (args.rewriteResources) {
            b.resources(new UmbraConfig.ResourceOptions(true));
        }
        UmbraConfig.ReferenceOptions references = base.referenceObfuscation();
        boolean referenceEnabled = references.enabled() || args.referenceObfuscation
                || args.referenceVirtual || args.referenceFields || args.referenceConstructors;
        if (referenceEnabled) {
            boolean staticCalls = references.staticCalls() || args.referenceObfuscation;
            boolean virtualCalls = references.virtualCalls() || args.referenceVirtual;
            boolean fields = references.fields() || args.referenceFields;
            boolean constructors = references.constructors() || args.referenceConstructors;
            b.referenceObfuscation(new UmbraConfig.ReferenceOptions(true, staticCalls,
                    virtualCalls, fields, constructors));
        }
        if (args.exceptionObfuscation) {
            b.exceptionObfuscation(new UmbraConfig.ExceptionOptions(true));
        }
        UmbraConfig.IncrementalOptions incremental = base.incremental();
        if (args.incrementalPrevious != null || args.incrementalMetadata != null) {
            incremental = new UmbraConfig.IncrementalOptions(true,
                    args.incrementalPrevious == null ? incremental.previousOutput() : args.incrementalPrevious,
                    args.incrementalMetadata == null ? incremental.metadataFile() : args.incrementalMetadata);
        }
        b.incremental(incremental);
        if (args.antiDebug) {
            b.antiDebug(true);
        }
        UmbraConfig.AuthGateOptions gate = base.authGate();
        boolean gateTouched = args.authGate || args.authServer != null || args.authSoftware != null
                || args.authTitle != null || args.authNoRegister || args.authCache != null
                || args.authTimeout != null || !args.authEntries.isEmpty();
        if (gateTouched) {
            List<String> gateEntries = new ArrayList<String>(gate.entryPoints());
            gateEntries.addAll(args.authEntries);
            gate = new UmbraConfig.AuthGateOptions(
                    true,
                    args.authServer == null ? gate.server() : args.authServer,
                    args.authSoftware == null ? gate.software() : args.authSoftware,
                    args.authTitle == null ? gate.title() : args.authTitle,
                    args.authNoRegister ? false : gate.allowRegister(),
                    args.authCache == null ? gate.cacheFile() : args.authCache,
                    args.authTimeout == null ? gate.timeoutMs() : args.authTimeout.intValue(),
                    gateEntries);
            b.authGate(gate);
        }
        UmbraConfig.LicenseOptions license = base.license();
        String server = args.licenseServer == null ? license.server() : args.licenseServer;
        if (server.trim().isEmpty()) {
            String environment = System.getenv("UMBRA_LICENSE_SERVER");
            if (environment != null) {
                server = environment.trim();
            }
        }
        boolean licenseEnabled = license.enabled();
        String licenseFile = license.file();
        String licenseKey = args.licenseKey == null ? license.publicKey() : args.licenseKey;
        boolean requireLicense = license.require();
        List<String> licenseFeatures = license.requiredFeatures();
        if (args.license != null) {
            licenseEnabled = true;
            licenseFile = args.license;
            // Explicit --license switches the file but must not silently drop
            // the configured public key or downgrade a required license.
            requireLicense = args.requireLicense || requireLicense;
        } else if (args.requireLicense) {
            licenseEnabled = license.enabled() || !license.file().isEmpty();
            requireLicense = true;
        }
        if (!args.licenseFeatures.isEmpty()) {
            licenseFeatures = args.licenseFeatures;
            // --require-feature is a hard gate: the license must exist, be
            // valid and contain every requested feature (engine enforces it).
            requireLicense = true;
        }
        b.license(new UmbraConfig.LicenseOptions(licenseEnabled, licenseFile, licenseKey,
                requireLicense, licenseFeatures, server));

        UmbraConfig result = b.build();
        if (result.authGate().enabled()
                && (result.authGate().server().isEmpty() || result.authGate().software().isEmpty())) {
            throw new ConfigException("authGate.server and authGate.software are required when the auth gate is enabled");
        }
        if (args.verbose) {
            log.debug("Effective configuration: input=%s output=%s seed=%d preset=%s",
                    result.input(), result.output(), result.seed(), result.preset());
        }
        return result;
    }

    /**
     * Starts the desktop console.
     *
     * <p>The console is a separate JavaFX jar: the engine jar has to stay free of
     * JavaFX so it runs on any JDK 8, while the console needs a JDK that ships
     * JavaFX. So this looks for {@code umbra-gui-fx.jar} next to the running jar and
     * for a JavaFX-capable {@code javaw}, and spawns the console as a child process.
     * When either is missing it prints the command line help instead of pretending
     * a window opened.</p>
     */
    private static boolean launchConsole() {
        java.nio.file.Path engine = runningJar();
        java.nio.file.Path gui = null;
        if (engine != null && engine.getParent() != null) {
            java.nio.file.Path sibling = engine.getParent().resolve("umbra-gui-fx.jar");
            if (Files.isRegularFile(sibling)) {
                gui = sibling;
            }
        }
        java.nio.file.Path javaFx = javaFxLauncher();
        if (engine == null || gui == null || javaFx == null) {
            System.out.println("The desktop console is not available next to this jar.");
            if (gui == null) {
                System.out.println("  missing: umbra-gui-fx.jar (built by gui-fx\\build-fx.cmd)");
            }
            if (javaFx == null) {
                System.out.println("  missing: a JDK 8 with JavaFX (set JFX_JAVA_HOME)");
            }
            System.out.println();
            usage();
            return false;
        }
        try {
            new ProcessBuilder(javaFx.toString(),
                    "-cp", gui + java.io.File.pathSeparator + engine,
                    "io.umbra.guifx.FxGui", "--jar", engine.toString())
                    .start();
            return true;
        } catch (Exception failure) {
            System.err.println("Cannot start the desktop console: " + failure);
            usage();
            return false;
        }
    }

    /** Path of the jar this class was loaded from, or {@code null} in a class directory. */
    private static java.nio.file.Path runningJar() {
        try {
            java.security.CodeSource source = Main.class.getProtectionDomain().getCodeSource();
            if (source == null || source.getLocation() == null) {
                return null;
            }
            java.nio.file.Path path = Paths.get(source.getLocation().toURI());
            return Files.isRegularFile(path) ? path : null;
        } catch (Exception failure) {
            return null;
        }
    }

    /**
     * A {@code javaw} from a JDK that ships JavaFX: {@code JFX_JAVA_HOME} first, then
     * the running JVM, then the usual installation roots.
     */
    private static java.nio.file.Path javaFxLauncher() {
        List<java.nio.file.Path> roots = new ArrayList<java.nio.file.Path>();
        String configured = System.getenv("JFX_JAVA_HOME");
        if (configured != null && !configured.trim().isEmpty()) {
            roots.add(Paths.get(configured.trim()));
        }
        String home = System.getProperty("java.home");
        if (home != null && !home.isEmpty()) {
            java.nio.file.Path current = Paths.get(home);
            roots.add(current);
            if (current.getParent() != null) {
                roots.add(current.getParent());
            }
        }
        // The running JVM is often a plain JDK 8 without JavaFX, while the machine
        // has a JavaFX build installed; the launcher scripts already look in these
        // roots, so the jar has to agree with them.
        String userHome = System.getProperty("user.home");
        if (userHome != null && !userHome.isEmpty()) {
            roots.add(Paths.get(userHome, ".jdks", "corretto-1.8.0_462"));
            roots.add(Paths.get(userHome, ".jdks", "jdk1.8.0_462"));
        }
        roots.add(Paths.get("C:\\Program Files\\Java\\jdk1.8.0_261"));
        roots.add(Paths.get("C:\\Program Files\\Java\\jre1.8.0_471"));
        for (java.nio.file.Path root : roots) {
            java.nio.file.Path jfx = root.resolve("jre").resolve("lib").resolve("ext").resolve("jfxrt.jar");
            java.nio.file.Path launcher = root.resolve("bin").resolve("javaw.exe");
            if (Files.isRegularFile(jfx) && Files.isRegularFile(launcher)) {
                return launcher;
            }
        }
        return null;
    }

    private static void usage() {
        System.out.println("Umbra " + VERSION + " - Java bytecode obfuscator");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -jar umbra-all.jar -c <config.yml>");
        System.out.println("  java -jar umbra-all.jar -i <input.jar> -o <output.jar> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -c, --config <file>    YAML configuration");
        System.out.println("  -i, --input <jar>      input JAR");
        System.out.println("  -o, --output <jar>     output JAR");
        System.out.println("  --lib <path>           library JAR or directory (repeatable)");
        System.out.println("  --keep <pattern>       keep glob or @annotation (repeatable/comma-separated)");
        System.out.println("  --preset <name>        library|spring-boot|jackson|service-loader|micronaut|aggressive|light|balanced|maximum|nocturne");
        System.out.println("  --keep-public-api      keep public/protected classes completely");
        System.out.println("  --soft-keep-public-api keep public/protected names only (other transforms still run)");
        System.out.println("  --reflection-off       disable automatic reflection keep analysis");
        System.out.println("  --trim                 remove unused private members");
        System.out.println("  --parameter-obfuscation add unused parameters to private methods");
        System.out.println("  --rewrite-resources    rewrite class names in text resources");
        System.out.println("  --reference-obfuscation hide static calls behind invokedynamic");
        System.out.println("  --reference-virtual    hide virtual/interface calls behind invokedynamic");
        System.out.println("  --reference-fields     hide field access behind invokedynamic");
        System.out.println("  --reference-constructors hide new/constructor sequences behind factory methods");
        System.out.println("  --exception-obfuscation add synthetic catch-all exception handlers");
        System.out.println("  --virtualize           virtualize eligible method bodies (custom VM)");
        System.out.println("  --virtualize-max-instructions <n>  skip methods larger than n instructions");
        System.out.println("  --virtualize-max-methods <n>       cap virtualized methods per class (0 = unlimited)");
        System.out.println("  --anti-llm             enable anti-LLM countermeasures (decoys + wrapper walls)");
        System.out.println("  --anti-llm-decoys <n>  decoy methods injected per class");
        System.out.println("  --anti-llm-layers <n>  nested forwarding layers per wrapped method (0-4)");
        System.out.println("  --incremental <prev.jar> reuse unchanged classes from a previous output");
        System.out.println("  --incremental-metadata <file> incremental metadata path");
        System.out.println("  --anti-debug           add a startup debug-agent guard");
        System.out.println("  --auth-gate            inject the server-backed authorization gate");
        System.out.println("  --auth-server <url>    authorization server base URL (e.g. http://127.0.0.1:8090)");
        System.out.println("  --auth-software <id>   software id registered on the authorization server");
        System.out.println("  --auth-title <t>       authorization window title");
        System.out.println("  --auth-no-register     hide account registration in the gate window");
        System.out.println("  --auth-cache <file>    token cache file (default ~/.umbra-auth/<software>.token)");
        System.out.println("  --auth-timeout <ms>    HTTP connect/read timeout for the gate (default 5000)");
        System.out.println("  --auth-entry <class#method>  extra verification entry point (repeatable/comma-separated)");
        System.out.println("  --dictionary <chars>   identifier character dictionary");
        System.out.println("  --min-name-length <n>  minimum generated name length");
        System.out.println("  --input-mapping <file> reuse a previous mapping for stable builds");
        System.out.println("  --mapping <file>       write the name mapping to this file");
        System.out.println("  --report <html>        write an HTML audit report");
        System.out.println("  --report-json <json>   write a JSON audit report");
        System.out.println("  --inspect              inspect the input archive layout/compatibility and exit");
        System.out.println("  --inspect-json <file>  write the inspection report as JSON and exit");
        System.out.println("  --dump-preset <name>   print the effective option values of a preset and exit");
        System.out.println("  --compat-report <json> write layout + run statistics JSON after the run");
        System.out.println("  --diff-mapping <old> <new>  print a mapping difference and exit");
        System.out.println("  --trace-watermark <jar>     print embedded Umbra watermark(s) and exit");
        System.out.println("  --license <file>       signed enterprise license");
        System.out.println("  --license-key <pem>    RSA public key for license verification");
        System.out.println("  --license-server <url> online license server for revocation/feature checks");
        System.out.println("  --require-license      exit with code 3 when the license is missing/invalid");
        System.out.println("  --require-feature <f>  require a license feature (repeatable): audit, policy, ...");
        System.out.println("  --seed <value>         deterministic seed");
        System.out.println("  --set, -D key=value    advanced option (repeatable); see docs/OPTIONS.md");
        System.out.println("  --dry-run              analyze only, do not write output");
        System.out.println("  --verify               load output classes to force JVM verification");
        System.out.println("  --fixed-time           write a fixed ZIP timestamp (reproducible builds)");
        System.out.println("  --allow-in-place       allow output to overwrite the input JAR (destructive; default rejects)");
        System.out.println("  --no-rename            disable renaming");
        System.out.println("  --no-string            disable string encryption");
        System.out.println("  --no-integer           disable integer constant encryption");
        System.out.println("  --flatten              enable state-machine control-flow flattening");
        System.out.println("  --no-flow              disable control-flow obfuscation");
        System.out.println("  --no-shuffle           disable member shuffling");
        System.out.println("  --no-junk              disable junk members");
        System.out.println("  --no-watermark         disable watermark");
        System.out.println("  -v, --verbose          verbose logging");
        System.out.println("  -q, --quiet            only warnings and errors");
        System.out.println("  -h, --help             show this help");
        System.out.println("  --version              print version");
        System.out.println();
        System.out.println("Run without arguments (or with --gui) to start the desktop console.");
        System.out.println("The console ships as umbra-gui-fx.jar next to this jar and needs a JDK 8 with JavaFX.");
    }

    private static final class Args {
        String config;
        String input;
        String output;
        final List<String> libraries = new ArrayList<String>();
        final List<String> keep = new ArrayList<String>();
        String preset;
        boolean keepPublicApi;
        boolean softKeepPublicApi;
        boolean noReflection;
        boolean trim;
        boolean parameterObfuscation;
        boolean rewriteResources;
        boolean referenceObfuscation;
        boolean referenceVirtual;
        boolean referenceFields;
        boolean referenceConstructors;
        boolean exceptionObfuscation;
        boolean virtualize;
        Integer virtualizeMaxInstructions;
        Integer virtualizeMaxMethods;
        boolean antiLlm;
        Integer antiLlmDecoys;
        Integer antiLlmLayers;
        boolean authGate;
        String authServer;
        String authSoftware;
        String authTitle;
        boolean authNoRegister;
        String authCache;
        Integer authTimeout;
        final List<String> authEntries = new ArrayList<String>();
        String incrementalPrevious;
        String incrementalMetadata;
        boolean antiDebug;
        String dictionary;
        Integer minNameLength;
        String mappingFile;
        final List<String> licenseFeatures = new ArrayList<String>();
        /** Advanced options in {@code key=value} form; see docs/OPTIONS.md. */
        final List<String> sets = new ArrayList<String>();
        String inputMapping;
        String reportHtml;
        String reportJson;
        boolean inspect;
        String inspectJson;

        String compatReport;
        String diffOld;
        String diffNew;
        String traceWatermark;
        String license;
        String licenseKey;
        String licenseServer;
        boolean requireLicense;
        Long seed;
        /** Prints the effective option values of a preset and exits. */
        String dumpPreset;
        boolean dryRun;
        boolean verify;
        boolean allowInPlace;
        boolean fixedTime;
        boolean noRename;
        boolean noString;
        boolean noInteger;
        boolean noFlow;
        boolean flatten;
        boolean noShuffle;
        boolean noJunk;
        boolean noWatermark;
        boolean verbose;
        boolean quiet;
        boolean help;
        boolean version;

        static Args parse(String[] argv) throws ConfigException {
            Args a = new Args();
            for (int i = 0; i < argv.length; i++) {
                String arg = argv[i];
                if ("-c".equals(arg) || "--config".equals(arg)) {
                    a.config = value(argv, ++i, arg);
                } else if ("-i".equals(arg) || "--input".equals(arg)) {
                    a.input = value(argv, ++i, arg);
                } else if ("-o".equals(arg) || "--output".equals(arg)) {
                    a.output = value(argv, ++i, arg);
                } else if ("--lib".equals(arg) || "--library".equals(arg)) {
                    a.libraries.add(value(argv, ++i, arg));
                } else if ("--keep".equals(arg)) {
                    for (String part : value(argv, ++i, arg).split(",")) {
                        if (!part.trim().isEmpty()) {
                            a.keep.add(part.trim());
                        }
                    }
                } else if ("--preset".equals(arg)) {
                    a.preset = value(argv, ++i, arg);
                } else if ("--keep-public-api".equals(arg)) {
                    a.keepPublicApi = true;
                } else if ("--soft-keep-public-api".equals(arg)) {
                    a.softKeepPublicApi = true;
                } else if ("--reflection-off".equals(arg)) {
                    a.noReflection = true;
                } else if ("--trim".equals(arg)) {
                    a.trim = true;
                } else if ("--parameter-obfuscation".equals(arg)) {
                    a.parameterObfuscation = true;
                } else if ("--rewrite-resources".equals(arg)) {
                    a.rewriteResources = true;
                } else if ("--reference-obfuscation".equals(arg)) {
                    a.referenceObfuscation = true;
                } else if ("--reference-virtual".equals(arg)) {
                    a.referenceVirtual = true;
                } else if ("--reference-fields".equals(arg)) {
                    a.referenceFields = true;
                } else if ("--reference-constructors".equals(arg)) {
                    a.referenceConstructors = true;
                } else if ("--exception-obfuscation".equals(arg)) {
                    a.exceptionObfuscation = true;
                } else if ("--virtualize".equals(arg)) {
                    a.virtualize = true;
                } else if ("--virtualize-max-instructions".equals(arg)) {
                    a.virtualizeMaxInstructions = Integer.valueOf(intValue(argv, ++i, arg));
                } else if ("--virtualize-max-methods".equals(arg)) {
                    a.virtualizeMaxMethods = Integer.valueOf(intValue(argv, ++i, arg));
                } else if ("--anti-llm".equals(arg)) {
                    a.antiLlm = true;
                } else if ("--anti-llm-decoys".equals(arg)) {
                    a.antiLlmDecoys = Integer.valueOf(intValue(argv, ++i, arg));
                } else if ("--anti-llm-layers".equals(arg)) {
                    a.antiLlmLayers = Integer.valueOf(intValue(argv, ++i, arg));
                } else if ("--auth-gate".equals(arg)) {
                    a.authGate = true;
                } else if ("--auth-server".equals(arg)) {
                    a.authServer = value(argv, ++i, arg);
                    a.authGate = true;
                } else if ("--auth-software".equals(arg)) {
                    a.authSoftware = value(argv, ++i, arg);
                    a.authGate = true;
                } else if ("--auth-title".equals(arg)) {
                    a.authTitle = value(argv, ++i, arg);
                    a.authGate = true;
                } else if ("--auth-no-register".equals(arg)) {
                    a.authNoRegister = true;
                    a.authGate = true;
                } else if ("--auth-cache".equals(arg)) {
                    a.authCache = value(argv, ++i, arg);
                    a.authGate = true;
                } else if ("--auth-timeout".equals(arg)) {
                    a.authTimeout = Integer.valueOf(intValue(argv, ++i, arg));
                    a.authGate = true;
                } else if ("--auth-entry".equals(arg)) {
                    for (String part : value(argv, ++i, arg).split(",")) {
                        if (!part.trim().isEmpty()) {
                            a.authEntries.add(part.trim());
                        }
                    }
                    a.authGate = true;
                } else if ("--incremental".equals(arg)) {
                    a.incrementalPrevious = value(argv, ++i, arg);
                } else if ("--incremental-metadata".equals(arg)) {
                    a.incrementalMetadata = value(argv, ++i, arg);
                } else if ("--anti-debug".equals(arg)) {
                    a.antiDebug = true;
                } else if ("--dictionary".equals(arg)) {
                    a.dictionary = value(argv, ++i, arg);
                } else if ("--min-name-length".equals(arg)) {
                    a.minNameLength = Integer.valueOf(intValue(argv, ++i, arg));
                } else if ("--mapping".equals(arg)) {
                    a.mappingFile = value(argv, ++i, arg);
                } else if ("--require-feature".equals(arg)) {
                    a.licenseFeatures.add(value(argv, ++i, arg));
                } else if ("--input-mapping".equals(arg)) {
                    a.inputMapping = value(argv, ++i, arg);
                } else if ("--report".equals(arg)) {
                    a.reportHtml = value(argv, ++i, arg);
                } else if ("--report-json".equals(arg)) {
                    a.reportJson = value(argv, ++i, arg);
                } else if ("--inspect".equals(arg)) {
                    a.inspect = true;
                } else if ("--inspect-json".equals(arg)) {
                    a.inspect = true;
                    a.inspectJson = value(argv, ++i, arg);
                } else if ("--dump-preset".equals(arg)) {
                    a.dumpPreset = value(argv, ++i, arg);

                } else if ("--compat-report".equals(arg)) {
                    a.compatReport = value(argv, ++i, arg);
                } else if ("--diff-mapping".equals(arg)) {
                    a.diffOld = value(argv, ++i, arg);
                    a.diffNew = value(argv, ++i, arg);
                } else if ("--trace-watermark".equals(arg)) {
                    a.traceWatermark = value(argv, ++i, arg);
                } else if ("--license".equals(arg)) {
                    a.license = value(argv, ++i, arg);
                } else if ("--license-key".equals(arg)) {
                    a.licenseKey = value(argv, ++i, arg);
                } else if ("--license-server".equals(arg)) {
                    a.licenseServer = value(argv, ++i, arg);
                } else if ("--require-license".equals(arg)) {
                    a.requireLicense = true;
                } else if ("--seed".equals(arg)) {
                    a.seed = Long.valueOf(longValue(argv, ++i, arg));
                } else if ("--set".equals(arg) || "-D".equals(arg)) {
                    a.sets.add(value(argv, ++i, arg));
                } else if ("--dry-run".equals(arg)) {
                    a.dryRun = true;
                } else if ("--verify".equals(arg)) {
                    a.verify = true;
                } else if ("--fixed-time".equals(arg)) {
                    a.fixedTime = true;
                } else if ("--allow-in-place".equals(arg)) {
                    a.allowInPlace = true;
                } else if ("--no-rename".equals(arg)) {
                    a.noRename = true;
                } else if ("--no-string".equals(arg)) {
                    a.noString = true;
                } else if ("--no-integer".equals(arg)) {
                    a.noInteger = true;
                } else if ("--flatten".equals(arg)) {
                    a.flatten = true;
                } else if ("--no-flow".equals(arg)) {
                    a.noFlow = true;
                } else if ("--no-shuffle".equals(arg)) {
                    a.noShuffle = true;
                } else if ("--no-junk".equals(arg)) {
                    a.noJunk = true;
                } else if ("--no-watermark".equals(arg)) {
                    a.noWatermark = true;
                } else if ("-v".equals(arg) || "--verbose".equals(arg)) {
                    a.verbose = true;
                } else if ("-q".equals(arg) || "--quiet".equals(arg)) {
                    a.quiet = true;
                } else if ("-h".equals(arg) || "--help".equals(arg)) {
                    a.help = true;
                } else if ("--version".equals(arg)) {
                    a.version = true;
                } else {
                    throw new ConfigException("Unknown argument: " + arg);
                }
            }
            validate(a);
            return a;
        }

        /** Rejects out-of-range values before the config builder clamps them silently. */
        private static void validate(Args a) throws ConfigException {
            if (a.virtualizeMaxInstructions != null && a.virtualizeMaxInstructions.intValue() < 0) {
                throw new ConfigException("--virtualize-max-instructions must be >= 0");
            }
            if (a.virtualizeMaxMethods != null && a.virtualizeMaxMethods.intValue() < 0) {
                throw new ConfigException("--virtualize-max-methods must be >= 0");
            }
            if (a.antiLlmDecoys != null && a.antiLlmDecoys.intValue() < 0) {
                throw new ConfigException("--anti-llm-decoys must be >= 0");
            }
            if (a.antiLlmLayers != null
                    && (a.antiLlmLayers.intValue() < 0 || a.antiLlmLayers.intValue() > 4)) {
                throw new ConfigException("--anti-llm-layers must be between 0 and 4");
            }
            if (a.authTimeout != null && a.authTimeout.intValue() < 0) {
                throw new ConfigException("--auth-timeout must be >= 0");
            }
            if (a.minNameLength != null && a.minNameLength.intValue() < 0) {
                throw new ConfigException("--min-name-length must be >= 0");
            }
        }

        private static String value(String[] argv, int index, String option) throws ConfigException {
            if (index >= argv.length) {
                throw new ConfigException("Missing value for " + option);
            }
            return argv[index];
        }

        private static int intValue(String[] argv, int index, String option) throws ConfigException {
            String raw = value(argv, index, option).trim();
            try {
                return Integer.parseInt(raw);
            } catch (NumberFormatException e) {
                throw new ConfigException("Invalid integer for " + option + ": " + raw);
            }
        }

        private static long longValue(String[] argv, int index, String option) throws ConfigException {
            String raw = value(argv, index, option).trim();
            try {
                return Long.parseLong(raw);
            } catch (NumberFormatException e) {
                throw new ConfigException("Invalid number for " + option + ": " + raw);
            }
        }
    }
}
