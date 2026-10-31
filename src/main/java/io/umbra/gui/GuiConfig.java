package io.umbra.gui;

import io.umbra.core.config.ConfigWriter;
import io.umbra.core.config.UmbraConfig;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Builds an {@link UmbraConfig} from the desktop GUI's controls and keeps the
 * GUI, YAML and CLI on the same option vocabulary.
 *
 * <p>The GUI owns a curated set of toggles; each toggle writes one
 * {@code key=value} entry into the advanced option map (see
 * {@link GuiSwitches}). This class adds conservative 3.0 defaults for options
 * the current build knows about, fills the typed configuration sections, and
 * resolves the mapping file location.</p>
 */
public final class GuiConfig {

    /** Stable version string shown by the desktop GUI. */
    public static final String VERSION = "3.2.2";

    private GuiConfig() {
    }

    /**
     * Default output next to the input: {@code app.jar} -> {@code app-obf.jar}.
     * Returns an empty string when no input is selected.
     */
    public static String defaultOutput(Path input) {
        if (input == null) {
            return "";
        }
        Path fileName = input.getFileName();
        if (fileName == null) {
            return "";
        }
        String name = fileName.toString();
        String base = name.toLowerCase(Locale.ROOT).endsWith(".jar")
                ? name.substring(0, name.length() - 4) : name;
        Path parent = input.getParent();
        Path suggested = parent == null
                ? Paths.get(base + "-obf.jar")
                : parent.resolve(base + "-obf.jar");
        return suggested.toAbsolutePath().toString();
    }

    /**
     * Builds the run configuration.
     *
     * @param input         input JAR
     * @param output        output JAR
     * @param seed          deterministic seed
     * @param options       advanced options (same keys as the CLI {@code --set})
     * @param mappingTarget mapping file path; a directory resolves to
     *                      {@code umbra-mapping.txt} inside it, {@code null}
     *                      places the mapping next to the output
     * @return validated configuration
     * @throws Exception when the configuration is incomplete
     */
    public static UmbraConfig build(Path input, Path output, long seed,
                                    Map<String, String> options, Path mappingTarget)
            throws Exception {
        Map<String, String> opts = options == null
                ? new LinkedHashMap<String, String>() : new LinkedHashMap<String, String>(options);

        // Anti-debug is expressed as a level in the engine; the GUI exposes a
        // single switch that maps to level 2.
        if (!opts.containsKey("antiDebug.level") && opts.containsKey("antiDebug.enabled")) {
            opts.put("antiDebug.level", bool(opts, "antiDebug.enabled", false) ? "2" : "0");
        }
        int antiDebugLevel = Math.max(0, Math.min(3, intOption(opts, "antiDebug.level", 0)));
        opts.put("antiDebug.level", String.valueOf(antiDebugLevel));
        if (antiDebugLevel > 0) {
            opts.put("antiDebug.nativeGuard", "true");
        }

        // Conservative defaults for the 3.0 option surface. The GUI normally
        // sends every one of these explicitly through its switches; the defaults
        // keep programmatic and legacy callers working.
        defaultPut(opts, "string.strength", "2");
        defaultPut(opts, "nocturne.encoding", "arx");
        defaultPut(opts, "string.engine", "auto");
        defaultPut(opts, "string.stackTraceHide", "true");
        defaultPut(opts, "string.wipe", "true");
        defaultPut(opts, "flow.aggressive", "false");
        defaultPut(opts, "reflectionGate.enabled", "false");
        defaultPut(opts, "typeConfusion.enabled", "false");
        defaultPut(opts, "vm2.fusion", "true");
        defaultPut(opts, "native.antiDump", "true");
        defaultPut(opts, "layout.springBoot", "true");
        defaultPut(opts, "layout.war", "true");
        defaultPut(opts, "layout.multiRelease", "preserve");
        defaultPut(opts, "layout.moduleInfo", "auto");

        String mappingFile = resolveMappingFile(output, mappingTarget, opts);

        UmbraConfig.Builder b = new UmbraConfig.Builder()
                .input(input)
                .output(output)
                .seed(seed)
                .options(opts);
        b.preset("");

        boolean renamer = bool(opts, "renamer.enabled", true);
        b.renamer(new UmbraConfig.RenamerOptions(renamer,
                str(opts, "renamer.prefix", ""),
                bool(opts, "renamer.repackage", true),
                "",
                bool(opts, "renamer.renameClasses", true),
                bool(opts, "renamer.renameMethods", true),
                bool(opts, "renamer.renameFields", true),
                mappingFile,
                str(opts, "renamer.dictionary",
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                intOption(opts, "renamer.minimumNameLength", 1)));
        b.keepPublicApi(bool(opts, "keepPublicApi", false));

        b.stringEncryption(new UmbraConfig.StringEncryptionOptions(
                bool(opts, "stringEncryption.enabled", true),
                intOption(opts, "stringEncryption.minLength", 2)));
        b.integerEncryption(new UmbraConfig.IntegerEncryptionOptions(
                bool(opts, "integerEncryption.enabled", true),
                bool(opts, "integerEncryption.includeLong", true)));

        b.flow(new UmbraConfig.FlowOptions(
                bool(opts, "flowObfuscation.enabled", true),
                str(opts, "flowObfuscation.level",
                        bool(opts, "flow.aggressive", false) ? "normal" : "light"),
                intOption(opts, "flowObfuscation.maxInstructions", 8000),
                bool(opts, "flowObfuscation.flattening", true)));
        b.exceptionObfuscation(new UmbraConfig.ExceptionOptions(
                bool(opts, "exceptionObfuscation.enabled", true)));
        b.methodVirtualization(new UmbraConfig.VirtualizationOptions(
                bool(opts, "methodVirtualization.enabled", true), 4000, 0));
        b.antiLlm(new UmbraConfig.AntiLlmOptions(
                bool(opts, "antiLlm.enabled", true),
                intOption(opts, "antiLlm.decoyMethodsPerClass", 2),
                intOption(opts, "antiLlm.decoyCallSitesPerClass", 2),
                intOption(opts, "antiLlm.wrapperLayers", 1),
                intOption(opts, "antiLlm.maxWrappedMethodsPerClass", 12),
                bool(opts, "antiLlm.shieldVirtualization", true)));

        b.debug(new UmbraConfig.DebugOptions(
                bool(opts, "debugInfo.enabled", true), true, true, true, false, false, true));
        b.shuffle(new UmbraConfig.ShuffleOptions(true));
        b.junk(new UmbraConfig.JunkOptions(true, 2, 2));
        b.trim(new UmbraConfig.TrimOptions(false, true, true));
        b.parameterObfuscation(new UmbraConfig.ParameterOptions(false));
        b.invokeWrapper(new UmbraConfig.WrapperOptions(false, 200));
        b.referenceObfuscation(new UmbraConfig.ReferenceOptions(false));
        b.resources(new UmbraConfig.ResourceOptions(false));
        b.watermark(new UmbraConfig.WatermarkOptions(
                bool(opts, "watermark.enabled", true), "umbra"));
        b.reflection(new UmbraConfig.ReflectionOptions(
                bool(opts, "reflection.enabled", true),
                bool(opts, "reflection.rewriteClassStrings", false)));
        b.mapping(new UmbraConfig.MappingOptions(true, mappingFile,
                str(opts, "mapping.inputFile", "")));

        b.antiDebug(antiDebugLevel > 0);
        return b.build();
    }

    /** Serializes a configuration to the YAML dialect the CLI reads back. */
    public static String toYaml(UmbraConfig config) {
        return ConfigWriter.toYaml(config);
    }

    /**
     * Effective option map of a configuration: typed sections first, then the
     * raw advanced options (which win, exactly like the CLI).
     */
    public static Map<String, String> describe(UmbraConfig config) {
        Map<String, String> map = new LinkedHashMap<String, String>();
        map.put("renamer.enabled", String.valueOf(config.renamer().enabled()));
        map.put("renamer.renameClasses", String.valueOf(config.renamer().renameClasses()));
        map.put("renamer.renameMethods", String.valueOf(config.renamer().renameMethods()));
        map.put("renamer.renameFields", String.valueOf(config.renamer().renameFields()));
        map.put("renamer.repackage", String.valueOf(config.renamer().repackage()));
        map.put("renamer.prefix", config.renamer().prefix());
        map.put("renamer.dictionary", config.renamer().dictionary());
        map.put("renamer.minimumNameLength", String.valueOf(config.renamer().minimumNameLength()));
        map.put("keepPublicApi", String.valueOf(config.keepPublicApi()));
        map.put("stringEncryption.enabled", String.valueOf(config.stringEncryption().enabled()));
        map.put("integerEncryption.enabled", String.valueOf(config.integerEncryption().enabled()));
        map.put("flowObfuscation.enabled", String.valueOf(config.flow().enabled()));
        map.put("flowObfuscation.flattening", String.valueOf(config.flow().flattening()));
        map.put("flowObfuscation.level", config.flow().level());
        map.put("exceptionObfuscation.enabled",
                String.valueOf(config.exceptionObfuscation().enabled()));
        map.put("methodVirtualization.enabled",
                String.valueOf(config.methodVirtualization().enabled()));
        map.put("antiLlm.enabled", String.valueOf(config.antiLlm().enabled()));
        map.put("antiLlm.decoyMethodsPerClass",
                String.valueOf(config.antiLlm().decoyMethodsPerClass()));
        map.put("antiLlm.decoyCallSitesPerClass",
                String.valueOf(config.antiLlm().decoyCallSitesPerClass()));
        map.put("antiLlm.wrapperLayers", String.valueOf(config.antiLlm().wrapperLayers()));
        map.put("antiLlm.maxWrappedMethodsPerClass",
                String.valueOf(config.antiLlm().maxWrappedMethodsPerClass()));
        map.put("antiLlm.shieldVirtualization",
                String.valueOf(config.antiLlm().shieldVirtualization()));
        map.put("watermark.enabled", String.valueOf(config.watermark().enabled()));
        map.put("reflection.enabled", String.valueOf(config.reflection().enabled()));
        map.put("mapping.file", config.mapping().file());
        map.put("antiDebug.level", config.option("antiDebug.level",
                config.antiDebug() ? "2" : "0"));
        map.putAll(config.options());
        return map;
    }

    private static String resolveMappingFile(Path output, Path mappingTarget,
                                             Map<String, String> opts) {
        String explicit = opts.get("mapping.file");
        if (explicit != null && !explicit.trim().isEmpty()) {
            return explicit.trim();
        }
        Path base = mappingTarget;
        if (base == null) {
            base = output == null || output.getParent() == null
                    ? Paths.get(".") : output.getParent();
        }
        String name = base.getFileName() == null ? "" : base.getFileName().toString();
        boolean looksLikeFile = name.indexOf('.') > 0
                && !name.toLowerCase(Locale.ROOT).endsWith(".jar");
        if (looksLikeFile) {
            return base.toAbsolutePath().toString();
        }
        return base.resolve("umbra-mapping.txt").toAbsolutePath().toString();
    }

    private static void defaultPut(Map<String, String> options, String key, String value) {
        if (!options.containsKey(key)) {
            options.put(key, value);
        }
    }

    private static String str(Map<String, String> options, String key, String def) {
        String value = options.get(key);
        return value == null || value.trim().isEmpty() ? def : value.trim();
    }

    private static boolean bool(Map<String, String> options, String key, boolean def) {
        String value = options.get(key);
        if (value == null) {
            return def;
        }
        String v = value.trim().toLowerCase(Locale.ROOT);
        return "true".equals(v) || "on".equals(v) || "yes".equals(v) || "1".equals(v);
    }

    private static int intOption(Map<String, String> options, String key, int def) {
        try {
            String value = options.get(key);
            return value == null || value.trim().isEmpty() ? def : Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    /** Returns true when the output path is usable and not the input itself. */
    public static String validate(Path input, Path output) {
        if (input == null || !Files.isRegularFile(input)) {
            return "Select an existing input JAR.";
        }
        if (output == null || output.getFileName() == null) {
            return "Select an output JAR path.";
        }
        if (!output.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar")) {
            return "The output file must end with .jar.";
        }
        try {
            if (Files.exists(output) && Files.isSameFile(input, output)) {
                return "Input and output must be different files.";
            }
        } catch (Exception ignored) {
            // A non-existent output cannot be the same file.
        }
        Path parent = output.toAbsolutePath().getParent();
        if (parent == null) {
            return "The output directory is invalid.";
        }
        if (Files.exists(parent) && !Files.isDirectory(parent)) {
            return "The output path is not a directory.";
        }
        if (Files.isDirectory(output)) {
            return "The output path is a directory; choose a .jar file.";
        }
        return null;
    }
}
