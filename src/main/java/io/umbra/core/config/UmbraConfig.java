package io.umbra.core.config;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Immutable Umbra configuration.
 *
 * <p>Instances are created through {@link Builder}; the CLI, the GUI and tests
 * all build the same model so that a configuration round-trips between them.</p>
 */
public final class UmbraConfig {

    private final Path input;
    private final Path output;
    private final List<Path> libraries;
    private final List<String> keep;
    private final List<String> softKeep;
    private final long seed;
    private final boolean preserveTimestamps;
    private final boolean dryRun;
    private final String preset;
    private final boolean keepPublicApi;
    private final boolean softKeepPublicApi;
    private final ReportOptions report;
    private final ReflectionOptions reflection;
    private final TrimOptions trim;
    private final ParameterOptions parameterObfuscation;
    private final LicenseOptions license;
    private final ResourceOptions resources;
    private final ReferenceOptions referenceObfuscation;
    private final ExceptionOptions exceptionObfuscation;
    private final IncrementalOptions incremental;
    private final VirtualizationOptions methodVirtualization;
    private final AntiLlmOptions antiLlm;
    private final AuthGateOptions authGate;
    private final boolean antiDebug;

    private final RenamerOptions renamer;
    private final StringEncryptionOptions stringEncryption;
    private final IntegerEncryptionOptions integerEncryption;
    private final FlowOptions flow;
    private final DebugOptions debug;
    private final ShuffleOptions shuffle;
    private final WrapperOptions invokeWrapper;
    private final WatermarkOptions watermark;
    private final MappingOptions mapping;
    private final JunkOptions junk;
    /**
     * Free-form advanced options ({@code options:} YAML section).
     *
     * <p>Each newer protection pass owns its own namespaced keys (for example
     * {@code native.enabled}, {@code vm2.encryptPayload},
     * {@code classEncryption.integrity}). Keeping them in one typed map avoids a
     * schema change for every knob while still giving the CLI, YAML, JSON and
     * GUI one shared representation.</p>
     */
    private final Map<String, String> options;

    private UmbraConfig(Builder b) {
        this.input = b.input;
        this.output = b.output;
        this.libraries = Collections.unmodifiableList(new ArrayList<Path>(b.libraries));
        this.keep = Collections.unmodifiableList(new ArrayList<String>(b.keep));
        this.softKeep = Collections.unmodifiableList(new ArrayList<String>(b.softKeep));
        this.seed = b.seed;
        this.preserveTimestamps = b.preserveTimestamps;
        this.dryRun = b.dryRun;
        this.preset = b.preset;
        this.keepPublicApi = b.keepPublicApi;
        this.softKeepPublicApi = b.softKeepPublicApi;
        this.report = b.report;
        this.reflection = b.reflection;
        this.trim = b.trim;
        this.parameterObfuscation = b.parameterObfuscation;
        this.license = b.license;
        this.resources = b.resources;
        this.referenceObfuscation = b.referenceObfuscation;
        this.exceptionObfuscation = b.exceptionObfuscation;
        this.incremental = b.incremental;
        this.methodVirtualization = b.methodVirtualization;
        this.antiLlm = b.antiLlm;
        this.authGate = b.authGate;
        this.antiDebug = b.antiDebug;
        this.renamer = b.renamer;
        this.stringEncryption = b.stringEncryption;
        this.integerEncryption = b.integerEncryption;
        this.flow = b.flow;
        this.debug = b.debug;
        this.shuffle = b.shuffle;
        this.invokeWrapper = b.invokeWrapper;
        this.watermark = b.watermark;
        this.mapping = b.mapping;
        this.junk = b.junk;
        this.options = Collections.unmodifiableMap(new LinkedHashMap<String, String>(b.options));
    }

    public Path input() { return input; }
    public Path output() { return output; }
    public List<Path> libraries() { return libraries; }
    public List<String> keep() { return keep; }
    public List<String> softKeep() { return softKeep; }
    public long seed() { return seed; }
    public boolean preserveTimestamps() { return preserveTimestamps; }
    public boolean dryRun() { return dryRun; }
    public String preset() { return preset; }
    public boolean keepPublicApi() { return keepPublicApi; }
    public boolean softKeepPublicApi() { return softKeepPublicApi; }
    public ReportOptions report() { return report; }
    public ReflectionOptions reflection() { return reflection; }
    public TrimOptions trim() { return trim; }
    public ParameterOptions parameterObfuscation() { return parameterObfuscation; }
    public LicenseOptions license() { return license; }
    public ResourceOptions resources() { return resources; }
    public ReferenceOptions referenceObfuscation() { return referenceObfuscation; }
    public ExceptionOptions exceptionObfuscation() { return exceptionObfuscation; }
    public IncrementalOptions incremental() { return incremental; }
    public VirtualizationOptions methodVirtualization() { return methodVirtualization; }
    public AntiLlmOptions antiLlm() { return antiLlm; }
    public AuthGateOptions authGate() { return authGate; }
    public boolean antiDebug() { return antiDebug; }
    public RenamerOptions renamer() { return renamer; }
    public StringEncryptionOptions stringEncryption() { return stringEncryption; }
    public IntegerEncryptionOptions integerEncryption() { return integerEncryption; }
    public FlowOptions flow() { return flow; }
    public DebugOptions debug() { return debug; }
    public ShuffleOptions shuffle() { return shuffle; }
    public WrapperOptions invokeWrapper() { return invokeWrapper; }
    public WatermarkOptions watermark() { return watermark; }
    public MappingOptions mapping() { return mapping; }
    public JunkOptions junk() { return junk; }

    /** Immutable advanced-option map (never {@code null}). */
    public Map<String, String> options() { return options; }

    /** Returns an advanced option or {@code def} when it is absent. */
    public String option(String key, String def) {
        String value = options.get(key);
        return value == null ? def : value;
    }

    /** Returns a boolean advanced option (accepts true/false/yes/no/1/0/on/off). */
    public boolean optionBool(String key, boolean def) {
        String value = options.get(key);
        if (value == null) {
            return def;
        }
        String v = value.trim().toLowerCase(java.util.Locale.ROOT);
        if ("true".equals(v) || "yes".equals(v) || "1".equals(v) || "on".equals(v)) {
            return true;
        }
        if ("false".equals(v) || "no".equals(v) || "0".equals(v) || "off".equals(v)) {
            return false;
        }
        return def;
    }

    /** Returns an int advanced option or {@code def} when absent or malformed. */
    public int optionInt(String key, int def) {
        String value = options.get(key);
        if (value == null) {
            return def;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    /** Returns a long advanced option or {@code def} when absent or malformed. */
    public long optionLong(String key, long def) {
        String value = options.get(key);
        if (value == null) {
            return def;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    /** Returns a double advanced option or {@code def} when absent or malformed. */
    public double optionDouble(String key, double def) {
        String value = options.get(key);
        if (value == null) {
            return def;
        }
        try {
            return Double.parseDouble(value.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    /** Returns a builder pre-populated with this configuration. */
    public Builder toBuilder() {
        Builder b = new Builder();
        b.input = input;
        b.output = output;
        b.libraries.addAll(libraries);
        b.keep.addAll(keep);
        b.softKeep.addAll(softKeep);
        b.seed = seed;
        b.preserveTimestamps = preserveTimestamps;
        b.dryRun = dryRun;
        b.preset = preset;
        b.keepPublicApi = keepPublicApi;
        b.softKeepPublicApi = softKeepPublicApi;
        b.report = report;
        b.reflection = reflection;
        b.trim = trim;
        b.parameterObfuscation = parameterObfuscation;
        b.license = license;
        b.resources = resources;
        b.referenceObfuscation = referenceObfuscation;
        b.exceptionObfuscation = exceptionObfuscation;
        b.incremental = incremental;
        b.methodVirtualization = methodVirtualization;
        b.antiLlm = antiLlm;
        b.authGate = authGate;
        b.antiDebug = antiDebug;
        b.renamer = renamer;
        b.stringEncryption = stringEncryption;
        b.integerEncryption = integerEncryption;
        b.flow = flow;
        b.debug = debug;
        b.shuffle = shuffle;
        b.invokeWrapper = invokeWrapper;
        b.watermark = watermark;
        b.mapping = mapping;
        b.junk = junk;
        b.options.putAll(options);
        return b;
    }

    /** Mutable builder with production defaults. */
    public static final class Builder {
        private Path input;
        private Path output;
        private final List<Path> libraries = new ArrayList<Path>();
        private final List<String> keep = new ArrayList<String>();
        private final List<String> softKeep = new ArrayList<String>();
        private long seed = 0x5A17L;
        private boolean preserveTimestamps = true;
        private boolean dryRun = false;
        private String preset = "";
        private boolean keepPublicApi = false;
        private boolean softKeepPublicApi = false;
        private ReportOptions report = new ReportOptions(false, "", "");
        private ReflectionOptions reflection = new ReflectionOptions(true);
        private TrimOptions trim = new TrimOptions(false, true, true);
        private ParameterOptions parameterObfuscation = new ParameterOptions(false);
        private LicenseOptions license = new LicenseOptions(false, "", "", false);
        private ResourceOptions resources = new ResourceOptions(false);
        private ReferenceOptions referenceObfuscation = new ReferenceOptions(false);
        private ExceptionOptions exceptionObfuscation = new ExceptionOptions(false);
        private IncrementalOptions incremental = new IncrementalOptions(false, "", "umbra-incremental.tsv");
        private VirtualizationOptions methodVirtualization = new VirtualizationOptions(false, 2000, 0);
        private AntiLlmOptions antiLlm = new AntiLlmOptions(false, 2, 2, 1, 12, true);
        private AuthGateOptions authGate = new AuthGateOptions(false, "", "", "Software Authorization",
                true, "", 5000, Collections.<String>emptyList());
        private boolean antiDebug = false;

        private RenamerOptions renamer = new RenamerOptions(true, "", false, "", true, true, true,
                "umbra-mapping.txt", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 1);
        private StringEncryptionOptions stringEncryption = new StringEncryptionOptions(true, 2);
        private IntegerEncryptionOptions integerEncryption = new IntegerEncryptionOptions(true, true);
        private FlowOptions flow = new FlowOptions(true, "light", 8000);
        private DebugOptions debug = new DebugOptions(true, true, true, true, true, false, true);
        private ShuffleOptions shuffle = new ShuffleOptions(true);
        private WrapperOptions invokeWrapper = new WrapperOptions(false, 200);
        private WatermarkOptions watermark = new WatermarkOptions(true, "umbra");
        private MappingOptions mapping = new MappingOptions(true, "umbra-mapping.txt", "");
        private JunkOptions junk = new JunkOptions(true, 2, 2);
        private final Map<String, String> options = new LinkedHashMap<String, String>();

        public Builder input(Path value) { this.input = value; return this; }
        public Builder output(Path value) { this.output = value; return this; }
        public Builder addLibrary(Path value) { if (value != null) this.libraries.add(value); return this; }
        public Builder libraries(List<Path> values) { this.libraries.clear(); if (values != null) this.libraries.addAll(values); return this; }
        public Builder keep(List<String> values) { this.keep.clear(); if (values != null) this.keep.addAll(values); return this; }
        public Builder softKeep(List<String> values) { this.softKeep.clear(); if (values != null) this.softKeep.addAll(values); return this; }
        public Builder seed(long value) { this.seed = value; return this; }
        public Builder preserveTimestamps(boolean value) { this.preserveTimestamps = value; return this; }
        public Builder dryRun(boolean value) { this.dryRun = value; return this; }
        public Builder preset(String value) { this.preset = value == null ? "" : value; return this; }
        public Builder keepPublicApi(boolean value) { this.keepPublicApi = value; return this; }
        public Builder softKeepPublicApi(boolean value) { this.softKeepPublicApi = value; return this; }
        public Builder report(ReportOptions value) { this.report = value; return this; }
        public Builder reflection(ReflectionOptions value) { this.reflection = value; return this; }
        public Builder trim(TrimOptions value) { this.trim = value; return this; }
        public Builder parameterObfuscation(ParameterOptions value) { this.parameterObfuscation = value; return this; }
        public Builder license(LicenseOptions value) { this.license = value; return this; }
        public Builder resources(ResourceOptions value) { this.resources = value; return this; }
        public Builder referenceObfuscation(ReferenceOptions value) { this.referenceObfuscation = value; return this; }
        public Builder exceptionObfuscation(ExceptionOptions value) { this.exceptionObfuscation = value; return this; }
        public Builder incremental(IncrementalOptions value) { this.incremental = value; return this; }
        public Builder methodVirtualization(VirtualizationOptions value) { this.methodVirtualization = value; return this; }
        public Builder antiLlm(AntiLlmOptions value) { this.antiLlm = value; return this; }
        public Builder authGate(AuthGateOptions value) { this.authGate = value; return this; }
        public Builder antiDebug(boolean value) { this.antiDebug = value; return this; }
        public Builder renamer(RenamerOptions value) { this.renamer = value; return this; }
        public Builder stringEncryption(StringEncryptionOptions value) { this.stringEncryption = value; return this; }
        public Builder integerEncryption(IntegerEncryptionOptions value) { this.integerEncryption = value; return this; }
        public Builder flow(FlowOptions value) { this.flow = value; return this; }
        public Builder debug(DebugOptions value) { this.debug = value; return this; }
        public Builder shuffle(ShuffleOptions value) { this.shuffle = value; return this; }
        public Builder invokeWrapper(WrapperOptions value) { this.invokeWrapper = value; return this; }
        public Builder watermark(WatermarkOptions value) { this.watermark = value; return this; }
        public Builder mapping(MappingOptions value) { this.mapping = value; return this; }
        public Builder junk(JunkOptions value) { this.junk = value; return this; }
        /** Replaces the advanced-option map. */
        public Builder options(Map<String, String> values) {
            this.options.clear();
            if (values != null) {
                for (Map.Entry<String, String> entry : values.entrySet()) {
                    if (entry.getKey() != null && entry.getValue() != null) {
                        this.options.put(entry.getKey().trim(), entry.getValue());
                    }
                }
            }
            return this;
        }
        /** Adds or replaces one advanced option. */
        public Builder option(String key, String value) {
            if (key != null && !key.trim().isEmpty()) {
                this.options.put(key.trim(), value == null ? "" : value);
            }
            return this;
        }

        public UmbraConfig build() throws ConfigException {
            return build(true);
        }

        /**
         * Builds a configuration, optionally allowing {@code input}/{@code output}
         * to stay unset. The lenient mode exists for configuration-file loading in
         * front ends (CLI) that apply {@code -i}/{@code -o} overrides afterwards;
         * callers must build strictly again before running the engine.
         *
         * @param requirePaths whether {@code input} and {@code output} are mandatory
         * @return immutable configuration
         * @throws ConfigException when a required path is missing
         */
        public UmbraConfig build(boolean requirePaths) throws ConfigException {
            if (requirePaths) {
                if (input == null) {
                    throw new ConfigException("Missing required configuration key: input");
                }
                if (output == null) {
                    throw new ConfigException("Missing required configuration key: output");
                }
            }
            return new UmbraConfig(this);
        }
    }

    public static final class RenamerOptions {
        private final boolean enabled;
        private final String prefix;
        private final boolean repackage;
        private final String repackagePackage;
        private final boolean renameClasses;
        private final boolean renameMethods;
        private final boolean renameFields;
        private final String mappingFile;
        private final String dictionary;
        private final int minimumNameLength;
        private final List<String> repackageKept;

        public RenamerOptions(boolean enabled, String prefix, boolean repackage, String repackagePackage,
                              boolean renameClasses, boolean renameMethods, boolean renameFields,
                              String mappingFile, String dictionary, int minimumNameLength) {
            this(enabled, prefix, repackage, repackagePackage, renameClasses, renameMethods,
                    renameFields, mappingFile, dictionary, minimumNameLength,
                    Collections.<String>emptyList());
        }

        public RenamerOptions(boolean enabled, String prefix, boolean repackage, String repackagePackage,
                              boolean renameClasses, boolean renameMethods, boolean renameFields,
                              String mappingFile, String dictionary, int minimumNameLength,
                              List<String> repackageKept) {
            this.enabled = enabled;
            this.prefix = prefix == null ? "" : prefix;
            this.repackage = repackage;
            this.repackagePackage = repackagePackage == null ? "" : repackagePackage;
            this.renameClasses = renameClasses;
            this.renameMethods = renameMethods;
            this.renameFields = renameFields;
            this.mappingFile = mappingFile;
            this.dictionary = dictionary == null || dictionary.length() < 2
                    ? "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" : dictionary;
            this.minimumNameLength = Math.max(1, minimumNameLength);
            this.repackageKept = Collections.unmodifiableList(new ArrayList<String>(
                    repackageKept == null ? Collections.<String>emptyList() : repackageKept));
        }

        public boolean enabled() { return enabled; }
        public String prefix() { return prefix; }
        public boolean repackage() { return repackage; }
        public String repackagePackage() { return repackagePackage; }
        public boolean renameClasses() { return renameClasses; }
        public boolean renameMethods() { return renameMethods; }
        public boolean renameFields() { return renameFields; }
        public String mappingFile() { return mappingFile; }
        public String dictionary() { return dictionary; }
        public int minimumNameLength() { return minimumNameLength; }
        /** Kept class globs that still receive a package-only rename. */
        public List<String> repackageKept() { return repackageKept; }
    }

    public static final class StringEncryptionOptions {
        private final boolean enabled;
        private final int minLength;

        public StringEncryptionOptions(boolean enabled, int minLength) {
            this.enabled = enabled;
            this.minLength = minLength;
        }

        public boolean enabled() { return enabled; }
        public int minLength() { return minLength; }
    }

    public static final class IntegerEncryptionOptions {
        private final boolean enabled;
        private final boolean includeLong;

        public IntegerEncryptionOptions(boolean enabled, boolean includeLong) {
            this.enabled = enabled;
            this.includeLong = includeLong;
        }

        public boolean enabled() { return enabled; }
        public boolean includeLong() { return includeLong; }
    }

    public static final class FlowOptions {
        private final boolean enabled;
        private final String level;
        private final int maxInstructions;
        private final boolean flattening;
        private final List<String> flatteningExclude;

        public FlowOptions(boolean enabled, String level, int maxInstructions) {
            this(enabled, level, maxInstructions, false);
        }

        public FlowOptions(boolean enabled, String level, int maxInstructions, boolean flattening) {
            this(enabled, level, maxInstructions, flattening, Collections.<String>emptyList());
        }

        public FlowOptions(boolean enabled, String level, int maxInstructions, boolean flattening,
                           List<String> flatteningExclude) {
            this.enabled = enabled;
            this.level = level == null ? "light" : level;
            this.maxInstructions = maxInstructions;
            this.flattening = flattening;
            this.flatteningExclude = Collections.unmodifiableList(new ArrayList<String>(
                    flatteningExclude == null ? Collections.<String>emptyList() : flatteningExclude));
        }

        public boolean enabled() { return enabled; }
        public String level() { return level; }
        public int maxInstructions() { return maxInstructions; }
        public boolean flattening() { return flattening; }
        /** Class globs (original names) that are not flattened. */
        public List<String> flatteningExclude() { return flatteningExclude; }
    }

    public static final class DebugOptions {
        private final boolean enabled;
        private final boolean removeSourceFile;
        private final boolean removeLineNumbers;
        private final boolean removeLocalVariables;
        private final boolean removeSignatures;
        private final boolean removeInnerClasses;
        private final boolean removeKotlin;

        public DebugOptions(boolean enabled, boolean removeSourceFile, boolean removeLineNumbers,
                            boolean removeLocalVariables, boolean removeSignatures,
                            boolean removeInnerClasses, boolean removeKotlin) {
            this.enabled = enabled;
            this.removeSourceFile = removeSourceFile;
            this.removeLineNumbers = removeLineNumbers;
            this.removeLocalVariables = removeLocalVariables;
            this.removeSignatures = removeSignatures;
            this.removeInnerClasses = removeInnerClasses;
            this.removeKotlin = removeKotlin;
        }

        public boolean enabled() { return enabled; }
        public boolean removeSourceFile() { return removeSourceFile; }
        public boolean removeLineNumbers() { return removeLineNumbers; }
        public boolean removeLocalVariables() { return removeLocalVariables; }
        public boolean removeSignatures() { return removeSignatures; }
        public boolean removeInnerClasses() { return removeInnerClasses; }
        public boolean removeKotlin() { return removeKotlin; }
    }

    public static final class ShuffleOptions {
        private final boolean enabled;
        public ShuffleOptions(boolean enabled) { this.enabled = enabled; }
        public boolean enabled() { return enabled; }
    }

    public static final class WrapperOptions {
        private final boolean enabled;
        private final int maxPerClass;
        public WrapperOptions(boolean enabled, int maxPerClass) {
            this.enabled = enabled;
            this.maxPerClass = maxPerClass;
        }
        public boolean enabled() { return enabled; }
        public int maxPerClass() { return maxPerClass; }
    }

    public static final class WatermarkOptions {
        private final boolean enabled;
        private final String id;
        public WatermarkOptions(boolean enabled, String id) {
            this.enabled = enabled;
            this.id = id == null ? "umbra" : id;
        }
        public boolean enabled() { return enabled; }
        public String id() { return id; }
    }

    public static final class MappingOptions {
        private final boolean enabled;
        private final String file;
        private final String inputFile;

        public MappingOptions(boolean enabled, String file, String inputFile) {
            this.enabled = enabled;
            this.file = file == null ? "umbra-mapping.txt" : file;
            this.inputFile = inputFile == null ? "" : inputFile;
        }

        public boolean enabled() { return enabled; }
        public String file() { return file; }
        /** Optional previous mapping used to keep names stable across builds. */
        public String inputFile() { return inputFile; }
    }

    public static final class ReportOptions {
        private final boolean enabled;
        private final String htmlFile;
        private final String jsonFile;

        public ReportOptions(boolean enabled, String htmlFile, String jsonFile) {
            this.enabled = enabled;
            this.htmlFile = htmlFile == null ? "" : htmlFile;
            this.jsonFile = jsonFile == null ? "" : jsonFile;
        }

        public boolean enabled() { return enabled; }
        public String htmlFile() { return htmlFile; }
        public String jsonFile() { return jsonFile; }
    }

    public static final class ReflectionOptions {
        private final boolean enabled;
        private final boolean rewriteClassStrings;

        public ReflectionOptions(boolean enabled) {
            this(enabled, false);
        }

        public ReflectionOptions(boolean enabled, boolean rewriteClassStrings) {
            this.enabled = enabled;
            this.rewriteClassStrings = rewriteClassStrings;
        }

        public boolean enabled() { return enabled; }
        /**
         * When true, class names found by {@code Class.forName} are renamed and
         * their string constants are rewritten instead of being kept.
         */
        public boolean rewriteClassStrings() { return rewriteClassStrings; }
    }

    public static final class TrimOptions {
        private final boolean enabled;
        private final boolean removeUnusedPrivateMethods;
        private final boolean removeUnusedPrivateFields;

        public TrimOptions(boolean enabled, boolean removeUnusedPrivateMethods, boolean removeUnusedPrivateFields) {
            this.enabled = enabled;
            this.removeUnusedPrivateMethods = removeUnusedPrivateMethods;
            this.removeUnusedPrivateFields = removeUnusedPrivateFields;
        }

        public boolean enabled() { return enabled; }
        public boolean removeUnusedPrivateMethods() { return removeUnusedPrivateMethods; }
        public boolean removeUnusedPrivateFields() { return removeUnusedPrivateFields; }
    }

    public static final class ParameterOptions {
        private final boolean enabled;
        public ParameterOptions(boolean enabled) { this.enabled = enabled; }
        public boolean enabled() { return enabled; }
    }

    public static final class LicenseOptions {
        private final boolean enabled;
        private final String file;
        private final String publicKey;
        private final boolean require;
        private final List<String> requiredFeatures;
        private final String server;

        public LicenseOptions(boolean enabled, String file, String publicKey, boolean require) {
            this(enabled, file, publicKey, require, Collections.<String>emptyList(), "");
        }

        public LicenseOptions(boolean enabled, String file, String publicKey, boolean require,
                              List<String> requiredFeatures) {
            this(enabled, file, publicKey, require, requiredFeatures, "");
        }

        public LicenseOptions(boolean enabled, String file, String publicKey, boolean require,
                              List<String> requiredFeatures, String server) {
            this.enabled = enabled;
            this.file = file == null ? "" : file;
            this.publicKey = publicKey == null ? "" : publicKey;
            this.require = require;
            this.requiredFeatures = Collections.unmodifiableList(new ArrayList<String>(
                    requiredFeatures == null ? Collections.<String>emptyList() : requiredFeatures));
            this.server = server == null ? "" : server;
        }

        public boolean enabled() { return enabled; }
        public String file() { return file; }
        public String publicKey() { return publicKey; }
        public boolean require() { return require; }
        public List<String> requiredFeatures() { return requiredFeatures; }
        /** Optional online license server base URL. */
        public String server() { return server; }
    }

    public static final class ResourceOptions {
        private final boolean rewriteContent;
        private final boolean obfuscatePaths;
        private final List<String> rewriteDomains;

        public ResourceOptions(boolean rewriteContent) {
            this(rewriteContent, false, Collections.<String>emptyList());
        }

        public ResourceOptions(boolean rewriteContent, boolean obfuscatePaths,
                               List<String> rewriteDomains) {
            this.rewriteContent = rewriteContent;
            this.obfuscatePaths = obfuscatePaths;
            this.rewriteDomains = Collections.unmodifiableList(new ArrayList<String>(
                    rewriteDomains == null ? Collections.<String>emptyList() : rewriteDomains));
        }

        public boolean rewriteContent() { return rewriteContent; }
        /** Rename {@code assets/<domain>} directories and rewrite matching path strings. */
        public boolean obfuscatePaths() { return obfuscatePaths; }
        /** Bare domain strings to rewrite (for ResourceLocation-style lookups). */
        public List<String> rewriteDomains() { return rewriteDomains; }
    }

    public static final class ReferenceOptions {
        private final boolean enabled;
        private final boolean staticCalls;
        private final boolean virtualCalls;
        private final boolean fields;
        private final boolean constructors;

        public ReferenceOptions(boolean enabled) {
            this(enabled, true, false, false, false);
        }

        public ReferenceOptions(boolean enabled, boolean staticCalls, boolean virtualCalls, boolean fields) {
            this(enabled, staticCalls, virtualCalls, fields, false);
        }

        public ReferenceOptions(boolean enabled, boolean staticCalls, boolean virtualCalls,
                                boolean fields, boolean constructors) {
            this.enabled = enabled;
            this.staticCalls = staticCalls;
            this.virtualCalls = virtualCalls;
            this.fields = fields;
            this.constructors = constructors;
        }

        public boolean enabled() { return enabled; }
        public boolean staticCalls() { return staticCalls; }
        public boolean virtualCalls() { return virtualCalls; }
        public boolean fields() { return fields; }
        public boolean constructors() { return constructors; }
    }

    public static final class ExceptionOptions {
        private final boolean enabled;
        public ExceptionOptions(boolean enabled) { this.enabled = enabled; }
        public boolean enabled() { return enabled; }
    }

    public static final class IncrementalOptions {
        private final boolean enabled;
        private final String previousOutput;
        private final String metadataFile;

        public IncrementalOptions(boolean enabled, String previousOutput, String metadataFile) {
            this.enabled = enabled;
            this.previousOutput = previousOutput == null ? "" : previousOutput;
            this.metadataFile = metadataFile == null || metadataFile.isEmpty()
                    ? "umbra-incremental.tsv" : metadataFile;
        }

        public boolean enabled() { return enabled; }
        public String previousOutput() { return previousOutput; }
        public String metadataFile() { return metadataFile; }
    }

    public static final class VirtualizationOptions {
        private final boolean enabled;
        private final int maxInstructions;
        private final int maxMethods;

        public VirtualizationOptions(boolean enabled, int maxInstructions, int maxMethods) {
            this.enabled = enabled;
            this.maxInstructions = Math.max(16, maxInstructions);
            this.maxMethods = Math.max(0, maxMethods);
        }

        public boolean enabled() { return enabled; }
        public int maxInstructions() { return maxInstructions; }
        /** Maximum virtualized methods per class; {@code 0} means unlimited. */
        public int maxMethods() { return maxMethods; }
    }

    /** Countermeasures aimed at automated / LLM-assisted static analysis. */
    public static final class AntiLlmOptions {
        private final boolean enabled;
        private final int decoyMethodsPerClass;
        private final int decoyCallSitesPerClass;
        private final int wrapperLayers;
        private final int maxWrappedMethodsPerClass;
        private final boolean shieldVirtualization;

        public AntiLlmOptions(boolean enabled, int decoyMethodsPerClass, int decoyCallSitesPerClass,
                              int wrapperLayers, int maxWrappedMethodsPerClass,
                              boolean shieldVirtualization) {
            this.enabled = enabled;
            this.decoyMethodsPerClass = Math.max(0, decoyMethodsPerClass);
            this.decoyCallSitesPerClass = Math.max(0, decoyCallSitesPerClass);
            this.wrapperLayers = Math.max(0, Math.min(4, wrapperLayers));
            this.maxWrappedMethodsPerClass = Math.max(0, maxWrappedMethodsPerClass);
            this.shieldVirtualization = shieldVirtualization;
        }

        public boolean enabled() { return enabled; }
        public int decoyMethodsPerClass() { return decoyMethodsPerClass; }
        public int decoyCallSitesPerClass() { return decoyCallSitesPerClass; }
        public int wrapperLayers() { return wrapperLayers; }
        public int maxWrappedMethodsPerClass() { return maxWrappedMethodsPerClass; }
        public boolean shieldVirtualization() { return shieldVirtualization; }
    }

    public static final class JunkOptions {
        private final boolean enabled;
        private final int methods;
        private final int fields;
        public JunkOptions(boolean enabled, int methods, int fields) {
            this.enabled = enabled;
            this.methods = methods;
            this.fields = fields;
        }
        public boolean enabled() { return enabled; }
        public int methods() { return methods; }
        public int fields() { return fields; }
    }

    /**
     * Server-backed authorization gate settings ({@code authGate:} YAML section).
     *
     * <p>A protected program calls the injected gate before its {@code main} (and
     * configured entry points); the gate validates a per-software token against
     * the authorization server, falling back to an interactive login / register /
     * card-activation dialog.</p>
     */
    public static final class AuthGateOptions {
        private final boolean enabled;
        private final String server;
        private final String software;
        private final String title;
        private final boolean allowRegister;
        private final String cacheFile;
        private final int timeoutMs;
        private final List<String> entryPoints;

        public AuthGateOptions(boolean enabled, String server, String software, String title,
                               boolean allowRegister, String cacheFile, int timeoutMs,
                               List<String> entryPoints) {
            this.enabled = enabled;
            this.server = server == null ? "" : server.trim();
            this.software = software == null ? "" : software.trim();
            this.title = title == null || title.trim().isEmpty()
                    ? "Software Authorization" : title.trim();
            this.allowRegister = allowRegister;
            this.cacheFile = cacheFile == null ? "" : cacheFile.trim();
            this.timeoutMs = Math.max(250, timeoutMs);
            this.entryPoints = Collections.unmodifiableList(new ArrayList<String>(
                    entryPoints == null ? Collections.<String>emptyList() : entryPoints));
        }

        public boolean enabled() { return enabled; }
        public String server() { return server; }
        public String software() { return software; }
        public String title() { return title; }
        public boolean allowRegister() { return allowRegister; }
        /** Explicit token cache file; empty means {@code ~/.umbra-auth/<software>.token}. */
        public String cacheFile() { return cacheFile; }
        public int timeoutMs() { return timeoutMs; }
        /** Additional entry points in {@code owner#method} or {@code owner#method#desc} form. */
        public List<String> entryPoints() { return entryPoints; }
    }
}
