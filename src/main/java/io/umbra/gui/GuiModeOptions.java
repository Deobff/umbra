package io.umbra.gui;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Catalogue of the per-mode detailed options shown by the "Mode options" dialog.
 *
 * <p>Every control maps to an option key that the CLI/YAML layer already
 * understands (see {@code docs/OPTIONS.md}); a handful of controls are UI-only
 * (seed, mapping path, verify) because they are not engine options. The list is
 * deliberately flat and string-valued so that the dialog, the left column, the
 * advanced {@code key=value} editor, the prefs file and the YAML round trip all
 * speak the same representation.</p>
 */
public final class GuiModeOptions {

    /** Control kind rendered by the dialog. */
    public enum Kind {
        BOOL,
        INT,
        ENUM,
        TEXT
    }

    /** One selectable row of the mode-options dialog. */
    public static final class Spec {
        public final String id;
        public final String label;
        public final String key;
        public final Kind kind;
        public final List<String> values;
        public final String defaultValue;
        public final int min;
        public final int max;
        public final int step;
        public final String hint;

        Spec(String id, String label, String key, Kind kind, List<String> values,
             String defaultValue, int min, int max, int step, String hint) {
            this.id = id;
            this.label = label;
            this.key = key;
            this.kind = kind;
            this.values = values == null ? Collections.<String>emptyList() : values;
            this.defaultValue = defaultValue;
            this.min = min;
            this.max = max;
            this.step = step;
            this.hint = hint == null ? "" : hint;
        }

        /** True when the value is stored only in the GUI (no engine option key). */
        public boolean uiOnly() {
            return key == null;
        }
    }

    /** A titled group of specs. */
    public static final class Group {
        public final String title;
        public final List<Spec> specs;

        Group(String title, List<Spec> specs) {
            this.title = title;
            this.specs = Collections.unmodifiableList(new ArrayList<Spec>(specs));
        }
    }

    private static final List<Group> GROUPS;
    private static final Map<String, Spec> BY_ID = new LinkedHashMap<String, Spec>();
    private static final Map<String, Spec> BY_KEY = new LinkedHashMap<String, Spec>();

    static {
        List<Group> groups = new ArrayList<Group>();

        groups.add(group("Names",
                bool("renamer.enabled", "Rename classes and members", "renamer.enabled", true),
                bool("renamer.renameClasses", "Rename classes", "renamer.renameClasses", true),
                bool("renamer.renameMethods", "Rename methods", "renamer.renameMethods", true),
                bool("renamer.renameFields", "Rename fields", "renamer.renameFields", true),
                bool("renamer.repackage", "Repackage classes", "renamer.repackage", true),
                text("renamer.prefix", "Name prefix", "renamer.prefix", ""),
                text("renamer.dictionary", "Identifier dictionary", "renamer.dictionary",
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                integer("renamer.minimumNameLength", "Minimum name length",
                        "renamer.minimumNameLength", 1, 1, 16, 1),
                bool("keepPublicApi", "Keep public API names", "keepPublicApi", false)));

        groups.add(group("Strings",
                bool("stringEncryption.enabled", "String encryption",
                        "stringEncryption.enabled", true),
                enumeration("string.engine", "Engine", "string.engine",
                        new String[]{"auto", "xor", "rc4", "chacha20", "aes-ctr", "speck"},
                        "auto"),
                integer("string.strength", "Strength preset", "string.strength", 2, 1, 3, 1),
                integer("stringEncryption.minLength", "Minimum length",
                        "stringEncryption.minLength", 2, 0, 64, 1),
                bool("string.split", "Split payloads", "string.split", true),
                integer("string.splitParts", "Split parts", "string.splitParts", 2, 1, 4, 1),
                bool("string.indy", "Invokedynamic decrypt", "string.indy", false),
                bool("string.cache", "Cache plaintext", "string.cache", true),
                bool("string.perClassKey", "Per-class key", "string.perClassKey", true),
                bool("string.wipe", "Wipe plaintext", "string.wipe", true),
                bool("string.stackTraceHide", "Hide stack traces",
                        "string.stackTraceHide", true),
                bool("string.encryptAll", "Encrypt all strings", "string.encryptAll", false),
                text("string.engineOrder", "Engine order (auto)", "string.engineOrder",
                        "chacha20,aes-ctr,rc4,speck")));

        groups.add(group("Integers & MBA",
                bool("integerEncryption.enabled", "Integer encryption",
                        "integerEncryption.enabled", true),
                bool("integerEncryption.includeLong", "Include long constants",
                        "integerEncryption.includeLong", true),
                bool("mba.enabled", "MBA expressions", "mba.enabled", false),
                integer("mba.depth", "MBA depth", "mba.depth", 2, 1, 4, 1),
                integer("mba.maxPerMethod", "MBA max per method", "mba.maxPerMethod",
                        400, 50, 2000, 50)));

        groups.add(group("Flow",
                bool("flowObfuscation.enabled", "Control-flow obfuscation",
                        "flowObfuscation.enabled", true),
                enumeration("flowObfuscation.level", "Flow level", "flowObfuscation.level",
                        new String[]{"light", "normal"}, "light"),
                integer("flowObfuscation.maxInstructions", "Max instructions",
                        "flowObfuscation.maxInstructions", 8000, 500, 20000, 500),
                bool("flowObfuscation.flattening", "Flattening",
                        "flowObfuscation.flattening", true),
                bool("flow.aggressive", "Aggressive flow", "flow.aggressive", false),
                bool("flow.transpose", "Transpose blocks", "flow.transpose", false),
                bool("flow.bogusRanges", "Bogus exception ranges", "flow.bogusRanges", false),
                integer("flow.maxBlocks", "Max blocks", "flow.maxBlocks", 512, 32, 4096, 32)));

        groups.add(group("Exceptions",
                bool("exceptionObfuscation.enabled", "Exception obfuscation",
                        "exceptionObfuscation.enabled", true),
                integer("exception.level", "Noise level", "exception.level", 2, 1, 3, 1)));

        groups.add(group("Virtualization",
                bool("methodVirtualization.enabled", "Virtualize methods",
                        "methodVirtualization.enabled", true),
                integer("methodVirtualization.maxInstructions", "Method budget",
                        "methodVirtualization.maxInstructions", 4000, 500, 20000, 500),
                bool("vm2.enabled", "Use hardened VM2", "vm2.enabled", true),
                integer("vm2.maxInstructions", "VM2 method budget", "vm2.maxInstructions",
                        4000, 500, 20000, 500),
                bool("vm2.encryptPayload", "Encrypt payload", "vm2.encryptPayload", true),
                bool("vm2.opcodeMap", "Permute opcodes", "vm2.opcodeMap", true),
                bool("vm2.trys", "Try/catch methods", "vm2.trys", true),
                bool("vm2.news", "Virtualize new", "vm2.news", false),
                bool("vm2.nested", "Nested dispatch", "vm2.nested", true),
                bool("vm2.fusion", "Superinstructions", "vm2.fusion", true),
                integer("vm2.holders", "Payload holders", "vm2.holders", 2, 1, 8, 1),
                bool("vm2.constructors", "Constructor bodies", "vm2.constructors", false),
                bool("vm2.indy", "Indy bridges", "vm2.indy", true),
                bool("nocturne.enabled", "Nocturne engine", "nocturne.enabled", false),
                bool("nocturne.compatible", "Nocturne compatible mode",
                        "nocturne.compatible", false),
                enumeration("nocturne.encoding", "Nocturne encoding", "nocturne.encoding",
                        new String[]{"arx", "xor"}, "arx"),
                integer("nocturne.variants", "Nocturne variants", "nocturne.variants",
                        3, 2, 4, 1)));

        groups.add(group("Native",
                bool("native.enabled", "Native compilation (JNI)", "native.enabled", false),
                bool("native.antiDump", "Native anti-dump", "native.antiDump", true),
                bool("native.antiBackfill", "Anti-backfill table",
                        "native.antiBackfill", true),
                bool("native.constructors", "Native constructors",
                        "native.constructors", true),
                bool("native.indy", "Native indy bridges", "native.indy", true),
                integer("native.maxInstructions", "Native method budget",
                        "native.maxInstructions", 800, 100, 5000, 100),
                bool("native.keepDll", "Keep generated library", "native.keepDll", false),
                text("native.compiler", "C compiler", "native.compiler", ""),
                bool("antiDebug.nativeGuard", "Native anti-debug guard",
                        "antiDebug.nativeGuard", true),
                bool("antiDebug.frida", "Frida checks", "antiDebug.frida", true),
                bool("antiDebug.nativeHash", "Guard code hash",
                        "antiDebug.nativeHash", true)));

        groups.add(group("Archive & class encryption",
                bool("classEncryption.enabled", "Encrypt class payload",
                        "classEncryption.enabled", false),
                enumeration("classEncryption.algorithm", "Cipher",
                        "classEncryption.algorithm",
                        new String[]{"chacha20", "aes-ctr"}, "chacha20"),
                bool("classEncryption.integrity", "Loader integrity",
                        "classEncryption.integrity", true),
                bool("classEncryption.antiDump", "Archive anti-dump",
                        "classEncryption.antiDump", true),
                bool("classEncryption.resources", "Encrypt resources",
                        "classEncryption.resources", true),
                bool("classEncryption.resourceIntegrity", "Resource integrity",
                        "classEncryption.resourceIntegrity", true),
                integer("classEncryption.minResourceSize", "Min resource size",
                        "classEncryption.minResourceSize", 0, 0, 65536, 32),
                bool("classEncryption.manifestMinimal", "Minimal manifest",
                        "classEncryption.manifestMinimal", true),
                text("classEncryption.loaderClass", "Loader class name",
                        "classEncryption.loaderClass", ""),
                text("classEncryption.entry", "Loader entry point",
                        "classEncryption.entry", ""),
                bool("integrity.enabled", "Startup integrity guard",
                        "integrity.enabled", false),
                integer("integrity.level", "Integrity level", "integrity.level", 1, 1, 3, 1),
                enumeration("integrity.action", "Integrity action", "integrity.action",
                        new String[]{"throw", "exit", "corrupt"}, "throw"),
                bool("integrity.antiDump", "Integrity anti-dump",
                        "integrity.antiDump", true)));

        groups.add(group("Anti-debug",
                integer("antiDebug.level", "Anti-debug level", "antiDebug.level", 0, 0, 3, 1),
                enumeration("antiDebug.action", "Detection action", "antiDebug.action",
                        new String[]{"throw", "exit", "corrupt", "log"}, "throw"),
                bool("antiDebug.attach", "Attach detection", "antiDebug.attach", true),
                bool("antiDebug.attachWatch", "Attach watcher", "antiDebug.attachWatch", true),
                bool("antiDebug.portProbe", "JDWP port probe", "antiDebug.portProbe", false),
                bool("antiDebug.env", "Environment markers", "antiDebug.env", true),
                bool("antiDebug.timing", "Timing checks", "antiDebug.timing", true),
                bool("antiDebug.jvmti", "JVMTI agents", "antiDebug.jvmti", true),
                bool("antiDebug.thread", "Watchdog thread", "antiDebug.thread", true),
                integer("antiDebug.watchdogMs", "Watchdog interval (ms)",
                        "antiDebug.watchdogMs", 4000, 500, 30000, 500)));

        groups.add(group("Type confusion & anti-analysis",
                bool("typeConfusion.enabled", "Type confusion", "typeConfusion.enabled", false),
                integer("typeConfusion.level", "Type confusion level",
                        "typeConfusion.level", 1, 1, 2, 1),
                integer("typeConfusion.maxPerMethod", "Type confusion max per method",
                        "typeConfusion.maxPerMethod", 64, 8, 512, 8),
                bool("reflectionGate.enabled", "Reflection gate",
                        "reflectionGate.enabled", false),
                enumeration("reflectionGate.action", "Gate action",
                        "reflectionGate.action", new String[]{"deny", "mask"}, "deny"),
                integer("reflectionGate.maxPerMethod", "Gate max per method",
                        "reflectionGate.maxPerMethod", 64, 8, 512, 8),
                bool("antiLlm.enabled", "Anti-LLM decoys", "antiLlm.enabled", true),
                integer("antiLlm.decoyMethodsPerClass", "Decoy methods per class",
                        "antiLlm.decoyMethodsPerClass", 2, 0, 16, 1),
                integer("antiLlm.wrapperLayers", "Wrapper layers",
                        "antiLlm.wrapperLayers", 1, 0, 4, 1),
                integer("antiLlm.maxWrappedMethodsPerClass", "Max wrapped methods",
                        "antiLlm.maxWrappedMethodsPerClass", 12, 0, 256, 4),
                bool("decompilerNoise.enabled", "Decompiler noise",
                        "decompilerNoise.enabled", true),
                integer("decompilerNoise.level", "Noise level",
                        "decompilerNoise.level", 1, 1, 4, 1)));

        groups.add(group("Compatibility",
                bool("layout.enabled", "Preserve non-flat layouts", "layout.enabled", true),
                bool("layout.springBoot", "Spring Boot fat JARs",
                        "layout.springBoot", true),
                bool("layout.war", "WAR layouts", "layout.war", true),
                enumeration("layout.multiRelease", "Multi-release mode",
                        "layout.multiRelease", new String[]{"preserve", "flatten"},
                        "preserve"),
                enumeration("layout.moduleInfo", "Module metadata", "layout.moduleInfo",
                        new String[]{"auto", "keep", "drop"}, "auto"),
                bool("minecraft.enabled", "Minecraft auto-adaptation",
                        "minecraft.enabled", true)));

        groups.add(group("Output",
                bool("gui.verify", "Verify output", null, true),
                bool("watermark.enabled", "Watermark", "watermark.enabled", true),
                text("gui.seed", "Seed", null, "23303"),
                text("gui.mapping", "Mapping file", null, "")));

        GROUPS = Collections.unmodifiableList(groups);
        for (Group group : GROUPS) {
            for (Spec spec : group.specs) {
                BY_ID.put(spec.id, spec);
                if (spec.key != null) {
                    BY_KEY.put(spec.key, spec);
                }
            }
        }
    }

    private GuiModeOptions() {
    }

    /* -------------------------------------------------------------- catalog */

    private static Group group(String title, Spec... specs) {
        return new Group(title, Arrays.asList(specs));
    }

    private static Spec bool(String id, String label, String key, boolean defaultValue) {
        return new Spec(id, label, key, Kind.BOOL, null, String.valueOf(defaultValue),
                0, 0, 0, "");
    }

    private static Spec integer(String id, String label, String key, int defaultValue,
                                int min, int max, int step) {
        return new Spec(id, label, key, Kind.INT, null, String.valueOf(defaultValue),
                min, max, step, "");
    }

    private static Spec enumeration(String id, String label, String key, String[] values,
                                    String defaultValue) {
        return new Spec(id, label, key, Kind.ENUM, Arrays.asList(values), defaultValue,
                0, 0, 0, "");
    }

    private static Spec text(String id, String label, String key, String defaultValue) {
        return new Spec(id, label, key, Kind.TEXT, null, defaultValue, 0, 0, 0, "");
    }

    public static List<Group> groups() {
        return GROUPS;
    }

    public static List<Spec> allSpecs() {
        List<Spec> specs = new ArrayList<Spec>();
        for (Group group : GROUPS) {
            specs.addAll(group.specs);
        }
        return specs;
    }

    public static Spec spec(String id) {
        return BY_ID.get(id);
    }

    public static Spec specForKey(String key) {
        return BY_KEY.get(key);
    }

    public static Set<String> optionKeys() {
        return new LinkedHashSet<String>(BY_KEY.keySet());
    }

    /* ------------------------------------------------------------- defaults */

    /** Base (documented) defaults before any mode is applied. */
    public static Map<String, String> baseDefaults() {
        Map<String, String> values = new LinkedHashMap<String, String>();
        for (Spec spec : allSpecs()) {
            values.put(spec.id, spec.defaultValue);
        }
        return values;
    }

    /** Detailed values for one GUI mode (Light/Balanced/.../Custom). */
    public static Map<String, String> defaults(String mode) {
        Map<String, String> values = baseDefaults();
        String preset = mode == null ? "custom" : mode.trim().toLowerCase(Locale.ROOT);
        if ("light".equals(preset)) {
            setValues(values, "renamer.enabled", "true", "renamer.renameClasses", "true",
                    "renamer.renameMethods", "true", "renamer.renameFields", "true",
                    "renamer.repackage", "true", "keepPublicApi", "false");
            setValues(values, "stringEncryption.enabled", "true", "string.strength", "1",
                    "string.split", "false", "string.cache", "false",
                    "string.perClassKey", "true", "string.wipe", "true",
                    "string.stackTraceHide", "true", "string.encryptAll", "false");
            setValues(values, "integerEncryption.enabled", "false",
                    "integerEncryption.includeLong", "false", "mba.enabled", "false");
            setValues(values, "flowObfuscation.enabled", "false",
                    "flowObfuscation.flattening", "false", "flow.aggressive", "false",
                    "flow.transpose", "false", "flow.bogusRanges", "false");
            setValues(values, "exceptionObfuscation.enabled", "false");
            setValues(values, "methodVirtualization.enabled", "false",
                    "vm2.enabled", "false", "nocturne.enabled", "false",
                    "nocturne.compatible", "false");
            setValues(values, "native.enabled", "false", "native.antiDump", "true");
            setValues(values, "classEncryption.enabled", "false",
                    "classEncryption.resources", "false", "integrity.enabled", "false");
            setValues(values, "antiDebug.level", "0", "antiDebug.nativeGuard", "true");
            setValues(values, "typeConfusion.enabled", "false",
                    "reflectionGate.enabled", "false", "antiLlm.enabled", "false",
                    "decompilerNoise.enabled", "false", "decompilerNoise.level", "1");
            setValues(values, "layout.enabled", "true", "layout.springBoot", "true",
                    "layout.war", "true", "layout.multiRelease", "preserve",
                    "layout.moduleInfo", "auto", "minecraft.enabled", "true");
            setValues(values, "gui.verify", "true", "watermark.enabled", "true");
        } else if ("balanced".equals(preset)) {
            setValues(values, "string.strength", "2", "string.split", "true",
                    "string.cache", "true", "string.wipe", "true",
                    "string.stackTraceHide", "true");
            setValues(values, "classEncryption.enabled", "false",
                    "classEncryption.resources", "false", "integrity.enabled", "false");
            setValues(values, "flowObfuscation.enabled", "true",
                    "flowObfuscation.flattening", "true", "flow.aggressive", "false");
            setValues(values, "antiDebug.level", "0",
                    "typeConfusion.enabled", "false", "reflectionGate.enabled", "false");
        } else if ("aggressive".equals(preset)) {
            setValues(values, "string.strength", "2", "string.split", "true",
                    "string.cache", "true", "string.wipe", "true",
                    "string.stackTraceHide", "true");
            setValues(values, "flow.aggressive", "true", "flow.transpose", "true",
                    "flow.bogusRanges", "true");
            setValues(values, "exceptionObfuscation.enabled", "true");
            setValues(values, "methodVirtualization.enabled", "true", "vm2.enabled", "true");
            setValues(values, "classEncryption.enabled", "true",
                    "classEncryption.resources", "true", "integrity.enabled", "true",
                    "integrity.level", "2");
            setValues(values, "antiDebug.level", "2");
            setValues(values, "decompilerNoise.enabled", "true", "decompilerNoise.level", "2");
            setValues(values, "antiLlm.enabled", "true", "typeConfusion.enabled", "false",
                    "reflectionGate.enabled", "false");
        } else if ("maximum".equals(preset)) {
            setValues(values, "string.strength", "3", "string.split", "true",
                    "string.encryptAll", "false");
            setValues(values, "mba.enabled", "true", "mba.depth", "2");
            setValues(values, "flow.aggressive", "true", "flow.transpose", "true",
                    "flow.bogusRanges", "true", "flowObfuscation.level", "normal");
            setValues(values, "exceptionObfuscation.enabled", "true");
            setValues(values, "methodVirtualization.enabled", "true", "vm2.enabled", "true");
            setValues(values, "classEncryption.enabled", "true",
                    "classEncryption.resources", "true", "integrity.enabled", "true",
                    "integrity.level", "2");
            setValues(values, "antiDebug.level", "2");
            setValues(values, "decompilerNoise.enabled", "true", "decompilerNoise.level", "2");
            setValues(values, "typeConfusion.enabled", "true",
                    "reflectionGate.enabled", "false", "antiLlm.enabled", "true");
        } else if ("nocturne".equals(preset)) {
            setValues(values, "renamer.enabled", "false", "keepPublicApi", "false");
            setValues(values, "stringEncryption.enabled", "false",
                    "string.stackTraceHide", "false", "string.wipe", "false");
            setValues(values, "integerEncryption.enabled", "false", "mba.enabled", "false");
            setValues(values, "flowObfuscation.enabled", "false",
                    "flowObfuscation.flattening", "false", "flow.aggressive", "false");
            setValues(values, "exceptionObfuscation.enabled", "false");
            setValues(values, "methodVirtualization.enabled", "false", "vm2.enabled", "false",
                    "vm2.fusion", "false", "nocturne.enabled", "true",
                    "nocturne.compatible", "false", "nocturne.variants", "3");
            setValues(values, "native.enabled", "false");
            setValues(values, "classEncryption.enabled", "true",
                    "classEncryption.resources", "false", "integrity.enabled", "true",
                    "integrity.level", "2");
            setValues(values, "antiDebug.level", "2");
            setValues(values, "decompilerNoise.enabled", "true", "decompilerNoise.level", "3");
            setValues(values, "antiLlm.enabled", "false", "typeConfusion.enabled", "false",
                    "reflectionGate.enabled", "false");
        }
        // Balanced is the default/base mode: every listed value above already
        // matches it, and Custom starts from the same conservative profile.
        return values;
    }

    private static void setValues(Map<String, String> values, String... pairs) {
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            if (values.containsKey(pairs[i])) {
                values.put(pairs[i], pairs[i + 1]);
            }
        }
    }

    /** Mode names offered by the dialog (same list as the sidebar selector). */
    public static List<String> modeNames() {
        return GuiPresets.NAMES;
    }

    /* --------------------------------------------------------- conversions */

    /** Values read from a configuration's effective option map. */
    public static Map<String, String> fromEffective(Map<String, String> effective) {
        Map<String, String> values = baseDefaults();
        if (effective == null) {
            return values;
        }
        for (Spec spec : allSpecs()) {
            if (spec.uiOnly()) {
                continue;
            }
            String raw = effective.get(spec.key);
            if (raw == null || raw.trim().isEmpty()) {
                continue;
            }
            values.put(spec.id, normalize(spec, raw));
        }
        return values;
    }

    /** Normalises one raw value for its spec (clamps ints, validates enums). */
    public static String normalize(Spec spec, String raw) {
        String value = raw == null ? "" : raw.trim();
        switch (spec.kind) {
            case BOOL:
                String lower = value.toLowerCase(Locale.ROOT);
                boolean on = "true".equals(lower) || "yes".equals(lower)
                        || "on".equals(lower) || "1".equals(lower);
                return String.valueOf(on);
            case INT:
                try {
                    int parsed = Integer.parseInt(value);
                    return String.valueOf(Math.max(spec.min, Math.min(spec.max, parsed)));
                } catch (NumberFormatException e) {
                    return spec.defaultValue;
                }
            case ENUM:
                for (String allowed : spec.values) {
                    if (allowed.equalsIgnoreCase(value)) {
                        return allowed;
                    }
                }
                return spec.defaultValue;
            default:
                return value;
        }
    }

    /** Advanced option map contributed by the detailed values. */
    public static Map<String, String> toOptionMap(Map<String, String> values) {
        Map<String, String> options = new LinkedHashMap<String, String>();
        for (Spec spec : allSpecs()) {
            if (spec.uiOnly()) {
                continue;
            }
            String value = values.get(spec.id);
            if (value == null) {
                value = spec.defaultValue;
            }
            options.put(spec.key, normalize(spec, value));
        }
        return options;
    }

    /* ---------------------------------------------------------- left switch */

    /** Toggle id that owns / is fed by a spec, or null when none. */
    public static String toggleForSpec(String specId) {
        Spec spec = spec(specId);
        if (spec == null) {
            return null;
        }
        if ("gui.verify".equals(specId)) {
            return "verify";
        }
        if (spec.key == null) {
            return null;
        }
        if ("renamer.enabled".equals(spec.key)) {
            return "rename";
        } else if ("keepPublicApi".equals(spec.key)) {
            return "keepPublic";
        } else if ("stringEncryption.enabled".equals(spec.key)) {
            return "strings";
        } else if ("string.stackTraceHide".equals(spec.key)) {
            return "stringHide";
        } else if ("string.wipe".equals(spec.key)) {
            return "stringWipe";
        } else if ("integerEncryption.enabled".equals(spec.key)) {
            return "integers";
        } else if ("flowObfuscation.enabled".equals(spec.key)) {
            return "flow";
        } else if ("flowObfuscation.flattening".equals(spec.key)) {
            return "flatten";
        } else if ("flow.aggressive".equals(spec.key)) {
            return "aggressiveFlow";
        } else if ("exceptionObfuscation.enabled".equals(spec.key)) {
            return "exceptions";
        } else if ("methodVirtualization.enabled".equals(spec.key)) {
            return "vm2";
        } else if ("vm2.fusion".equals(spec.key)) {
            return "fusion";
        } else if ("nocturne.enabled".equals(spec.key)) {
            return "nocturne";
        } else if ("nocturne.compatible".equals(spec.key)) {
            return "nocturneCompatible";
        } else if ("native.enabled".equals(spec.key)) {
            return "nativeCode";
        } else if ("native.antiDump".equals(spec.key)) {
            return "antiDump";
        } else if ("classEncryption.enabled".equals(spec.key)) {
            return "classEnc";
        } else if ("classEncryption.resources".equals(spec.key)) {
            return "encryptResources";
        } else if ("integrity.enabled".equals(spec.key)) {
            return "integrity";
        } else if ("layout.springBoot".equals(spec.key)) {
            return "springBoot";
        } else if ("layout.war".equals(spec.key)) {
            return "war";
        } else if ("layout.multiRelease".equals(spec.key)) {
            return "multiRelease";
        } else if ("layout.moduleInfo".equals(spec.key)) {
            return "moduleInfo";
        } else if ("decompilerNoise.enabled".equals(spec.key)) {
            return "noise";
        } else if ("antiLlm.enabled".equals(spec.key)) {
            return "antiLlm";
        } else if ("antiDebug.level".equals(spec.key)) {
            return "antiDebug";
        } else if ("reflectionGate.enabled".equals(spec.key)) {
            return "reflectionGate";
        } else if ("typeConfusion.enabled".equals(spec.key)) {
            return "typeConfusion";
        } else if ("watermark.enabled".equals(spec.key)) {
            return "watermark";
        } else if ("minecraft.enabled".equals(spec.key)) {
            return "minecraft";
        }
        return null;
    }

    /**
     * Switch states implied by the detailed values (the left column must stay
     * in sync with the dialog).
     */
    public static Map<String, Boolean> syncToggles(Map<String, String> values) {
        Map<String, Boolean> states = new LinkedHashMap<String, Boolean>();
        for (Spec spec : allSpecs()) {
            String toggleId = toggleForSpec(spec.id);
            if (toggleId == null) {
                continue;
            }
            String value = values.get(spec.id);
            if (value == null) {
                value = spec.defaultValue;
            }
            if ("layout.multiRelease".equals(spec.key)) {
                states.put(toggleId, Boolean.valueOf("preserve".equalsIgnoreCase(value)));
            } else if ("layout.moduleInfo".equals(spec.key)) {
                states.put(toggleId, Boolean.valueOf(!"drop".equalsIgnoreCase(value)));
            } else if ("antiDebug.level".equals(spec.key)) {
                int level = parseInt(value, 0);
                states.put(toggleId, Boolean.valueOf(level > 0));
            } else {
                states.put(toggleId, Boolean.valueOf(parseBool(value)));
            }
        }
        return states;
    }

    /**
     * Applies one left-column switch change to the detailed values (bool specs
     * only; enum quirks mirror the switches in the sidebar).
     */
    public static void applyToggle(Map<String, String> values, String toggleId,
                                   boolean on) {
        for (Spec spec : allSpecs()) {
            if (!toggleId.equals(toggleForSpec(spec.id))) {
                continue;
            }
            if (spec.kind == Kind.BOOL) {
                values.put(spec.id, String.valueOf(on));
            } else if ("layout.multiRelease".equals(spec.key)) {
                values.put(spec.id, on ? "preserve" : "flatten");
            } else if ("layout.moduleInfo".equals(spec.key)) {
                values.put(spec.id, on ? "auto" : "drop");
            } else if ("antiDebug.level".equals(spec.key)) {
                values.put(spec.id, on ? "2" : "0");
            }
        }
    }

    /** True when the detailed values diverge from the mode's defaults. */
    public static boolean overridesModeDefaults(String mode, Map<String, String> values) {
        Map<String, String> defaults = defaults(mode);
        for (Spec spec : allSpecs()) {
            String expected = defaults.get(spec.id);
            String actual = values.get(spec.id);
            if (expected == null) {
                continue;
            }
            if (actual == null) {
                return true;
            }
            if (!expected.equals(normalize(spec, actual))) {
                return true;
            }
        }
        return false;
    }

    /** Keys/ids of the GUI-only controls. */
    public static Set<String> uiOnlyIds() {
        Set<String> ids = new LinkedHashSet<String>();
        for (Spec spec : allSpecs()) {
            if (spec.uiOnly()) {
                ids.add(spec.id);
            }
        }
        return ids;
    }

    private static boolean parseBool(String value) {
        String lower = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        return "true".equals(lower) || "yes".equals(lower) || "on".equals(lower)
                || "1".equals(lower);
    }

    private static int parseInt(String value, int fallback) {
        try {
            return Integer.parseInt(value == null ? "" : value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
