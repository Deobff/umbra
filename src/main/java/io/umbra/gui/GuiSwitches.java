package io.umbra.gui;

import io.umbra.core.config.UmbraConfig;

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
 * The catalogue of configuration groups and toggles shown in the left column.
 *
 * <p>Each toggle is a pure option mapping: the on/off state translates into one
 * {@code key=value} pair of the advanced option map, which keeps the GUI, the
 * YAML configuration and the CLI on one shared representation. A {@code null}
 * key marks a GUI-only switch ({@code Verify output}).</p>
 */
public final class GuiSwitches {

    public enum Kind {
        SWITCHES,
        INPUT_OUTPUT,
        PRESET,
        ADVANCED
    }

    public static final class Toggle {
        public final String id;
        public final String label;
        public final String key;
        public final String onValue;
        public final String offValue;
        public final boolean defaultOn;

        Toggle(String id, String label, String key, String onValue, String offValue,
               boolean defaultOn) {
            this.id = id;
            this.label = label;
            this.key = key;
            this.onValue = onValue;
            this.offValue = offValue;
            this.defaultOn = defaultOn;
        }
    }

    public static final class GroupDef {
        public final String title;
        public final boolean expanded;
        public final Kind kind;
        public final List<Toggle> toggles;

        GroupDef(String title, boolean expanded, Kind kind, List<Toggle> toggles) {
            this.title = title;
            this.expanded = expanded;
            this.kind = kind;
            this.toggles = toggles;
        }
    }

    private static final List<GroupDef> GROUPS;

    static {
        List<GroupDef> groups = new ArrayList<GroupDef>();

        groups.add(new GroupDef("Input & Output", true, Kind.INPUT_OUTPUT,
                Collections.<Toggle>emptyList()));

        groups.add(new GroupDef("Preset", true, Kind.PRESET,
                Collections.<Toggle>emptyList()));

        groups.add(group("Compatibility", true,
                toggle("springBoot", "Spring Boot fat JARs", "layout.springBoot", true),
                toggle("war", "WAR layouts", "layout.war", true),
                toggle("multiRelease", "Preserve multi-release", "layout.multiRelease",
                        "preserve", "flatten", true),
                toggle("moduleInfo", "Module metadata", "layout.moduleInfo",
                        "auto", "drop", true)));

        groups.add(group("Names", true,
                toggle("rename", "Rename classes & members", "renamer.enabled", true),
                toggle("recordComponents", "Rename record components", "renamer.records", false),
                toggle("keepPublic", "Keep public API names", "keepPublicApi", false)));

        groups.add(group("Data", true,
                toggle("strings", "String encryption", "stringEncryption.enabled", true),
                toggle("stringHide", "Hide decryption traces", "string.stackTraceHide", true),
                toggle("stringWipe", "Wipe decrypted strings", "string.wipe", true),
                toggle("keylessFallback", "Allow keyless string tier (weak)",
                        "string.allowKeylessFallback", false),
                toggle("integers", "Integer encryption", "integerEncryption.enabled", true)));

        groups.add(group("Control flow", true,
                toggle("flow", "Control-flow obfuscation", "flowObfuscation.enabled", true),
                toggle("flatten", "Flattening", "flowObfuscation.flattening", true),
                toggle("aggressiveFlow", "Aggressive flow", "flow.aggressive", false),
                toggle("crossClass", "Cross-class guard fields", "flow.crossClass", true),
                toggle("mbaPredicates", "MBA opaque predicates", "flow.mbaPredicates", true),
                toggle("entryShuffle", "Entry shuffle", "flow.entryShuffle", false),
                toggle("exceptions", "Exception obfuscation", "exceptionObfuscation.enabled", true)));

        groups.add(group("Virtualization", false,
                toggle("vm2", "Virtualize methods (VM2)", "methodVirtualization.enabled", true),
                toggle("fusion", "VM2 superinstructions", "vm2.fusion", true),
                toggle("semanticCodes", "VM2 per-payload opcodes", "vm2.semanticCodes", true),
                toggle("localCallIds", "VM2 local call ids", "vm2.localCallIds", true),
                toggle("perPayloadOpcodes", "VM2 per-payload dispatch",
                        "vm2.perPayloadOpcodes", true),
                toggle("nocturne", "Nocturne engine", "nocturne.enabled", false),
                toggle("nocturneCompatible", "Nocturne + body passes",
                        "nocturne.compatible", false)));

        groups.add(group("Native", false,
                toggle("nativeCode", "Native compilation (JNI)", "native.enabled", false),
                toggle("antiDump", "Native anti-dump", "native.antiDump", true),
                toggle("nativeKey", "Bind master to native root",
                        "classEncryption.nativeKey", false),
                toggle("nativeKeyFallback", "Allow seed fallback",
                        "classEncryption.nativeKey.fallback", true)));

        groups.add(group("Archive", false,
                toggle("classEnc", "Encrypt class payload", "classEncryption.enabled", false),
                toggle("encryptResources", "Encrypt resources", "classEncryption.resources",
                        false),
                toggle("constantPool", "Encrypt constant pool",
                        "classEncryption.constantPool", true),
                toggle("integrity", "Integrity guard", "integrity.enabled", false),
                toggle("libraryMode", "Sealed library (key never in archive)",
                        "classEncryption.libraryMode", false),
                toggle("allowSkip", "Allow unsealed archive (weak)",
                        "classEncryption.allowSkip", false)));

        groups.add(group("Anti-analysis", false,
                toggle("noise", "Decompiler noise", "decompilerNoise.enabled", true),
                toggle("antiLlm", "Anti-LLM decoys", "antiLlm.enabled", true),
                toggle("antiDebug", "Anti-debug guard", "antiDebug.level", "2", "0", false),
                toggle("reflectionGate", "Reflection gate", "reflectionGate.enabled", false),
                toggle("typeConfusion", "Type confusion", "typeConfusion.enabled", false)));

        groups.add(group("Verification", false,
                toggle("verify", "Verify output", null, true),
                toggle("watermark", "Watermark", "watermark.enabled", true),
                toggle("watermarkBlind", "RSA-blind watermark", "watermark.blind", true),
                toggle("minecraft", "Minecraft auto-adaptation", "minecraft.enabled", true)));

        // Ported layers stay collapsed and off: the engine treats every one of them
        // as opt-in, so the console must not enable them by accident.
        groups.add(group("Ported layers", false,
                toggle("salt", "Salt system", "salt.enabled", false),
                toggle("saltParams", "Salt method parameters", "salt.methodParams", false),
                toggle("polyStrings", "Polymorphic string decoders", "polyStrings.enabled", false),
                toggle("integerMasks", "Polymorphic integer masks", "integer.masks", false),
                toggle("numberHash", "Hash-encoded numbers", "numberHash.enabled", false),
                toggle("opaque", "Seed-chain opaque predicates", "opaque.enabled", false),
                toggle("branchShape", "Branch shape rewriting", "branch.enabled", false),
                toggle("definalize", "Remove final modifiers", "definalize.enabled", false),
                toggle("flowInts", "Flow-sensitive state ints", "flowInts.enabled", false),
                toggle("classInitOrder", "Class-init order analysis", "classInitOrder.enabled",
                        false),
                toggle("bodyOptimize", "Body optimisation", "bodyOptimize.enabled", false),
                toggle("nativePayload", "Compressed native payload", "native.payload", true)));

        groups.add(new GroupDef("Advanced", false, Kind.ADVANCED,
                Collections.<Toggle>emptyList()));

        GROUPS = Collections.unmodifiableList(groups);
    }

    private GuiSwitches() {
    }

    private static GroupDef group(String title, boolean expanded, Toggle... toggles) {
        return new GroupDef(title, expanded, Kind.SWITCHES, Arrays.asList(toggles));
    }

    private static Toggle toggle(String id, String label, String key, boolean defaultOn) {
        return new Toggle(id, label, key, "true", "false", defaultOn);
    }

    private static Toggle toggle(String id, String label, String key,
                                 String onValue, String offValue, boolean defaultOn) {
        return new Toggle(id, label, key, onValue, offValue, defaultOn);
    }

    public static List<GroupDef> groups() {
        return GROUPS;
    }

    public static List<Toggle> allToggles() {
        List<Toggle> toggles = new ArrayList<Toggle>();
        for (GroupDef group : GROUPS) {
            toggles.addAll(group.toggles);
        }
        return toggles;
    }

    public static Map<String, Boolean> defaults() {
        Map<String, Boolean> states = new LinkedHashMap<String, Boolean>();
        for (Toggle toggle : allToggles()) {
            states.put(toggle.id, Boolean.valueOf(toggle.defaultOn));
        }
        return states;
    }

    public static Set<String> coveredKeys() {
        Set<String> keys = new LinkedHashSet<String>();
        for (Toggle toggle : allToggles()) {
            if (toggle.key != null) {
                keys.add(toggle.key);
            }
        }
        return keys;
    }

    public static Map<String, String> baseOptions(Map<String, Boolean> states) {
        Map<String, String> options = new LinkedHashMap<String, String>();
        for (Toggle toggle : allToggles()) {
            if (toggle.key == null) {
                continue;
            }
            Boolean state = states.get(toggle.id);
            boolean on = state != null ? state.booleanValue() : toggle.defaultOn;
            options.put(toggle.key, on ? toggle.onValue : toggle.offValue);
        }
        return options;
    }

    public static Map<String, String> parseAdvanced(String text) {
        Map<String, String> options = new LinkedHashMap<String, String>();
        if (text == null) {
            return options;
        }
        String[] lines = text.split("\\r?\\n");
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int split = line.indexOf('=');
            if (split <= 0) {
                continue;
            }
            String key = line.substring(0, split).trim();
            String value = line.substring(split + 1).trim();
            if (!key.isEmpty()) {
                options.put(key, value);
            }
        }
        return options;
    }

    public static Map<String, Boolean> fromConfig(UmbraConfig config) {
        Map<String, String> effective = GuiConfig.describe(config);
        Map<String, Boolean> states = new LinkedHashMap<String, Boolean>();
        for (Toggle toggle : allToggles()) {
            if (toggle.key == null) {
                states.put(toggle.id, Boolean.valueOf(toggle.defaultOn));
                continue;
            }
            String value = effective.get(toggle.key);
            states.put(toggle.id, Boolean.valueOf(matches(value, toggle)));
        }
        return states;
    }

    public static Map<String, String> advancedOverrides(UmbraConfig config) {
        Set<String> covered = coveredKeys();
        Map<String, String> overrides = new LinkedHashMap<String, String>();
        for (Map.Entry<String, String> entry : config.options().entrySet()) {
            if (!covered.contains(entry.getKey())) {
                overrides.put(entry.getKey(), entry.getValue());
            }
        }
        return overrides;
    }

    public static boolean matches(String value, Toggle toggle) {
        if (value == null) {
            return toggle.defaultOn;
        }
        String v = value.trim().toLowerCase(Locale.ROOT);
        if (v.equals(toggle.onValue.toLowerCase(Locale.ROOT))) {
            return true;
        }
        if (v.equals(toggle.offValue.toLowerCase(Locale.ROOT))) {
            return false;
        }
        if ("true".equals(toggle.onValue)) {
            return "true".equals(v) || "yes".equals(v) || "on".equals(v) || "1".equals(v);
        }
        try {
            return Integer.parseInt(v) != 0;
        } catch (NumberFormatException ignored) {
            return toggle.defaultOn;
        }
    }

    public static String formatAdvanced(Map<String, String> overrides) {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> entry : overrides.entrySet()) {
            out.append(entry.getKey()).append('=').append(entry.getValue()).append('\n');
        }
        return out.toString();
    }
}
