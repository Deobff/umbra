package io.umbra.gui;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The GUI presets. They only populate switch states; every value is editable
 * afterwards and the selector flips to "Custom" as soon as a switch changes.
 *
 * <p>Preset names mirror the CLI presets (light, balanced, aggressive, maximum,
 * nocturne). Strength scalars that have no switch (string strength, decompiler
 * noise level, MBA) are emitted as extra advanced options so a GUI run matches
 * the CLI equivalent closely.</p>
 */
public final class GuiPresets {

    /** Ordered names shown by the preset selector. */
    public static final List<String> NAMES = Arrays.asList(
            "Light", "Balanced", "Aggressive", "Maximum", "Nocturne", "Custom");

    public static final String DEFAULT = "Balanced";

    private GuiPresets() {
    }

    /** Full switch-state map for a preset name; unknown names mean Custom. */
    public static Map<String, Boolean> states(String name) {
        Map<String, Boolean> states = GuiSwitches.defaults();
        String preset = name == null ? "custom" : name.toLowerCase(java.util.Locale.ROOT);
        if ("light".equals(preset)) {
            set(states, false, "integers", "flow", "flatten", "aggressiveFlow", "exceptions",
                    "vm2", "nocturne", "nocturneCompatible", "nativeCode", "classEnc",
                    "encryptResources", "integrity", "noise", "antiLlm", "antiDebug",
                    "reflectionGate", "typeConfusion");
            set(states, true, "rename", "strings", "stringHide", "stringWipe", "verify",
                    "watermark", "minecraft", "springBoot", "war", "multiRelease",
                    "moduleInfo", "antiDump", "fusion");
        } else if ("balanced".equals(preset)) {
            set(states, false, "nativeCode", "classEnc", "encryptResources", "integrity",
                    "nocturne", "nocturneCompatible", "antiDebug", "reflectionGate",
                    "typeConfusion", "aggressiveFlow", "keepPublic");
            set(states, true, "rename", "strings", "stringHide", "stringWipe", "integers",
                    "flow", "flatten", "exceptions", "vm2", "fusion", "antiLlm", "noise",
                    "verify", "watermark", "minecraft", "springBoot", "war", "multiRelease",
                    "moduleInfo", "antiDump");
        } else if ("aggressive".equals(preset)) {
            set(states, false, "nativeCode", "nocturne", "nocturneCompatible", "reflectionGate",
                    "typeConfusion", "keepPublic");
            set(states, true, "rename", "strings", "stringHide", "stringWipe", "integers",
                    "flow", "flatten", "aggressiveFlow", "exceptions", "vm2", "fusion",
                    "antiLlm", "noise", "antiDebug", "classEnc", "encryptResources",
                    "integrity", "verify", "watermark", "minecraft", "springBoot", "war",
                    "multiRelease", "moduleInfo", "antiDump");
        } else if ("maximum".equals(preset)) {
            set(states, false, "nativeCode", "nocturne", "nocturneCompatible", "reflectionGate",
                    "keepPublic");
            set(states, true, "rename", "strings", "stringHide", "stringWipe", "integers",
                    "flow", "flatten", "aggressiveFlow", "exceptions", "vm2", "fusion",
                    "antiLlm", "noise", "antiDebug", "classEnc", "encryptResources",
                    "integrity", "typeConfusion", "verify", "watermark", "minecraft",
                    "springBoot", "war", "multiRelease", "moduleInfo", "antiDump");
        } else if ("nocturne".equals(preset)) {
            set(states, false, "rename", "strings", "stringHide", "stringWipe", "integers",
                    "flow", "flatten", "aggressiveFlow", "exceptions", "vm2", "fusion",
                    "nocturneCompatible", "nativeCode", "encryptResources", "antiLlm",
                    "reflectionGate", "typeConfusion", "keepPublic");
            set(states, true, "nocturne", "noise", "antiDebug", "classEnc", "integrity",
                    "verify", "watermark", "minecraft", "springBoot", "war", "multiRelease",
                    "moduleInfo", "antiDump");
        }
        return states;
    }

    private static void set(Map<String, Boolean> states, boolean value, String... ids) {
        for (String id : ids) {
            if (states.containsKey(id)) {
                states.put(id, Boolean.valueOf(value));
            }
        }
    }

    /** Returns the preset name matching the states exactly, or "Custom". */
    public static String detect(Map<String, Boolean> states) {
        for (String name : NAMES) {
            if ("Custom".equals(name)) {
                continue;
            }
            if (states(name).equals(states)) {
                return name;
            }
        }
        return "Custom";
    }

    /**
     * Extra scalar options implied by a preset (string strength, noise level,
     * MBA). Custom keeps the conservative balanced values.
     */
    public static Map<String, String> extraOptions(String name) {
        Map<String, String> options = new LinkedHashMap<String, String>();
        String preset = name == null ? "custom" : name.toLowerCase(java.util.Locale.ROOT);
        String strength = "3";
        String noiseLevel = "1";
        boolean mba = false;
        if ("light".equals(preset)) {
            strength = "1";
        } else if ("balanced".equals(preset) || "custom".equals(preset)) {
            strength = "2";
        } else if ("aggressive".equals(preset)) {
            strength = "2";
            noiseLevel = "2";
        } else if ("maximum".equals(preset)) {
            strength = "3";
            noiseLevel = "2";
            mba = true;
        } else if ("nocturne".equals(preset)) {
            strength = "3";
            noiseLevel = "3";
        }
        options.put("string.strength", strength);
        options.put("decompilerNoise.level", noiseLevel);
        options.put("mba.enabled", String.valueOf(mba));
        return options;
    }

    /** Canonical preset name for a GUI-selected label (CLI-compatible). */
    public static String coreName(String guiName) {
        if (guiName == null) {
            return "balanced";
        }
        String name = guiName.trim().toLowerCase(java.util.Locale.ROOT);
        if ("light".equals(name) || "balanced".equals(name) || "aggressive".equals(name)
                || "maximum".equals(name) || "nocturne".equals(name)) {
            return name;
        }
        return "balanced";
    }
}
