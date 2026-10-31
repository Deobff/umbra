package io.umbra.guifx;

import io.umbra.gui.GuiModeOptions;
import io.umbra.gui.GuiPresets;
import io.umbra.gui.GuiSwitches;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Everything the shell needs to know about the run: the control values, the
 * target paths and the engine command line derived from them.
 *
 * <p>The command line is the single output of this class: the preview pane, the
 * clipboard copy and the spawned process all come from {@link #command()}, so
 * what the user reads is exactly what runs. Explicit {@code --set} values win
 * over the preset in the engine, which is why a preset change first loads the
 * preset's effective values into the controls ({@link #presetValues(String)}
 * reads them from {@code --dump-preset}).</p>
 */
final class ConsoleModel {

    /** Switch states keyed by {@link GuiSwitches.Toggle#id}. */
    final Map<String, Boolean> toggles = new LinkedHashMap<String, Boolean>();

    /** Spec values keyed by {@link GuiModeOptions.Spec#id}. */
    final Map<String, String> specs = new LinkedHashMap<String, String>();

    private final Map<String, Map<String, String>> presetCache =
            new HashMap<String, Map<String, String>>();

    String jarPath = "dist/umbra.jar";
    String input = "";
    String output = "";
    String preset = GuiPresets.DEFAULT;
    String seed = "";
    boolean verify = true;

    ConsoleModel() {
        seedDefaults();
    }

    /** Loads the defaults published by the engine-side control model. */
    void seedDefaults() {
        for (GuiSwitches.Toggle toggle : GuiSwitches.allToggles()) {
            toggles.put(toggle.id, Boolean.valueOf(toggle.defaultOn));
        }
        for (GuiModeOptions.Group group : GuiModeOptions.groups()) {
            for (GuiModeOptions.Spec spec : group.specs) {
                specs.put(spec.id, spec.defaultValue == null ? "" : spec.defaultValue);
            }
        }
    }

    /** Spec keys win over switches that write the same engine option. */
    Set<String> specKeys() {
        Set<String> keys = new HashSet<String>();
        for (GuiModeOptions.Group group : GuiModeOptions.groups()) {
            for (GuiModeOptions.Spec spec : group.specs) {
                if (spec.key != null) {
                    keys.add(spec.key);
                }
            }
        }
        return keys;
    }

    /** The exact command line the engine receives. */
    String command() {
        StringBuilder cmd = new StringBuilder("java -jar ").append(quote(jarPath));
        cmd.append(" -i ").append(quote(input.trim()));
        cmd.append(" -o ").append(quote(output.trim()));
        if (preset != null && !preset.isEmpty() && !"Custom".equalsIgnoreCase(preset)) {
            cmd.append(" --preset ").append(preset.toLowerCase(Locale.ROOT));
        }
        if (seed != null && !seed.trim().isEmpty()) {
            cmd.append(" --seed ").append(seed.trim());
        }
        if (verify) {
            cmd.append(" --verify");
        }
        Set<String> specKeys = specKeys();
        for (GuiSwitches.GroupDef group : GuiSwitches.groups()) {
            for (GuiSwitches.Toggle toggle : group.toggles) {
                if (toggle.key == null || specKeys.contains(toggle.key)) {
                    continue;
                }
                boolean on = Boolean.TRUE.equals(toggles.get(toggle.id));
                String value = on ? toggle.onValue : toggle.offValue;
                if (value == null || value.isEmpty()) {
                    value = on ? "true" : "false";
                }
                cmd.append(" --set ").append(toggle.key).append('=').append(value);
            }
        }
        for (GuiModeOptions.Group group : GuiModeOptions.groups()) {
            for (GuiModeOptions.Spec spec : group.specs) {
                if (spec.key == null || spec.kind == GuiModeOptions.Kind.BOOL) {
                    continue;
                }
                String value = specs.get(spec.id);
                if (value == null || value.isEmpty()) {
                    continue;
                }
                cmd.append(" --set ").append(spec.key).append('=')
                        .append(value.indexOf(' ') >= 0 ? quote(value) : value);
            }
        }
        return cmd.toString();
    }

    /**
     * Everything after {@code -i input -o output}: the argument list the spawned
     * process gets, parsed back out of the previewed command so the two can never
     * disagree.
     */
    List<String> engineArguments() {
        String full = command();
        String head = "java -jar " + quote(jarPath) + " -i " + quote(input.trim())
                + " -o " + quote(output.trim());
        String rest = full.startsWith(head) ? full.substring(head.length()).trim() : full;
        List<String> args = new ArrayList<String>();
        StringBuilder current = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == '"') {
                quoted = !quoted;
            } else if (c == ' ' && !quoted) {
                if (current.length() > 0) {
                    args.add(current.toString());
                    current.setLength(0);
                }
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) {
            args.add(current.toString());
        }
        return args;
    }

    /** Effective values of {@code preset}, cached; read from {@code --dump-preset}. */
    Map<String, String> presetValues(String presetName) {
        Map<String, String> cached = presetCache.get(presetName);
        if (cached != null) {
            return cached;
        }
        Map<String, String> values = new LinkedHashMap<String, String>();
        try {
            Process dump = new ProcessBuilder("java", "-jar", jarPath,
                    "--dump-preset", presetName).start();
            Charset charset = Charset.defaultCharset();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(dump.getInputStream(), charset))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    int tab = line.indexOf('\t');
                    if (tab > 0) {
                        values.put(line.substring(0, tab), line.substring(tab + 1));
                    }
                }
            }
            dump.waitFor();
        } catch (Exception failure) {
            values.clear();
        }
        presetCache.put(presetName, values);
        return values;
    }

    /** Copies the preset's effective values into the controls. */
    void applyPresetValues(Map<String, String> values) {
        if (values == null || values.isEmpty()) {
            return;
        }
        for (GuiModeOptions.Group group : GuiModeOptions.groups()) {
            for (GuiModeOptions.Spec spec : group.specs) {
                if (spec.key == null) {
                    continue;
                }
                String value = values.get(spec.key);
                if (value != null) {
                    specs.put(spec.id, value);
                }
            }
        }
        for (GuiSwitches.GroupDef group : GuiSwitches.groups()) {
            for (GuiSwitches.Toggle toggle : group.toggles) {
                if (toggle.key == null) {
                    continue;
                }
                Boolean on = toggleValue(toggle, values.get(toggle.key));
                if (on != null) {
                    toggles.put(toggle.id, on);
                }
            }
        }
    }

    /** Maps a preset value onto a switch state, honouring its on/off values. */
    static Boolean toggleValue(GuiSwitches.Toggle toggle, String value) {
        if (value == null) {
            return null;
        }
        if (toggle.onValue != null && toggle.onValue.equalsIgnoreCase(value)) {
            return Boolean.TRUE;
        }
        if (toggle.offValue != null && toggle.offValue.equalsIgnoreCase(value)) {
            return Boolean.FALSE;
        }
        if ("true".equalsIgnoreCase(value)) {
            return Boolean.TRUE;
        }
        if ("false".equalsIgnoreCase(value)) {
            return Boolean.FALSE;
        }
        return null;
    }

    static String quote(String value) {
        return '"' + value.replace("\"", "\\\"") + '"';
    }
}
