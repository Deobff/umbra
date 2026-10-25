package io.umbra.gui;

import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.ConfigException;
import io.umbra.core.config.ConfigLoader;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.Stats;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.engine.UmbraVerifier;
import io.umbra.core.util.Log;
import io.umbra.gui.theme.Aurora;
import io.umbra.gui.theme.Tokens;
import io.umbra.gui.ui.Buttons;
import io.umbra.gui.ui.ConsolePanel;
import io.umbra.gui.ui.GroupSection;
import io.umbra.gui.ui.PathRow;
import io.umbra.gui.ui.PresetSelector;
import io.umbra.gui.ui.PrimaryButton;
import io.umbra.gui.ui.RightColumn;
import io.umbra.gui.ui.Sidebar;
import io.umbra.gui.ui.StatCard;
import io.umbra.gui.ui.StatusBar;
import io.umbra.gui.ui.TopBar;

import javax.swing.AbstractAction;
import javax.swing.ActionMap;
import javax.swing.BorderFactory;
import javax.swing.InputMap;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CancellationException;

/**
 * The assembled GUI: three columns, top bar, status bar, aurora background,
 * frosted glass and all product behaviour (presets, YAML, drag and drop,
 * start/cancel, preferences, shortcuts).
 *
 * <p>{@code GuiRoot} is a plain panel rather than a frame so the exact same UI
 * can be rendered offscreen for {@code --screenshot} and {@code --self-test}
 * without a display. {@link GuiFrame} only wraps it in a native window.</p>
 */
public final class GuiRoot extends JPanel implements Aurora.SurfaceProvider {

    private enum Mode {
        WIDE,
        MEDIUM,
        COMPACT
    }

    private static final int MIN_WIDTH = 720;

    private final GuiPrefs prefs;
    private final TopBar topBar;
    private final Sidebar sidebar;
    private final ConsolePanel console;
    private final RightColumn rightColumn;
    private final StatusBar statusBar;
    private final PathRow inputRow;
    private final PathRow outputRow;
    private final PathRow mappingRow;
    private final PresetSelector presetSelector;
    private final io.umbra.gui.ui.AdvancedEditor advancedEditor;
    private JButton modeOptionsButton;

    private Mode mode = Mode.WIDE;
    private BufferedImage surface;
    private int surfaceWidth;
    private int surfaceHeight;

    private boolean animations;
    private boolean entranceRunning;
    private long entranceStarted;
    private Timer entranceTimer;
    private final Map<Component, Entrance> entrances = new LinkedHashMap<Component, Entrance>();
    private final Map<Component, Integer> entranceOffsets = new LinkedHashMap<Component, Integer>();

    private boolean drawerOpen;
    private int statsNudge;
    private Timer statsNudgeTimer;

    private String preset = GuiPresets.DEFAULT;
    /** Per-mode detailed values (mode options dialog); authoritative for the run. */
    private final Map<String, String> detailedOptions = new LinkedHashMap<String, String>();
    /** Last non-custom mode, used by "Reset to mode defaults" and Custom runs. */
    private String detailedMode = GuiPresets.DEFAULT;
    private String lastAutoOutput = "";
    private Path lastOutput;

    private volatile boolean running;
    private volatile boolean cancelRequested;
    private boolean closeWhenIdle;
    private boolean applyingPreset;
    private SwingWorker<Outcome, Void> worker;
    private Outcome lastOutcome;
    private String failureMessage = "";
    private boolean trialMode;
    private Runnable closeHandler;

    private int progressPercent;
    private long lastClasses;
    private long lastMethods;
    private long lastStrings;
    private long lastMillis;

    public GuiRoot(boolean animations) {
        super(null);
        this.animations = animations;
        this.prefs = GuiPrefs.load();
        setOpaque(true);

        topBar = new TopBar();
        console = new ConsolePanel();
        rightColumn = new RightColumn();
        sidebar = new Sidebar();
        statusBar = new StatusBar();
        inputRow = new PathRow("Input JAR", "Choose or drop a JAR", false,
                "Browse input JAR", "Select the JAR to protect", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                browseInput();
            }
        });
        outputRow = new PathRow("Output JAR", "Defaults next to the input", false,
                "Save output JAR as", "Choose where the protected JAR is written",
                new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                browseOutput();
            }
        });
        mappingRow = new PathRow("Mapping file", "Next to output",
                true, "Choose mapping file", "Rewrite mapping path (optional)",
                new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                browseMapping();
            }
        });
        presetSelector = new PresetSelector();
        advancedEditor = new io.umbra.gui.ui.AdvancedEditor("cc / clang path",
                "key=value per line \u2014 e.g. string.engine=rc4",
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        browseCompiler();
                    }
                });

        // Painting order: the sidebar must sit above the console so the compact
        // drawer can overlay it; the status bar is painted last.
        add(topBar);
        add(console);
        add(rightColumn);
        add(sidebar);
        add(statusBar);

        buildSidebar();
        collectEntrances();
        bindActions();
        installShortcuts();
        installDrawerDismiss();
        installDragAndDrop();

        topBar.seedField().setText(String.valueOf(prefs.seed()));
        applyPreset(prefs.preset(), false);
        resetStats();
        updateStatusIdle();
        updateFacts();
        if (animations) {
            startEntrance();
        }
        getAccessibleContext().setAccessibleName("Umbra");
        getAccessibleContext().setAccessibleDescription(
                "Umbra " + GuiConfig.VERSION + " Java bytecode protection");
    }

    /* -------------------------------------------------------- construction */

    private void buildSidebar() {
        for (GuiSwitches.GroupDef def : GuiSwitches.groups()) {
            GroupSection group = sidebar.addGroup(def.title, def.expanded);
            if (def.kind == GuiSwitches.Kind.SWITCHES) {
                for (GuiSwitches.Toggle toggle : def.toggles) {
                    sidebar.addSwitch(group, toggle.id, toggle.label, toggle.defaultOn);
                }
            } else if (def.kind == GuiSwitches.Kind.INPUT_OUTPUT) {
                group.addRow(inputRow, PathRow.HEIGHT);
                group.addRow(outputRow, PathRow.HEIGHT);
                group.addRow(mappingRow, PathRow.HEIGHT);
            } else if (def.kind == GuiSwitches.Kind.PRESET) {
                group.addRow(presetSelector, PresetSelector.HEIGHT);
                group.addRow(buildPresetActions(), 66);
            } else if (def.kind == GuiSwitches.Kind.ADVANCED) {
                group.addRow(advancedEditor, io.umbra.gui.ui.AdvancedEditor.HEIGHT);
            }
        }
        sidebar.finishGroups();
        sidebar.setToggleListener(new Runnable() {
            @Override
            public void run() {
                onUserToggle();
            }
        });
        sidebar.setGroupToggleListener(new Runnable() {
            @Override
            public void run() {
                triggerStatsNudge();
            }
        });
    }

    private JPanel buildPresetActions() {
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        actions.setOpaque(false);
        actions.setBorder(BorderFactory.createEmptyBorder(0, 32, 0, 0));
        modeOptionsButton = Buttons.quiet("Mode options\u2026", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                openModeOptions();
            }
        });
        actions.add(modeOptionsButton);
        actions.add(Buttons.quiet("Load YAML", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                loadYaml();
            }
        }));
        actions.add(Buttons.quiet("Save YAML", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveYaml();
            }
        }));
        return actions;
    }

    private void bindActions() {
        topBar.primaryButton().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (running) {
                    cancel();
                } else {
                    start();
                }
            }
        });
        console.clearButton().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                console.clear();
                updateStatusIdle();
            }
        });
        console.openFolderButton().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                openOutputFolder();
            }
        });
        console.openFolderButton().setEnabled(false);
        topBar.menuButton().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                drawerOpen = !drawerOpen;
                revalidate();
                repaint();
            }
        });
        presetSelector.setListener(new PresetSelector.Listener() {
            @Override
            public void selected(String name) {
                if (!applyingPreset) {
                    applyPreset(name, true);
                }
            }
        });
    }

    private void ownInput(String text) {
        inputRow.setText(text);
    }

    /* ------------------------------------------------------------ behaviour */

    private void applyPreset(String name, boolean fromUser) {
        applyingPreset = true;
        try {
            if (!"Custom".equals(name)) {
                Map<String, Boolean> states = GuiPresets.states(name);
                for (Map.Entry<String, Boolean> entry : states.entrySet()) {
                    sidebar.setOn(entry.getKey(), entry.getValue().booleanValue());
                }
                detailedMode = name;
                detailedOptions.clear();
                detailedOptions.putAll(GuiModeOptions.defaults(name));
            } else if (detailedOptions.isEmpty()) {
                // Custom keeps the current switches; it only needs a base for
                // the detailed editor to start from.
                detailedOptions.putAll(GuiModeOptions.defaults(detailedMode));
            }
            presetSelector.setSelected(name);
            preset = name;
        } finally {
            applyingPreset = false;
        }
        if (fromUser) {
            console.append("INFO", "Mode applied: " + name
                    + ("Custom".equals(name) ? " (current values kept)"
                    : " (preset + detailed defaults)"));
        }
        prefs.setPreset(name);
        updateFacts();
    }

    private void onUserToggle() {
        if (applyingPreset) {
            return;
        }
        // Keep the detailed mode values in step with the left-column switch.
        String toggleId = sidebar.lastToggleId();
        Map<String, Boolean> states = sidebar.switchStates();
        Boolean value = states.get(toggleId);
        if (value != null) {
            GuiModeOptions.applyToggle(detailedOptions, toggleId, value.booleanValue());
        }
        if (!"Custom".equals(preset)) {
            preset = "Custom";
            presetSelector.setSelected("Custom");
            prefs.setPreset("Custom");
        }
        updateFacts();
    }

    /** Current detailed values; a preset uses its defaults, Custom keeps edits. */
    Map<String, String> currentDetailedValues() {
        Map<String, String> values = new LinkedHashMap<String, String>();
        if ("Custom".equals(preset) && !detailedOptions.isEmpty()) {
            values.putAll(detailedOptions);
        } else if (!"Custom".equals(preset)) {
            values.putAll(GuiModeOptions.defaults(preset));
        } else {
            values.putAll(GuiModeOptions.defaults(detailedMode));
        }
        values.put("gui.seed", topBar.seedField().getText().trim());
        values.put("gui.mapping", mappingRow.text());
        values.put("gui.verify", String.valueOf(sidebar.isOn("verify")));
        return values;
    }

    /** Opens the per-mode detailed option dialog from the Preset group. */
    void openModeOptions() {
        String mode = "Custom".equals(preset) ? detailedMode : preset;
        GuiModeOptionsDialog.Result result = GuiModeOptionsDialog.show(
                this, currentDetailedValues(), mode);
        if (result == null) {
            return;
        }
        applyModeOptions(result.values, result.mode);
    }

    /** Applies values returned by the mode-options dialog (also used by tests). */
    void applyModeOptions(Map<String, String> values, String mode) {
        applyingPreset = true;
        try {
            detailedOptions.clear();
            detailedOptions.putAll(values);
            for (GuiModeOptions.Spec spec : GuiModeOptions.allSpecs()) {
                if (spec.uiOnly() && !"gui.verify".equals(spec.id)) {
                    continue;
                }
                String value = values.get(spec.id);
                if (value == null) {
                    continue;
                }
                if ("gui.seed".equals(spec.id)) {
                    topBar.seedField().setText(value.trim());
                } else if ("gui.mapping".equals(spec.id)) {
                    mappingRow.setText(value.trim());
                }
            }
            // The detailed values drive the left-column switches, whichever
            // mode was selected (mode defaults are simply a preset shortcut).
            Map<String, Boolean> synced = GuiModeOptions.syncToggles(values);
            for (Map.Entry<String, Boolean> entry : synced.entrySet()) {
                sidebar.setOn(entry.getKey(), entry.getValue().booleanValue());
            }
            preset = mode;
            if (!"Custom".equals(mode)) {
                detailedMode = mode;
            }
            presetSelector.setSelected(preset);
        } finally {
            applyingPreset = false;
        }
        prefs.setPreset(preset);
        console.append("INFO", "Mode options applied: " + mode
                + ("Custom".equals(mode) ? " (custom edits)" : " defaults")
                + " \u00b7 " + GuiModeOptions.allSpecs().size() + " controls");
        updateFacts();
    }

    private long collectSeed() {
        String text = topBar.seedField().getText().trim();
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException e) {
            return Long.MIN_VALUE;
        }
    }

    private boolean seedValid() {
        String text = topBar.seedField().getText().trim();
        if (text.isEmpty()) {
            return false;
        }
        try {
            Long.parseLong(text);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private Path inputPath() {
        return pathOf(inputRow.text());
    }

    private Path outputPath() {
        return pathOf(outputRow.text());
    }

    private static Path pathOf(String text) {
        if (text == null || text.trim().isEmpty()) {
            return null;
        }
        try {
            return Paths.get(text.trim()).toAbsolutePath().normalize();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Reads the output directory from the output or input path. */
    private Path currentDirectory(boolean output) {
        Path path = output ? outputPath() : inputPath();
        if (path != null) {
            Path parent = path.getParent();
            if (parent != null) {
                return parent;
            }
        }
        String remembered = output ? prefs.lastOutputDir() : prefs.lastInputDir();
        if (remembered != null && !remembered.trim().isEmpty()) {
            return Paths.get(remembered);
        }
        return Paths.get(System.getProperty("user.home", "."));
    }

    private void browseInput() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select input JAR");
        chooser.setFileFilter(new FileNameExtensionFilter("JAR files", "jar"));
        Path current = inputPath();
        if (current != null) {
            chooser.setSelectedFile(current.toFile());
        }
        chooser.setCurrentDirectory(currentDirectory(false).toFile());
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        if (file == null) {
            return;
        }
        setInput(file.toPath());
        prefs.rememberInput(file.toPath());
        prefs.save();
    }

    private void setInput(Path raw) {
        Path input = raw.toAbsolutePath().normalize();
        String previousDefault = lastAutoOutput;
        String suggested = GuiConfig.defaultOutput(input);
        lastAutoOutput = suggested;
        ownInput(input.toString());
        inputRow.setToolTip(input.toString());
        String currentOutput = outputRow.text().trim();
        if (currentOutput.isEmpty() || currentOutput.equals(previousDefault)) {
            outputRow.setText(suggested);
            outputRow.setToolTip(suggested);
        }
        updateFacts();
    }

    private void browseOutput() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save protected JAR as");
        chooser.setFileFilter(new FileNameExtensionFilter("JAR files", "jar"));
        Path suggested = outputPath();
        if (suggested == null && inputPath() != null) {
            suggested = Paths.get(GuiConfig.defaultOutput(inputPath()));
        }
        if (suggested != null) {
            chooser.setSelectedFile(suggested.toFile());
            if (suggested.getParent() != null) {
                chooser.setCurrentDirectory(suggested.getParent().toFile());
            }
        } else {
            chooser.setCurrentDirectory(currentDirectory(true).toFile());
        }
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        if (file == null) {
            return;
        }
        String path = file.getAbsolutePath();
        if (!path.toLowerCase(Locale.ROOT).endsWith(".jar")) {
            path = path + ".jar";
        }
        outputRow.setText(path);
        outputRow.setToolTip(path);
        prefs.rememberOutput(Paths.get(path));
        prefs.save();
    }

    private void browseMapping() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Mapping file");
        chooser.setFileFilter(new FileNameExtensionFilter("Text files", "txt"));
        Path current = pathOf(mappingRow.text());
        if (current != null) {
            chooser.setSelectedFile(current.toFile());
        } else {
            Path base = outputPath();
            chooser.setSelectedFile((base == null ? Paths.get("umbra-mapping.txt")
                    : (base.getParent() == null ? Paths.get("umbra-mapping.txt")
                    : base.getParent().resolve("umbra-mapping.txt"))).toFile());
        }
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        if (file == null) {
            return;
        }
        mappingRow.setText(file.getAbsolutePath());
    }

    private void browseCompiler() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Native compiler executable");
        String current = advancedEditor.compilerField().getText().trim();
        if (!current.isEmpty()) {
            File file = new File(current);
            if (file.getParentFile() != null) {
                chooser.setCurrentDirectory(file.getParentFile());
            }
        }
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        if (file != null) {
            advancedEditor.compilerField().setText(file.getAbsolutePath());
        }
    }

    /* ------------------------------------------------------------- YAML IO */

    private void loadYaml() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Load configuration");
        chooser.setFileFilter(new FileNameExtensionFilter("YAML configuration", "yml", "yaml"));
        String remembered = prefs.lastConfigDir();
        if (remembered != null && !remembered.trim().isEmpty()) {
            chooser.setCurrentDirectory(new File(remembered));
        }
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        if (file == null) {
            return;
        }
        try {
            UmbraConfig config = ConfigLoader.load(file.toPath(), false);
            applyConfiguration(config);
            prefs.rememberConfig(file.toPath());
            prefs.save();
            console.append("INFO", "Configuration loaded: " + file.getAbsolutePath());
            updateStatusIdle();
        } catch (Exception e) {
            console.append("ERROR", "Cannot load configuration: " + describeError(e));
            GuiDialogs.error(this, "Cannot load configuration", describeError(e));
        }
    }

    /** Applies a loaded configuration to every control without firing presets. */
    void applyConfiguration(UmbraConfig config) {
        applyingPreset = true;
        try {
            Map<String, Boolean> states = GuiSwitches.fromConfig(config);
            for (Map.Entry<String, Boolean> entry : states.entrySet()) {
                sidebar.setOn(entry.getKey(), entry.getValue().booleanValue());
            }
            if (config.input() != null) {
                srcSetInputSilently(config.input());
            }
            if (config.output() != null) {
                outputRow.setText(config.output().toAbsolutePath().toString());
            }
            if (config.mapping().file() != null && !config.mapping().file().trim().isEmpty()) {
                mappingRow.setText(config.mapping().file());
            }
            String compiler = GuiConfig.describe(config).get("native.compiler");
            if (compiler != null && !compiler.trim().isEmpty()) {
                advancedEditor.compilerField().setText(compiler);
            }
            advancedEditor.setOptionsText(GuiSwitches.formatAdvanced(
                    GuiSwitches.advancedOverrides(config)));
            topBar.seedField().setText(String.valueOf(config.seed()));
            Map<String, String> effective = GuiConfig.describe(config);
            Map<String, String> loaded = GuiModeOptions.fromEffective(effective);
            loaded.put("gui.seed", String.valueOf(config.seed()));
            loaded.put("gui.mapping", config.mapping().file());
            loaded.put("gui.verify", String.valueOf(sidebar.isOn("verify")));
            detailedOptions.clear();
            detailedOptions.putAll(loaded);
            String detected = GuiPresets.detect(states);
            if (!"Custom".equals(detected)
                    && GuiModeOptions.overridesModeDefaults(detected, loaded)) {
                detected = "Custom";
            }
            if (!"Custom".equals(detected)) {
                detailedMode = detected;
            }
            presetSelector.setSelected(detected);
            preset = detected;
            prefs.setPreset(detected);
        } finally {
            applyingPreset = false;
        }
        updateFacts();
    }

    private void srcSetInputSilently(Path raw) {
        Path input = raw.toAbsolutePath().normalize();
        lastAutoOutput = GuiConfig.defaultOutput(input);
        inputRow.setText(input.toString());
        inputRow.setToolTip(input.toString());
    }

    private void saveYaml() {
        Path input = inputPath();
        Path output = outputPath();
        String problem = GuiConfig.validate(input, output);
        if (problem != null) {
            GuiDialogs.error(this, "Cannot save configuration",
                    problem + "\nA configuration records the input and output paths.");
            return;
        }
        if (!seedValid()) {
            GuiDialogs.error(this, "Cannot save configuration",
                    "Seed must be a whole number.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save configuration");
        chooser.setFileFilter(new FileNameExtensionFilter("YAML configuration", "yml", "yaml"));
        String remembered = prefs.lastConfigDir();
        if (remembered != null && !remembered.trim().isEmpty()) {
            chooser.setCurrentDirectory(new File(remembered));
        }
        chooser.setSelectedFile(new File("umbra.yml"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        if (file == null) {
            return;
        }
        Path target = file.toPath();
        String name = target.getFileName() == null ? "" : target.getFileName().toString();
        if (!name.toLowerCase(Locale.ROOT).endsWith(".yml")
                && !name.toLowerCase(Locale.ROOT).endsWith(".yaml")) {
            target = target.resolveSibling(name + ".yml");
        }
        if (Files.exists(target)) {
            boolean overwrite = GuiDialogs.confirm(this, "Overwrite configuration",
                    "The file already exists:\n" + target + "\n\nOverwrite it?",
                    "Overwrite", "Cancel");
            if (!overwrite) {
                return;
            }
        }
        try {
            Map<String, String> options = collectOptions();
            UmbraConfig config = GuiConfig.build(input, output, collectSeed(), options,
                    mappingTarget());
            Files.write(target, GuiConfig.toYaml(config).getBytes(StandardCharsets.UTF_8));
            prefs.rememberConfig(target);
            prefs.save();
            console.append("INFO", "Configuration saved: " + target.toAbsolutePath());
        } catch (Exception e) {
            console.append("ERROR", "Cannot save configuration: " + describeError(e));
            GuiDialogs.error(this, "Cannot save configuration", describeError(e));
        }
    }

    private Path mappingTarget() {
        Path mapping = pathOf(mappingRow.text());
        return mapping;
    }

    Map<String, String> collectOptions() {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.putAll(GuiSwitches.baseOptions(sidebar.switchStates()));
        options.putAll(GuiPresets.extraOptions(preset));
        if (sidebar.isOn("classEnc")) {
            options.put("classEncryption.antiDump", "true");
        }
        // Detailed per-mode values are authoritative for every option they
        // expose (seed/mapping are handled separately, not as engine options).
        options.putAll(GuiModeOptions.toOptionMap(currentDetailedValues()));
        String compiler = advancedEditor.compilerField().getText().trim();
        if (!compiler.isEmpty()) {
            options.put("native.compiler", compiler);
        }
        // The advanced editor stays the last word.
        options.putAll(GuiSwitches.parseAdvanced(advancedEditor.getOptionsText()));
        return options;
    }

    /* --------------------------------------------------------------- start */

    private void start() {
        beginRun(false);
    }

    /**
     * Starts a protection run without dialogs, used by the deterministic
     * {@code --screenshot --run} QA path. Returns false when validation fails.
     */
    boolean startTrial(Path input, Path output, long seed, String presetName) {
        trialMode = true;
        applyingPreset = true;
        try {
            srcSetInputSilently(input);
            outputRow.setText(output.toAbsolutePath().normalize().toString());
            topBar.seedField().setText(String.valueOf(seed));
            applyPresetStatesOnly(presetName);
        } finally {
            applyingPreset = false;
        }
        return beginRun(true);
    }

    private void applyPresetStatesOnly(String name) {
        Map<String, Boolean> states = GuiPresets.states(name);
        for (Map.Entry<String, Boolean> entry : states.entrySet()) {
            sidebar.setOn(entry.getKey(), entry.getValue().booleanValue());
        }
        presetSelector.setSelected(name);
        preset = name;
        if (!"Custom".equals(name)) {
            detailedMode = name;
            detailedOptions.clear();
            detailedOptions.putAll(GuiModeOptions.defaults(name));
        } else if (detailedOptions.isEmpty()) {
            detailedOptions.putAll(GuiModeOptions.defaults(detailedMode));
        }
        updateFacts();
    }

    /** Applies a preset for the deterministic screenshot path (no logging). */
    void applyPresetForScreenshot(String name) {
        applyPresetStatesOnly(name);
    }

    /** Opens the compact drawer before an offscreen screenshot. */
    void openDrawerForScreenshot() {
        drawerOpen = true;
        revalidate();
        repaint();
    }

    private boolean beginRun(boolean quiet) {
        if (running) {
            return false;
        }
        failureMessage = "";
        Path input = inputPath();
        Path output = outputPath();
        if (input == null) {
            return validationFailure("Select an input JAR first.", quiet);
        }
        if (!seedValid()) {
            return validationFailure("Seed must be a whole number.", quiet);
        }
        String problem = GuiConfig.validate(input, output);
        if (problem != null) {
            return validationFailure(problem, quiet);
        }
        if (!quiet && Files.exists(output)) {
            boolean overwrite = GuiDialogs.confirm(this, "Overwrite output",
                    "The output file already exists:\n" + output + "\n\nOverwrite it?",
                    "Overwrite", "Cancel");
            if (!overwrite) {
                return false;
            }
        }
        if (quiet) {
            try {
                if (Files.exists(output)) {
                    Files.delete(output);
                }
            } catch (Exception ignored) {
                // The engine surfaces a clearer error when the write fails.
            }
        }
        try {
            Path parent = output.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (Exception e) {
            return validationFailure("Cannot create the output directory: "
                    + describeError(e), quiet);
        }
        final Map<String, String> options = collectOptions();
        final long seed = collectSeed();
        final boolean verify = sidebar.isOn("verify");
        final UmbraConfig config;
        try {
            config = GuiConfig.build(input, output, seed, options, mappingTarget());
        } catch (Throwable e) {
            return validationFailure("Cannot build the configuration: "
                    + describeError(e), quiet);
        }

        running = true;
        cancelRequested = false;
        prefs.setSeed(seed);
        prefs.setPreset(preset);
        prefs.rememberInput(input);
        prefs.rememberOutput(output);
        prefs.save();

        progressPercent = 0;
        lastOutcome = null;
        rightColumn.reset();
        console.clear();
        console.setRunningHighlight(true);
        topBar.primaryButton().setText("Cancel");
        topBar.primaryButton().setProgress(0);
        topBar.primaryButton().setEnabled(true);
        console.openFolderButton().setEnabled(false);
        setStatus("Protecting classes\u2026", StatusBar.Tone.PENDING);
        updateFacts();
        appendLog("INFO", "Umbra " + GuiConfig.VERSION + " starting");
        appendLog("INFO", "Input:  " + input);
        appendLog("INFO", "Output: " + output);
        appendLog("INFO", "Preset: " + preset + " \u00b7 seed " + seed);

        worker = new SwingWorker<Outcome, Void>() {
            @Override
            protected Outcome doInBackground() {
                return runJob(config, verify);
            }

            @Override
            protected void done() {
                finish();
            }
        };
        worker.execute();
        return true;
    }

    private boolean validationFailure(String message, boolean quiet) {
        failureMessage = message;
        console.append("ERROR", message);
        setStatus("Cannot start: " + message, StatusBar.Tone.ERROR);
        if (!quiet) {
            GuiDialogs.error(this, "Cannot start", message);
        }
        return false;
    }

    private Outcome runJob(UmbraConfig config, boolean verify) {
        try {
            Log log = new Log(new Log.Sink() {
                @Override
                public void line(String level, String message) {
                    appendLog(level, message);
                }
            }, false);
            ProgressListener listener = new ProgressListener() {
                @Override
                public void onProgress(final int percent, final String message) {
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            reportProgress(percent, message);
                        }
                    });
                }

                @Override
                public boolean isCancelled() {
                    return cancelRequested || Thread.currentThread().isInterrupted();
                }
            };
            EngineResult result = new UmbraEngine(log).run(config, listener);
            if (verify) {
                List<String> errors = UmbraVerifier.verify(config.output(), config.libraries());
                if (errors != null && !errors.isEmpty()) {
                    StringBuilder text = new StringBuilder("Verification failed:");
                    for (String error : errors) {
                        text.append('\n').append(error);
                    }
                    return Outcome.failed(text.toString());
                }
                appendLog("INFO", "Verification: OK");
            }
            long bytes = 0L;
            try {
                bytes = Files.size(result.output());
            } catch (Exception ignored) {
                // Size is informational only.
            }
            return Outcome.ok(result, bytes);
        } catch (CancellationException e) {
            return Outcome.cancelled();
        } catch (Throwable e) {
            return Outcome.failed(describeError(e));
        }
    }

    private void reportProgress(int percent, String message) {
        progressPercent = Math.max(0, Math.min(100, percent));
        topBar.primaryButton().setProgress(progressPercent);
        if (message != null && !message.trim().isEmpty()) {
            setStatus(conciseStage(message), StatusBar.Tone.PENDING);
        }
        updateFacts();
    }

    /** Turns an engine progress line into a short status-bar phrase. */
    private static String conciseStage(String message) {
        String text = message == null ? "" : message.trim();
        if (text.startsWith("Loading input")) {
            return "Loading classes";
        }
        if (text.startsWith("Writing")) {
            return "Writing output";
        }
        if (text.length() > 64) {
            return text.substring(0, 61) + "\u2026";
        }
        return text;
    }

    private void cancel() {
        if (!running) {
            return;
        }
        cancelRequested = true;
        topBar.primaryButton().setText("Cancelling");
        topBar.primaryButton().setEnabled(false);
        setStatus("Cancelling\u2026", StatusBar.Tone.PENDING);
        console.append("WARN",
                "Cancellation requested; the current pass stops at its next checkpoint.");
        updateFacts();
    }

    private void finish() {
        running = false;
        topBar.primaryButton().setText("Start");
        topBar.primaryButton().setProgress(-1);
        topBar.primaryButton().setEnabled(true);
        console.setRunningHighlight(false);
        Outcome outcome;
        try {
            outcome = worker == null ? Outcome.failed("Unknown failure") : worker.get();
        } catch (CancellationException e) {
            outcome = Outcome.cancelled();
        } catch (Throwable e) {
            outcome = Outcome.failed(describeError(e));
        } finally {
            worker = null;
        }
        if (cancelRequested && outcome.error == null && !outcome.cancelled) {
            outcome = Outcome.cancelled();
        }
        lastOutcome = outcome;
        if (outcome.error != null) {
            failureMessage = outcome.error;
            setStatus("Protection failed.", StatusBar.Tone.ERROR);
            console.append("ERROR", outcome.error);
            updateFacts();
            if (!trialMode) {
                GuiDialogs.error(this, "Umbra failed", outcome.error);
            }
        } else if (outcome.cancelled) {
            setStatus("Run cancelled.", StatusBar.Tone.PENDING);
            console.append("WARN", "Run cancelled.");
            updateFacts();
        } else {
            EngineResult result = outcome.result;
            lastClasses = result == null ? 0 : result.classes();
            Stats stats = result == null ? null : result.stats();
            Map<String, Long> values = stats == null
                    ? new LinkedHashMap<String, Long>() : stats.snapshot();
            lastMethods = value(values, "methods.renamed");
            lastStrings = value(values, "strings.encrypted");
            lastMillis = result == null ? 0L : result.millis();
            lastOutput = result == null ? outputPath() : result.output();
            setStatus("Protection complete.", StatusBar.Tone.SUCCESS);
            topBar.primaryButton().setProgress(100);
            StatCard[] cards = rightColumn.cards();
            cards[0].setValue(lastClasses);
            cards[1].setValue(lastMethods);
            cards[2].setValue(lastStrings);
            cards[3].setValue(lastMillis);
            cards[0].setEmphasis(true);
            console.openFolderButton().setEnabled(lastOutput != null
                    && lastOutput.getParent() != null
                    && Files.isDirectory(lastOutput.getParent()));
            console.append("INFO", "Finished: " + lastClasses + " classes, "
                    + lastMethods + " methods renamed, " + lastStrings
                    + " strings encrypted in " + Tokens.duration(lastMillis));
            console.append("INFO", "Output: " + lastOutput);
            updateFacts();
        }
        if (closeWhenIdle) {
            persistPrefs();
            java.awt.Window window = SwingUtilities.getWindowAncestor(this);
            if (window != null) {
                window.dispose();
            }
            System.exit(0);
        }
    }

    private static long value(Map<String, Long> values, String key) {
        Long value = values.get(key);
        return value == null ? 0L : value.longValue();
    }

    private void appendLog(String level, String message) {
        console.append(level, message);
        if (trialMode) {
            if ("ERROR".equals(level)) {
                System.err.println("[ERROR] " + message);
            } else {
                System.out.println("[" + level + "] " + message);
            }
        }
    }

    /* ---------------------------------------------------------- open folder */

    private void openOutputFolder() {
        Path output = lastOutput != null ? lastOutput : outputPath();
        if (output == null) {
            return;
        }
        Path parent = output.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            GuiDialogs.error(this, "Folder not found", "The output folder does not exist yet.");
            return;
        }
        try {
            if (Desktop.isDesktopSupported()
                    && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
                Desktop.getDesktop().open(parent.toFile());
                return;
            }
        } catch (Exception ignored) {
            // Fall through to the platform command.
        }
        try {
            String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
            if (os.contains("win")) {
                new ProcessBuilder("explorer.exe", "/select," + output).start();
            } else if (os.contains("mac")) {
                new ProcessBuilder("open", parent.toString()).start();
            } else {
                new ProcessBuilder("xdg-open", parent.toString()).start();
            }
        } catch (Exception e) {
            GuiDialogs.error(this, "Cannot open folder", describeError(e));
        }
    }

    /* ---------------------------------------------------------- status text */

    private void setStatus(String text, StatusBar.Tone tone) {
        statusBar.setStatus(text, tone);
    }

    private void updateStatusIdle() {
        if (running) {
            return;
        }
        setStatus("Waiting to start", StatusBar.Tone.PENDING);
        updateFacts();
    }

    private void updateFacts() {
        List<String> facts = new ArrayList<String>();
        facts.add("seed " + (topBar.seedField().getText().trim().isEmpty()
                ? "23303" : topBar.seedField().getText().trim()));
        if (running) {
            facts.add(preset + " preset");
            facts.add(progressPercent + "%");
        } else if (lastOutcome != null && lastOutcome.result != null && !lastOutcome.cancelled
                && lastOutcome.error == null) {
            facts.add(lastClasses + " classes");
            facts.add(Tokens.duration(lastMillis));
        } else {
            facts.add(preset + " preset");
        }
        statusBar.setFacts(facts.toArray(new String[facts.size()]));
    }

    private void resetStats() {
        rightColumn.reset();
    }

    private void persistPrefs() {
        long seed = collectSeed();
        if (seed != Long.MIN_VALUE) {
            prefs.setSeed(seed);
        }
        prefs.setPreset(preset);
        prefs.rememberInput(inputPath());
        prefs.rememberOutput(outputPath());
        prefs.save();
    }

    void setCloseHandler(Runnable closeHandler) {
        this.closeHandler = closeHandler;
    }

    /** Called by the window's close button and by Escape when idle. */
    void requestClose() {
        if (running) {
            boolean cancelAndClose = GuiDialogs.confirm(this, "Run in progress",
                    "A protection run is still active.\nCancel it and exit Umbra?",
                    "Cancel run and exit", "Keep running");
            if (cancelAndClose) {
                closeWhenIdle = true;
                cancel();
            }
            return;
        }
        persistPrefs();
        if (closeHandler != null) {
            closeHandler.run();
        }
    }

    boolean isBusy() {
        return running;
    }

    String failureMessage() {
        return failureMessage;
    }

    Outcome lastOutcome() {
        return lastOutcome;
    }

    void setTrialMode(boolean trialMode) {
        this.trialMode = trialMode;
    }

    /* ---------------------------------------------------------- keyboard */

    private void installShortcuts() {
        InputMap input = getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        ActionMap actions = getActionMap();
        bind(input, actions, KeyStroke.getKeyStroke("ctrl O"), "umbra.browseInput",
                new Runnable() {
                    @Override
                    public void run() {
                        browseInput();
                    }
                });
        bind(input, actions, KeyStroke.getKeyStroke("ctrl S"), "umbra.saveAs",
                new Runnable() {
                    @Override
                    public void run() {
                        browseOutput();
                    }
                });
        bind(input, actions, KeyStroke.getKeyStroke("ctrl ENTER"), "umbra.start",
                new Runnable() {
                    @Override
                    public void run() {
                        if (!running) {
                            start();
                        }
                    }
                });
        bind(input, actions, KeyStroke.getKeyStroke("ESCAPE"), "umbra.escape",
                new Runnable() {
                    @Override
                    public void run() {
                        if (drawerOpen) {
                            drawerOpen = false;
                            revalidate();
                            repaint();
                        } else if (running) {
                            cancel();
                        } else {
                            requestClose();
                        }
                    }
                });
    }

    /** Clicking beside the compact drawer closes it. */
    private void installDrawerDismiss() {
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (drawerOpen && mode == Mode.COMPACT
                        && e.getX() > Tokens.SIDEBAR_WIDTH) {
                    drawerOpen = false;
                    revalidate();
                    repaint();
                }
            }
        });
    }

    private static void bind(InputMap input, ActionMap actions, KeyStroke stroke,
                             String name, final Runnable action) {
        input.put(stroke, name);
        actions.put(name, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
    }

    /* ------------------------------------------------------- drag and drop */

    private void installDragAndDrop() {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        try {
            java.awt.dnd.DropTargetListener listener = new java.awt.dnd.DropTargetAdapter() {
                @Override
                public void dragEnter(java.awt.dnd.DropTargetDragEvent event) {
                    if (event.isDataFlavorSupported(java.awt.datatransfer.DataFlavor
                            .javaFileListFlavor)) {
                        console.setDragHighlight(true);
                        event.acceptDrag(java.awt.dnd.DnDConstants.ACTION_COPY);
                    } else {
                        event.rejectDrag();
                    }
                }

                @Override
                public void dragExit(java.awt.dnd.DropTargetEvent event) {
                    console.setDragHighlight(false);
                }

                @Override
                public void drop(java.awt.dnd.DropTargetDropEvent event) {
                    console.setDragHighlight(false);
                    try {
                        event.acceptDrop(java.awt.dnd.DnDConstants.ACTION_COPY);
                        Object data = event.getTransferable()
                                .getTransferData(java.awt.datatransfer.DataFlavor
                                        .javaFileListFlavor);
                        if (data instanceof List) {
                            handleDrop((List<?>) data);
                        }
                        event.dropComplete(true);
                    } catch (Exception e) {
                        event.dropComplete(false);
                        console.append("WARN", "Drop failed: " + describeError(e));
                    }
                }
            };
            new java.awt.dnd.DropTarget(console, java.awt.dnd.DnDConstants.ACTION_COPY,
                    listener);
        } catch (Throwable ignored) {
            // Drag and drop is optional (for example on a restricted desktop).
        }
    }

    private void handleDrop(List<?> files) {
        boolean changed = false;
        for (Object element : files) {
            if (!(element instanceof File)) {
                continue;
            }
            File file = (File) element;
            if (file.isDirectory()) {
                if (inputPath() != null) {
                    String name = Paths.get(GuiConfig.defaultOutput(inputPath()))
                            .getFileName().toString();
                    Path output = file.toPath().resolve(name).toAbsolutePath().normalize();
                    outputRow.setText(output.toString());
                    outputRow.setToolTip(output.toString());
                    prefs.rememberOutput(output);
                    console.append("INFO", "Output set to " + output);
                    changed = true;
                } else {
                    console.append("WARN", "Drop a JAR first \u2014 the folder becomes "
                            + "the output directory.");
                }
            } else if (file.getName().toLowerCase(Locale.ROOT).endsWith(".jar")) {
                setInput(file.toPath());
                prefs.rememberInput(file.toPath());
                console.append("INFO", "Input dropped: " + file.getAbsolutePath());
                changed = true;
            } else {
                console.append("WARN", "Ignored non-JAR drop: " + file.getName());
            }
        }
        if (changed) {
            prefs.save();
            updateFacts();
        }
    }

    /* ------------------------------------------------------------- drawing */

    @Override
    public BufferedImage surfaceImage() {
        return surface;
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        int w = getWidth();
        int h = getHeight();
        if (w <= 0 || h <= 0) {
            return;
        }
        if (surface == null || surfaceWidth != w || surfaceHeight != h) {
            surface = Aurora.render(w, h);
            surfaceWidth = w;
            surfaceHeight = h;
        }
        graphics.drawImage(surface, 0, 0, null);
    }

    @Override
    protected void paintChildren(Graphics graphics) {
        // Standard Swing child painting: it owns translation and clipping,
        // which is what keeps on-screen repaints crisp.
        super.paintChildren(graphics);
        if (entranceRunning) {
            paintEntranceVeil(graphics);
        }
        paintDrawerOverlay(graphics);
    }

    /** Soft paper-coloured veil that fades the staggered slide-in reveal. */
    private void paintEntranceVeil(Graphics graphics) {
        long elapsed = System.currentTimeMillis() - entranceStarted;
        float raw = Tokens.clamp01((elapsed - 80L) / 900f);
        float alpha = (1f - Tokens.easeOut(raw)) * 0.92f;
        if (elapsed > 1500L) {
            stopEntrance();
            repaint();
            return;
        }
        if (alpha <= 0.004f) {
            return;
        }
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            g.setColor(Tokens.alpha(Tokens.CANVAS, alpha));
            g.fillRect(0, 0, getWidth(), getHeight());
        } finally {
            g.dispose();
        }
    }

    private void paintDrawerOverlay(Graphics graphics) {
        if (mode != Mode.COMPACT || !drawerOpen) {
            return;
        }
        Graphics2D scrim = (Graphics2D) graphics.create();
        try {
            scrim.setColor(new Color(0, 0, 0, 46));
            scrim.fillRect(Tokens.SIDEBAR_WIDTH, Tokens.TOP_BAR,
                    getWidth() - Tokens.SIDEBAR_WIDTH,
                    Math.max(0, getHeight() - Tokens.TOP_BAR - Tokens.STATUS_BAR));
        } finally {
            scrim.dispose();
        }
        Graphics2D sg = (Graphics2D) graphics.create();
        try {
            java.awt.Shape previous = sg.getClip();
            sg.clipRect(sidebar.getX(), sidebar.getY(), sidebar.getWidth(),
                    sidebar.getHeight());
            sg.translate(sidebar.getX(), sidebar.getY());
            sidebar.paint(sg);
            sg.setClip(previous);
        } finally {
            sg.dispose();
        }
    }

    private void collectEntrances() {
        entrances.put(topBar, new Entrance(100, -8));
        entrances.put(sidebar, new Entrance(250, 12));
        entrances.put(console, new Entrance(400, 12));
        entrances.put(rightColumn, new Entrance(500, 12));
        entrances.put(statusBar, new Entrance(700, -8));
    }

    private void startEntrance() {
        entranceStarted = System.currentTimeMillis();
        entranceRunning = true;
        entranceTimer = new Timer(16, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateEntranceOffsets();
                doLayout();
                repaint();
            }
        });
        entranceTimer.start();
    }

    /** Recomputes the staggered slide offsets of the five top-level regions. */
    private void updateEntranceOffsets() {
        long elapsed = System.currentTimeMillis() - entranceStarted;
        boolean moving = false;
        for (Component child : getComponents()) {
            Entrance entrance = entrances.get(child);
            if (entrance == null) {
                continue;
            }
            float raw = Tokens.clamp01((elapsed - entrance.delay) / 900f);
            float progress = Tokens.easeOut(raw);
            int offset = Math.round(entrance.offsetY * (1f - progress));
            entranceOffsets.put(child, Integer.valueOf(offset));
            if (raw < 1f) {
                moving = true;
            }
        }
        if (!moving) {
            entranceOffsets.clear();
            if (entranceTimer != null) {
                entranceTimer.stop();
                entranceTimer = null;
            }
            entranceRunning = false;
            doLayout();
            repaint();
        }
    }

    private int entranceOffset(Component child) {
        Integer offset = entranceOffsets.get(child);
        return offset == null ? 0 : offset.intValue();
    }

    private void stopEntrance() {
        entranceRunning = false;
        if (entranceTimer != null) {
            entranceTimer.stop();
            entranceTimer = null;
        }
        entranceOffsets.clear();
        doLayout();
        repaint();
    }

    /** Disables all motion and jumps to the final state (screenshots, tests). */
    void setAnimationsEnabled(boolean enabled) {
        animations = enabled;
        if (!enabled) {
            stopEntrance();
            if (statsNudgeTimer != null) {
                statsNudgeTimer.stop();
                statsNudgeTimer = null;
            }
            statsNudge = 0;
            sidebar.setAnimationsEnabled(false);
            sidebar.settle();
            console.setAnimationsEnabled(false);
            rightColumn.setAnimationsEnabled(false);
        } else {
            sidebar.setAnimationsEnabled(true);
            console.setAnimationsEnabled(true);
            rightColumn.setAnimationsEnabled(true);
            startEntrance();
        }
        repaint();
    }

    boolean animationsEnabled() {
        return animations;
    }

    /* ---------------------------------------------------------------- layout */

    @Override
    public void doLayout() {
        int w = getWidth();
        int h = getHeight();
        Mode newMode = w < Tokens.COMPACT_BREAKPOINT ? Mode.COMPACT
                : (w < Tokens.WIDE_BREAKPOINT ? Mode.MEDIUM : Mode.WIDE);
        if (newMode != mode) {
            mode = newMode;
            if (mode != Mode.COMPACT) {
                drawerOpen = false;
            }
            topBar.setCompact(mode == Mode.COMPACT, true);
            rightColumn.setHorizontal(mode != Mode.WIDE);
        }
        boolean compact = mode == Mode.COMPACT;
        int middleY = Tokens.TOP_BAR;
        int middleHeight = Math.max(0, h - Tokens.TOP_BAR - Tokens.STATUS_BAR);
        int leftOccupied = compact ? 0 : Tokens.SIDEBAR_WIDTH;
        int rightWidth = mode == Mode.WIDE ? Tokens.STATS_WIDTH : 0;
        int areaWidth = Math.max(120, w - leftOccupied - rightWidth);
        int consoleX = leftOccupied + Tokens.PAD;
        int consoleY = middleY + Tokens.PAD;
        int consoleWidth = Math.max(120, areaWidth - Tokens.PAD * 2);
        int consoleHeight = Math.max(120, middleHeight - Tokens.PAD * 2);
        int stripHeight = mode == Mode.WIDE ? 0 : RightColumn.STRIP_HEIGHT + Tokens.GAP;

        topBar.setBounds(0, entranceOffset(topBar), w, Tokens.TOP_BAR);
        statusBar.setBounds(0, h - Tokens.STATUS_BAR + entranceOffset(statusBar), w,
                Tokens.STATUS_BAR);
        if (compact) {
            // The drawer overlays the content instead of pushing it, so the
            // underlying layout stays exactly as in the closed state.
            sidebar.setBounds(drawerOpen ? 0 : -Tokens.SIDEBAR_WIDTH,
                    middleY + entranceOffset(sidebar), Tokens.SIDEBAR_WIDTH, middleHeight);
        } else {
            sidebar.setBounds(0, middleY + entranceOffset(sidebar), Tokens.SIDEBAR_WIDTH,
                    middleHeight);
        }
        console.setBounds(consoleX, consoleY + entranceOffset(console), consoleWidth,
                Math.max(120, consoleHeight - stripHeight));
        int statsY = mode == Mode.WIDE
                ? middleY + statsNudge
                : consoleY + consoleHeight - RightColumn.STRIP_HEIGHT + statsNudge;
        rightColumn.setBounds(mode == Mode.WIDE ? w - Tokens.STATS_WIDTH : consoleX,
                statsY + entranceOffset(rightColumn),
                mode == Mode.WIDE ? Tokens.STATS_WIDTH : consoleWidth,
                mode == Mode.WIDE ? middleHeight : RightColumn.STRIP_HEIGHT);
    }

    /**
     * Micro-interaction from the spec: expanding a group nudges the statistics
     * column down 4px and back once (the interface "breathes").
     */
    private void triggerStatsNudge() {
        if (!animations) {
            return;
        }
        if (statsNudgeTimer != null) {
            statsNudgeTimer.stop();
        }
        final long started = System.currentTimeMillis();
        statsNudgeTimer = new Timer(15, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                float t = Math.min(1f, (System.currentTimeMillis() - started) / 200f);
                statsNudge = Math.round(4f * (float) Math.sin(Math.PI * t));
                revalidate();
                repaint();
                if (t >= 1f) {
                    statsNudge = 0;
                    if (statsNudgeTimer != null) {
                        statsNudgeTimer.stop();
                        statsNudgeTimer = null;
                    }
                    revalidate();
                }
            }
        });
        statsNudgeTimer.start();
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(1440, 900);
    }

    /* ------------------------------------------------------ inspection hooks */

    TopBar topBar() {
        return topBar;
    }

    Sidebar sidebarPanel() {
        return sidebar;
    }

    ConsolePanel consolePanel() {
        return console;
    }

    RightColumn rightColumn() {
        return rightColumn;
    }

    StatusBar statusBar() {
        return statusBar;
    }

    PathRow inputRow() {
        return inputRow;
    }

    PathRow outputRow() {
        return outputRow;
    }

    PathRow mappingRow() {
        return mappingRow;
    }

    PresetSelector presetSelector() {
        return presetSelector;
    }

    io.umbra.gui.ui.AdvancedEditor advancedEditor() {
        return advancedEditor;
    }

    JButton modeOptionsButton() {
        return modeOptionsButton;
    }

    Map<String, String> detailedOptionsForTest() {
        return currentDetailedValues();
    }

    boolean drawerOpen() {
        return drawerOpen;
    }

    /** "WIDE" / "MEDIUM" / "COMPACT" for structural tests. */
    String layoutModeName() {
        return mode.name();
    }

    /** True when the compact drawer layout is active (< 900px). */
    boolean compactMode() {
        return mode == Mode.COMPACT;
    }

    /* --------------------------------------------------------------- helpers */

    private static String describeError(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return error.getClass().getSimpleName();
        }
        return message;
    }

    /** One component's entrance animation timing. */
    private static final class Entrance {
        final int delay;
        final int offsetY;

        Entrance(int delay, int offsetY) {
            this.delay = delay;
            this.offsetY = offsetY;
        }
    }

    /** Result of one protection run. */
    static final class Outcome {
        final EngineResult result;
        final long bytes;
        final boolean cancelled;
        final String error;

        private Outcome(EngineResult result, long bytes, boolean cancelled, String error) {
            this.result = result;
            this.bytes = bytes;
            this.cancelled = cancelled;
            this.error = error;
        }

        static Outcome ok(EngineResult result, long bytes) {
            return new Outcome(result, bytes, false, null);
        }

        static Outcome cancelled() {
            return new Outcome(null, 0L, true, null);
        }

        static Outcome failed(String error) {
            return new Outcome(null, 0L, false,
                    error == null || error.trim().isEmpty() ? "Unknown failure" : error);
        }
    }
}
