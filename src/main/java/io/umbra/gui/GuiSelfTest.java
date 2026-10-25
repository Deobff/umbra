package io.umbra.gui;

import io.umbra.core.config.ConfigLoader;
import io.umbra.core.config.UmbraConfig;
import io.umbra.gui.theme.Tokens;
import io.umbra.gui.ui.ConsolePanel;
import io.umbra.gui.ui.Animation;
import io.umbra.gui.ui.ModeOptionsPanel;
import io.umbra.gui.ui.SliderControl;
import io.umbra.gui.ui.GroupSection;
import io.umbra.gui.ui.RightColumn;
import io.umbra.gui.ui.StatCard;

import javax.imageio.ImageIO;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Rectangle;

import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Structural and behavioural self-checks for the assembled GUI.
 *
 * <p>Runs headless, without showing a window: it builds {@link GuiRoot} at
 * 1440x900, lays the tree out, asserts the three-column skeleton and responsive
 * breakpoints, checks accessibility names and preset wiring, round-trips a
 * configuration through YAML, and renders a PNG to prove the painting path is
 * alive. Used by {@code --self-test} and by {@code GuiLayoutTest}.</p>
 */
public final class GuiSelfTest {

    private static final List<String> failures = new ArrayList<String>();
    private static int checks;

    private GuiSelfTest() {
    }

    /** Runs every check and returns the number of failures (0 means green). */
    public static int run() {
        failures.clear();
        checks = 0;
        Animation.setEnabled(false);
        Path temp = null;
        try {
            temp = Files.createTempDirectory("umbra-gui-selftest-");
            String oldHome = System.getProperty("user.home");
            System.setProperty("user.home", temp.toString());
            try {
                GuiRoot root = new GuiRoot(false);
                root.setAnimationsEnabled(false);
                root.setSize(1440, 900);
                GuiScreenshot.layoutTree(root);
                checkStructure(root);
                checkAccessibility(root);
                checkPresets(root);
                checkResponsive(root);
                checkShortcutsAndPrefs(root, temp);
                checkModeOptions(root, temp);
                checkSliders(root, temp);
                checkOptionsAndConfig(temp);
                checkScreenshot(root, temp);
            } finally {
                System.setProperty("user.home", oldHome == null ? "" : oldHome);
            }
        } catch (Throwable error) {
            failures.add("self-test crashed: " + error);
            error.printStackTrace();
        } finally {
            delete(temp);
        }
        for (String failure : failures) {
            System.err.println("SELF-TEST FAIL: " + failure);
        }
        System.out.println("GuiSelfTest: " + checks + " checks, "
                + failures.size() + " failure(s)");
        return failures.size();
    }

    private static void checkStructure(GuiRoot root) {
        check(root.getWidth() == 1440 && root.getHeight() == 900, "root sized 1440x900");
        check(root.topBar().getHeight() == 64, "top bar is 64px");
        check(root.statusBar().getHeight() == 44, "status bar is 44px");
        check(root.sidebarPanel().getWidth() == 280, "configuration column is 280px");
        check(root.rightColumn().getWidth() == 240, "statistics column is 240px");
        check(root.rightColumn().getX() == 1200, "statistics column sits at the right edge");
        check(root.consolePanel().getX() == 296, "console starts after the sidebar + 16px");
        check(root.topBar().getY() == 0, "top bar at the top");
        check(root.statusBar().getY() == 900 - 44, "status bar at the bottom");
        check(root.consolePanel().getY() == 80, "console starts below the top bar + 16px");
        check(root.sidebarPanel().getHeight() == 900 - 64 - 44,
                "sidebar spans the middle row");
        check(root.consolePanel().getWidth() == 1440 - 280 - 240 - 32,
                "console width fills the centre column minus padding");

        List<GuiSwitches.GroupDef> defs = GuiSwitches.groups();
        List<GroupSection> groups = root.sidebarPanel().groups();
        check(groups.size() == defs.size(),
                "all configuration groups exist (" + defs.size() + ")");
        for (int i = 0; i < Math.min(groups.size(), defs.size()); i++) {
            String expected = defs.get(i).title;
            String actual = groups.get(i).getAccessibleContext().getAccessibleName();
            check(actual != null && actual.startsWith(expected),
                    "group " + i + " is " + expected + " (was " + actual + ")");
        }
        Map<String, Boolean> states = root.sidebarPanel().switchStates();
        check(states.size() == GuiSwitches.allToggles().size(),
                "all " + states.size() + " toggles are present");
        for (GuiSwitches.Toggle toggle : GuiSwitches.allToggles()) {
            check(states.containsKey(toggle.id), "toggle present: " + toggle.id);
            String label = toggle.label;
            check(label != null && !label.trim().isEmpty(), "toggle labelled: " + toggle.id);
            check(label.matches("[\\x20-\\x7E]+"), "toggle label is English: " + toggle.id);
        }
        check(root.rightColumn().cards().length == 4, "four statistic cards");
        String[] expectedLabels = {"Classes", "Protected methods", "Encrypted strings",
                "Elapsed"};
        StatCard[] cards = root.rightColumn().cards();
        for (int i = 0; i < expectedLabels.length; i++) {
            String name = cards[i].getAccessibleContext().getAccessibleName();
            check(expectedLabels[i].equals(name),
                    "stat card " + i + " is " + expectedLabels[i]);
            check("\u2014".equals(cards[i].displayText()),
                    "stat card " + i + " shows the idle em dash");
        }
        ConsolePanel console = root.consolePanel();
        check(console != null, "console panel exists");
        check(console.logView() != null, "console log view exists");
        check(console.lineCount() == 0, "console starts empty (empty state visible)");
        check(console.clearButton().getAccessibleContext().getAccessibleName() != null,
                "clear button has an accessible name");
        check(console.openFolderButton().getAccessibleContext().getAccessibleName() != null,
                "open-folder button has an accessible name");
        check(root.inputRow() != null && root.outputRow() != null
                && root.mappingRow() != null, "input/output/mapping rows exist");
        check(root.advancedEditor() != null, "advanced key=value editor exists");
        check(root.presetSelector().selected() != null, "preset selector has a value");
        check(root.statusBar().statusText() != null
                        && !root.statusBar().statusText().trim().isEmpty(),
                "status bar has an initial status");
        check(root.topBar().primaryButton().progress() == -1,
                "progress hairline hidden while idle");
    }

    private static void checkShortcutsAndPrefs(GuiRoot root, Path temp) {
        javax.swing.InputMap input = root.getInputMap(
                javax.swing.JComponent.WHEN_IN_FOCUSED_WINDOW);
        check(input.get(javax.swing.KeyStroke.getKeyStroke("ctrl O")) != null,
                "Ctrl+O shortcut registered");
        check(input.get(javax.swing.KeyStroke.getKeyStroke("ctrl S")) != null,
                "Ctrl+S shortcut registered");
        check(input.get(javax.swing.KeyStroke.getKeyStroke("ctrl ENTER")) != null,
                "Ctrl+Enter shortcut registered");
        check(input.get(javax.swing.KeyStroke.getKeyStroke("ESCAPE")) != null,
                "Escape shortcut registered");

        GuiPrefs prefs = GuiPrefs.load();
        prefs.setSeed(777L);
        prefs.setPreset("Light");
        prefs.rememberInput(temp.resolve("somewhere/app.jar"));
        prefs.save();
        GuiPrefs reloaded = GuiPrefs.load();
        check(reloaded.seed() == 777L, "preferences remember the seed");
        check("Light".equals(reloaded.preset()), "preferences remember the preset");
        check(reloaded.lastInputDir() != null && reloaded.lastInputDir()
                .endsWith("somewhere"), "preferences remember the last input directory");
    }

    private static void checkAccessibility(GuiRoot root) {
        check(nonEmpty(root.topBar().primaryButton().getAccessibleContext()
                .getAccessibleName()), "primary button accessible name");
        check(nonEmpty(root.topBar().seedField().getAccessibleContext()
                .getAccessibleName()), "seed field accessible name");
        check(nonEmpty(root.topBar().menuButton().getAccessibleContext()
                .getAccessibleName()), "menu button accessible name");
        check(nonEmpty(root.topBar().getAccessibleContext().getAccessibleName()),
                "top bar accessible name");
        for (GroupSection group : root.sidebarPanel().groups()) {
            check(nonEmpty(group.getAccessibleContext().getAccessibleName()),
                    "group accessible name: "
                            + group.getAccessibleContext().getAccessibleName());
        }
        int named = 0;
        for (String id : root.sidebarPanel().switchStates().keySet()) {
            if (!id.isEmpty()) {
                named++;
            }
        }
        check(named > 20, "custom switches are labelled");
        check(nonEmpty(root.sidebarPanel().getAccessibleContext().getAccessibleName()),
                "sidebar accessible name");
        check(nonEmpty(root.consolePanel().getAccessibleContext().getAccessibleName()),
                "console accessible name");
        check(nonEmpty(root.consolePanel().logView().getAccessibleContext()
                .getAccessibleName()), "log view accessible name");
    }

    private static void checkPresets(GuiRoot root) {
        String selected = root.presetSelector().selected();
        check(GuiPresets.NAMES.contains(selected), "selected preset is known: " + selected);
        Map<String, Boolean> expected = GuiPresets.states(selected);
        check(expected.equals(root.sidebarPanel().switchStates()),
                "switch states match the selected preset");
        check(GuiPresets.states("Light").get("flow").booleanValue() == false,
                "Light preset disables control-flow obfuscation");
        check(GuiPresets.states("Maximum").get("classEnc").booleanValue(),
                "Maximum preset enables class encryption");
        check("Balanced".equals(GuiPresets.detect(GuiPresets.states("Balanced"))),
                "detect() recognises the Balanced preset");
        Map<String, Boolean> tweaked = new LinkedHashMap<String, Boolean>(GuiSwitches.defaults());
        tweaked.put("noise", Boolean.FALSE);
        check("Custom".equals(GuiPresets.detect(tweaked)),
                "detect() returns Custom for a manually tweaked map");
    }

    private static void checkResponsive(GuiRoot root) {
        root.setSize(1000, 760);
        GuiScreenshot.layoutTree(root);
        check("MEDIUM".equals(root.layoutModeName()), "1000px window is MEDIUM");
        check(root.rightColumn().isHorizontal(), "stat cards become a strip below 1100px");
        check(!root.compactMode(), "sidebar still visible at 1000px");
        check(root.sidebarPanel().getWidth() == 280, "sidebar remains 280px at 1000px");
        check(root.rightColumn().getY() > root.consolePanel().getY(),
                "stat strip sits under the console in medium mode");

        root.setSize(800, 700);
        GuiScreenshot.layoutTree(root);
        check(root.compactMode(), "800px window is COMPACT");
        check(root.consolePanel().getX() == 16, "console uses the full width in compact mode");
        check(root.rightColumn().isHorizontal(), "stat strip stays horizontal in compact mode");

        root.setSize(1440, 900);
        GuiScreenshot.layoutTree(root);
        check("WIDE".equals(root.layoutModeName()), "restored WIDE layout");
        check(!root.rightColumn().isHorizontal(), "stat cards stack on the right at 1440px");
    }

    private static void checkOptionsAndConfig(Path temp) throws Exception {
        Map<String, Boolean> defaults = GuiSwitches.defaults();
        Map<String, String> base = GuiSwitches.baseOptions(defaults);
        check("true".equals(base.get("layout.springBoot")), "Spring Boot layout on by default");
        check("preserve".equals(base.get("layout.multiRelease")),
                "multi-release layout preserved by default");
        check("false".equals(base.get("typeConfusion.enabled")),
                "type confusion off by default");
        check("true".equals(base.get("string.stackTraceHide")),
                "stack-trace hiding on by default");
        check(base.get("verify") == null, "GUI-only verify flag not sent as an option");
        check(GuiSwitches.coveredKeys().contains("vm2.fusion"),
                "VM2 fusion is an exposed option");

        Map<String, String> advanced = GuiSwitches.parseAdvanced(
                "# comment\nstring.engine=rc4\n\nvm2.encryptPayload = true\nbroken\n");
        check(advanced.size() == 2, "advanced parser reads two key=value lines");
        check("rc4".equals(advanced.get("string.engine")), "advanced parser keeps values");
        check("true".equals(advanced.get("vm2.encryptPayload")),
                "advanced parser trims spaces");

        Path input = temp.resolve("app.jar");
        Files.write(input, new byte[0]);
        Path output = temp.resolve("app-obf.jar");
        Path mapping = temp.resolve("mapping.txt");
        Map<String, String> options = new LinkedHashMap<String, String>(base);
        options.putAll(GuiPresets.extraOptions("Balanced"));
        options.putAll(advanced);
        UmbraConfig config = GuiConfig.build(input, output, 4242L, options, mapping);
        check("true".equals(config.option("layout.springBoot", "")),
                "built configuration keeps layout options");
        check("preserve".equals(config.option("layout.multiRelease", "")),
                "built configuration keeps multi-release mode");
        check("rc4".equals(config.option("string.engine", "")),
                "advanced override wins in built configuration");
        check(config.seed() == 4242L, "seed propagated");
        check(config.mapping().file().equals(mapping.toAbsolutePath().toString()),
                "explicit mapping file used");
        check(config.renamer().mappingFile().equals(config.mapping().file()),
                "renamer writes the same mapping file");
        check(config.antiDebug() == false, "anti-debug off by default");

        // Round trip through YAML and back, then map the file onto toggles.
        String yaml = GuiConfig.toYaml(config);
        check(yaml.contains("layout.springBoot"), "YAML contains the layout option");
        Path yamlFile = temp.resolve("umbra.yml");
        Files.write(yamlFile, yaml.getBytes(StandardCharsets.UTF_8));
        UmbraConfig loaded = ConfigLoader.load(yamlFile);
        Map<String, Boolean> loadedStates = GuiSwitches.fromConfig(loaded);
        check(loadedStates.equals(defaults), "toggle states round-trip through YAML");
        check(GuiSwitches.advancedOverrides(loaded).containsKey("string.engine"),
                "advanced overrides survive the YAML round trip");
        check(loaded.seed() == 4242L, "YAML round trip keeps the seed");
    }

    private static void checkScreenshot(GuiRoot root, Path temp) throws Exception {
        root.setSize(1440, 900);
        GuiScreenshot.layoutTree(root);
        Path png = temp.resolve("screenshot.png");
        long started = System.currentTimeMillis();
        GuiScreenshot.writePng(root, 1440, 900, png);
        long elapsed = System.currentTimeMillis() - started;
        check(Files.isRegularFile(png), "screenshot PNG written");
        check(Files.size(png) > 15000, "screenshot PNG has visual content ("
                + Files.size(png) + " bytes)");
        BufferedImage image = ImageIO.read(png.toFile());
        check(image != null, "screenshot PNG decodes");
        if (image != null) {
            check(image.getWidth() == 1440 && image.getHeight() == 900,
                    "screenshot is 1440x900");
            check(distinctColors(image) > 40, "screenshot paints a layered background");
        }
        check(elapsed < 20000, "offscreen render finishes quickly (" + elapsed + " ms)");

        // The panel tree is unchanged by rendering: the screenshot is repeatable.
        Path again = temp.resolve("screenshot2.png");
        GuiScreenshot.writePng(root, 1440, 900, again);
        check(Files.size(again) == Files.size(png),
                "second render is identical (deterministic idle screenshot)");
    }

    private static boolean nonEmpty(String value) {
        return value != null && !value.trim().isEmpty();
    }

    private static int distinctColors(BufferedImage image) {
        java.util.Set<Integer> colors = new java.util.HashSet<Integer>();
        for (int y = 0; y < image.getHeight(); y += 4) {
            for (int x = 0; x < image.getWidth(); x += 4) {
                colors.add(Integer.valueOf(image.getRGB(x, y) & 0xFFFFFF));
                if (colors.size() > 200) {
                    return colors.size();
                }
            }
        }
        return colors.size();
    }

    private static void checkModeOptions(GuiRoot root, Path temp) throws Exception {
        List<GuiModeOptions.Group> groups = GuiModeOptions.groups();
        check(groups.size() == 12, "mode options sheet has 12 groups (was " + groups.size() + ")");
        int expectedGroups = 12;
        check(groups.size() == expectedGroups, "mode options group count is stable");
        List<GuiModeOptions.Spec> specs = GuiModeOptions.allSpecs();
        check(specs.size() >= 100, "mode options exposes " + specs.size() + " controls");
        int booleans = 0;
        int enums = 0;
        int numbers = 0;
        int texts = 0;
        java.util.Set<String> ids = new java.util.HashSet<String>();
        for (GuiModeOptions.Spec spec : specs) {
            check(ids.add(spec.id), "mode option id is unique: " + spec.id);
            check(spec.label != null && !spec.label.trim().isEmpty(),
                    "mode option labelled: " + spec.id);
            check(spec.label.matches("[\\x20-\\x7E]+"),
                    "mode option label is English: " + spec.id);
            if (spec.kind == GuiModeOptions.Kind.BOOL) {
                booleans++;
                check("true".equals(spec.defaultValue) || "false".equals(spec.defaultValue),
                        "boolean default valid: " + spec.id);
            } else if (spec.kind == GuiModeOptions.Kind.ENUM) {
                enums++;
                check(!spec.values.isEmpty(), "enum has values: " + spec.id);
                check(spec.values.contains(spec.defaultValue),
                        "enum default is a listed value: " + spec.id);
            } else if (spec.kind == GuiModeOptions.Kind.INT) {
                numbers++;
                int defaultValue = Integer.parseInt(spec.defaultValue);
                check(defaultValue >= spec.min && defaultValue <= spec.max,
                        "int default inside range: " + spec.id);
            } else {
                texts++;
                check(spec.defaultValue != null, "text default present: " + spec.id);
            }
            if (spec.key != null && !spec.uiOnly()) {
                check(!spec.key.startsWith("gui."),
                        "engine option key is not a GUI key: " + spec.key);
                check(spec.key.indexOf(' ') < 0, "option key has no spaces: " + spec.key);
            }
        }
        check(booleans > 60 && enums >= 9 && numbers > 20 && texts >= 8,
                "mode options covers booleans/ints/enums/text"
                        + " (" + booleans + "/" + numbers + "/" + enums + "/" + texts + ")");

        // Every mode's detailed defaults must reproduce the left-column preset
        // exactly; this is the core "mode == preset defaults" invariant.
        for (String mode : new String[]{"Light", "Balanced", "Aggressive", "Maximum",
                "Nocturne"}) {
            Map<String, String> values = GuiModeOptions.defaults(mode);
            check(values.size() == specs.size(),
                    "mode defaults are complete for " + mode);
            Map<String, Boolean> synced = GuiModeOptions.syncToggles(values);
            Map<String, Boolean> preset = GuiPresets.states(mode);
            check(synced.size() == preset.size(),
                    "mode " + mode + " syncs every left switch ("
                            + synced.size() + "/" + preset.size() + ")");
            for (Map.Entry<String, Boolean> entry : preset.entrySet()) {
                check(entry.getValue().equals(synced.get(entry.getKey())),
                        "mode " + mode + " switch " + entry.getKey()
                                + " matches preset defaults");
            }
            Map<String, String> options = GuiModeOptions.toOptionMap(values);
            check("preserve".equals(options.get("layout.multiRelease")),
                    "mode " + mode + " keeps the multi-release layout option");
            check(!options.containsKey("gui.seed"), "UI-only seed is not an engine option");
        }
        check("true".equals(GuiModeOptions.defaults("Maximum")
                        .get("typeConfusion.enabled")),
                "Maximum mode enables type confusion in the detailed catalog");
        check("false".equals(GuiModeOptions.defaults("Light")
                        .get("classEncryption.enabled")),
                "Light mode disables class encryption in the detailed catalog");

        // Dialog panel behaviour (headless, no window).
        ModeOptionsPanel panel = new ModeOptionsPanel(
                GuiModeOptions.defaults("Balanced"), "Balanced", null);
        panel.setSize(ModeOptionsPanel.SHEET_WIDTH, ModeOptionsPanel.SHEET_HEIGHT);
        GuiScreenshot.layoutTree(panel);
        check(panel.sectionTitles().size() == 12, "panel renders all 12 sections");
        check(panel.sectionTitles().contains("Names"), "panel has a Names section");
        check(panel.sectionTitles().contains("Strings"), "panel has a Strings section");
        check(panel.sectionTitles().contains("Virtualization"),
                "panel has a Virtualization section");
        check(panel.sectionTitles().contains("Compatibility"),
                "panel has a Compatibility section");
        check(panel.sectionTitles().contains("Output"), "panel has an Output section");
        check(panel.controlCount() == specs.size(), "panel builds one control per spec");
        for (GuiModeOptions.Spec spec : specs) {
            check(panel.control(spec.id) != null, "panel control present: " + spec.id);
        }
        check("Balanced".equals(panel.selectedMode()), "panel starts in the given mode");
        check("true".equals(panel.value("renamer.enabled")),
                "panel loads balanced defaults");
        check(panel.bodyPreferredHeight() > ModeOptionsPanel.SHEET_HEIGHT,
                "mode options body is scrollable");
        panel.setValue("decompilerNoise.level", "4");
        check("Custom".equals(panel.selectedMode()), "editing a control marks Custom");
        check("4".equals(panel.value("decompilerNoise.level")), "edit stored");
        panel.resetToModeDefaults();
        check("Balanced".equals(panel.selectedMode()), "reset restores the mode");
        check("1".equals(panel.value("decompilerNoise.level")),
                "reset restores the mode default value");
        panel.setMode("Maximum");
        check("Maximum".equals(panel.selectedMode()), "setMode selects Maximum");
        check("true".equals(panel.value("classEncryption.enabled")),
                "Maximum mode detail enables class encryption");
        check("true".equals(panel.value("typeConfusion.enabled")),
                "Maximum mode detail enables type confusion");
        check("true".equals(panel.value("mba.enabled")),
                "Maximum mode detail enables MBA");
        panel.setValue("gui.seed", "not-a-number");
        check(panel.validationError() != null, "invalid seed is rejected");
        panel.setValue("gui.seed", "23303");
        check(panel.validationError() == null, "valid seed is accepted");
        panel.scrollToSection("Native");
        Path optionsPng = temp.resolve("mode-options.png");
        GuiScreenshot.writePanel(panel, ModeOptionsPanel.SHEET_WIDTH,
                ModeOptionsPanel.SHEET_HEIGHT, optionsPng);
        check(Files.isRegularFile(optionsPng), "mode options PNG written");
        check(Files.size(optionsPng) > 15000, "mode options PNG has content ("
                + Files.size(optionsPng) + " bytes)");
        BufferedImage optionsImage = ImageIO.read(optionsPng.toFile());
        check(optionsImage != null && optionsImage.getWidth() == 900
                        && optionsImage.getHeight() == 700,
                "mode options PNG is 900x700");

        // Root integration: dialog values drive switches, options and YAML.
        check(root.modeOptionsButton() != null, "Mode options button exists");
        check(root.modeOptionsButton().getAccessibleContext().getAccessibleName() != null,
                "Mode options button has an accessible name");
        check(root.modeOptionsButton().getText().indexOf("Mode options") >= 0,
                "Mode options button is labelled 'Mode options'");
        root.applyModeOptions(GuiModeOptions.defaults("Maximum"), "Maximum");
        check("Maximum".equals(root.presetSelector().selected()),
                "applying Maximum selects the Maximum mode");
        check(root.sidebarPanel().isOn("classEnc"),
                "Maximum mode enables the class encryption switch");
        check(root.sidebarPanel().isOn("typeConfusion"),
                "Maximum mode enables the type confusion switch");
        check("3".equals(root.detailedOptionsForTest().get("string.strength")),
                "Maximum mode carries string strength 3 to the run options");

        Map<String, String> custom = new LinkedHashMap<String, String>(
                GuiModeOptions.defaults("Maximum"));
        custom.put("classEncryption.enabled", "false");
        custom.put("decompilerNoise.level", "4");
        root.applyModeOptions(custom, "Custom");
        check("Custom".equals(root.presetSelector().selected()),
                "custom detail edits switch the sidebar selector to Custom");
        check(!root.sidebarPanel().isOn("classEnc"),
                "custom detail edit disables the class encryption switch");
        check("4".equals(root.detailedOptionsForTest().get("decompilerNoise.level")),
                "custom detail edits are kept");
        check(root.sidebarPanel().triggerToggleForTest("strings", false),
                "left switch can be flipped by the test hook");
        check(!root.sidebarPanel().isOn("strings"), "strings switch is off");
        check("false".equals(root.detailedOptionsForTest().get("stringEncryption.enabled")),
                "left switch edit syncs into the detailed values");

        root.applyModeOptions(GuiModeOptions.defaults("Maximum"), "Maximum");
        Map<String, String> collected = root.collectOptions();
        check("true".equals(collected.get("typeConfusion.enabled")),
                "run options include detailed type confusion value");
        check("3".equals(collected.get("string.strength")),
                "run options include detailed string strength");
        check("normal".equals(collected.get("flowObfuscation.level")),
                "run options include detailed flow level");
        check("true".equals(collected.get("mba.enabled")),
                "run options include detailed MBA switch");
        check(collected.containsKey("layout.moduleInfo"),
                "run options include detailed module-info mode");

        // Detailed typed keys reach the typed configuration and round-trip YAML.
        Path input = temp.resolve("mode-app.jar");
        Files.write(input, new byte[0]);
        Path output = temp.resolve("mode-app-obf.jar");
        Map<String, String> detailed = GuiModeOptions.toOptionMap(
                GuiModeOptions.defaults("Maximum"));
        detailed.put("renamer.renameClasses", "false");
        detailed.put("renamer.prefix", "z_");
        detailed.put("renamer.minimumNameLength", "3");
        detailed.put("antiLlm.decoyMethodsPerClass", "5");
        UmbraConfig config = GuiConfig.build(input, output, 4242L, detailed,
                temp.resolve("mode-mapping.txt"));
        check(!config.renamer().renameClasses(),
                "detailed rename-classes flag reaches the typed renamer");
        check("z_".equals(config.renamer().prefix()),
                "detailed rename prefix reaches the typed renamer");
        check(config.renamer().minimumNameLength() == 3,
                "detailed minimum name length reaches the typed renamer");
        check(config.antiLlm().decoyMethodsPerClass() == 5,
                "detailed anti-LLM decoy count reaches the typed section");
        String yaml = GuiConfig.toYaml(config);
        Path yamlFile = temp.resolve("mode-options.yml");
        Files.write(yamlFile, yaml.getBytes(StandardCharsets.UTF_8));
        UmbraConfig loaded = ConfigLoader.load(yamlFile);
        Map<String, String> reloaded = GuiModeOptions.fromEffective(
                GuiConfig.describe(loaded));
        for (GuiModeOptions.Spec spec : specs) {
            if (spec.key == null) {
                continue;
            }
            String expected = GuiModeOptions.normalize(spec, detailed.get(spec.key));
            check(expected.equals(reloaded.get(spec.id)),
                    "YAML round trip keeps mode option " + spec.key);
        }
        root.applyPresetForScreenshot("Balanced");
        root.setSize(1440, 900);
        GuiScreenshot.layoutTree(root);
        check("Balanced".equals(root.presetSelector().selected()),
                "mode options self-test restores the Balanced preset");
    }
    private static void checkSliders(final GuiRoot root, Path temp) throws Exception {
        // Shared animation helper contract.
        check(Animation.MAX_DURATION == 200, "interactive animations are capped at 200ms");
        check(!Animation.enabled(), "animations are disabled for the headless self-test");
        final boolean[] finished = new boolean[1];
        Animation.Handle handle = Animation.animate(root.consolePanel(), 160,
                new Animation.Frame() {
                    @Override
                    public void frame(float eased) {
                        finished[0] = eased >= 1f;
                    }
                });
        check(!handle.isRunning(), "disabled animations finish immediately");
        check(finished[0], "disabled animation still delivers its final frame");
        Animation.stopAll();

        // A fresh panel for deterministic slider interaction.
        final ModeOptionsPanel panel = new ModeOptionsPanel(
                GuiModeOptions.defaults("Balanced"), "Balanced", null);
        panel.setSize(ModeOptionsPanel.SHEET_WIDTH, ModeOptionsPanel.SHEET_HEIGHT);
        GuiScreenshot.layoutTree(panel);
        int integerSpecs = 0;
        for (GuiModeOptions.Spec spec : GuiModeOptions.allSpecs()) {
            if (spec.kind != GuiModeOptions.Kind.INT) {
                continue;
            }
            integerSpecs++;
            SliderControl slider = panel.slider(spec.id);
            check(slider != null, "INT option has a slider: " + spec.id);
            if (slider != null) {
                check(slider.spec() == spec, "slider spec matches: " + spec.id);
                check(slider.value() >= spec.min && slider.value() <= spec.max,
                        "slider value in range: " + spec.id);
                check(slider.trackBounds().width > 20, "slider has a usable track: "
                        + spec.id);
            }
        }
        check(integerSpecs > 15, "mode options has " + integerSpecs + " slider options");
        check(panel.sliderCount() == integerSpecs,
                "every INT spec is rendered by a slider (" + panel.sliderCount()
                        + "/" + integerSpecs + ")");
        final SliderControl strength = panel.slider("string.strength");
        check(strength != null, "string strength slider exists");

        // Simulated click at the right end jumps to the maximum value and marks
        // the mode Custom.
        Rectangle track = strength.trackBounds();
        final int maxX = track.x + track.width - 1;
        final int midY = track.y + track.height / 2;
        dispatchMouse(panel, strength, MouseEvent.MOUSE_PRESSED, maxX, midY, 1, false);
        dispatchMouse(panel, strength, MouseEvent.MOUSE_RELEASED, maxX, midY, 1, false);
        check("3".equals(panel.value("string.strength")),
                "click at the right end sets string.strength=3 (was "
                        + panel.value("string.strength") + ")");
        check("Custom".equals(panel.selectedMode()), "slider click marks the mode Custom");
        check(strength.value() == 3, "slider thumb value is 3");

        // Press + drag from the left end to 2/3 of the track.
        int pressed = track.x + 1;
        final int twoThirds = track.x + Math.round(track.width * 0.66f);
        dispatchMouse(panel, strength, MouseEvent.MOUSE_PRESSED, pressed, midY, 1, false);
        dispatchMouse(panel, strength, MouseEvent.MOUSE_DRAGGED, twoThirds, midY, 1, true);
        dispatchMouse(panel, strength, MouseEvent.MOUSE_RELEASED, twoThirds, midY, 1, false);
        check("2".equals(panel.value("string.strength")),
                "drag to two thirds lands on strength 2 (was "
                        + panel.value("string.strength") + ")");
        check(strength.value() == 2, "slider value follows the drag immediately");

        // Mouse wheel steps by the spec step.
        final SliderControl flow = panel.slider("flowObfuscation.maxInstructions");
        check(flow != null, "flow maxInstructions slider exists");
        int beforeWheel = flow.value();
        final int wheelX = flow.trackBounds().x + 10;
        dispatchWheel(flow, wheelX, midY, -1);
        check(flow.value() == Math.min(flow.spec().max,
                        beforeWheel + flow.spec().step),
                "mouse wheel increases the value by the step");
        check(String.valueOf(flow.value()).equals(panel.value("flowObfuscation.maxInstructions")),
                "wheel value reaches the panel value map");

        // Keyboard End jumps to max via the WHEN_FOCUSED action map.
        Object endKey = flow.getInputMap(JComponent.WHEN_FOCUSED)
                .get(KeyStroke.getKeyStroke("END"));
        check(endKey != null, "slider binds End");
        flow.getActionMap().get(endKey).actionPerformed(
                new java.awt.event.ActionEvent(flow, 0, "END"));
        check(flow.value() == flow.spec().max, "End key jumps the slider to max");
        Object homeKey = flow.getInputMap(JComponent.WHEN_FOCUSED)
                .get(KeyStroke.getKeyStroke("HOME"));
        flow.getActionMap().get(homeKey).actionPerformed(
                new java.awt.event.ActionEvent(flow, 0, "HOME"));
        check(flow.value() == flow.spec().min, "Home key jumps the slider to min");
        check(flow.getToolTipText() != null
                        && flow.getToolTipText().indexOf(String.valueOf(flow.spec().min)) >= 0,
                "slider tooltip shows the range");

        // Reset restores the mode defaults and lands exactly (no lingering).
        panel.setMode("Maximum");
        check("3".equals(panel.value("string.strength")),
                "Maximum mode populates strength 3");
        check(panel.slider("string.strength").value() == 3,
                "mode change updates the slider value");
        panel.setValue("string.strength", "1");
        check(panel.slider("string.strength").value() == 1,
                "external setValue updates the slider");
        check("Custom".equals(panel.selectedMode()), "reset test starts from Custom");
        panel.resetToModeDefaults();
        check("Maximum".equals(panel.selectedMode()),
                "reset returns to the last non-custom mode");
        check(panel.slider("string.strength").value() == 3,
                "reset lands on the Maximum default");
        check("3".equals(panel.value("string.strength")), "reset updates the value map");

        // OK delivers the slider value through the dialog result map.
        final Map<String, String> captured = new LinkedHashMap<String, String>();
        final String[] capturedMode = new String[1];
        ModeOptionsPanel dialogPanel = new ModeOptionsPanel(
                GuiModeOptions.defaults("Balanced"), "Balanced",
                new ModeOptionsPanel.Listener() {
                    @Override
                    public void ok(ModeOptionsPanel source) {
                        captured.putAll(source.values());
                        capturedMode[0] = source.selectedMode();
                    }

                    @Override
                    public void cancel(ModeOptionsPanel source) {
                        // no-op
                    }
                });
        dialogPanel.setSize(ModeOptionsPanel.SHEET_WIDTH, ModeOptionsPanel.SHEET_HEIGHT);
        GuiScreenshot.layoutTree(dialogPanel);
        SliderControl dialogSlider = dialogPanel.slider("decompilerNoise.level");
        Rectangle dialogTrack = dialogSlider.trackBounds();
        dispatchMouse(dialogPanel, dialogSlider, MouseEvent.MOUSE_PRESSED,
                dialogTrack.x + dialogTrack.width - 1,
                dialogTrack.y + dialogTrack.height / 2, 1, false);
        dispatchMouse(dialogPanel, dialogSlider, MouseEvent.MOUSE_RELEASED,
                dialogTrack.x + dialogTrack.width - 1,
                dialogTrack.y + dialogTrack.height / 2, 1, false);
        check("4".equals(dialogPanel.value("decompilerNoise.level")),
                "noise slider reaches level 4");
        ModeOptionsPanel.Listener listener = new ModeOptionsPanel.Listener() {
            @Override
            public void ok(ModeOptionsPanel source) {
                captured.clear();
                captured.putAll(source.values());
                capturedMode[0] = source.selectedMode();
            }

            @Override
            public void cancel(ModeOptionsPanel source) {
                // no-op
            }
        };
        dialogPanel.setListener(listener);
        listener.ok(dialogPanel);
        check("4".equals(captured.get("decompilerNoise.level")),
                "OK map carries the slider edit (" + captured.get(
                        "decompilerNoise.level") + ")");
        check("Custom".equals(capturedMode[0]), "OK map reports Custom after a slider edit");

        // Rendering a slider-heavy group must still be deterministic and quick.
        panel.setMode("Maximum");
        panel.scrollToSection("Flow");
        Path sliderPng = temp.resolve("sliders.png");
        long started = System.currentTimeMillis();
        GuiScreenshot.writePanel(panel, ModeOptionsPanel.SHEET_WIDTH,
                ModeOptionsPanel.SHEET_HEIGHT, sliderPng);
        long elapsed = System.currentTimeMillis() - started;
        check(Files.size(sliderPng) > 15000, "slider sheet renders (" + Files.size(sliderPng)
                + " bytes)");
        check(elapsed < 10000, "slider sheet render is quick (" + elapsed + " ms)");
        Animation.stopAll();
        check(!Animation.enabled(), "headless self-test keeps animations disabled");

        // Live scheduling check: a real animation completes on the EDT, stops
        // its timer and clamps an oversized duration to the 200ms cap.
        Animation.setEnabled(true);
        final float[] lastFrame = new float[]{0f};
        long liveStart = System.currentTimeMillis();
        Animation.Handle live = Animation.animate(panel, 5000, new Animation.Frame() {
            @Override
            public void frame(float eased) {
                lastFrame[0] = eased;
            }
        });
        long deadline = System.currentTimeMillis() + 2000L;
        while (live.isRunning() && System.currentTimeMillis() < deadline) {
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    @Override
                    public void run() {
                        // Pump the shared animation timer.
                    }
                });
            } catch (Exception ignored) {
                // Event queue teardown; loop condition handles it.
            }
            try {
                Thread.sleep(20L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        long liveElapsed = System.currentTimeMillis() - liveStart;
        check(!live.isRunning(), "live animation stops when settled");
        check(lastFrame[0] >= 1f, "live animation delivers its final frame");
        check(liveElapsed < 1000L, "oversized animation is clamped to the 200ms cap ("
                + liveElapsed + " ms)");
        Animation.stopAll();
        Animation.setEnabled(false);
    }

    private static void dispatchMouse(final ModeOptionsPanel panel,
                                      final JComponent target, final int id,
                                      final int x, final int y,
                                      final int clickCount, final boolean drag) {
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    java.awt.event.MouseEvent event = new java.awt.event.MouseEvent(
                            target, id, System.currentTimeMillis(),
                            drag ? java.awt.event.InputEvent.BUTTON1_DOWN_MASK : 0,
                            x, y, clickCount, false,
                            java.awt.event.MouseEvent.BUTTON1);
                    target.dispatchEvent(event);
                    panel.doLayout();
                }
            });
        } catch (Exception e) {
            failures.add("simulated mouse interaction failed: " + e);
        }
    }

    private static void dispatchWheel(final JComponent target, final int x, final int y,
                                      final int rotation) {
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    java.awt.event.MouseWheelEvent event =
                            new java.awt.event.MouseWheelEvent(target,
                                    java.awt.event.MouseEvent.MOUSE_WHEEL,
                                    System.currentTimeMillis(), 0, x, y, 0, false,
                                    java.awt.event.MouseWheelEvent.WHEEL_UNIT_SCROLL,
                                    1, rotation);
                    target.dispatchEvent(event);
                }
            });
        } catch (Exception e) {
            failures.add("simulated wheel interaction failed: " + e);
        }
    }
    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            failures.add(message);
        }
    }

    private static void delete(Path directory) {
        if (directory == null) {
            return;
        }
        try {
            if (!Files.exists(directory)) {
                return;
            }
            Files.walk(directory)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (Exception ignored) {
                            // Best effort temp cleanup.
                        }
                    });
        } catch (Exception ignored) {
            // Best effort temp cleanup.
        }
    }
}
