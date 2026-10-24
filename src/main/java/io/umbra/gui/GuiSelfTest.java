package io.umbra.gui;

import io.umbra.core.config.ConfigLoader;
import io.umbra.core.config.UmbraConfig;
import io.umbra.gui.theme.Tokens;
import io.umbra.gui.ui.ConsolePanel;
import io.umbra.gui.ui.GroupSection;
import io.umbra.gui.ui.RightColumn;
import io.umbra.gui.ui.StatCard;

import javax.imageio.ImageIO;
import java.awt.Component;
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
