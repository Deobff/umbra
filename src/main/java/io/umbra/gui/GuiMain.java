package io.umbra.gui;

import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.Stats;
import io.umbra.gui.theme.Tokens;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.awt.GraphicsEnvironment;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Desktop GUI entry point.
 *
 * <p>Normal usage ({@code java -jar umbra.jar}, {@code --gui}) opens the window.
 * Two hidden options exist for automated visual QA and CI:</p>
 *
 * <ul>
 *   <li>{@code --screenshot <png>} assembles the frame at 1440x900, renders it
 *       offscreen (no {@code Robot}, no visible window) and writes a PNG. Works
 *       on a headless JVM and exits 0.</li>
 *   <li>{@code --run} with {@code --screenshot} performs a real protection run
 *       through the GUI's own start path before rendering; combine with
 *       {@code --delay <ms>} to capture the running state.</li>
 *   <li>{@code --self-test} asserts the assembled structure, accessibility
 *       names, preset wiring, YAML round trip and the PNG renderer.</li>
 * </ul>
 */
public final class GuiMain {

    private GuiMain() {
    }

    public static void main(String[] args) {
        Options options = parse(args);
        if (options.error != null) {
            System.err.println(options.error);
            System.err.println("Run with --help for the GUI options.");
            System.exit(2);
            return;
        }
        if (options.help) {
            printUsage();
            return;
        }
        if (options.selfTest) {
            io.umbra.gui.ui.Animation.setEnabled(false);
            int failures = GuiSelfTest.run();
            System.out.println(failures == 0 ? "SELF-TEST OK"
                    : "SELF-TEST FAILED (" + failures + " failure(s))");
            System.exit(failures == 0 ? 0 : 1);
            return;
        }
        if (options.screenshot != null) {
            int code = runScreenshot(options);
            System.exit(code);
            return;
        }
        if (options.optionsScreenshot != null) {
            int code = runModeOptionsScreenshot(options);
            System.exit(code);
            return;
        }
        if (GraphicsEnvironment.isHeadless()) {
            System.err.println("Umbra GUI requires a graphical desktop. Use the CLI instead: "
                    + "java -jar umbra.jar -i input.jar -o output.jar");
            System.err.println("For automated visual QA use: java -cp umbra.jar "
                    + "io.umbra.gui.GuiMain --screenshot <png>");
            // Nothing was started: report failure instead of exiting 0, so
            // scripts and CI can tell that no window was opened.
            System.exit(1);
            return;
        }
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // Keep the cross-platform look and feel for the few stock widgets.
        }
        UIManager.put("TextField.caretBlinkRate", Integer.valueOf(500));
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new GuiFrame().setVisible(true);
            }
        });
    }

    /* ----------------------------------------------------------- screenshot */

    private static int runScreenshot(Options options) {
        Path png = Paths.get(options.screenshot).toAbsolutePath();
        io.umbra.gui.ui.Animation.setEnabled(false);
        GuiRoot root = new GuiRoot(false);
        root.setAnimationsEnabled(false);
        root.setSize(options.width, options.height);
        GuiScreenshot.layoutTree(root);

        if (!options.run) {
            // QA screenshots are deterministic: explicit or default seed/preset,
            // independent of the persisted user preferences.
            root.topBar().seedField().setText(String.valueOf(
                    options.seed == null ? 23303L : options.seed.longValue()));
            root.applyPresetForScreenshot(options.preset == null
                    ? GuiPresets.DEFAULT : options.preset);
            if (options.drawer) {
                root.openDrawerForScreenshot();
            }
            GuiScreenshot.layoutTree(root);
            try {
                GuiScreenshot.writePng(root, options.width, options.height, png);
            } catch (IOException e) {
                System.err.println("Cannot write screenshot: " + e.getMessage());
                return 1;
            }
            System.out.println("Wrote screenshot: " + png + " (" + options.width + "x"
                    + options.height + ") state=idle");
            return 0;
        }

        if (options.input == null || options.output == null) {
            System.err.println("--run requires --input <jar> and --output <jar>");
            return 2;
        }
        Path input = Paths.get(options.input).toAbsolutePath();
        Path output = Paths.get(options.output).toAbsolutePath();
        long seed = options.seed == null ? 23303L : options.seed.longValue();
        String preset = options.preset == null ? GuiPresets.DEFAULT : options.preset;
        Map<String, String> detailOverrides = new LinkedHashMap<String, String>();
        for (String detail : options.details) {
            int split = detail.indexOf('=');
            if (split > 0 && split < detail.length() - 1) {
                detailOverrides.put(detail.substring(0, split).trim(),
                        detail.substring(split + 1).trim());
            }
        }
        root.setTrialMode(true);
        boolean started = root.startTrialWithDetails(input, output, seed, preset,
                detailOverrides);
        if (!started) {
            GuiScreenshot.layoutTree(root);
            try {
                GuiScreenshot.writePng(root, options.width, options.height, png);
            } catch (IOException e) {
                System.err.println("Cannot write screenshot: " + e.getMessage());
                return 1;
            }
            System.err.println("Run did not start: " + root.failureMessage());
            return 1;
        }
        String state;
        if (options.delayMs > 0L) {
            sleepPumping(options.delayMs, root);
            state = root.isBusy() ? "running" : "completed";
        } else {
            waitForRun(root, 10L * 60L * 1000L);
            state = "completed";
        }
        GuiScreenshot.layoutTree(root);
        try {
            GuiScreenshot.writePng(root, options.width, options.height, png);
        } catch (IOException e) {
            System.err.println("Cannot write screenshot: " + e.getMessage());
            return 1;
        }
        System.out.println("Wrote screenshot: " + png + " (" + options.width + "x"
                + options.height + ") state=" + state);
        if (root.isBusy()) {
            waitForRun(root, 10L * 60L * 1000L);
        }
        GuiRoot.Outcome outcome = root.lastOutcome();
        if (outcome == null) {
            System.err.println("Run outcome missing (timeout?)");
            return 2;
        }
        if (outcome.cancelled) {
            System.err.println("Run cancelled");
            return 1;
        }
        if (outcome.error != null) {
            System.err.println("Run failed: " + outcome.error);
            return 1;
        }
        EngineResult result = outcome.result;
        Stats stats = result == null ? null : result.stats();
        Map<String, Long> values = stats == null ? null : stats.snapshot();
        System.out.println("Run: SUCCESS");
        System.out.println("  output:  " + (result == null ? output : result.output()));
        System.out.println("  classes: " + (result == null ? 0 : result.classes()));
        System.out.println("  methods: " + value(values, "methods.renamed"));
        System.out.println("  strings: " + value(values, "strings.encrypted"));
        System.out.println("  elapsed: " + (result == null ? 0L : result.millis()) + " ms");
        return 0;
    }

    /** Renders the per-mode detailed option sheet offscreen (QA evidence). */
    private static int runModeOptionsScreenshot(Options options) {
        Path png = Paths.get(options.optionsScreenshot).toAbsolutePath();
        io.umbra.gui.ui.Animation.setEnabled(false);
        String mode = options.preset == null ? GuiPresets.DEFAULT : options.preset;
        Map<String, String> values = GuiModeOptions.defaults(mode);
        io.umbra.gui.ui.ModeOptionsPanel panel =
                new io.umbra.gui.ui.ModeOptionsPanel(values, mode, null);
        if (options.optionsScroll != null) {
            panel.scrollToSection(options.optionsScroll);
        }
        if (options.sliderProgress >= 0f) {
            panel.setSliderProgressForScreenshot(options.sliderProgress);
        }
        try {
            GuiScreenshot.writePanel(panel, io.umbra.gui.ui.ModeOptionsPanel.SHEET_WIDTH,
                    io.umbra.gui.ui.ModeOptionsPanel.SHEET_HEIGHT, png);
        } catch (IOException e) {
            System.err.println("Cannot write mode-options screenshot: " + e.getMessage());
            return 1;
        }
        System.out.println("Wrote mode-options screenshot: " + png + " ("
                + io.umbra.gui.ui.ModeOptionsPanel.SHEET_WIDTH + "x"
                + io.umbra.gui.ui.ModeOptionsPanel.SHEET_HEIGHT + ") mode=" + mode
                + " controls=" + panel.controlCount());
        return 0;
    }
    private static long value(Map<String, Long> values, String key) {
        if (values == null) {
            return 0L;
        }
        Long value = values.get(key);
        return value == null ? 0L : value.longValue();
    }

    private static void waitForRun(GuiRoot root, long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (root.isBusy() && System.currentTimeMillis() < deadline) {
            pumpEventQueue();
            try {
                Thread.sleep(40L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        pumpEventQueue();
        pumpEventQueue();
    }

    private static void sleepPumping(long millis, GuiRoot root) {
        long deadline = System.currentTimeMillis() + millis;
        while (System.currentTimeMillis() < deadline) {
            pumpEventQueue();
            try {
                Thread.sleep(25L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        pumpEventQueue();
    }

    private static void pumpEventQueue() {
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    // Flush pending repaints and SwingWorker done() callbacks.
                }
            });
        } catch (Exception ignored) {
            // The event queue is gone (shutting down); nothing to flush.
        }
    }

    /* --------------------------------------------------------------- options */

    private static Options parse(String[] args) {
        Options options = new Options();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--gui".equals(arg) || "gui".equals(arg)) {
                continue;
            }
            if ("-h".equals(arg) || "--help".equals(arg)) {
                options.help = true;
                continue;
            }
            if ("--self-test".equals(arg)) {
                options.selfTest = true;
                continue;
            }
            if ("--run".equals(arg)) {
                options.run = true;
                continue;
            }
            if ("--drawer".equals(arg)) {
                options.drawer = true;
                continue;
            }
            if (i + 1 >= args.length) {
                options.error = isValueOption(arg)
                        ? "Missing value for " + arg : "Unknown argument: " + arg;
                continue;
            }
            String value = args[++i];
            if ("--screenshot".equals(arg)) {
                options.screenshot = value;
            } else if ("--options-screenshot".equals(arg)) {
                options.optionsScreenshot = value;
            } else if ("--options-scroll".equals(arg)) {
                options.optionsScroll = value;
            } else if ("--options-slider-progress".equals(arg)) {
                options.sliderProgress = parseFloat(value, options);
            } else if ("--detail".equals(arg)) {
                options.details.add(value);
            } else if ("--input".equals(arg)) {
                options.input = value;
            } else if ("--output".equals(arg)) {
                options.output = value;
            } else if ("--preset".equals(arg)) {
                options.preset = value;
            } else if ("--seed".equals(arg)) {
                try {
                    options.seed = Long.valueOf(value);
                } catch (NumberFormatException e) {
                    options.error = "Invalid number for --seed: " + value;
                }
            } else if ("--width".equals(arg)) {
                options.width = parseInt(value, options.width, "--width", options);
            } else if ("--height".equals(arg)) {
                options.height = parseInt(value, options.height, "--height", options);
            } else if ("--delay".equals(arg)) {
                options.delayMs = parseLong(value, 0L, "--delay", options);
            } else {
                options.error = "Unknown argument: " + arg;
            }
        }
        return options;
    }

    private static boolean isValueOption(String arg) {
        return "--screenshot".equals(arg) || "--options-screenshot".equals(arg)
                || "--options-scroll".equals(arg) || "--options-slider-progress".equals(arg)
                || "--detail".equals(arg) || "--input".equals(arg)
                || "--output".equals(arg)
                || "--preset".equals(arg) || "--seed".equals(arg) || "--width".equals(arg)
                || "--height".equals(arg) || "--delay".equals(arg);
    }

    private static int parseInt(String text, int fallback, String option, Options options) {
        try {
            return Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            options.error = "Invalid integer for " + option + ": " + text;
            return fallback;
        }
    }

    private static long parseLong(String text, long fallback, String option, Options options) {
        try {
            return Long.parseLong(text.trim());
        } catch (NumberFormatException e) {
            options.error = "Invalid integer for " + option + ": " + text;
            return fallback;
        }
    }

    private static float parseFloat(String text, Options options) {
        try {
            return Float.parseFloat(text.trim());
        } catch (NumberFormatException e) {
            options.error = "Invalid number for --options-slider-progress: " + text;
            return -1f;
        }
    }

    private static void printUsage() {
        System.out.println("Umbra " + GuiConfig.VERSION + " desktop GUI");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -cp umbra.jar io.umbra.gui.GuiMain");
        System.out.println("  java -cp umbra.jar io.umbra.gui.GuiMain --gui");
        System.out.println();
        System.out.println("Visual QA (headless, deterministic):");
        System.out.println("  --screenshot <png>   render the assembled GUI offscreen and exit");
        System.out.println("  --width <n>          screenshot width (default 1440)");
        System.out.println("  --height <n>         screenshot height (default 900)");
        System.out.println("  --run                run a real protection before the screenshot");
        System.out.println("  --input <jar>        input JAR for --run");
        System.out.println("  --output <jar>       output JAR for --run");
        System.out.println("  --seed <n>           seed for --run (default 23303)");
        System.out.println("  --preset <name>      Light | Balanced | Aggressive | Maximum | Nocturne");
        System.out.println("  --delay <ms>         with --run, capture after this delay (running state)");
        System.out.println("  --drawer             open the compact configuration drawer (narrow width)");
        System.out.println("  --options-screenshot <png>  render the per-mode detailed options sheet (900x700)");
        System.out.println("  --options-scroll <group>    scroll the rendered sheet to a group (e.g. Native)");
        System.out.println("  --options-slider-progress <0..1>  deterministic simulated slider frame");
        System.out.println("  --detail <id=value>  override a mode option before --run (repeatable)");
        System.out.println("  --self-test          structural/accessibility/YAML self test");
    }

    private static final class Options {
        String screenshot;
        String optionsScreenshot;
        String optionsScroll;
        float sliderProgress = -1f;
        final List<String> details = new ArrayList<String>();
        String input;
        String output;
        String preset;
        Long seed;
        boolean run;
        boolean drawer;
        boolean selfTest;
        boolean help;
        int width = 1440;
        int height = 900;
        long delayMs;
        /** First command-line error; non-null means exit code 2 before doing anything. */
        String error;
    }
}
