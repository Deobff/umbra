package io.umbra.guifx;

import io.umbra.gui.GuiModeOptions;
import io.umbra.gui.GuiPresets;
import io.umbra.gui.GuiSwitches;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Tooltip;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The console window: header, configuration rail, segmented views, targets and
 * the action bar.
 *
 * <p>The shell owns the process: it spawns the engine with exactly the arguments
 * the preview shows, streams its stdout and stderr into the log, and reports the
 * outcome - the reason of a failure included - in the log and the header pill.
 * Views are swapped inside one {@link StackPane} so the window never changes size
 * when the segment changes.</p>
 */
final class ConsoleShell {

    private final ConsoleModel model;
    private final OptionsView options;

    private final javafx.stage.Stage stage;
    private final TitleBar titleBar;

    private final TreeView<String> tree = new TreeView<String>();
    private final Label summaryGroups = new Label();
    private final Label summaryPreset = new Label();

    private final TextArea outputArea = new TextArea();
    private final TextArea commandArea = new TextArea();
    private final StackPane content = new StackPane();
    private final ToggleGroup segments = new ToggleGroup();

    private final TextField inputField = new TextField();
    private final TextField outputField = new TextField();
    private final TextField seedField = new TextField();
    private final CheckBox verifyBox = new CheckBox("verify");
    private final ChoiceBox<String> presetBox = new ChoiceBox<String>();
    private final ProgressBar progress = new ProgressBar(0);
    private final FusionButton protectButton = new FusionButton("Protect");
    private final FusionButton cancelButton = new FusionButton("Cancel");

    private Process process;

    /** Set by {@link #cancel()}: a destroyed engine is a cancel, not a crash. */
    private volatile boolean cancelRequested;

    private Runnable onDone;

    ConsoleShell(javafx.stage.Stage stage, ConsoleModel model) {
        this.stage = stage;
        this.titleBar = new TitleBar(stage, FxGui.VERSION);
        this.model = model;
        this.options = new OptionsView(model);
        this.options.setOnChange(this::refreshCommand);
    }

    /** Called when the About button in the title bar is pressed. */
    void setOnAbout(Runnable onAbout) {
        titleBar.setOnAbout(onAbout);
    }

    /** Called once when a run finishes (used by the exit-when-done self-test). */
    void setOnDone(Runnable onDone) {
        this.onDone = onDone;
    }

    // ------------------------------------------------------------------ layout

    Parent build() {
        BorderPane root = new BorderPane();
        root.getStyleClass().add("ux-root");
        root.setTop(titleBar);
        root.setLeft(rail());
        root.setCenter(workspace());
        root.setBottom(actions());
        buildTree();
        selectFirstGroup();
        // Load the preset's effective values before the first paint: the shell sends
        // an explicit --set for every control, and explicit values win over the
        // preset in the engine, so without this the preset would be dead weight.
        applyPreset(presetBox.getValue());
        refreshCommand();
        return withResizeHandles(root);
    }

    /**
     * Wraps the body with the thin drag strips an undecorated window needs on its
     * right, bottom and bottom-right corner. Six pixels keeps them out of the way
     * while still being grabbable.
     */
    private javafx.scene.Parent withResizeHandles(javafx.scene.Parent body) {
        StackPane frame = new StackPane(body);
        frame.getStyleClass().add("ux-frame");
        Region right = new Region();
        right.setCursor(javafx.scene.Cursor.E_RESIZE);
        right.setMinWidth(6);
        right.setMaxWidth(6);
        right.setMaxHeight(Double.MAX_VALUE);
        StackPane.setAlignment(right, Pos.CENTER_RIGHT);
        final double[] grab = new double[2];
        right.setOnMousePressed(event -> grab[0] = stage.getWidth() - event.getScreenX());
        right.setOnMouseDragged(event -> stage.setWidth(
                Math.max(stage.getMinWidth(), grab[0] + event.getScreenX())));

        Region bottom = new Region();
        bottom.setCursor(javafx.scene.Cursor.S_RESIZE);
        bottom.setMinHeight(6);
        bottom.setMaxHeight(6);
        bottom.setMaxWidth(Double.MAX_VALUE);
        StackPane.setAlignment(bottom, Pos.BOTTOM_CENTER);
        bottom.setOnMousePressed(event -> grab[1] = stage.getHeight() - event.getScreenY());
        bottom.setOnMouseDragged(event -> stage.setHeight(
                Math.max(stage.getMinHeight(), grab[1] + event.getScreenY())));

        Region corner = new Region();
        corner.setCursor(javafx.scene.Cursor.SE_RESIZE);
        corner.setMinWidth(14);
        corner.setMinHeight(14);
        corner.setMaxWidth(14);
        corner.setMaxHeight(14);
        StackPane.setAlignment(corner, Pos.BOTTOM_RIGHT);
        corner.setOnMousePressed(event -> {
            grab[0] = stage.getWidth() - event.getScreenX();
            grab[1] = stage.getHeight() - event.getScreenY();
        });
        corner.setOnMouseDragged(event -> {
            stage.setWidth(Math.max(stage.getMinWidth(), grab[0] + event.getScreenX()));
            stage.setHeight(Math.max(stage.getMinHeight(), grab[1] + event.getScreenY()));
        });

        frame.getChildren().addAll(right, bottom, corner);
        return frame;
    }

    private Node rail() {
        Label caption = new Label("CONFIGURATION");
        caption.getStyleClass().add("ux-caption");
        VBox.setVgrow(tree, Priority.ALWAYS);
        tree.getStyleClass().add("ux-tree");
        tree.setShowRoot(false);

        summaryGroups.getStyleClass().add("ux-summary");
        summaryPreset.getStyleClass().add("ux-summary");
        VBox summary = new VBox(3, summaryGroups, summaryPreset);
        summary.getStyleClass().add("ux-rail-foot");

        VBox rail = new VBox(10, caption, tree, summary);
        rail.setPrefWidth(Tokens.RAIL_WIDTH);
        rail.setMinWidth(Tokens.RAIL_WIDTH);
        rail.getStyleClass().add("ux-rail");
        return rail;
    }

    private Node workspace() {
        ToggleButton optionsTab = segment("Options");
        ToggleButton commandTab = segment("Command");
        ToggleButton outputTab = segment("Output");
        optionsTab.setSelected(true);
        HBox strip = new HBox(6, optionsTab, commandTab, outputTab);
        strip.getStyleClass().add("ux-segments");

        commandArea.getStyleClass().add("ux-mono");
        commandArea.setEditable(false);
        commandArea.setWrapText(true);
        outputArea.getStyleClass().add("ux-mono");
        outputArea.setEditable(false);

        Node commandPane = padded(commandArea);
        Node outputPane = padded(outputArea);
        Node optionsPane = options.node();
        content.getChildren().addAll(optionsPane, commandPane, outputPane);
        show(optionsPane);

        optionsTab.setOnAction(event -> {
            segments.selectToggle(optionsTab);
            show(optionsPane);
        });
        commandTab.setOnAction(event -> {
            segments.selectToggle(commandTab);
            show(commandPane);
            refreshCommand();
        });
        outputTab.setOnAction(event -> {
            segments.selectToggle(outputTab);
            show(outputPane);
        });

        VBox workspace = new VBox(12, strip, content);
        VBox.setVgrow(content, Priority.ALWAYS);
        workspace.getStyleClass().add("ux-workspace");
        return workspace;
    }

    private ToggleButton segment(String text) {
        ToggleButton button = new ToggleButton(text);
        button.setToggleGroup(segments);
        button.getStyleClass().add("ux-segment");
        return button;
    }

    private static Node padded(Node node) {
        VBox box = new VBox(node);
        VBox.setVgrow(node, Priority.ALWAYS);
        box.setPadding(new Insets(2, 2, 2, 2));
        box.getStyleClass().add("ux-card");
        return box;
    }

    private void show(Node node) {
        for (Node child : content.getChildren()) {
            child.setVisible(child == node);
            child.setManaged(child == node);
        }
        Motion.swap(node);
    }

    private Node actions() {
        inputField.setPromptText("jar to protect");
        outputField.setPromptText("protected jar");
        inputField.getStyleClass().add("ux-field");
        outputField.getStyleClass().add("ux-field");
        inputField.textProperty().addListener((obs, old, next) -> {
            model.input = next;
            refreshCommand();
        });
        outputField.textProperty().addListener((obs, old, next) -> {
            model.output = next;
            refreshCommand();
        });

        GridPane targets = new GridPane();
        targets.setHgap(10);
        targets.setVgap(8);
        ColumnConstraints labels = new ColumnConstraints();
        labels.setMinWidth(46);
        ColumnConstraints fields = new ColumnConstraints();
        fields.setHgrow(Priority.ALWAYS);
        fields.setFillWidth(true);
        ColumnConstraints browse = new ColumnConstraints();
        targets.getColumnConstraints().addAll(labels, fields, browse);
        targets.add(caption("input"), 0, 0);
        targets.add(inputField, 1, 0);
        targets.add(browse(inputField, "Select the jar to protect"), 2, 0);
        targets.add(caption("output"), 0, 1);
        targets.add(outputField, 1, 1);
        targets.add(browse(outputField, "Select the protected jar"), 2, 1);
        targets.getStyleClass().add("ux-targets");

        presetBox.getItems().addAll(GuiPresets.NAMES);
        presetBox.setValue(model.preset);
        presetBox.setPrefWidth(148);
        presetBox.getStyleClass().add("ux-choice");
        presetBox.valueProperty().addListener((obs, old, next) -> applyPreset(next));

        seedField.setPromptText("seed");
        seedField.setPrefWidth(120);
        seedField.getStyleClass().add("ux-field");
        seedField.textProperty().addListener((obs, old, next) -> {
            model.seed = next;
            refreshCommand();
        });

        verifyBox.setSelected(true);
        verifyBox.selectedProperty().addListener((obs, old, next) -> {
            model.verify = next;
            refreshCommand();
        });

        progress.setPrefWidth(160);
        progress.setVisible(false);

        protectButton.getStyleClass().add("ux-primary");
        protectButton.setOnAction(event -> protect());
        Motion.press(protectButton);
        cancelButton.getStyleClass().add("ux-ghost");
        cancelButton.setDisable(true);
        cancelButton.setOnAction(event -> cancel());
        Motion.press(cancelButton);

        HBox left = new HBox(8, caption("preset"), presetBox, caption("seed"), seedField, verifyBox);
        left.setAlignment(Pos.CENTER_LEFT);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        HBox bar = new HBox(12, left, spacer, progress, cancelButton, protectButton);
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.getStyleClass().add("ux-actionbar");

        VBox bottom = new VBox(10, targets, bar);
        bottom.getStyleClass().add("ux-bottom");
        return bottom;
    }

    private static Label caption(String text) {
        Label label = new Label(text);
        label.getStyleClass().add("ux-caption-inline");
        return label;
    }

    private Button browse(TextField target, String title) {
        FusionButton button = new FusionButton("…");
        button.getStyleClass().add("ux-ghost");
        Motion.press(button);
        button.setOnAction(event -> {
            javafx.stage.FileChooser chooser = new javafx.stage.FileChooser();
            chooser.setTitle(title);
            chooser.getExtensionFilters().add(
                    new javafx.stage.FileChooser.ExtensionFilter("JAR", "*.jar"));
            File file = chooser.showOpenDialog(button.getScene().getWindow());
            if (file != null) {
                target.setText(file.getAbsolutePath());
            }
        });
        return button;
    }

    // ------------------------------------------------------------------- tree

    private void buildTree() {
        // The engine publishes two control models with different taxonomies: specs
        // (12 groups) and switches (12 groups), and only four titles are shared. The
        // tree has to be the union, otherwise the switches of Data / Control flow /
        // Archive / Anti-analysis / Verification (19 of them) would never be
        // reachable from the UI.
        java.util.List<String> titles = new java.util.ArrayList<String>();
        java.util.Map<String, Integer> counts = new java.util.LinkedHashMap<String, Integer>();
        java.util.Set<String> specKeys = model.specKeys();
        for (GuiModeOptions.Group group : GuiModeOptions.groups()) {
            if (!titles.contains(group.title)) {
                titles.add(group.title);
                counts.put(group.title, Integer.valueOf(0));
            }
            int visible = 0;
            for (GuiModeOptions.Spec spec : group.specs) {
                if (!spec.uiOnly()) {
                    visible++;
                }
            }
            counts.put(group.title, Integer.valueOf(counts.get(group.title).intValue() + visible));
        }
        for (GuiSwitches.GroupDef def : GuiSwitches.groups()) {
            if (def.toggles.isEmpty()) {
                continue;
            }
            // A switch whose engine key is also exposed as a spec is rendered by that
            // spec's group instead (one control per key). Only groups that still have
            // a renderable switch deserve a tree entry, otherwise the entry opens an
            // empty card.
            int visible = 0;
            for (GuiSwitches.Toggle toggle : def.toggles) {
                if (toggle.key == null || !specKeys.contains(toggle.key)) {
                    visible++;
                }
            }
            if (visible == 0) {
                continue;
            }
            if (!titles.contains(def.title)) {
                titles.add(def.title);
                counts.put(def.title, Integer.valueOf(0));
            }
            counts.put(def.title, Integer.valueOf(counts.get(def.title).intValue() + visible));
        }
        TreeItem<String> root = new TreeItem<String>("groups");
        int switches = 0;
        for (String title : titles) {
            root.getChildren().add(new TreeItem<String>(title + "  " + counts.get(title)));
            switches += counts.get(title).intValue();
        }
        tree.setRoot(root);
        summaryGroups.setText(titles.size() + " groups · " + switches + " controls");
        tree.getSelectionModel().selectedItemProperty().addListener((obs, old, next) -> {
            if (next != null) {
                options.show(stripCount(next.getValue()));
            }
        });
    }

    private void selectFirstGroup() {
        if (tree.getRoot() != null && !tree.getRoot().getChildren().isEmpty()) {
            tree.getSelectionModel().select(tree.getRoot().getChildren().get(0));
        }
    }

    private static String stripCount(String label) {
        int cut = label.lastIndexOf("  ");
        return cut > 0 ? label.substring(0, cut) : label;
    }

    // ---------------------------------------------------------------- actions

    private void applyPreset(String preset) {
        model.preset = preset;
        summaryPreset.setText("preset · " + (preset == null ? "custom" : preset.toLowerCase(Locale.ROOT)));
        if (preset == null || "Custom".equalsIgnoreCase(preset)) {
            refreshCommand();
            return;
        }
        Map<String, String> values = model.presetValues(preset);
        if (values.isEmpty()) {
            log("!! preset values unavailable for " + preset);
            refreshCommand();
            return;
        }
        model.applyPresetValues(values);
        options.refresh();
        refreshCommand();
    }

    private void refreshCommand() {
        commandArea.setText(model.command());
    }

    /** Runs the engine with exactly the previewed arguments. */
    void protect() {
        if (process != null) {
            return;
        }
        if (model.input.trim().isEmpty() || model.output.trim().isEmpty()) {
            log("!! set the input and output jar first");
            return;
        }
        List<String> argv = new ArrayList<String>();
        argv.add("java");
        argv.add("-jar");
        argv.add(model.jarPath);
        argv.add("-i");
        argv.add(model.input.trim());
        argv.add("-o");
        argv.add(model.output.trim());
        argv.addAll(model.engineArguments());
        log("> " + model.command());
        protectButton.setDisable(true);
        cancelButton.setDisable(false);
        progress.setVisible(true);
        progress.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        setStatus("protecting", "busy");
        Thread worker = new Thread(() -> watch(argv), "umbra-fx-worker");
        worker.setDaemon(true);
        worker.start();
    }

    void cancel() {
        Process running = process;
        if (running != null) {
            // The watcher still reports the outcome; the flag only tells it that the
            // non-zero exit code is the user's doing and not a crash.
            cancelRequested = true;
            running.destroy();
            log("!! cancelled");
        }
    }

    /** How many output lines a run keeps for the failure reason; the newest win. */
    private static final int CAPTURED_LINES = 2000;

    /** "[ERROR] <summary>" - the CLI's own one-line reason, summary not indented. */
    private static final Pattern REASON_LINE = Pattern.compile("^\\[ERROR\\] \\S.*");

    /** "Umbra failed: ..." / "Umbra crashed: ...": the one-line report of older builds. */
    private static final Pattern LEGACY_LINE = Pattern.compile(
            "^Umbra (failed|crashed|ran out of stack|ran out of memory).*");

    /** "Caused by: ..." - the root cause of a wrapped failure. */
    private static final Pattern CAUSE_LINE = Pattern.compile("^\\s*Caused by: \\S.*");

    /** "[ERROR]   cause: ..." / "[ERROR]   hint: ...": details of the failure block. */
    private static final Pattern DETAIL_LINE = Pattern.compile("^\\[ERROR\\]  +\\S.*");

    /** "Verification failed for 3 class(es):". */
    private static final Pattern VERIFY_LINE = Pattern.compile(
            "(?i)^(verification|verify) failed.*");

    /** The JVM line for an uncaught throwable: Exception in thread "main" ... */
    private static final Pattern THREAD_LINE = Pattern.compile("^Exception in thread .*");

    /** A stack trace header: "java.lang.OutOfMemoryError: Java heap space". */
    private static final Pattern THROWABLE_LINE = Pattern.compile(
            "^[A-Za-z_$][A-Za-z0-9_$.]*[A-Za-z_$][A-Za-z0-9_$]*(Exception|Error|Throwable)(: .*)?$");

    /** Anything that reads like a failure, in either language. */
    private static final Pattern FAILURE_WORDS = Pattern.compile(
            "(?i)(fail|failure|error|exception|denied|refused|invalid|cannot|could not|"
            + " unable|missing|unsupported|abort|timeout|timed out)"
            + "|失败|错误|异常|无法|不能|不支持|中止|超时");

    private void watch(List<String> argv) {
        // Every line the run printed. When the engine exits non-zero the reason is
        // picked from these lines, so a failed run never ends in silence again.
        List<String> captured = new ArrayList<String>();
        int exit = -1;
        String startupFailure = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(argv);
            // The engine writes progress to System.out and failures to System.err
            // ("Umbra failed: ...", the [ERROR] block, the stack trace). Merging both
            // into the one pipe read here is what makes the reason visible; reading
            // getInputStream() and getErrorStream() side by side would instead let the
            // pipe nobody drains fill up and block the engine before it exits.
            builder.redirectErrorStream(true);
            process = builder.start();
            // The child's console output uses the platform code page (GBK on a zh-CN
            // Windows), which is exactly what the default charset decodes. Forcing
            // UTF-8 would turn a Chinese failure message into mojibake in the very
            // moment the user needs to read it.
            Charset charset = Charset.defaultCharset();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), charset))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    captured.add(line);
                    // Keep the recent window only: the reason is always near the end,
                    // and an unbounded list would grow for the whole run.
                    if (captured.size() > CAPTURED_LINES) {
                        captured.subList(0, CAPTURED_LINES / 2).clear();
                    }
                    String current = line;
                    Platform.runLater(() -> log(current));
                }
            }
            exit = process.waitFor();
        } catch (Throwable failure) {
            // start() itself failed (no java on PATH, the jar moved, no rights), or the
            // reader died on something an Exception does not cover. The worker is a
            // daemon thread: an Escape here would kill it silently and leave the window
            // on "protecting" with no exit code and no reason for ever.
            startupFailure = describeFailure(failure);
            String message = startupFailure;
            Platform.runLater(() -> log("!! " + message));
        } finally {
            int code = exit;
            boolean cancelled = cancelRequested;
            cancelRequested = false;
            process = null;
            String reason = null;
            if (code != 0) {
                if (cancelled) {
                    reason = "stopped by the user";
                } else if (startupFailure != null) {
                    reason = startupFailure;
                } else {
                    reason = failureReason(captured);
                }
            }
            String status;
            String kind;
            String finish;
            if (code == 0) {
                status = "done";
                kind = "ok";
                finish = "== done";
            } else if (cancelled) {
                status = "cancelled";
                kind = "err";
                finish = "== cancelled";
            } else if (code == -1) {
                status = "not started";
                kind = "err";
                finish = "== the engine did not start";
            } else {
                status = "exit " + code;
                kind = "err";
                finish = "== finished with exit " + code;
            }
            if (reason != null) {
                finish = finish + ": " + reason;
                status = status + " · " + shorten(reason, 44);
            }
            final String finalStatus = status;
            final String finalKind = kind;
            final String finalLine = finish;
            Platform.runLater(() -> {
                protectButton.setDisable(false);
                cancelButton.setDisable(true);
                progress.setVisible(false);
                setStatus(finalStatus, finalKind);
                log(finalLine);
                if (onDone != null) {
                    onDone.run();
                }
            });
        }
    }

    /**
     * The one line of a finished run that explains it best.
     *
     * <p>The engine answers a failure in several shapes and the merged stream holds
     * all of them: current builds print "[ERROR] &lt;summary&gt; ..." on stdout plus a
     * compact block on stderr, older ones print "Umbra failed: ..." followed by the
     * stack trace, --verify prints "Verification failed for N class(es):", and an
     * uncaught Error prints its exception header first. The rules are tried from the
     * last line backwards, so the newest explanation wins, and the root cause of a
     * wrapped failure beats the wrapper sentence that only repeats it. The result is
     * never empty, so a failed run always says something.</p>
     *
     * @param lines everything the run printed, in order
     * @return a single non-empty line describing the failure
     */
    static String failureReason(List<String> lines) {
        String reason = lastMatching(lines, REASON_LINE);
        if (reason == null) {
            reason = lastMatching(lines, CAUSE_LINE);
        }
        if (reason == null) {
            reason = lastMatching(lines, LEGACY_LINE);
        }
        if (reason == null) {
            reason = lastMatching(lines, DETAIL_LINE);
        }
        if (reason == null) {
            reason = lastMatching(lines, VERIFY_LINE);
        }
        if (reason == null) {
            reason = lastMatching(lines, THREAD_LINE);
        }
        if (reason == null) {
            reason = lastMatching(lines, THROWABLE_LINE);
        }
        if (reason == null) {
            reason = lastContaining(lines, FAILURE_WORDS);
        }
        if (reason == null) {
            reason = lastNonBlank(lines);
        }
        return reason == null ? "the engine exited without printing a message" : unlabelled(reason);
    }

    /**
     * Drops the "[ERROR]" tag from a picked line: the finish line already says the
     * run failed, so "== finished with exit 1: [ERROR] Umbra failed: ..." would
     * repeat the same word twice.
     */
    private static String unlabelled(String line) {
        String text = line.trim();
        while (text.startsWith("[ERROR]") || text.startsWith("[error]")) {
            text = text.substring("[ERROR]".length()).trim();
        }
        return text;
    }

    /** The last line that matches {@code pattern} completely and says something. */
    private static String lastMatching(List<String> lines, Pattern pattern) {
        for (int i = lines.size() - 1; i >= 0; i--) {
            String line = lines.get(i);
            if (speaks(line) && pattern.matcher(line).matches()) {
                return line.trim();
            }
        }
        return null;
    }

    /** The last line that contains a match for {@code pattern} and says something. */
    private static String lastContaining(List<String> lines, Pattern pattern) {
        for (int i = lines.size() - 1; i >= 0; i--) {
            String line = lines.get(i);
            if (speaks(line) && pattern.matcher(line).find()) {
                return line.trim();
            }
        }
        return null;
    }

    /** The last line that is not blank, used when nothing reads like a failure. */
    private static String lastNonBlank(List<String> lines) {
        for (int i = lines.size() - 1; i >= 0; i--) {
            String line = lines.get(i);
            if (speaks(line)) {
                return line.trim();
            }
        }
        return null;
    }

    /**
     * Whether a line says anything: {@code e.getMessage()} is null for a great many
     * exceptions, and "Umbra failed: null" used as the reason would only hide the
     * exception type the stack trace still names.
     */
    private static boolean speaks(String line) {
        String trimmed = line == null ? "" : line.trim();
        return !trimmed.isEmpty() && !trimmed.endsWith(": null") && !trimmed.equals("null");
    }

    /** "java.io.IOException: Cannot run program ..." with the type kept in front. */
    private static String describeFailure(Throwable failure) {
        String message = failure.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return failure.toString();
        }
        return failure.getClass().getName() + ": " + message.trim();
    }

    /** Trims a reason for the header pill; the log keeps the whole sentence. */
    private static String shorten(String text, int max) {
        String flat = text.replace('\r', ' ').replace('\n', ' ').trim();
        return flat.length() <= max ? flat : flat.substring(0, max - 1) + "…";
    }

    // ------------------------------------------------------------------- state

    void log(String line) {
        outputArea.appendText(line + System.lineSeparator());
        outputArea.setScrollTop(Double.MAX_VALUE);
    }

    /** The whole console text, used by the headless check that dumps a finished run. */
    String logText() {
        return outputArea.getText();
    }

    /** Sets the header pill text and signal colour; the dot pulses once. */
    void setStatus(String text, String kind) {
        titleBar.setStatus(text, kind);
    }

    // -------------------------------------------------------------- self-test

    void prefill(String input, String output, String preset) {
        if (input != null && !input.isEmpty()) {
            inputField.setText(input);
            model.input = input;
        }
        if (output != null && !output.isEmpty()) {
            outputField.setText(output);
            model.output = output;
        }
        if (preset != null) {
            for (String name : GuiPresets.NAMES) {
                if (name.equalsIgnoreCase(preset)) {
                    presetBox.setValue(name);
                    break;
                }
            }
        }
    }

    /** The scroll containers, exposed so the shot writer can force a full render. */
    List<ScrollPane> scrollPanes() {
        List<ScrollPane> panes = new ArrayList<ScrollPane>();
        for (Node child : content.getChildren()) {
            if (child instanceof ScrollPane) {
                panes.add((ScrollPane) child);
            }
        }
        return panes;
    }

    /** The exact command line the Protect button will run. */
    String commandPreview() {
        return model.command();
    }

    /**
     * Renders every configuration group once and reports controls whose value and
     * representation disagree (an enum value outside its declared list, an integer
     * outside its slider range, a boolean the engine would not parse, a group with
     * no rows, a duplicated engine key). Used by the headless QA hook.
     */
    List<String> auditOptions() {
        List<String> report = new ArrayList<String>();
        options.clearIssues();
        java.util.Set<String> specKeys = model.specKeys();
        // Reachability: every switch that has no spec twin must be rendered by its own
        // group, and every spec must be rendered by its group. The two control models
        // use different taxonomies, which is exactly where controls used to vanish.
        for (GuiSwitches.GroupDef def : GuiSwitches.groups()) {
            if (def.toggles.isEmpty()) {
                continue;
            }
            int renderable = 0;
            for (GuiSwitches.Toggle toggle : def.toggles) {
                if (toggle.key == null || !specKeys.contains(toggle.key)) {
                    renderable++;
                }
            }
            if (renderable == 0) {
                continue;
            }
            options.show(def.title);
            if (options.rowCount() < renderable) {
                report.add("group '" + def.title + "' rendered " + options.rowCount()
                        + " rows for " + renderable + " switches");
            }
        }
        // Every toggle either has a control of its own or is covered by a spec with
        // the same engine key; report the mapping so the coverage is auditable.
        for (GuiSwitches.GroupDef def : GuiSwitches.groups()) {
            for (GuiSwitches.Toggle toggle : def.toggles) {
                if (toggle.key != null && specKeys.contains(toggle.key)) {
                    report.add("note: toggle '" + toggle.id + "' (" + def.title + ") shares its key "
                            + toggle.key + " with a spec; the spec control owns it");
                }
            }
        }
        for (GuiModeOptions.Group group : GuiModeOptions.groups()) {
            for (GuiModeOptions.Spec spec : group.specs) {
                if (spec.uiOnly() && spec.key != null) {
                    report.add(group.title + " / " + spec.id
                            + ": ui-only spec carries an engine key '" + spec.key + "'");
                }
                if (spec.label == null || spec.label.trim().isEmpty()) {
                    report.add(group.title + " / " + spec.id + ": empty label");
                }
            }
            options.show(group.title);
            if (options.rowCount() == 0) {
                report.add(group.title + ": no controls rendered");
            }
        }
        report.addAll(options.issues());
        // Geometry needs a laid-out scene, so the caller runs this after the first
        // pulse (see FxGui's audit hook).
        report.addAll(layoutAudit());
        return report;
    }

    /** Scene-space rectangles of every slider and readout in the current group. */
    List<String> sliderGeometry() {
        // The rects are meaningless until the scroll content has been measured, and
        // the audit loop rebuilds the card without laying it out again.
        for (int pass = 0; pass < 2; pass++) {
            content.applyCss();
            content.layout();
        }
        return options.sliderGeometry();
    }

    /**
     * Re-renders the current group once the window has been shown.
     *
     * <p>The first layout pass can measure the scroll content at its preferred
     * width, which makes the slider skin lay its track out at that huge width and
     * never shrink it again — the track then runs underneath the value readout.
     * Rebuilding the rows after the scene has a real width gives every control its
     * final size from the start.</p>
     */
    void settleLayout() {
        options.refresh();
        for (int pass = 0; pass < 2; pass++) {
            content.applyCss();
            content.layout();
        }
        // A Slider's skin lays its track out with the width the control had when the
        // skin first ran; after the card shrinks to the viewport the track can keep
        // the huge width and paint under the readout. Re-running the skin layout for
        // each slider after the final sizing fixes the track to the control width.
        relayoutSliders(content);
        content.layout();
    }

    private static void relayoutSliders(Node node) {
        if (node instanceof javafx.scene.control.Slider) {
            node.applyCss();
            ((javafx.scene.Parent) node).layout();
        }
        if (node instanceof javafx.scene.Parent) {
            for (Node child : ((javafx.scene.Parent) node).getChildrenUnmodifiable()) {
                relayoutSliders(child);
            }
        }
    }

    /** Concatenated label text under {@code node}, used by the content self-check. */
    private static String textOf(Node node) {
        StringBuilder text = new StringBuilder();
        if (node instanceof Label) {
            text.append(((Label) node).getText()).append(' ');
        }
        if (node instanceof javafx.scene.Parent) {
            for (Node child : ((javafx.scene.Parent) node).getChildrenUnmodifiable()) {
                text.append(textOf(child));
            }
        }
        return text.toString();
    }

    /**
     * Dumps every node whose scene bounds intersect the horizontal band
     * {@code [fromY, toY]}: class name, style classes and rectangle. This is how a
     * pixel-level artefact gets traced back to the node that painted it.
     */
    List<String> nodesInBand(double fromY, double toY) {
        List<String> out = new ArrayList<String>();
        javafx.scene.Parent root = content.getScene() == null ? null : content.getScene().getRoot();
        if (root == null) {
            return out;
        }
        for (int pass = 0; pass < 2; pass++) {
            root.applyCss();
            root.layout();
        }
        collectBand(root, fromY, toY, out);
        return out;
    }

    private static void collectBand(Node node, double fromY, double toY, List<String> out) {
        javafx.geometry.Bounds bounds = node.localToScene(node.getLayoutBounds());
        if (bounds.getMaxY() < fromY || bounds.getMinY() > toY) {
            return;
        }
        if (node instanceof javafx.scene.control.Slider) {
            javafx.scene.control.Slider slider = (javafx.scene.control.Slider) node;
            String track = "no-track";
            for (Node child : slider.getChildrenUnmodifiable()) {
                if (child.getStyleClass().contains("track")) {
                    javafx.geometry.Bounds tb = child.localToScene(child.getLayoutBounds());
                    track = Math.round(tb.getWidth()) + "x" + Math.round(tb.getHeight())
                            + "@" + Math.round(tb.getMinX());
                }
            }
            out.add("Slider width=" + Math.round(slider.getWidth())
                    + " pref=" + Math.round(slider.prefWidth(-1))
                    + " max=" + Math.round(slider.getMaxWidth())
                    + " track=" + track
                    + " [" + Math.round(bounds.getMinX()) + "," + Math.round(bounds.getMinY())
                    + " " + Math.round(bounds.getWidth()) + "x" + Math.round(bounds.getHeight()) + "]");
        }
        if (node instanceof Region) {
            Region region = (Region) node;
            if (region.getBackground() != null || region.getBorder() != null) {
                out.add(region.getClass().getSimpleName()
                        + " " + region.getStyleClass()
                        + " [" + Math.round(bounds.getMinX()) + "," + Math.round(bounds.getMinY())
                        + " " + Math.round(bounds.getWidth()) + "x" + Math.round(bounds.getHeight()) + "]");
            }
        }
        if (node instanceof javafx.scene.Parent) {
            for (Node child : ((javafx.scene.Parent) node).getChildrenUnmodifiable()) {
                collectBand(child, fromY, toY, out);
            }
        }
    }

    /**
     * Renders every group, forces a layout pass for each and collects the geometry
     * problems {@link OptionsView#layoutIssues()} reports. This is what catches the
     * "text drawn inside the slider" class of bug, which no value audit can see.
     */
    List<String> layoutAudit() {
        List<String> report = new ArrayList<String>();
        List<String> titles = new ArrayList<String>();
        for (GuiModeOptions.Group group : GuiModeOptions.groups()) {
            titles.add(group.title);
        }
        for (GuiSwitches.GroupDef def : GuiSwitches.groups()) {
            if (!def.toggles.isEmpty() && !titles.contains(def.title)) {
                titles.add(def.title);
            }
        }
        for (String title : titles) {
            options.show(title);
            // Two passes: the first one sizes the card, the second one gives the rows
            // their final width, which is what the measurement depends on.
            for (int pass = 0; pass < 2; pass++) {
                content.applyCss();
                content.layout();
            }
            report.addAll(options.layoutIssues());
        }
        if (!titles.isEmpty()) {
            options.show(titles.get(0));
        }
        return report;
    }

    private List<String> unusedAuditTail() {
        List<String> report = new ArrayList<String>();
        Map<String, Integer> keys = new java.util.LinkedHashMap<String, Integer>();
        for (GuiModeOptions.Group group : GuiModeOptions.groups()) {
            for (GuiModeOptions.Spec spec : group.specs) {
                if (spec.key == null) {
                    continue;
                }
                Integer count = keys.get(spec.key);
                keys.put(spec.key, Integer.valueOf(count == null ? 1 : count.intValue() + 1));
            }
        }
        for (Map.Entry<String, Integer> entry : keys.entrySet()) {
            if (entry.getValue().intValue() > 1) {
                report.add("duplicate engine key: " + entry.getKey()
                        + " (" + entry.getValue() + " specs)");
            }
        }
        if (!GuiModeOptions.groups().isEmpty()) {
            options.show(GuiModeOptions.groups().get(0).title);
        }
        return report;
    }
    /**
     * Structural self-check for the headless QA loop: the parts the screenshots
     * cannot prove (rail width, segment count, tree size, rendered rows, both
     * target fields) are asserted here instead.
     *
     * @return human readable failures, empty when the shell is well formed
     */
    List<String> selfCheck() {
        List<String> failures = new ArrayList<String>();
        if (tree.getRoot() == null || tree.getRoot().getChildren().size() < GuiModeOptions.groups().size()) {
            failures.add("tree groups: expected at least " + GuiModeOptions.groups().size()
                    + ", got " + (tree.getRoot() == null ? -1 : tree.getRoot().getChildren().size()));
        }
        if (tree.getSelectionModel().getSelectedItem() == null) {
            failures.add("no group selected after build");
        }
        if (options.currentGroup() == null) {
            failures.add("options view has no group");
        }
        if (content.getChildren().size() != 3) {
            failures.add("workspace views: expected 3, got " + content.getChildren().size());
        }
        int visible = 0;
        for (Node child : content.getChildren()) {
            if (child.isVisible()) {
                visible++;
            }
        }
        if (visible != 1) {
            failures.add("workspace shows " + visible + " views at once");
        }
        if (inputField.getText().isEmpty() && outputField.getText().isEmpty()
                && inputField.getPromptText() == null) {
            failures.add("target fields are not initialised");
        }
        if (protectButton.getStyleClass().contains("ux-fusion") == false) {
            failures.add("protect button lost its fusion style class");
        }
        if (stage.getStyle() != javafx.stage.StageStyle.UNDECORATED) {
            failures.add("window is not self-drawn (stage style " + stage.getStyle() + ")");
        }
        int windowButtons = 0;
        for (Node node : titleBar.getChildren()) {
            if (node instanceof Label && ((Label) node).getStyleClass().contains("ux-winbtn")) {
                windowButtons++;
            }
        }
        // About + minimize + maximize + close.
        if (windowButtons != 4) {
            failures.add("title bar has " + windowButtons + " buttons, expected 4 (about + 3 window)");
        }
        if (titleBar.dot().getStyleClass().isEmpty()) {
            failures.add("status dot has no style class");
        }
        if (!stage.isShowing()) {
            failures.add("stage is not showing");
        }
        if (titleBar.statusTextWidth() + 0.5 < titleBar.statusPrefWidth()) {
            failures.add("status pill clips its text (" + Math.round(titleBar.statusTextWidth())
                    + " < " + Math.round(titleBar.statusPrefWidth()) + ")");
        }
        String aboutText = textOf(AboutDialog.build(model.jarPath));
        if (!aboutText.contains("bytecode protection suite")) {
            failures.add("About window does not introduce the product");
        }
        if (!aboutText.contains("PROTECTION LAYERS")) {
            failures.add("About window lists no protection layers");
        }
        return failures;
    }
}
