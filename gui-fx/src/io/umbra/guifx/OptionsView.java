package io.umbra.guifx;

import io.umbra.gui.GuiModeOptions;
import io.umbra.gui.GuiSwitches;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Slider;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * One configuration group, rendered as a card of rows.
 *
 * <p>A row is a label (plus its engine key as a hint) on the left and the control
 * on the right, so scanning down the card gives a column of labels and a column
 * of controls instead of a ragged grid. Every rebuild cascades the rows in over
 * ~180 ms; the rows are new nodes each time, so there is nothing to reuse.</p>
 */
final class OptionsView {

    private final ConsoleModel model;
    private final VBox card = new VBox(0);
    private final Label title = new Label();
    private final Label meta = new Label();
    private final VBox rows = new VBox(0);
    private final ScrollPane scroll = new ScrollPane();

    private Runnable onChange = () -> { };
    private String current;
    private final java.util.List<String> issues = new java.util.ArrayList<String>();

    OptionsView(ConsoleModel model) {
        this.model = model;
        title.getStyleClass().add("ux-card-title");
        meta.getStyleClass().add("ux-card-meta");
        HBox head = new HBox(10, title, meta);
        head.setAlignment(Pos.BASELINE_LEFT);
        head.getStyleClass().add("ux-card-head");
        VBox body = new VBox(0, head, rows);
        body.setPadding(new Insets(4, 4, 4, 4));
        card.getStyleClass().add("ux-card");
        card.getChildren().add(body);
        scroll.setContent(card);
        scroll.setFitToWidth(true);
        scroll.getStyleClass().add("ux-scroll");
        scroll.setPadding(new Insets(0, 2, 0, 0));
        // Pin the card to the viewport width. Without this the first layout pass
        // measures the content at its preferred width, and a Slider whose skin ran
        // layoutChildren at that width keeps a track that wide forever — the track
        // then paints underneath the value readout.
        card.maxWidthProperty().bind(scroll.widthProperty().subtract(24));
        card.prefWidthProperty().bind(scroll.widthProperty().subtract(24));
    }

    Node node() {
        return scroll;
    }

    void setOnChange(Runnable onChange) {
        this.onChange = onChange == null ? () -> { } : onChange;
    }

    String currentGroup() {
        return current;
    }

    /** Rebuilds the card for {@code groupTitle}. */
    void show(String groupTitle) {
        if (groupTitle == null) {
            return;
        }
        current = groupTitle;
        title.setText(groupTitle);
        rows.getChildren().clear();
        Set<String> specKeys = model.specKeys();
        int toggles = 0;
        int specs = 0;
        for (GuiSwitches.GroupDef group : GuiSwitches.groups()) {
            if (!group.title.equals(groupTitle)) {
                continue;
            }
            for (GuiSwitches.Toggle toggle : group.toggles) {
                if (toggle.key != null && specKeys.contains(toggle.key)) {
                    continue;
                }
                CheckBox box = new CheckBox();
                box.setSelected(Boolean.TRUE.equals(model.toggles.get(toggle.id)));
                box.selectedProperty().addListener((obs, old, next) -> {
                    model.toggles.put(toggle.id, next);
                    onChange.run();
                });
                rows.getChildren().add(row(toggle.label, toggle.key, box));
                toggles++;
            }
        }
        for (GuiModeOptions.Group group : GuiModeOptions.groups()) {
            if (!group.title.equals(groupTitle)) {
                continue;
            }
            for (GuiModeOptions.Spec spec : group.specs) {
                if (spec.uiOnly()) {
                    // These drive the front end itself (verify / seed / mapping) and
                    // carry no engine key; the real controls live in the target bar,
                    // so rendering them here would be a dead switch.
                    continue;
                }
                rows.getChildren().add(row(spec.label, spec.hint, control(spec)));
                specs++;
            }
        }
        meta.setText(toggles + " switches · " + specs + " values");
        List<Node> animated = new ArrayList<Node>(rows.getChildren());
        for (int i = 0; i < animated.size(); i++) {
            Motion.rise(animated.get(i), i);
        }
    }

    /** Re-renders the current group (after a preset load). */
    void refresh() {
        if (current != null) {
            show(current);
        }
    }

    /** Value/control mismatches found while rendering; empty when everything lines up. */
    java.util.List<String> issues() {
        return issues;
    }

    void clearIssues() {
        issues.clear();
    }

    /** Number of rendered rows for the current group. */
    int rowCount() {
        return rows.getChildren().size();
    }

    /** Rendered row nodes, in display order (layout auditing). */
    java.util.List<Node> renderedRows() {
        return new java.util.ArrayList<Node>(rows.getChildren());
    }

    /** Width available to a row, after the stylesheet and one layout pass. */
    double availableWidth() {
        return card.getWidth() - 8;
    }

    /**
     * Measures the rendered rows after a layout pass and reports geometry that
     * reads as broken: a control wider than its row, a control pushed outside the
     * row's bounds, or a label overlapping its control (the "text inside the
     * slider" case).
     *
     * <p>Coordinates are taken from {@code boundsInParent} because both nodes share
     * the row as parent; scene coordinates depend on the whole scroll pane being
     * laid out and silently lie when it is not.</p>
     */
    java.util.List<String> layoutIssues() {
        java.util.List<String> found = new java.util.ArrayList<String>();
        for (Node row : rows.getChildren()) {
            if (!(row instanceof HBox)) {
                continue;
            }
            HBox box = (HBox) row;
            if (box.getChildren().size() < 3) {
                continue;
            }
            Node text = box.getChildren().get(0);
            Node control = box.getChildren().get(box.getChildren().size() - 1);
            double rowWidth = box.getWidth();
            // Preferred-width arithmetic is layout-independent and is what the row
            // actually needs; the bounds below can be stale when the scroll pane has
            // not been resized to its viewport yet, so they are only consulted when
            // the row was laid out at a plausible width.
            double labelPref = text.prefWidth(-1);
            double controlPref = control.prefWidth(-1);
            double needed = labelPref + controlPref + box.getSpacing();
            if (needed > rowWidth + 1) {
                found.add(current + ": row needs " + Math.round(needed) + "px but has "
                        + Math.round(rowWidth) + "px (" + labelOf(text) + ": label "
                        + Math.round(labelPref) + " + control " + Math.round(controlPref) + ")");
            }
            double controlWidth = control.getBoundsInParent().getWidth();
            if (controlWidth <= rowWidth * 2) {
                javafx.geometry.Bounds labelBounds = text.getBoundsInParent();
                javafx.geometry.Bounds controlBounds = control.getBoundsInParent();
                if (labelBounds.intersects(controlBounds)) {
                    found.add(current + ": label overlaps its control (" + labelOf(text) + ")"
                            + " [label=" + Math.round(labelBounds.getWidth()) + "@"
                            + Math.round(labelBounds.getMinX())
                            + " control=" + Math.round(controlBounds.getWidth()) + "@"
                            + Math.round(controlBounds.getMinX()) + "]");
                }
                if (controlBounds.getMaxX() > rowWidth + 1) {
                    found.add(current + ": control overflows the row by "
                            + Math.round(controlBounds.getMaxX() - rowWidth) + "px ("
                            + labelOf(text) + ")");
                }
            }
        }
        return found;
    }

    private static String labelOf(Node node) {
        if (node instanceof Label) {
            return ((Label) node).getText();
        }
        if (node instanceof VBox && !((VBox) node).getChildren().isEmpty()) {
            return labelOf(((VBox) node).getChildren().get(0));
        }
        return node.getClass().getSimpleName();
    }

    /**
     * Scene-space rectangles of every slider and its value readout in the current
     * group, one line per row: {@code <label> slider=x,y,w,h readout=x,y,w,h}.
     * Used by the pixel check that proves the readout is not drawn on the track.
     */
    java.util.List<String> sliderGeometry() {
        java.util.List<String> out = new java.util.ArrayList<String>();
        for (Node row : rows.getChildren()) {
            if (!(row instanceof HBox)) {
                continue;
            }
            HBox box = (HBox) row;
            if (box.getChildren().size() < 3) {
                continue;
            }
            Node control = box.getChildren().get(box.getChildren().size() - 1);
            if (!(control instanceof GridPane)) {
                continue;
            }
            GridPane pair = (GridPane) control;
            if (pair.getChildren().size() < 2 || !(pair.getChildren().get(0) instanceof Slider)) {
                continue;
            }
            Node slider = pair.getChildren().get(0);
            Node readout = pair.getChildren().get(1);
            javafx.geometry.Bounds s = slider.localToScene(slider.getLayoutBounds());
            javafx.geometry.Bounds r = readout.localToScene(readout.getLayoutBounds());
            out.add(labelOf(box.getChildren().get(0))
                    + " sliderScene=" + Math.round(s.getMinX()) + "," + Math.round(s.getMinY())
                    + "," + Math.round(s.getWidth()) + "," + Math.round(s.getHeight())
                    + " readoutScene=" + Math.round(r.getMinX()) + "," + Math.round(r.getMinY())
                    + "," + Math.round(r.getWidth()) + "," + Math.round(r.getHeight()));
        }
        return out;
    }

    private Node row(String label, String hint, Node control) {
        Label name = new Label(label);
        name.getStyleClass().add("ux-row-label");
        VBox text = new VBox(1, name);
        if (hint != null && !hint.isEmpty()) {
            Label sub = new Label(hint);
            sub.getStyleClass().add("ux-row-hint");
            text.getChildren().add(sub);
            name.setTooltip(new Tooltip(hint));
        }
        // The label column is bounded and the control keeps its preferred width:
        // without the two bounds HBox shrinks both under pressure and the value
        // readout ends up drawn on top of the slider track.
        text.setMaxWidth(420);
        text.setMinWidth(0);
        HBox.setHgrow(text, Priority.NEVER);
        if (control instanceof Region) {
            ((Region) control).setMinWidth(Region.USE_PREF_SIZE);
        }
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        HBox row = new HBox(12, text, spacer, control);
        row.setAlignment(Pos.CENTER_LEFT);
        row.setPadding(new Insets(8, 12, 8, 12));
        row.getStyleClass().add("ux-row");
        return row;
    }

    private Node control(GuiModeOptions.Spec spec) {
        String raw = model.specs.get(spec.id);
        if (spec.kind == GuiModeOptions.Kind.BOOL) {
            Boolean parsed = parseBool(raw);
            if (parsed == null) {
                issues.add(spec.id + ": bool value '" + raw + "' is not a boolean");
                parsed = Boolean.FALSE;
            }
            CheckBox box = new CheckBox();
            box.setSelected(parsed.booleanValue());
            box.selectedProperty().addListener((obs, old, next) -> {
                model.specs.put(spec.id, String.valueOf(next));
                onChange.run();
            });
            return box;
        }
        if (spec.kind == GuiModeOptions.Kind.INT) {
            int value = parseInt(raw, spec.defaultValue, spec.min, spec.max);
            if (raw != null && !raw.trim().isEmpty() && !raw.trim().equals(String.valueOf(value))) {
                issues.add(spec.id + ": int value '" + raw + "' clamped to " + value
                        + " (range " + spec.min + ".." + spec.max + ")");
            }
            Slider slider = new Slider(spec.min, spec.max, value);
            // The hard maximum is the important one: a Region reports MAX_VALUE for
            // its max width, so an HBox happily stretches a slider across the whole
            // row and the readout then sits on top of the track.
            slider.setPrefWidth(200);
            slider.setMinWidth(140);
            slider.setMaxWidth(200);
            // Belt and braces: the JavaFX 8 slider skin can lay its track out wider
            // than the control (it keeps the width from an earlier layout pass), and
            // the track then paints underneath the neighbouring readout. Clipping to
            // the control bounds makes that impossible regardless of the skin.
            javafx.scene.shape.Rectangle clip = new javafx.scene.shape.Rectangle();
            clip.widthProperty().bind(slider.widthProperty());
            clip.heightProperty().bind(slider.heightProperty());
            slider.setClip(clip);
            slider.setBlockIncrement(spec.step > 0 ? spec.step : 1);
            if (spec.max > spec.min) {
                slider.setMajorTickUnit(Math.max(1, (spec.max - spec.min) / 5.0));
            }
            Label readout = new Label(String.valueOf(value));
            readout.getStyleClass().add("ux-value");
            readout.setMinWidth(46);
            readout.setPrefWidth(46);
            readout.setMaxWidth(46);
            readout.setAlignment(Pos.CENTER_RIGHT);
            slider.valueProperty().addListener((obs, old, next) -> {
                int current = (int) Math.round(next.doubleValue());
                if (spec.step > 1) {
                    int snapped = spec.min + Math.round((current - spec.min) / (float) spec.step) * spec.step;
                    current = Math.max(spec.min, Math.min(spec.max, snapped));
                }
                readout.setText(String.valueOf(current));
                model.specs.put(spec.id, String.valueOf(current));
                onChange.run();
            });
            // GridPane instead of HBox: two columns with fixed widths cannot overlap
            // each other, while an HBox happily squeezes a child under pressure and
            // paints the readout on top of the track.
            GridPane pair = new GridPane();
            pair.setHgap(10);
            pair.setAlignment(Pos.CENTER_LEFT);
            ColumnConstraints sliderColumn = new ColumnConstraints();
            sliderColumn.setMinWidth(140);
            sliderColumn.setPrefWidth(200);
            sliderColumn.setMaxWidth(200);
            sliderColumn.setHgrow(Priority.ALWAYS);
            ColumnConstraints readoutColumn = new ColumnConstraints();
            readoutColumn.setMinWidth(46);
            readoutColumn.setPrefWidth(46);
            readoutColumn.setMaxWidth(46);
            pair.getColumnConstraints().addAll(sliderColumn, readoutColumn);
            pair.add(slider, 0, 0);
            pair.add(readout, 1, 0);
            pair.setMinWidth(Region.USE_PREF_SIZE);
            pair.setMaxWidth(270);
            return pair;
        }
        if (spec.kind == GuiModeOptions.Kind.ENUM && spec.values != null && !spec.values.isEmpty()) {
            ChoiceBox<String> choice = new ChoiceBox<String>();
            choice.getItems().addAll(spec.values);
            String value = raw == null || raw.trim().isEmpty() ? spec.defaultValue : raw.trim();
            if (value != null && !value.isEmpty() && !spec.values.contains(value)) {
                // A preset can name a value the control model does not list; showing it
                // keeps the control truthful instead of rendering an empty box.
                choice.getItems().add(value);
                issues.add(spec.id + ": enum value '" + value + "' is not in the declared list");
            }
            choice.setValue(value);
            choice.setPrefWidth(180);
            choice.valueProperty().addListener((obs, old, next) -> {
                model.specs.put(spec.id, next);
                onChange.run();
            });
            return choice;
        }
        TextField field = new TextField(raw == null ? "" : raw);
        field.setPrefWidth(220);
        field.getStyleClass().add("ux-field");
        field.textProperty().addListener((obs, old, next) -> {
            model.specs.put(spec.id, next);
            onChange.run();
        });
        return field;
    }

    /** {@code true/false/1/0/on/off/yes/no} in any case; {@code null} when unknown. */
    private static Boolean parseBool(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        String v = value.trim().toLowerCase(java.util.Locale.ROOT);
        if ("true".equals(v) || "1".equals(v) || "on".equals(v) || "yes".equals(v)) {
            return Boolean.TRUE;
        }
        if ("false".equals(v) || "0".equals(v) || "off".equals(v) || "no".equals(v)) {
            return Boolean.FALSE;
        }
        return null;
    }

    private static int parseInt(String value, String fallback, int min, int max) {
        int parsed;
        try {
            parsed = Integer.parseInt(value == null || value.trim().isEmpty() ? fallback : value.trim());
        } catch (NumberFormatException ignored) {
            parsed = min;
        }
        return Math.max(min, Math.min(max, parsed));
    }
}
