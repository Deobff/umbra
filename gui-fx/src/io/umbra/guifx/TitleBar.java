package io.umbra.guifx;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.stage.Stage;

/**
 * Self-drawn window chrome, modelled on the vfx window header: the application
 * mark and title on the left, the run status pill in the middle-right, and the
 * three window buttons on the right.
 *
 * <p>Details that matter and are easy to miss:</p>
 * <ul>
 *   <li>dragging anywhere on the bar moves the window (an undecorated stage has
 *       no native drag),</li>
 *   <li>double-click toggles maximize,</li>
 *   <li>the buttons light up in their own signal colour on hover — close red,
 *       maximize green, minimize amber — the same mapping vfx uses, so the
 *       destructive action is the only red thing in the window,</li>
 *   <li>maximize flips to "restore" while the window is maximized.</li>
 * </ul>
 */
final class TitleBar extends HBox {

    private final Stage stage;
    private final Label maximize = new Label("□");
    private final Region statusDot = new Region();
    private final Label status = new Label("ready");
    private Runnable onAbout;

    private double dragX;
    private double dragY;

    /** Called when the About button is pressed. */
    void setOnAbout(Runnable onAbout) {
        this.onAbout = onAbout;
    }

    TitleBar(Stage stage, String version) {
        this.stage = stage;
        getStyleClass().add("ux-titlebar");
        setAlignment(Pos.CENTER_LEFT);
        setSpacing(10);
        setPadding(new Insets(0, 10, 0, 14));

        Label mark = new Label("U");
        mark.getStyleClass().add("ux-brand-mark");
        Label name = new Label("UMBRA");
        name.getStyleClass().add("ux-brand");
        Label caption = new Label(version);
        caption.getStyleClass().add("ux-version");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        status.getStyleClass().add("ux-status");
        statusDot.getStyleClass().addAll("ux-dot", "ux-dot-idle");
        HBox pill = new HBox(7, statusDot, status);
        pill.setAlignment(Pos.CENTER_LEFT);
        pill.getStyleClass().add("ux-pill");
        // The pill must keep its full width: an HBox under pressure shrinks it and
        // the label then clips to something like "rd" instead of "ready".
        pill.setMinWidth(Region.USE_PREF_SIZE);
        status.setMinWidth(Region.USE_PREF_SIZE);
        statusDot.setMinWidth(7);
        statusDot.setMinHeight(7);

        Label about = windowButton("?", "ux-winbtn-about");
        about.setOnMouseClicked(event -> {
            if (onAbout != null) {
                onAbout.run();
            }
        });
        Label minimize = windowButton("–", "ux-winbtn-min");
        minimize.setOnMouseClicked(event -> stage.setIconified(true));
        maximize.getStyleClass().addAll("ux-winbtn", "ux-winbtn-max");
        maximize.setOnMouseClicked(event -> toggleMaximize());
        Label close = windowButton("×", "ux-winbtn-close");
        close.setOnMouseClicked(event -> stage.close());

        getChildren().addAll(mark, name, caption, spacer, pill, about,
                minimize, maximize, close);

        setOnMousePressed(event -> {
            dragX = event.getScreenX() - stage.getX();
            dragY = event.getScreenY() - stage.getY();
        });
        setOnMouseDragged(event -> {
            if (stage.isMaximized() || event.getTarget() instanceof Label
                    && ((Label) event.getTarget()).getStyleClass().contains("ux-winbtn")) {
                return;
            }
            stage.setX(event.getScreenX() - dragX);
            stage.setY(event.getScreenY() - dragY);
        });
        setOnMouseClicked(event -> {
            if (event.getClickCount() == 2
                    && !(event.getTarget() instanceof Label
                    && ((Label) event.getTarget()).getStyleClass().contains("ux-winbtn"))) {
                toggleMaximize();
            }
        });
    }

    private void toggleMaximize() {
        boolean maximizeNow = !stage.isMaximized();
        stage.setMaximized(maximizeNow);
        maximize.setText(maximizeNow ? "❐" : "□");
    }

    private static Label windowButton(String glyph, String extraClass) {
        Label button = new Label(glyph);
        button.getStyleClass().addAll("ux-winbtn", extraClass);
        return button;
    }

    /** Sets the pill text and signal colour; the dot pulses once per change. */
    void setStatus(String text, String kind) {
        status.setText(text);
        statusDot.getStyleClass().setAll("ux-dot", "ux-dot-" + kind);
        Motion.pulse(statusDot);
    }

    Region dot() {
        return statusDot;
    }

    /** Rendered width of the status text (used by the headless self-check). */
    double statusTextWidth() {
        return status.getWidth();
    }

    /** Width the status text needs, so the check can prove it is not clipped. */
    double statusPrefWidth() {
        return status.prefWidth(-1);
    }
}
