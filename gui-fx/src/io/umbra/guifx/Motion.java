package io.umbra.guifx;

import javafx.animation.FadeTransition;
import javafx.animation.Interpolator;
import javafx.animation.ParallelTransition;
import javafx.animation.ScaleTransition;
import javafx.animation.TranslateTransition;
import javafx.scene.Node;
import javafx.scene.control.ButtonBase;
import javafx.util.Duration;

/**
 * Motion primitives for the console shell.
 *
 * <p>Frequency decides everything here. The tree, the segments and the action
 * buttons are used tens of times a day or are keyboard reachable, so they get no
 * entrance animation; only a 0.97 press scale for pointer feedback. Content that
 * swaps in place (a different group, a different view) gets a 160 ms fade so it
 * does not teleport, and rows cascade in once per rebuild. The window itself
 * enters once per launch and is the only place with a slightly longer budget.</p>
 *
 * <p>Properties: opacity and transform only (no layout-triggering properties).
 * Curves: strong ease-out for entrances, strong ease-in-out for on-screen
 * movement. Budget: everything stays under 300 ms.</p>
 */
final class Motion {

    /** Strong ease-out, cubic-bezier(0.23, 1, 0.32, 1). */
    static final Interpolator EASE_OUT = Interpolator.SPLINE(0.23, 1, 0.32, 1);

    /** Strong ease-in-out, cubic-bezier(0.77, 0, 0.175, 1). */
    static final Interpolator EASE_IN_OUT = Interpolator.SPLINE(0.77, 0, 0.175, 1);

    /** Rows past this index reuse the last delay instead of accumulating more. */
    private static final int STAGGER_LIMIT = 8;

    private static final boolean REDUCED = Boolean.getBoolean("Dumbra.fx.reduceMotion")
            || Boolean.getBoolean("Dumbra.gui.reduceMotion")
            || "false".equalsIgnoreCase(System.getProperty("Dumbra.fx.animations"))
            || "false".equalsIgnoreCase(System.getProperty("Dumbra.gui.animations"));

    private Motion() {
    }

    static boolean reduced() {
        return REDUCED;
    }

    private static Duration ms(double millis) {
        return Duration.millis(REDUCED ? 0 : millis);
    }

    /** Pointer press feedback: 0.97 down, 1.0 up. Keyboard activation does not scale. */
    static void press(ButtonBase button) {
        if (REDUCED || button == null) {
            return;
        }
        button.setOnMousePressed(event -> scale(button, 0.97, 110));
        button.setOnMouseReleased(event -> scale(button, 1.0, 140));
        button.setOnMouseExited(event -> {
            if (!button.isPressed()) {
                scale(button, 1.0, 140);
            }
        });
    }

    private static void scale(Node node, double value, double millis) {
        ScaleTransition transition = new ScaleTransition(ms(millis), node);
        transition.setToX(value);
        transition.setToY(value);
        transition.setInterpolator(EASE_OUT);
        transition.play();
    }

    /** One row of a rebuilt list: 6 px rise plus fade, 30 ms between rows. */
    static void rise(Node node, int index) {
        if (node == null) {
            return;
        }
        node.setOpacity(REDUCED ? 1 : 0);
        node.setTranslateY(REDUCED ? 0 : 6);
        double delay = Math.min(index, STAGGER_LIMIT) * 30.0;
        FadeTransition fade = new FadeTransition(ms(180), node);
        fade.setFromValue(REDUCED ? 1 : 0);
        fade.setToValue(1);
        fade.setDelay(ms(delay));
        fade.setInterpolator(EASE_OUT);
        TranslateTransition slide = new TranslateTransition(ms(180), node);
        slide.setFromY(REDUCED ? 0 : 6);
        slide.setToY(0);
        slide.setDelay(ms(delay));
        slide.setInterpolator(EASE_OUT);
        new ParallelTransition(fade, slide).play();
    }

    /** Bridges an in-place content swap: fade in from 4 px below. */
    static void swap(Node node) {
        if (node == null) {
            return;
        }
        node.setOpacity(REDUCED ? 1 : 0.2);
        node.setTranslateY(REDUCED ? 0 : 4);
        FadeTransition fade = new FadeTransition(ms(160), node);
        fade.setToValue(1);
        fade.setInterpolator(EASE_OUT);
        TranslateTransition slide = new TranslateTransition(ms(160), node);
        slide.setToY(0);
        slide.setInterpolator(EASE_OUT);
        new ParallelTransition(fade, slide).play();
    }

    /** Window entrance: 0.985 -> 1 keeps a visible shape instead of growing from nothing. */
    static void entrance(Node node) {
        if (node == null) {
            return;
        }
        node.setOpacity(REDUCED ? 1 : 0);
        node.setScaleX(REDUCED ? 1 : 0.985);
        node.setScaleY(REDUCED ? 1 : 0.985);
        FadeTransition fade = new FadeTransition(ms(220), node);
        fade.setToValue(1);
        fade.setInterpolator(EASE_OUT);
        ScaleTransition grow = new ScaleTransition(ms(220), node);
        grow.setToX(1);
        grow.setToY(1);
        grow.setInterpolator(EASE_OUT);
        new ParallelTransition(fade, grow).play();
    }

    /** Confirms a state change on the status dot; no motion when reduced. */
    static void pulse(Node node) {
        if (node == null || REDUCED) {
            return;
        }
        ScaleTransition pulse = new ScaleTransition(ms(180), node);
        pulse.setFromX(1.4);
        pulse.setFromY(1.4);
        pulse.setToX(1);
        pulse.setToY(1);
        pulse.setInterpolator(EASE_OUT);
        pulse.play();
    }
}
