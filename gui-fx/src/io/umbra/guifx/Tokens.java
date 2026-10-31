package io.umbra.guifx;

import javafx.scene.paint.Color;

/**
 * Design tokens for the console shell.
 *
 * <p>Single source of truth for everything that is painted from Java instead of
 * from the stylesheet: the window fill, the status dot colours and the two
 * canvas gradients. The stylesheet {@code umbra-fx.css} repeats the same values
 * as literals (JavaFX 8 has no CSS custom properties); when a token changes,
 * change both — the class names below mirror the CSS sections so the pair is
 * easy to keep in sync.</p>
 *
 * <p>Ramp: graphite, adapted from the vfx dark theme, one accent, one success,
 * one warning, one danger. Nothing else is allowed to carry colour.</p>
 */
final class Tokens {

    /** Window background: the deepest surface. */
    static final Color CANVAS = Color.web("#171b1e");
    /** Chrome: header, rail, action bar. */
    static final Color PANEL = Color.web("#1b2024");
    /** Cards, inputs, selected segments. */
    static final Color RAISED = Color.web("#24292e");
    /** Pointer hover on neutral surfaces. */
    static final Color HOVER = Color.web("#2b3237");
    /** Hairline borders. */
    static final Color STROKE = Color.web("#2e363b");
    /** Emphasised borders and dividers. */
    static final Color STROKE_STRONG = Color.web("#46505a");
    /** Primary text. */
    static final Color TEXT = Color.web("#ececec");
    /** Secondary text. */
    static final Color TEXT_2 = Color.web("#a9b3ba");
    /** Captions and hints. */
    static final Color TEXT_3 = Color.web("#7d878e");
    /** The single accent: actions and selection only. */
    static final Color ACCENT = Color.web("#4d6ebe");
    /** Accent hover. */
    static final Color ACCENT_HI = Color.web("#5d81d4");
    /** Accent press. */
    static final Color ACCENT_LO = Color.web("#3d5998");
    /** Success signal. */
    static final Color OK = Color.web("#59b655");
    /** Warning signal. */
    static final Color WARN = Color.web("#d8a23a");
    /** Failure signal. */
    static final Color DANGER = Color.web("#d1584f");

    /** Base corner radius for controls. */
    static final double RADIUS_CONTROL = 10;
    /** Corner radius for cards and panels. */
    static final double RADIUS_CARD = 14;
    /** Rail width in pixels. */
    static final double RAIL_WIDTH = 268;

    private Tokens() {
    }

    /** Colour of the status dot for a state name ({@code idle|busy|ok|err}). */
    static Color stateColor(String kind) {
        if ("busy".equals(kind)) {
            return ACCENT;
        }
        if ("ok".equals(kind)) {
            return OK;
        }
        if ("err".equals(kind)) {
            return DANGER;
        }
        return TEXT_3;
    }
}
