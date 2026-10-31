package io.umbra.guifx;

import javafx.animation.Interpolator;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.scene.control.Button;
import javafx.scene.layout.Border;
import javafx.scene.layout.BorderStroke;
import javafx.scene.layout.BorderStrokeStyle;
import javafx.scene.layout.BorderWidths;
import javafx.scene.layout.CornerRadii;
import javafx.scene.paint.Color;
import javafx.util.Duration;

/**
 * Button with the vfx "fusion" behaviour: the resting skin is a flat raised
 * rectangle with a hairline border, and on hover an accent border fades in over
 * 150 ms instead of the whole button changing colour.
 *
 * <p>Why animate the border instead of the background: the background lift alone
 * reads as a generic web button, while a border that lights up in the accent
 * colour is the cue vfx uses to say "this control is armed". The fade is short
 * because the button is pressed tens of times a day.</p>
 *
 * <p>Background, text colour and the pressed state stay in the stylesheet
 * ({@code .ux-fusion}), so a theme change does not have to touch this class.</p>
 */
class FusionButton extends Button {

    /** 0 = resting border, 1 = full accent border. */
    private final DoubleProperty heat = new SimpleDoubleProperty(0);
    private final Timeline fade = new Timeline();

    FusionButton(String text) {
        super(text);
        getStyleClass().add("ux-fusion");
        heat.addListener((obs, old, value) -> applyBorder(value.doubleValue()));
        applyBorder(0);
        setOnMouseEntered(event -> animate(1));
        setOnMouseExited(event -> animate(0));
        setFocusTraversable(true);
    }

    private void animate(double target) {
        fade.stop();
        fade.getKeyFrames().setAll(new KeyFrame(
                Duration.millis(Motion.reduced() ? 0 : 150),
                new KeyValue(heat, target, Interpolator.SPLINE(0.23, 1, 0.32, 1))));
        fade.play();
    }

    private void applyBorder(double amount) {
        Color stroke = Tokens.STROKE.interpolate(Tokens.ACCENT, Math.max(0, Math.min(1, amount)));
        setBorder(new Border(new BorderStroke(stroke, BorderStrokeStyle.SOLID,
                new CornerRadii(Tokens.RADIUS_CONTROL), new BorderWidths(1))));
    }
}
