package io.umbra.gui.ui;

import javax.swing.JComponent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Small shared hover/press transition state for custom-painted buttons.
 *
 * <p>Two eased values in {@code 0..1} are driven by the shared
 * {@link Animation} helper (150 ms hover, 120 ms press) and repaint only the
 * owning component. Buttons read {@link #hover()} and {@link #press()} while
 * painting instead of switching colours instantly.</p>
 */
final class HoverState extends MouseAdapter {

    private final JComponent owner;
    private float hover;
    private float press;
    private Animation.Handle hoverAnimation;
    private Animation.Handle pressAnimation;

    HoverState(JComponent owner) {
        this.owner = owner;
        owner.addMouseListener(this);
    }

    void install() {
        // Constructor wires the listener; method kept for call-site clarity.
    }

    float hover() {
        return hover;
    }

    float press() {
        return press;
    }

    @Override
    public void mouseEntered(MouseEvent e) {
        animateHover(1f);
    }

    @Override
    public void mouseExited(MouseEvent e) {
        animateHover(0f);
    }

    @Override
    public void mousePressed(MouseEvent e) {
        if (!owner.isEnabled()) {
            return;
        }
        animatePress(1f);
    }

    @Override
    public void mouseReleased(MouseEvent e) {
        animatePress(0f);
    }

    private void animateHover(final float target) {
        if (hoverAnimation != null) {
            hoverAnimation.stop();
        }
        final float from = hover;
        hoverAnimation = Animation.animate(owner, 150, new Animation.Frame() {
            @Override
            public void frame(float eased) {
                hover = from + (target - from) * eased;
                owner.repaint();
            }
        });
    }

    private void animatePress(final float target) {
        if (pressAnimation != null) {
            pressAnimation.stop();
        }
        final float from = press;
        pressAnimation = Animation.animate(owner, 120, new Animation.Frame() {
            @Override
            public void frame(float eased) {
                press = from + (target - from) * eased;
                owner.repaint();
            }
        });
    }
}
