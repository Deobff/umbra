package io.umbra.gui.ui;

import io.umbra.gui.GuiModeOptions;
import io.umbra.gui.theme.Tokens;

import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.awt.geom.Ellipse2D;
import java.awt.geom.RoundRectangle2D;
import java.util.Locale;

/**
 * Custom-painted slider for integer mode options.
 *
 * <p>Rounded track with an accent filled portion and a white thumb with a subtle
 * accent glow, in the same paper/serif language as the rest of the sheet. The
 * thumb and fill ease toward the target value in a 160 ms animation driven by
 * {@link Animation}; drags update the value immediately so the control never
 * feels sticky. Click/drag, mouse wheel, arrow keys, Home/End, tooltip and
 * focus ring are supported; range/step come from the option spec.</p>
 */
public final class SliderControl extends JComponent {

    /** Receives the new integer value after a user edit. */
    public interface Listener {
        void valueChanged(int value);
    }

    private final GuiModeOptions.Spec spec;
    private int value;
    private float displayed;
    private boolean dragging;
    private boolean suppressCallback;
    private Listener listener;
    private Animation.Handle animation;
    private float hover;

    public SliderControl(GuiModeOptions.Spec spec, int initialValue) {
        this.spec = spec;
        this.value = clamp(align(initialValue));
        this.displayed = fraction(this.value);
        setOpaque(false);
        setFocusable(true);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setPreferredSize(new Dimension(320, 28));
        setMinimumSize(new Dimension(180, 26));
        setToolTipText(spec.label + " (" + spec.min + ".." + spec.max
                + ", step " + Math.max(1, spec.step) + ")");
        getAccessibleContext().setAccessibleName(spec.label);
        getAccessibleContext().setAccessibleDescription(
                "Slider from " + spec.min + " to " + spec.max
                        + "; current value " + value);
        addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (!isEnabled()) {
                    return;
                }
                requestFocusInWindow();
                dragging = true;
                setTargetValue(valueAt(e.getX()), true, false);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (!dragging) {
                    return;
                }
                dragging = false;
                setTargetValue(valueAt(e.getX()), true, false);
                animateTo(fraction(value));
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                startHover(1f);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                startHover(0f);
            }
        });
        addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            @Override
            public void mouseDragged(MouseEvent e) {
                if (dragging && isEnabled()) {
                    setTargetValue(valueAt(e.getX()), true, false);
                }
            }
        });
        addMouseWheelListener(new MouseWheelListener() {
            @Override
            public void mouseWheelMoved(MouseWheelEvent e) {
                if (!isEnabled()) {
                    return;
                }
                int step = Math.max(1, spec.step);
                int direction = e.getWheelRotation() > 0 ? -1 : 1;
                setTargetValue(clamp(value + direction * step), true, true);
            }
        });
        addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                repaint();
            }

            @Override
            public void focusLost(FocusEvent e) {
                repaint();
            }
        });
        installKeys();
    }

    private void installKeys() {
        bind("LEFT", new Runnable() {
            @Override
            public void run() {
                stepBy(-1);
            }
        });
        bind("DOWN", new Runnable() {
            @Override
            public void run() {
                stepBy(-1);
            }
        });
        bind("RIGHT", new Runnable() {
            @Override
            public void run() {
                stepBy(1);
            }
        });
        bind("UP", new Runnable() {
            @Override
            public void run() {
                stepBy(1);
            }
        });
        bind("PAGE_DOWN", new Runnable() {
            @Override
            public void run() {
                stepBy(-5);
            }
        });
        bind("PAGE_UP", new Runnable() {
            @Override
            public void run() {
                stepBy(5);
            }
        });
        bind("HOME", new Runnable() {
            @Override
            public void run() {
                setTargetValue(spec.min, true, true);
            }
        });
        bind("END", new Runnable() {
            @Override
            public void run() {
                setTargetValue(spec.max, true, true);
            }
        });
    }

    private void bind(String key, final Runnable action) {
        final String name = "umbra.slider." + key;
        getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(key), name);
        getActionMap().put(name, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (isEnabled()) {
                    action.run();
                }
            }
        });
    }

    private void stepBy(int steps) {
        setTargetValue(clamp(value + steps * Math.max(1, spec.step)), true, true);
    }

    @Override
    public javax.accessibility.AccessibleContext getAccessibleContext() {
        if (accessibleContext == null) {
            accessibleContext = new AccessibleJComponent() {
                // Default context for this custom-painted slider.
            };
            accessibleContext.setAccessibleName(spec.label);
            accessibleContext.setAccessibleDescription(
                    "Slider from " + spec.min + " to " + spec.max);
        }
        return accessibleContext;
    }
    /* ------------------------------------------------------------- queries */

    public int value() {
        return value;
    }

    /** Visual thumb position as a 0..1 fraction of the track. */
    public float displayedProgress() {
        return displayed;
    }

    /** Current value as a 0..1 fraction (test/debug helper). */
    public float valueFraction() {
        return fraction(value);
    }

    public GuiModeOptions.Spec spec() {
        return spec;
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    /** Track rectangle in local coordinates (used by simulated input in tests). */
    public Rectangle trackBounds() {
        int width = getWidth();
        int height = getHeight();
        return new Rectangle(TRACK_LEFT, (height - TRACK_HEIGHT) / 2,
                Math.max(10, width - TRACK_RIGHT_PADDING - TRACK_LEFT), TRACK_HEIGHT);
    }

    /**
     * Updates the value without firing the user callback (mode defaults /
     * Reset / YAML refresh). Repaints immediately when animations are off.
     */
    public void setValueExternal(String valueText) {
        int parsed;
        try {
            parsed = Integer.parseInt(valueText == null ? "" : valueText.trim());
        } catch (NumberFormatException e) {
            parsed = Integer.parseInt(spec.defaultValue);
        }
        suppressCallback = true;
        try {
            setTargetValue(parsed, false, true);
        } finally {
            suppressCallback = false;
        }
    }

    /** Deterministic thumb position for offscreen screenshots (0..1 fraction). */
    public void setDisplayedProgressForScreenshot(float progress) {
        if (animation != null) {
            animation.stop();
            animation = null;
        }
        displayed = Math.max(0f, Math.min(1f, progress));
        repaint();
    }

    /* ------------------------------------------------------------ internals */

    private static final int TRACK_LEFT = 4;
    private static final int TRACK_RIGHT_PADDING = 54;
    private static final int TRACK_HEIGHT = 6;
    private static final int THUMB = 14;

    private void setTargetValue(int rawValue, boolean fireCallback, boolean animate) {
        int next = clamp(align(rawValue));
        if (next == value) {
            if (!animate) {
                displayed = fraction(value);
                repaint();
            }
            return;
        }
        value = next;
        getAccessibleContext().setAccessibleDescription(
                "Slider from " + spec.min + " to " + spec.max
                        + "; current value " + value);
        if (animate) {
            animateTo(fraction(value));
        } else {
            displayed = fraction(value);
            if (animation != null) {
                animation.stop();
                animation = null;
            }
            repaint();
        }
        if (fireCallback && !suppressCallback && listener != null) {
            listener.valueChanged(value);
        }
    }

    private void animateTo(final float target) {
        if (animation != null) {
            animation.stop();
            animation = null;
        }
        final float from = displayed;
        if (Math.abs(target - from) < 0.0005f) {
            displayed = target;
            repaint();
            return;
        }
        animation = Animation.animate(this, 160, new Animation.Frame() {
            @Override
            public void frame(float eased) {
                displayed = from + (target - from) * eased;
                repaint();
            }
        });
    }

    private void startHover(final float target) {
        final float from = hover;
        Animation.animate(this, 140, new Animation.Frame() {
            @Override
            public void frame(float eased) {
                hover = from + (target - from) * eased;
                repaint();
            }
        });
    }

    private int clamp(int raw) {
        return Math.max(spec.min, Math.min(spec.max, raw));
    }

    private int align(int raw) {
        int step = Math.max(1, spec.step);
        int clamped = clamp(raw);
        int steps = Math.round((clamped - spec.min) / (float) step);
        return clamp(spec.min + steps * step);
    }

    private int valueAt(int mouseX) {
        Rectangle track = trackBounds();
        float frac = (mouseX - track.x) / (float) Math.max(1, track.width);
        frac = Math.max(0f, Math.min(1f, frac));
        return align(spec.min + Math.round(frac * (spec.max - spec.min)));
    }

    private float fraction(int v) {
        int range = Math.max(1, spec.max - spec.min);
        return Math.max(0f, Math.min(1f, (v - spec.min) / (float) range));
    }

    @Override
    public String getToolTipText(MouseEvent event) {
        return spec.label + " (" + spec.min + ".." + spec.max
                + ", step " + Math.max(1, spec.step) + ")";
    }

    @Override
    public String toString() {
        return "SliderControl[" + spec.id + "=" + value + "]";
    }

    /* --------------------------------------------------------------- paint */

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();
            Rectangle track = trackBounds();
            float radius = TRACK_HEIGHT / 2f;

            // Track wash + accent filled portion.
            g.setColor(new Color(0, 0, 0, 16 + Math.round(hover * 10f)));
            g.fill(new RoundRectangle2D.Float(track.x, track.y, track.width,
                    track.height, TRACK_HEIGHT, TRACK_HEIGHT));
            int fillWidth = Math.round(track.width * displayed);
            if (fillWidth > 0) {
                g.setColor(Tokens.alpha(Tokens.ACCENT, 0.82f));
                g.fill(new RoundRectangle2D.Float(track.x, track.y, fillWidth,
                        track.height, TRACK_HEIGHT, TRACK_HEIGHT));
            }

            // Thumb with subtle accent glow (no drop shadows).
            float thumbCenter = track.x + track.width * displayed;
            float thumbX = thumbCenter - THUMB / 2f;
            float thumbY = (h - THUMB) / 2f;
            g.setColor(Tokens.alpha(Tokens.ACCENT, 0.16f + 0.10f * hover));
            g.fill(new Ellipse2D.Float(thumbCenter - THUMB, (h - THUMB * 2) / 2f,
                    THUMB * 2f, THUMB * 2f));
            g.setColor(new Color(255, 255, 255, 252));
            g.fill(new Ellipse2D.Float(thumbX, thumbY, THUMB, THUMB));
            g.setColor(Tokens.LINE_STRONG);
            g.setStroke(new BasicStroke(1f));
            g.draw(new Ellipse2D.Float(thumbX + 0.5f, thumbY + 0.5f,
                    THUMB - 1f, THUMB - 1f));

            // Numeric value, right aligned and tabular-ish mono.
            String text = String.valueOf(value);
            Font font = Tokens.mono(12.5f);
            FontMetrics metrics = g.getFontMetrics(font);
            float textX = w - 44f + (44f - metrics.stringWidth(text)) / 2f;
            float baseline = (h - metrics.getHeight()) / 2f + metrics.getAscent();
            Tokens.drawText(g, text, font, Tokens.FG, textX, baseline, 0f);

            if (isFocusOwner()) {
                g.setColor(Tokens.alpha(Tokens.ACCENT, 0.85f));
                g.setStroke(new BasicStroke(2f));
                g.draw(new RoundRectangle2D.Float(1f, 1f, w - 2f, h - 2f,
                        radius * 2f + 8f, radius * 2f + 8f));
            }
            if (!isEnabled()) {
                g.setColor(Tokens.alpha(Tokens.CANVAS, 0.55f));
                g.fillRoundRect(0, 0, w, h, 10, 10);
            }
        } finally {
            g.dispose();
        }
    }

    @Override
    public String getName() {
        return spec.id;
    }

    /** Short label used by debug tools and tests. */
    public String label() {
        return spec.label;
    }

    /** Locale-safe number formatting hook kept for future decimal specs. */
    public String formatValue() {
        return String.format(Locale.ROOT, "%d", Integer.valueOf(value));
    }
}
