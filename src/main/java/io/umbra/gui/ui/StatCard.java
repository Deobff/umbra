package io.umbra.gui.ui;

import io.umbra.gui.theme.Tokens;

import javax.swing.Timer;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * One of the four statistics cards on the right: a big serif number on top and
 * an uppercase 10px caption below, in a lighter glass card than the console.
 *
 * <p>Numbers count up over 800ms with an ease-out cubic when a run completes;
 * the first card turns success green at the same time. Before the first run the
 * card shows an em dash so the empty state still looks finished.</p>
 */
public class StatCard extends GlassPanel {

    /** How a numeric value is rendered. */
    public enum Format {
        INTEGER,
        DURATION
    }

    private final String label;
    private final Format format;
    private long target = -1L;
    private double displayed = 0d;
    private boolean hasValue;
    private boolean animations = true;
    private boolean emphasis;
    private float emphasisMix;
    private Timer countUp;
    private Timer emphasisTimer;

    public StatCard(String label, Format format) {
        super(GlassPanel.Variant.STAT, Tokens.RADIUS_CARD);
        this.label = label;
        this.format = format;
        getAccessibleContext().setAccessibleName(label);
        getAccessibleContext().setAccessibleDescription("Protection statistic: " + label);
    }

    public void setAnimationsEnabled(boolean enabled) {
        this.animations = enabled;
    }

    /** Shows the em dash so the idle layout is complete without fake numbers. */
    public void reset() {
        stopTimers();
        hasValue = false;
        target = -1L;
        displayed = 0d;
        emphasis = false;
        emphasisMix = 0f;
        repaint();
    }

    /** Animates the card to {@code value}; renders immediately when disabled. */
    public void setValue(long value) {
        target = Math.max(0L, value);
        if (!animations) {
            displayed = target;
            hasValue = true;
            repaint();
            return;
        }
        final double from = hasValue ? displayed : 0d;
        hasValue = true;
        stopCountUp();
        final long started = System.currentTimeMillis();
        countUp = new Timer(15, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                float t = Math.min(1f, (System.currentTimeMillis() - started) / 800f);
                displayed = from + (target - from) * Tokens.easeOut(t);
                repaint();
                if (t >= 1f) {
                    displayed = target;
                    stopCountUp();
                    repaint();
                }
            }
        });
        countUp.start();
    }

    /** Success colour for the classes card after a completed run. */
    public void setEmphasis(boolean value) {
        if (emphasis == value) {
            return;
        }
        emphasis = value;
        stopEmphasis();
        if (!animations) {
            emphasisMix = value ? 1f : 0f;
            repaint();
            return;
        }
        final float from = emphasisMix;
        final float to = value ? 1f : 0f;
        final long started = System.currentTimeMillis();
        emphasisTimer = new Timer(15, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                float t = Math.min(1f, (System.currentTimeMillis() - started) / 500f);
                emphasisMix = from + (to - from) * Tokens.easeOut(t);
                repaint();
                if (t >= 1f) {
                    emphasisMix = to;
                    stopEmphasis();
                    repaint();
                }
            }
        });
        emphasisTimer.start();
    }

    public boolean isEmphasized() {
        return emphasis;
    }

    public String displayText() {
        if (!hasValue) {
            return "\u2014";
        }
        long rounded = Math.round(displayed);
        return format == Format.DURATION ? Tokens.duration(rounded)
                : String.valueOf(rounded);
    }

    private void stopCountUp() {
        if (countUp != null) {
            countUp.stop();
            countUp = null;
        }
    }

    private void stopEmphasis() {
        if (emphasisTimer != null) {
            emphasisTimer.stop();
            emphasisTimer = null;
        }
    }

    private void stopTimers() {
        stopCountUp();
        stopEmphasis();
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        super.paintComponent(graphics);
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();
            String value = displayText();

            Font numberFont = Tokens.serifFor(value, Tokens.STAT_SIZE, Font.BOLD);
            FontMetrics numberMetrics = g.getFontMetrics(numberFont);
            Font capsFont = Tokens.serifBold(Tokens.CAPS_SIZE);
            FontMetrics capsMetrics = g.getFontMetrics(capsFont);
            float blockHeight = numberMetrics.getHeight() + 6f + capsMetrics.getHeight();
            float top = (h - blockHeight) / 2f;
            float numberBaseline = top + numberMetrics.getAscent();
            float capsBaseline = top + numberMetrics.getHeight() + 6f + capsMetrics.getAscent();

            Color numberColor = hasValue
                    ? Tokens.mix(Tokens.FG, Tokens.SUCCESS, emphasisMix)
                    : Tokens.FG3;
            Tokens.drawText(g, value, numberFont, numberColor, 20f, numberBaseline, -0.01f);
            // Long labels ("PROTECTED METHODS") are tightened just enough to
            // respect the 20px card padding instead of running to the edge.
            float tracking = 0.22f;
            float available = w - 40f;
            float labelWidth = Tokens.capsWidth(g, label, Tokens.CAPS_SIZE, tracking);
            while (labelWidth > available && tracking > 0.06f) {
                tracking -= 0.02f;
                labelWidth = Tokens.capsWidth(g, label, Tokens.CAPS_SIZE, tracking);
            }
            Tokens.drawCaps(g, label, Tokens.FG3, 20f, capsBaseline, Tokens.CAPS_SIZE, tracking);
        } finally {
            g.dispose();
        }
    }
}
