package io.umbra.gui.ui;

import io.umbra.gui.theme.Icons;
import io.umbra.gui.theme.Tokens;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.SwingConstants;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Shape;
import java.awt.event.ActionListener;
import java.awt.geom.RoundRectangle2D;

/**
 * The single accent-coloured button of the window ("Start" / "Cancel").
 *
 * <p>Flat accent fill, 10px radius, serif 13.5px/600 letter-spaced white text.
 * A 2px progress hairline lives in the bottom edge of the button and is the
 * only running-progress indicator besides the status bar.</p>
 */
public class PrimaryButton extends JButton {

    private static final int RADIUS = Tokens.RADIUS_CONTROL;
    private int progress = -1;
    private final HoverState hoverState;

    public PrimaryButton(String text) {
        super(text);
        setOpaque(false);
        setContentAreaFilled(false);
        setBorderPainted(false);
        setFocusPainted(false);
        setRolloverEnabled(true);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setBorder(BorderFactory.createEmptyBorder());
        setHorizontalAlignment(SwingConstants.CENTER);
        setPreferredSize(new Dimension(96, 36));
        setMinimumSize(new Dimension(96, 36));
        hoverState = new HoverState(this);
        updateAccessible();
    }

    /** Progress in 0..100, or -1 to hide the hairline (idle / cancelled). */
    public void setProgress(int percent) {
        int value = percent < 0 ? -1 : Math.max(0, Math.min(100, percent));
        if (value != progress) {
            progress = value;
            repaint();
        }
    }

    public int progress() {
        return progress;
    }

    private void updateAccessible() {
        getAccessibleContext().setAccessibleName(getText());
        getAccessibleContext().setAccessibleDescription(
                "Starts protecting the selected JAR; becomes Cancel while a run is active.");
    }

    @Override
    public void setText(String text) {
        super.setText(text);
        updateAccessible();
    }

    public void addQuietAction(ActionListener listener) {
        addActionListener(listener);
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();
            // active: scale(0.98) approximated by easing the pressed fill one
            // pixel inside the bounds; hover darkening is animated as well.
            float inset = hoverState.press();
            Shape shape = new RoundRectangle2D.Float(inset, inset, w - inset * 2f,
                    h - inset * 2f, RADIUS * 2f, RADIUS * 2f);
            Color fill;
            if (!isEnabled()) {
                fill = Tokens.alpha(Tokens.ACCENT, 0.40f);
            } else {
                fill = Tokens.mix(Tokens.ACCENT, Color.BLACK,
                        0.04f * hoverState.hover() + 0.06f * hoverState.press());
            }
            g.setColor(fill);
            g.fill(shape);

            // Progress hairline: 2px track + white fill, clipped to the radius.
            if (progress >= 0) {
                Shape previous = g.getClip();
                g.clip(shape);
                g.setColor(Tokens.alpha(Color.WHITE, 0.22f));
                g.fillRect(0, h - 2, w, 2);
                int fillWidth = Math.round(w * (progress / 100f));
                g.setColor(Tokens.alpha(Color.WHITE, 0.75f));
                g.fillRect(0, h - 2, fillWidth, 2);
                g.setClip(previous);
            }

            String label = getText() == null ? "" : getText();
            float size = Tokens.BUTTON_SIZE;
            java.awt.Font font = Tokens.serifFor(label, size, java.awt.Font.BOLD);
            FontMetrics metrics = g.getFontMetrics(font);
            float baseline = (h - 2f - metrics.getHeight()) / 2f + metrics.getAscent();
            if (progress < 0) {
                baseline = (h - metrics.getHeight()) / 2f + metrics.getAscent();
            }
            Tokens.drawCentered(g, label, font, new Color(255, 255, 255, 242),
                    w / 2f, baseline, 0.02f);

            if (isFocusOwner()) {
                g.setColor(Tokens.alpha(Color.WHITE, 0.85f));
                g.setStroke(new java.awt.BasicStroke(2f));
                g.draw(new RoundRectangle2D.Float(3f, 3f, w - 6f, h - 6f,
                        RADIUS * 2f - 4f, RADIUS * 2f - 4f));
            }
        } finally {
            g.dispose();
        }
    }
}

/** A borderless quiet text button used for secondary actions. */
class QuietButton extends JButton {

    private final HoverState hoverState;

    QuietButton(String text) {
        super(text);
        setOpaque(false);
        setContentAreaFilled(false);
        setBorderPainted(false);
        setFocusPainted(false);
        setRolloverEnabled(true);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setBorder(BorderFactory.createEmptyBorder());
        setHorizontalAlignment(SwingConstants.CENTER);
        setFont(Tokens.serif(Tokens.BODY_SIZE));
        getAccessibleContext().setAccessibleName(text);
        setPreferredSize(new Dimension(
                Math.round(Tokens.measure(text, Tokens.serif(Tokens.BODY_SIZE), 0f)) + 20, 28));
        hoverState = new HoverState(this);
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();
            if (isEnabled() && hoverState.hover() > 0.01f) {
                g.setColor(new Color(0, 0, 0,
                        Math.round((9f + 5f * hoverState.press()) * hoverState.hover())));
                g.fill(new RoundRectangle2D.Float(0f, 0f, w, h, 16f, 16f));
            }
            String label = getText() == null ? "" : getText();
            java.awt.Font font = Tokens.serifFor(label, Tokens.BODY_SIZE, java.awt.Font.PLAIN);
            FontMetrics metrics = g.getFontMetrics(font);
            float baseline = (h - metrics.getHeight()) / 2f + metrics.getAscent();
            Color color = isEnabled()
                    ? Tokens.mix(Tokens.FG2, Tokens.FG, hoverState.hover())
                    : Tokens.alpha(Tokens.FG3, 0.7f);
            Tokens.drawCentered(g, label, font, color, w / 2f, baseline, 0f);
            if (isFocusOwner()) {
                g.setColor(Tokens.alpha(Tokens.ACCENT, 0.9f));
                g.setStroke(new java.awt.BasicStroke(2f));
                g.draw(new RoundRectangle2D.Float(1f, 1f, w - 2f, h - 2f, 14f, 14f));
            }
        } finally {
            g.dispose();
        }
    }
}

/** A small 28x28 icon-only button with an accessible name (no emoji). */
class IconButton extends JButton {

    static final int FOLDER = 0;
    static final int CLEAR = 1;
    static final int MENU = 2;
    static final int LOAD = 3;
    static final int SAVE = 4;
    static final int OPEN = 5;

    private final int icon;
    private final String accessibleName;
    private final HoverState hoverState;

    IconButton(int icon, String accessibleName, String tooltip) {
        this.icon = icon;
        this.accessibleName = accessibleName;
        setOpaque(false);
        setContentAreaFilled(false);
        setBorderPainted(false);
        setFocusPainted(false);
        setRolloverEnabled(true);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setBorder(BorderFactory.createEmptyBorder());
        setPreferredSize(new Dimension(28, 28));
        setMinimumSize(new Dimension(28, 28));
        setMaximumSize(new Dimension(28, 28));
        setToolTipText(tooltip);
        getAccessibleContext().setAccessibleName(accessibleName);
        getAccessibleContext().setAccessibleDescription(tooltip);
        hoverState = new HoverState(this);
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();
            if (isEnabled() && hoverState.hover() > 0.01f) {
                g.setColor(new Color(0, 0, 0,
                        Math.round((10f + 8f * hoverState.press()) * hoverState.hover())));
                g.fill(new RoundRectangle2D.Float(0f, 0f, w, h, 16f, 16f));
            }
            Color color = !isEnabled() ? Tokens.alpha(Tokens.FG3, 0.5f)
                    : Tokens.mix(Tokens.FG3, Tokens.FG2, hoverState.hover());
            double size = 16d;
            double x = (w - size) / 2d;
            double y = (h - size) / 2d;
            switch (icon) {
                case FOLDER:
                case LOAD:
                    if (icon == FOLDER) {
                        Icons.folder(g, x, y, size, color);
                    } else {
                        Icons.load(g, x, y, size, color);
                    }
                    break;
                case CLEAR:
                    Icons.close(g, x, y, size, color);
                    break;
                case MENU:
                    Icons.menu(g, x, y, size, color);
                    break;
                case SAVE:
                    Icons.save(g, x, y, size, color);
                    break;
                case OPEN:
                    Icons.openExternal(g, x, y, size, color);
                    break;
                default:
                    Icons.folder(g, x, y, size, color);
                    break;
            }
            if (isFocusOwner()) {
                g.setColor(Tokens.alpha(Tokens.ACCENT, 0.9f));
                g.setStroke(new java.awt.BasicStroke(2f));
                g.draw(new RoundRectangle2D.Float(1f, 1f, w - 2f, h - 2f, 14f, 14f));
            }
        } finally {
            g.dispose();
        }
    }
}
