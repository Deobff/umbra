package io.umbra.gui.ui;

import io.umbra.gui.theme.Tokens;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.basic.BasicScrollBarUI;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.geom.RoundRectangle2D;

/**
 * A rounded text field with the light-glass treatment from the spec: faint dark
 * wash, a soft border, and a bright white background with accent border on
 * focus (on light UI "getting brighter" reads as focus).
 */
public class GlassTextField extends JTextField {

    private final String placeholder;

    public GlassTextField(String placeholder) {
        this(placeholder, false);
    }

    public GlassTextField(String placeholder, boolean mono) {
        this.placeholder = placeholder == null ? "" : placeholder;
        setOpaque(false);
        setBorder(new EmptyBorder(0, 10, 0, 10));
        setForeground(Tokens.FG);
        setFont(mono ? Tokens.mono(Tokens.BODY_SIZE) : Tokens.serif(Tokens.BODY_SIZE));
        setCaretColor(Tokens.FG);
        setSelectionColor(Tokens.alpha(Tokens.ACCENT, 0.25f));
        setSelectedTextColor(Tokens.FG);
        setDisabledTextColor(Tokens.FG3);
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
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(120, 34);
    }

    @Override
    public Dimension getMinimumSize() {
        return new Dimension(60, 34);
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();
            boolean focused = isFocusOwner();
            RoundRectangle2D.Float shape = new RoundRectangle2D.Float(
                    0.5f, 0.5f, w - 1f, h - 1f, Tokens.RADIUS_CONTROL * 2f,
                    Tokens.RADIUS_CONTROL * 2f);
            g.setColor(focused ? Tokens.alpha(Color.WHITE, 0.92f)
                    : new Color(0, 0, 0, 10));
            g.fill(shape);
            g.setColor(focused ? Tokens.alpha(Tokens.ACCENT, 0.55f) : Tokens.LINE);
            g.setStroke(new java.awt.BasicStroke(1f));
            g.draw(shape);
        } finally {
            g.dispose();
        }
        String text = getText();
        FontMetrics metrics = graphics.getFontMetrics(getFont());
        int available = getWidth() - getInsets().left - getInsets().right;
        boolean tooLong = !isFocusOwner() && text != null && !text.isEmpty()
                && metrics.stringWidth(text) > available;
        if (tooLong) {
            // Path fields keep the meaningful tail visible instead of cutting
            // the string at an arbitrary character.
            Graphics2D clipped = (Graphics2D) graphics.create();
            try {
                Tokens.prepare(clipped);
                String shown = Tokens.ellipsizeLeft(clipped, text, getFont(), available);
                float baseline = (getHeight() - metrics.getHeight()) / 2f
                        + metrics.getAscent();
                Tokens.drawText(clipped, shown, getFont(), getForeground(),
                        getInsets().left, baseline, 0f);
            } finally {
                clipped.dispose();
            }
        } else {
            super.paintComponent(graphics);
        }
        if (getText().isEmpty() && !placeholder.isEmpty() && !isFocusOwner()) {
            Graphics2D hint = (Graphics2D) graphics.create();
            try {
                Tokens.prepare(hint);
                FontMetrics hintMetrics = hint.getFontMetrics(getFont());
                float baseline = (getHeight() - hintMetrics.getHeight()) / 2f
                        + hintMetrics.getAscent();
                Tokens.drawText(hint, placeholder, getFont(), Tokens.FG3, getInsets().left,
                        baseline, 0f);
            } finally {
                hint.dispose();
            }
        }
    }
}

/** Multi-line mono editor used by the advanced {@code key=value} section. */
class GlassTextArea extends JTextArea {

    private final String placeholder;

    GlassTextArea(String placeholder, int rows) {
        super(rows, 1);
        this.placeholder = placeholder == null ? "" : placeholder;
        setOpaque(false);
        setBorder(new EmptyBorder(8, 10, 8, 10));
        setForeground(Tokens.FG2);
        setFont(Tokens.mono(12f));
        setCaretColor(Tokens.FG);
        setSelectionColor(Tokens.alpha(Tokens.ACCENT, 0.25f));
        setLineWrap(true);
        setWrapStyleWord(false);
        setTabSize(4);
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
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();
            boolean focused = isFocusOwner();
            RoundRectangle2D.Float shape = new RoundRectangle2D.Float(
                    0.5f, 0.5f, w - 1f, h - 1f, Tokens.RADIUS_CONTROL * 2f,
                    Tokens.RADIUS_CONTROL * 2f);
            g.setColor(focused ? Tokens.alpha(Color.WHITE, 0.92f) : new Color(0, 0, 0, 10));
            g.fill(shape);
            g.setColor(focused ? Tokens.alpha(Tokens.ACCENT, 0.55f) : Tokens.LINE);
            g.setStroke(new java.awt.BasicStroke(1f));
            g.draw(shape);
        } finally {
            g.dispose();
        }
        super.paintComponent(graphics);
        if (getText().isEmpty() && !placeholder.isEmpty() && !isFocusOwner()) {
            Graphics2D hint = (Graphics2D) graphics.create();
            try {
                Tokens.prepare(hint);
                FontMetrics metrics = hint.getFontMetrics(getFont());
                float baseline = getInsets().top + metrics.getAscent();
                Tokens.drawText(hint, placeholder, getFont(), Tokens.FG3, getInsets().left,
                        baseline, 0f);
            } finally {
                hint.dispose();
            }
        }
    }
}

/**
 * An overlay-style scrollbar: transparent track, a 6px rounded thumb that only
 * appears when the content overflows. Width is hidden per the spec.
 */
class MinimalScrollBarUI extends BasicScrollBarUI {

    @Override
    protected JButton createDecreaseButton(int orientation) {
        return zeroButton();
    }

    @Override
    protected JButton createIncreaseButton(int orientation) {
        return zeroButton();
    }

    private JButton zeroButton() {
        JButton button = new JButton();
        button.setPreferredSize(new Dimension(0, 0));
        button.setMinimumSize(new Dimension(0, 0));
        button.setMaximumSize(new Dimension(0, 0));
        button.setBorder(BorderFactory.createEmptyBorder());
        button.setOpaque(false);
        button.setContentAreaFilled(false);
        return button;
    }

    @Override
    protected void paintTrack(Graphics g, javax.swing.JComponent c, Rectangle trackBounds) {
        // Transparent: the glass surface behind the scrollbar remains visible.
    }

    @Override
    protected void paintThumb(Graphics g, javax.swing.JComponent c, Rectangle thumbBounds) {
        if (thumbBounds.isEmpty() || !scrollbar.isEnabled()) {
            return;
        }
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            Tokens.prepare(g2);
            int inset = 2;
            int alpha = isDragging ? 58 : (isThumbRollover() ? 44 : 30);
            g2.setColor(new Color(0, 0, 0, alpha));
            g2.fill(new RoundRectangle2D.Float(thumbBounds.x + inset, thumbBounds.y + inset,
                    Math.max(3f, thumbBounds.width - inset * 2f),
                    Math.max(3f, thumbBounds.height - inset * 2f), 6f, 6f));
        } finally {
            g2.dispose();
        }
    }

    @Override
    protected Dimension getMinimumThumbSize() {
        return new Dimension(8, 28);
    }
}

/** Factory helpers shared by the panels. */
final class Scrollbars {

    private Scrollbars() {
    }

    static void style(JScrollPane pane) {
        pane.setBorder(BorderFactory.createEmptyBorder());
        pane.setOpaque(false);
        pane.getViewport().setOpaque(false);
        // SIMPLE mode paints the view directly instead of going through the
        // viewport backing store, which keeps nested lightweight painting
        // inside the parent clip on every platform.
        pane.getViewport().setScrollMode(javax.swing.JViewport.SIMPLE_SCROLL_MODE);
        pane.setViewportBorder(BorderFactory.createEmptyBorder());
        pane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        pane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        style(pane.getVerticalScrollBar());
        style(pane.getHorizontalScrollBar());
    }

    static void style(JScrollBar bar) {
        bar.setOpaque(false);
        bar.setUnitIncrement(18);
        bar.setBlockIncrement(120);
        bar.setPreferredSize(new Dimension(8, 8));
        bar.setUI(new MinimalScrollBarUI());
        bar.setCursor(Cursor.getDefaultCursor());
    }
}

