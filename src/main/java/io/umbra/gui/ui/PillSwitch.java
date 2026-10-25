package io.umbra.gui.ui;

import io.umbra.gui.theme.Tokens;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Ellipse2D;
import java.awt.geom.RoundRectangle2D;

/**
 * The custom 44x24 pill switch.
 *
 * <p>The knob and colour transition over 180ms with the standard decelerating
 * ease (driven by the shared {@link Animation} helper); there is no bounce,
 * loop or shadow. It is a passive visual: the owning
 * {@link SwitchRow} carries the focus, keyboard handling and accessibility
 * state, exactly like a label-linked switch on the web.</p>
 */
public class PillSwitch extends JPanel {

    public static final int WIDTH = 44;
    public static final int HEIGHT = 24;

    private boolean on;
    private float position;
    private Animation.Handle animation;
    private boolean animations = true;

    public PillSwitch(boolean on) {
        this.on = on;
        this.position = on ? 1f : 0f;
        setOpaque(false);
        setPreferredSize(new Dimension(WIDTH, HEIGHT));
        setMinimumSize(new Dimension(WIDTH, HEIGHT));
        setMaximumSize(new Dimension(WIDTH, HEIGHT));
        setFocusable(false);
    }

    public boolean isOn() {
        return on;
    }

    /** Enables or disables the knob movement animation (screenshots disable it). */
    public void setAnimationsEnabled(boolean enabled) {
        this.animations = enabled;
    }

    public void setOn(boolean value, boolean animate) {
        if (this.on == value) {
            if (!animate || animation == null) {
                position = value ? 1f : 0f;
                repaint();
            }
            return;
        }
        this.on = value;
        if (!animate || !animations) {
            stopAnimation();
            position = value ? 1f : 0f;
            repaint();
            return;
        }
        startAnimation(value ? 1f : 0f);
    }

    public void setOn(boolean value) {
        setOn(value, true);
    }

    private void startAnimation(final float target) {
        stopAnimation();
        final float from = position;
        animation = Animation.animate(this, 180, new Animation.Frame() {
            @Override
            public void frame(float eased) {
                position = from + (target - from) * eased;
                repaint();
            }
        });
    }

    private void stopAnimation() {
        if (animation != null) {
            animation.stop();
            animation = null;
        }
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();
            Color off = new Color(0, 0, 0, 26);
            Color track = Tokens.mix(off, Tokens.ACCENT, position);
            g.setColor(track);
            g.fill(new RoundRectangle2D.Float(0f, 0f, w, h, 24f, 24f));

            float knobDiameter = 20f;
            float travel = w - knobDiameter - 4f;
            float knobX = 2f + travel * position;
            float knobY = (h - knobDiameter) / 2f;
            g.setColor(new Color(255, 255, 255, 250));
            g.fill(new Ellipse2D.Float(knobX, knobY, knobDiameter, knobDiameter));
            // A 1px inner edge instead of the forbidden drop shadow gives the
            // white knob a clean edge on the accent track.
            g.setColor(new Color(0, 0, 0, 18));
            g.setStroke(new BasicStroke(1f));
            g.draw(new Ellipse2D.Float(knobX + 0.5f, knobY + 0.5f,
                    knobDiameter - 1f, knobDiameter - 1f));
        } finally {
            g.dispose();
        }
    }
}

/**
 * One option row: 40px high, label 13px, switch pinned right, 32px left inset.
 * The whole row is the hit target and the accessibility node.
 */
class SwitchRow extends JPanel {

    private final String id;
    private final String label;
    private final PillSwitch pill;
    private final Runnable onChange;
    private float hoverProgress;
    private boolean suppressEvents;

    SwitchRow(String id, String label, boolean initial, Runnable onChange) {
        this.id = id;
        this.label = label;
        this.pill = new PillSwitch(initial);
        this.onChange = onChange;
        setOpaque(false);
        setLayout(null);
        setPreferredSize(new Dimension(240, 40));
        add(pill);
        setFocusable(true);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        getAccessibleContext().setAccessibleName(label);
        getAccessibleContext().setAccessibleDescription("Toggle " + label);
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                toggle();
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                animateHover(1f);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                animateHover(0f);
            }
        });
        addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_SPACE || e.getKeyCode() == KeyEvent.VK_ENTER) {
                    e.consume();
                    toggle();
                }
            }
        });
        addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                repaint();
            }

            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                repaint();
            }
        });
    }

    String id() {
        return id;
    }

    boolean isSelected() {
        return pill.isOn();
    }

    void setSelected(boolean value) {
        suppressEvents = true;
        try {
            pill.setOn(value, true);
        } finally {
            suppressEvents = false;
        }
    }

    void setAnimationsEnabled(boolean enabled) {
        pill.setAnimationsEnabled(enabled);
    }

    private void animateHover(final float target) {
        final float from = hoverProgress;
        Animation.animate(this, 150, new Animation.Frame() {
            @Override
            public void frame(float eased) {
                hoverProgress = from + (target - from) * eased;
                repaint();
            }
        });
    }

    void toggle() {
        pill.setOn(!pill.isOn(), true);
        if (!suppressEvents && onChange != null) {
            onChange.run();
        }
        // Notify accessibility tools that the checked state changed.
        getAccessibleContext().firePropertyChange(
                javax.accessibility.AccessibleContext.ACCESSIBLE_STATE_PROPERTY, null,
                pill.isOn() ? javax.accessibility.AccessibleState.CHECKED : null);
        repaint();
    }

    @Override
    public javax.accessibility.AccessibleContext getAccessibleContext() {
        if (accessibleContext == null) {
            accessibleContext = new AccessibleSwitchRow();
            accessibleContext.setAccessibleName(label);
        }
        return accessibleContext;
    }

    /** Exposes the row as a checked toggle, the Swing analogue of role="switch". */
    protected class AccessibleSwitchRow extends AccessibleJPanel {

        @Override
        public javax.accessibility.AccessibleRole getAccessibleRole() {
            return javax.accessibility.AccessibleRole.TOGGLE_BUTTON;
        }

        @Override
        public javax.accessibility.AccessibleStateSet getAccessibleStateSet() {
            javax.accessibility.AccessibleStateSet states = super.getAccessibleStateSet();
            if (pill.isOn()) {
                states.add(javax.accessibility.AccessibleState.CHECKED);
            }
            return states;
        }

        @Override
        public String getAccessibleName() {
            return label;
        }
    }

    @Override
    public void doLayout() {
        int w = getWidth();
        int h = getHeight();
        pill.setBounds(w - Tokens.PAD - PillSwitch.WIDTH, (h - PillSwitch.HEIGHT) / 2,
                PillSwitch.WIDTH, PillSwitch.HEIGHT);
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();
            if (hoverProgress > 0.01f) {
                g.setColor(new Color(0, 0, 0, Math.round(9f * hoverProgress)));
                g.fill(new RoundRectangle2D.Float(8f, 2f, w - 16f, h - 4f, 12f, 12f));
            }
            java.awt.Font font = Tokens.serifFor(label, Tokens.BODY_SIZE, java.awt.Font.PLAIN);
            FontMetrics metrics = g.getFontMetrics(font);
            float baseline = (h - metrics.getHeight()) / 2f + metrics.getAscent();
            Tokens.drawText(g, label, font, Tokens.mix(Tokens.FG2, Tokens.FG, hoverProgress),
                    32f, baseline, 0f);
            if (isFocusOwner()) {
                g.setColor(Tokens.alpha(Tokens.ACCENT, 0.9f));
                g.setStroke(new BasicStroke(2f));
                g.draw(new RoundRectangle2D.Float(2f, 2f, w - 4f, h - 4f, 12f, 12f));
            }
        } finally {
            g.dispose();
        }
    }
}

/** Small helper: runs a task on the event dispatch thread later. */
final class Edt {

    private Edt() {
    }

    static void run(Runnable runnable) {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeLater(runnable);
        }
    }
}
