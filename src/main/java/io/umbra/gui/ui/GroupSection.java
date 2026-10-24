package io.umbra.gui.ui;

import io.umbra.gui.theme.Icons;
import io.umbra.gui.theme.Tokens;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Line2D;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A collapsible configuration group: 44px serif title header, 1px chevron that
 * rotates 90 degrees on expand, and a stack of 40px option rows.
 *
 * <p>Expansion animates the revealed content height over 400ms with a
 * decelerating ease (Swing cannot animate CSS grid-template-rows; animating the
 * clip height is the closest clean equivalent). The header is the keyboard and
 * accessibility node and exposes the expanded state.</p>
 */
public class GroupSection extends JPanel {

    private static final int HEADER_HEIGHT = 44;
    private static final int BOTTOM_PADDING = 8;

    private final String title;
    private final SectionHeader header;
    private final ContentPanel content;
    private final Map<String, SwitchRow> switches = new LinkedHashMap<String, SwitchRow>();
    private final List<Row> rows = new ArrayList<Row>();
    private boolean expanded;
    private float reveal;
    private Timer animation;
    private boolean animations = true;
    private boolean hoverHeader;
    private boolean showSeparator = true;
    private Runnable onToggle;

    public GroupSection(String title, boolean expanded) {
        super(null);
        this.title = title;
        this.expanded = expanded;
        this.reveal = expanded ? 1f : 0f;
        setOpaque(false);
        this.header = new SectionHeader();
        this.content = new ContentPanel();
        add(header);
        add(content);
        recomputePreferredSize();
        getAccessibleContext().setAccessibleName(title + " section");
        getAccessibleContext().setAccessibleDescription(
                "Collapsible configuration group " + title);
    }

    /** Flash a 1px separator under the section (the last group hides it). */
    public void setShowSeparator(boolean show) {
        this.showSeparator = show;
        repaint();
    }

    public boolean isExpanded() {
        return expanded;
    }

    public void setAnimationsEnabled(boolean enabled) {
        this.animations = enabled;
        for (SwitchRow row : switches.values()) {
            row.setAnimationsEnabled(enabled);
        }
    }

    public void setExpanded(boolean value, boolean animate) {
        if (expanded == value) {
            return;
        }
        expanded = value;
        header.invalidateAccessibleState();
        if (!animate || !animations) {
            stopAnimation();
            reveal = value ? 1f : 0f;
            recomputePreferredSize();
            revalidate();
            repaint();
            return;
        }
        startAnimation(value ? 1f : 0f);
    }

    private void startAnimation(final float target) {
        stopAnimation();
        final long started = System.currentTimeMillis();
        final float from = reveal;
        animation = new Timer(15, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                float t = Math.min(1f, (System.currentTimeMillis() - started) / 400f);
                reveal = from + (target - from) * Tokens.easeOut(t);
                recomputePreferredSize();
                if (getParent() != null) {
                    getParent().revalidate();
                }
                repaint();
                if (t >= 1f) {
                    stopAnimation();
                    reveal = target;
                    recomputePreferredSize();
                    if (getParent() != null) {
                        getParent().revalidate();
                    }
                    repaint();
                }
            }
        });
        animation.start();
    }

    private void stopAnimation() {
        if (animation != null) {
            animation.stop();
            animation = null;
        }
    }

    /** Adds a toggle row and returns its id (also keyed in {@link #switches}). */
    public String addSwitch(String id, String label, boolean initial, Runnable onChange) {
        SwitchRow row = new SwitchRow(id, label, initial, onChange);
        row.setAnimationsEnabled(animations);
        switches.put(id, row);
        addRow(row, 40);
        return id;
    }

    /** Adds an arbitrary component (path rows, preset chips, editors). */
    public void addRow(JComponent component, int height) {
        rows.add(new Row(component, height));
        content.add(component);
        recomputePreferredSize();
    }

    public SwitchRow switchRow(String id) {
        return switches.get(id);
    }

    public boolean isOn(String id) {
        SwitchRow row = switches.get(id);
        return row != null && row.isSelected();
    }

    public void setOn(String id, boolean value) {
        SwitchRow row = switches.get(id);
        if (row != null) {
            row.setSelected(value);
        }
    }

    /** Registers a listener fired whenever a switch in this group is toggled. */
    public void setOnToggle(Runnable listener) {
        this.onToggle = listener;
    }

    void fireToggled() {
        if (onToggle != null) {
            onToggle.run();
        }
    }

    public List<SwitchRow> switchRows() {
        return new ArrayList<SwitchRow>(switches.values());
    }

    private int contentHeight() {
        int total = 0;
        for (Row row : rows) {
            total += row.height;
        }
        return total;
    }

    private int revealedContentHeight() {
        return Math.round(contentHeight() * reveal);
    }

    private void recomputePreferredSize() {
        int height = HEADER_HEIGHT + revealedContentHeight();
        if (expanded || reveal > 0f) {
            height += BOTTOM_PADDING;
        }
        setPreferredSize(new Dimension(Tokens.SIDEBAR_WIDTH, height));
        setMaximumSize(new Dimension(Integer.MAX_VALUE, height));
        setMinimumSize(new Dimension(0, height));
        revalidate();
    }

    @Override
    public void doLayout() {
        int w = getWidth();
        header.setBounds(0, 0, w, HEADER_HEIGHT);
        content.setBounds(0, HEADER_HEIGHT, w, contentHeight());
        content.doLayout();
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            if (hoverHeader && reveal == 0f) {
                g.setColor(new Color(0, 0, 0, 8));
                g.fill(new RoundRectangle2D.Float(8f, 6f, w - 16f, HEADER_HEIGHT - 12f,
                        12f, 12f));
            }
        } finally {
            g.dispose();
        }
    }

    @Override
    protected void paintChildren(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            // Intersect with (never replace) the inherited clip so a collapsing
            // group cannot bleed into neighbouring rows or across the viewport.
            g.clipRect(0, 0, getWidth(), getHeight());
            super.paintChildren(g);
        } finally {
            g.dispose();
        }
        if (showSeparator) {
            Graphics2D line = (Graphics2D) graphics.create();
            try {
                line.setColor(Tokens.LINE);
                line.setStroke(new BasicStroke(1f));
                line.draw(new Line2D.Float(24f, getHeight() - 0.5f, getWidth() - 16f,
                        getHeight() - 0.5f));
            } finally {
                line.dispose();
            }
        }
    }

    private static final class Row {
        final JComponent component;
        final int height;

        Row(JComponent component, int height) {
            this.component = component;
            this.height = height;
        }
    }

    /** The content stack; lays rows out top-down. */
    private final class ContentPanel extends JPanel {

        ContentPanel() {
            super(null);
            setOpaque(false);
        }

        @Override
        public void doLayout() {
            int y = 0;
            for (Row row : rows) {
                row.component.setBounds(0, y, getWidth(), row.height);
                y += row.height;
                if (row.component instanceof SwitchRow) {
                    ((SwitchRow) row.component).doLayout();
                } else if (row.component instanceof JComponent) {
                    ((JComponent) row.component).doLayout();
                }
            }
        }
    }

    /** Focusable 44px header that owns the expand/collapse interaction. */
    private final class SectionHeader extends JComponent {

        SectionHeader() {
            setFocusable(true);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    toggleSection();
                }

                @Override
                public void mouseEntered(MouseEvent e) {
                    hoverHeader = true;
                    repaint();
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    hoverHeader = false;
                    repaint();
                }
            });
            addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    if (e.getKeyCode() == KeyEvent.VK_SPACE
                            || e.getKeyCode() == KeyEvent.VK_ENTER) {
                        e.consume();
                        toggleSection();
                    } else if (e.getKeyCode() == KeyEvent.VK_RIGHT && !expanded) {
                        e.consume();
                        setExpanded(true, true);
                    } else if (e.getKeyCode() == KeyEvent.VK_LEFT && expanded) {
                        e.consume();
                        setExpanded(false, true);
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
            updateAccessible();
        }

        @Override
        public javax.accessibility.AccessibleContext getAccessibleContext() {
            if (accessibleContext == null) {
                accessibleContext = new AccessibleSectionHeader();
                accessibleContext.setAccessibleName(title + " section");
            }
            return accessibleContext;
        }

        /** Exposes the collapsed/expanded state like aria-expanded on the web. */
        protected class AccessibleSectionHeader extends AccessibleJComponent {

            @Override
            public javax.accessibility.AccessibleRole getAccessibleRole() {
                return javax.accessibility.AccessibleRole.TOGGLE_BUTTON;
            }

            @Override
            public javax.accessibility.AccessibleStateSet getAccessibleStateSet() {
                javax.accessibility.AccessibleStateSet states = super.getAccessibleStateSet();
                if (expanded) {
                    states.add(javax.accessibility.AccessibleState.CHECKED);
                }
                return states;
            }

            @Override
            public String getAccessibleName() {
                return title + " section";
            }
        }

        private void toggleSection() {
            setExpanded(!expanded, true);
            if (onToggle != null) {
                onToggle.run();
            }
        }

        void invalidateAccessibleState() {
            updateAccessible();
            repaint();
        }

        private void updateAccessible() {
            getAccessibleContext().setAccessibleName(title + " section");
            getAccessibleContext().setAccessibleDescription(
                    (expanded ? "Expanded" : "Collapsed") + " configuration group: " + title);
        }

        @Override
        protected void paintComponent(Graphics graphics) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                Tokens.prepare(g);
                int w = getWidth();
                int h = getHeight();
                if (hoverHeader) {
                    g.setColor(new Color(0, 0, 0, 6));
                    g.fill(new RoundRectangle2D.Float(8f, 6f, w - 16f, h - 12f, 12f, 12f));
                }
                java.awt.Font font = Tokens.serifFor(title, Tokens.GROUP_SIZE,
                        java.awt.Font.BOLD);
                FontMetrics metrics = g.getFontMetrics(font);
                float baseline = (h - metrics.getHeight()) / 2f + metrics.getAscent();
                Tokens.drawText(g, title, font, Tokens.FG, 24f, baseline, 0.01f);

                double chevronSize = 14d;
                Graphics2D cg = (Graphics2D) g.create();
                try {
                    cg.translate(w - 24d - chevronSize / 2d, h / 2d);
                    cg.rotate(Math.toRadians(90d * reveal));
                    cg.translate(-chevronSize / 2d, -chevronSize / 2d);
                    Icons.chevron(cg, chevronSize / 2d, chevronSize / 2d, chevronSize,
                            Tokens.FG3);
                } finally {
                    cg.dispose();
                }
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

    /** Schedules a one-shot update on the EDT. */
    static void later(Runnable runnable) {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeLater(runnable);
        }
    }
}
