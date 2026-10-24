package io.umbra.gui.ui;

import io.umbra.gui.theme.Tokens;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The 280px left configuration column: lightweight glass, a fixed
 * "Configuration" caption and a scrollable stack of collapsible groups.
 *
 * <p>The column scrolls internally (no global scrollbars) and the custom
 * scrollbar is an 8px overlay so the glass stays clean.</p>
 */
public class Sidebar extends GlassPanel {

    public static final int CAPTION_HEIGHT = 44;

    /**
     * Scroll content with an explicit viewport clip.
     *
     * <p>Swing's viewport painting can ignore an ancestor clip when a component
     * is painted manually or through the repaint manager, which lets long
     * configuration stacks bleed over the status bar. Clipping to the viewport
     * rectangle here is belt and braces and makes the column robust for both
     * on-screen and offscreen rendering.</p>
     */
    private static final class ScrollContent extends JPanel {
        ScrollContent() {
            setOpaque(false);
            setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        }

        @Override
        protected void paintChildren(Graphics graphics) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                if (getParent() instanceof javax.swing.JViewport) {
                    java.awt.Rectangle view = ((javax.swing.JViewport) getParent()).getViewRect();
                    g.clipRect(view.x, view.y, view.width, view.height);
                }
                super.paintChildren(g);
            } finally {
                g.dispose();
            }
        }
    }

    private final JPanel content = new ScrollContent();
    private final JScrollPane scroll;
    private final List<GroupSection> groups = new ArrayList<GroupSection>();
    private Runnable toggleListener;
    private Runnable groupToggleListener;

    public Sidebar() {
        super(GlassPanel.Variant.SIDEBAR, 0);
        scroll = new JScrollPane(content);
        Scrollbars.style(scroll);
        scroll.getVerticalScrollBar().setUnitIncrement(22);
        add(scroll);
        content.add(Box.createVerticalStrut(6));
        getAccessibleContext().setAccessibleName("Configuration");
        getAccessibleContext().setAccessibleDescription(
                "Collapsible protection configuration groups");
    }

    /** Adds a group and returns it so the caller can populate it. */
    public GroupSection addGroup(String title, boolean expanded) {
        GroupSection group = new GroupSection(title, expanded);
        group.setOnToggle(new Runnable() {
            @Override
            public void run() {
                content.revalidate();
                content.repaint();
                if (groupToggleListener != null) {
                    groupToggleListener.run();
                }
            }
        });
        groups.add(group);
        content.add(group);
        content.add(Box.createVerticalStrut(2));
        content.revalidate();
        return group;
    }

    /** Called whenever a group is expanded or collapsed. */
    public void setGroupToggleListener(Runnable listener) {
        this.groupToggleListener = listener;
    }

    /** Must be called after the last group was added (hides the last rule). */
    public void finishGroups() {
        if (groups.isEmpty()) {
            return;
        }
        for (int i = 0; i < groups.size() - 1; i++) {
            groups.get(i).setShowSeparator(true);
        }
        groups.get(groups.size() - 1).setShowSeparator(false);
        content.add(Box.createVerticalStrut(28));
        content.revalidate();
    }

    /** Adds a toggle to a group; the sidebar forwards changes to its listener. */
    public void addSwitch(GroupSection group, final String id, String label,
                          boolean initial) {
        group.addSwitch(id, label, initial, new Runnable() {
            @Override
            public void run() {
                if (toggleListener != null) {
                    toggleListener.run();
                }
            }
        });
        content.revalidate();
    }

    public void setToggleListener(Runnable listener) {
        this.toggleListener = listener;
    }

    public List<GroupSection> groups() {
        return new ArrayList<GroupSection>(groups);
    }

    public GroupSection group(String title) {
        for (GroupSection group : groups) {
            if (group.getAccessibleContext().getAccessibleName() != null
                    && group.getAccessibleContext().getAccessibleName().startsWith(title)) {
                return group;
            }
        }
        return null;
    }

    /** Snapshot of every toggle state in display order. */
    public Map<String, Boolean> switchStates() {
        Map<String, Boolean> states = new LinkedHashMap<String, Boolean>();
        for (GroupSection group : groups) {
            for (SwitchRow row : group.switchRows()) {
                states.put(row.id(), Boolean.valueOf(row.isSelected()));
            }
        }
        return states;
    }

    public boolean isOn(String id) {
        Boolean value = switchStates().get(id);
        return value != null && value.booleanValue();
    }

    public void setOn(String id, boolean value) {
        for (GroupSection group : groups) {
            for (SwitchRow row : group.switchRows()) {
                if (row.id().equals(id)) {
                    row.setSelected(value);
                    return;
                }
            }
        }
    }

    public void setAnimationsEnabled(boolean enabled) {
        for (GroupSection group : groups) {
            group.setAnimationsEnabled(enabled);
        }
    }

    /** Clears all switch animations (screenshot mode jumps straight to final). */
    public void settle() {
        for (GroupSection group : groups) {
            group.setExpanded(group.isExpanded(), false);
        }
    }

    @Override
    public void doLayout() {
        scroll.setBounds(0, CAPTION_HEIGHT, getWidth(), Math.max(0, getHeight() - CAPTION_HEIGHT));
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        super.paintComponent(graphics);
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            FontMetrics metrics = g.getFontMetrics(Tokens.serifBold(Tokens.CAPS_SIZE));
            float baseline = 24f + metrics.getAscent();
            Tokens.drawCaps(g, "Configuration", Tokens.FG3, 24f, baseline,
                    Tokens.CAPS_SIZE, 0.22f);
        } finally {
            g.dispose();
        }
    }

    @Override
    protected void paintChildren(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            // A scrollable column must never paint outside its own 280px box:
            // offscreen rendering has no RepaintManager clip, and the log-style
            // columns rely on this explicit clip.
            g.clipRect(0, 0, getWidth(), getHeight());
            super.paintChildren(g);
            int w = getWidth();
            int h = getHeight();
            g.setPaint(new java.awt.GradientPaint(0f, h - 34f,
                    new java.awt.Color(255, 255, 255, 0), 0f, (float) h,
                    new java.awt.Color(255, 255, 255, 215)));
            g.fillRect(0, Math.max(0, h - 34), w, 34);
        } finally {
            g.dispose();
        }
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(Tokens.SIDEBAR_WIDTH, 600);
    }
}
