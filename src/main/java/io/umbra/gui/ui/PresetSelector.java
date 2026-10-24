package io.umbra.gui.ui;

import io.umbra.gui.theme.Tokens;

import javax.swing.JPanel;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Quiet preset selector drawn as serif pill chips.
 *
 * <p>Selected state is a bright white pill with a stronger hairline (accent is
 * reserved for the primary button, on-switches and key numbers, so the preset
 * chips stay monochrome). Two rows of chips fit the 280px column.</p>
 */
public class PresetSelector extends JPanel {

    /** Receives the preset name when the user picks one. */
    public interface Listener {
        void selected(String name);
    }

    public static final int HEIGHT = 94;

    private final List<String> names = new ArrayList<String>(Arrays.asList(
            "Light", "Balanced", "Aggressive", "Maximum", "Nocturne", "Custom"));
    private final List<int[]> layout = new ArrayList<int[]>();
    private final List<Integer> rowTops = new ArrayList<Integer>();
    private String selected = "Balanced";
    private String hover;
    private Listener listener;

    public PresetSelector() {
        setOpaque(false);
        setPreferredSize(new Dimension(Tokens.SIDEBAR_WIDTH - 30, HEIGHT));
        setMaximumSize(new Dimension(Integer.MAX_VALUE, HEIGHT));
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        getAccessibleContext().setAccessibleName("Preset");
        getAccessibleContext().setAccessibleDescription(
                "Protection preset: " + String.join(", ", names));
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                String hit = chipAt(e.getX(), e.getY());
                if (hit != null) {
                    select(hit);
                }
            }

            @Override
            public void mouseMoved(MouseEvent e) {
                String hit = chipAt(e.getX(), e.getY());
                if (hit != null ? !hit.equals(hover) : hover != null) {
                    hover = hit;
                    repaint();
                }
            }

            @Override
            public void mouseExited(MouseEvent e) {
                hover = null;
                repaint();
            }
        });
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    public String selected() {
        return selected;
    }

    /** Sets the selected preset without firing the listener (YAML load). */
    public void setSelected(String name) {
        selected = name == null ? "Custom" : name;
        repaint();
    }

    private void select(String name) {
        if (name.equals(selected)) {
            return;
        }
        selected = name;
        repaint();
        if (listener != null) {
            listener.selected(name);
        }
    }

    private String chipAt(int mouseX, int mouseY) {
        computeLayout();
        for (int i = 0; i < layout.size(); i++) {
            int[] bounds = layout.get(i);
            if (mouseX >= bounds[0] && mouseX <= bounds[0] + bounds[2]
                    && mouseY >= bounds[1] && mouseY <= bounds[1] + bounds[3]) {
                return names.get(i);
            }
        }
        return null;
    }

    private void computeLayout() {
        layout.clear();
        rowTops.clear();
        Graphics2D g = probe();
        try {
            Font font = Tokens.serif(Tokens.BODY_SIZE);
            int available = Math.max(120, getWidth() - 48);
            int x = 32;
            int y = 4;
            int chipHeight = 24;
            for (String name : names) {
                int width = Math.round(Tokens.textWidth(g, name, font)) + 24;
                if (x > 32 && x + width > 32 + available) {
                    x = 32;
                    y += chipHeight + 8;
                }
                layout.add(new int[]{x, y, width, chipHeight});
                x += width + 6;
            }
        } finally {
            g.dispose();
        }
    }

    private Graphics2D probe() {
        java.awt.image.BufferedImage image = new java.awt.image.BufferedImage(
                1, 1, java.awt.image.BufferedImage.TYPE_INT_RGB);
        return image.createGraphics();
    }

    @Override
    public void doLayout() {
        computeLayout();
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            computeLayout();
            for (int i = 0; i < layout.size(); i++) {
                int[] bounds = layout.get(i);
                String name = names.get(i);
                boolean isSelected = name.equals(selected);
                boolean isHover = name.equals(hover);
                RoundRectangle2D.Float shape = new RoundRectangle2D.Float(
                        bounds[0], bounds[1], bounds[2], bounds[3], 24f, 24f);
                if (isSelected) {
                    g.setColor(Tokens.alpha(java.awt.Color.WHITE, 0.92f));
                    g.fill(shape);
                    g.setColor(Tokens.LINE_STRONG);
                    g.setStroke(new BasicStroke(1f));
                    g.draw(shape);
                } else if (isHover) {
                    g.setColor(new Color(0, 0, 0, 8));
                    g.fill(shape);
                }
                Font font = Tokens.serifFor(name, Tokens.BODY_SIZE, Font.PLAIN);
                FontMetrics metrics = g.getFontMetrics(font);
                float baseline = bounds[1] + (bounds[3] - metrics.getHeight()) / 2f
                        + metrics.getAscent();
                java.awt.Color color = isSelected ? Tokens.FG : Tokens.FG2;
                Tokens.drawText(g, name, font, color, bounds[0] + 12f, baseline, 0f);
            }
            if (isFocusOwner()) {
                g.setColor(Tokens.alpha(Tokens.ACCENT, 0.9f));
                g.setStroke(new BasicStroke(2f));
                g.draw(new RoundRectangle2D.Float(2f, 2f, getWidth() - 4f,
                        getHeight() - 4f, 12f, 12f));
            }
        } finally {
            g.dispose();
        }
    }
}

