package io.umbra.gui.ui;

import io.umbra.gui.theme.Tokens;

import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.event.ActionListener;

/**
 * A labelled path row in the configuration column: uppercase 10.5px caption,
 * rounded 34px field underneath and an optional 28px browse icon on the right.
 * Height is 62px so three rows breathe inside the 280px column.
 */
public class PathRow extends JPanel {

    public static final int HEIGHT = 62;

    private final String label;
    private final GlassTextField field;
    private final IconButton browse;

    public PathRow(String label, String placeholder, boolean mono,
                   String browseAccessibleName, String browseTooltip,
                   ActionListener browseAction) {
        super(null);
        this.label = label;
        setOpaque(false);
        setPreferredSize(new java.awt.Dimension(Tokens.SIDEBAR_WIDTH - 30, HEIGHT));
        setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, HEIGHT));
        field = new GlassTextField(placeholder, mono);
        field.getAccessibleContext().setAccessibleName(label);
        field.getAccessibleContext().setAccessibleDescription(placeholder);
        add(field);
        if (browseAction != null) {
            browse = new IconButton(IconButton.FOLDER, browseAccessibleName, browseTooltip);
            browse.addActionListener(browseAction);
            add(browse);
        } else {
            browse = null;
        }
    }

    public JTextField field() {
        return field;
    }

    public String text() {
        return field.getText();
    }

    public void setText(String value) {
        field.setText(value == null ? "" : value);
    }

    public void setToolTip(String text) {
        field.setToolTipText(text);
    }

    @Override
    public void doLayout() {
        int w = getWidth();
        int rightInset = 16;
        int fieldW = w - 32 - rightInset - (browse == null ? 0 : 28 + 6);
        field.setBounds(32, 22, Math.max(40, fieldW), 34);
        if (browse != null) {
            browse.setBounds(w - rightInset - 28, 25, 28, 28);
        }
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            FontMetrics metrics = g.getFontMetrics(Tokens.serifBold(Tokens.CAPS_SIZE));
            float baseline = 13f + metrics.getAscent() - metrics.getHeight() / 2f;
            Tokens.drawCaps(g, label, Tokens.FG3, 32f, baseline, Tokens.CAPS_SIZE, 0.18f);
        } finally {
            g.dispose();
        }
    }
}
