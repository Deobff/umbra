package io.umbra.gui.ui;

import io.umbra.gui.theme.Tokens;

import javax.swing.JTextField;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;

/**
 * The 64px top bar: brand on the left, monospace seed field in the middle and
 * the single primary action on the right, with a 2px progress hairline built
 * into the button.
 */
public class TopBar extends GlassPanel {

    public static final int HEIGHT = Tokens.TOP_BAR;
    private static final int SEED_WIDTH = 120;
    private static final float SEED_LABEL_WIDTH = Tokens.measure("SEED",
            Tokens.serifBold(Tokens.CAPS_SIZE), 0.18f);

    private final GlassTextField seedField;
    private final PrimaryButton primary;
    private final IconButton menu;
    private boolean compact;
    private boolean seedVisible = true;

    public TopBar() {
        super(GlassPanel.Variant.TOOLBAR, 0);
        seedField = new GlassTextField("23303", true);
        seedField.setHorizontalAlignment(JTextField.RIGHT);
        seedField.setPreferredSize(new java.awt.Dimension(SEED_WIDTH, 34));
        seedField.getAccessibleContext().setAccessibleName("Seed");
        seedField.getAccessibleContext().setAccessibleDescription(
                "Deterministic seed used for every random choice in the run");
        add(seedField);
        primary = new PrimaryButton("Start");
        add(primary);
        menu = new IconButton(IconButton.MENU, "Show configuration",
                "Show or hide the configuration column");
        menu.setVisible(false);
        add(menu);
        getAccessibleContext().setAccessibleName("Top bar");
    }

    public JTextField seedField() {
        return seedField;
    }

    public PrimaryButton primaryButton() {
        return primary;
    }

    public javax.swing.JButton menuButton() {
        return menu;
    }

    /** Compact mode hides the seed field and shows the drawer button. */
    public void setCompact(boolean compact, boolean seedVisible) {
        this.compact = compact;
        this.seedVisible = seedVisible;
        menu.setVisible(compact);
        seedField.setVisible(seedVisible && !compact);
        revalidate();
        repaint();
    }

    public void setSeedVisible(boolean visible) {
        this.seedVisible = visible;
        seedField.setVisible(visible);
        revalidate();
        repaint();
    }

    @Override
    public void doLayout() {
        int w = getWidth();
        int h = getHeight();
        int left = 24;
        if (compact) {
            menu.setBounds(20, (h - 28) / 2, 28, 28);
            left = 56;
        }
        primary.setBounds(w - 24 - 96, (h - 36) / 2, 96, 36);
        if (seedVisible && !compact) {
            int groupWidth = Math.round(SEED_LABEL_WIDTH) + 8 + SEED_WIDTH;
            int x = Math.max(left + 120, (w - groupWidth) / 2);
            seedField.setBounds(x + groupWidth - SEED_WIDTH, (h - 34) / 2, SEED_WIDTH, 34);
        }
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        super.paintComponent(graphics);
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int h = getHeight();
            int x = compact ? 56 : 24;

            java.awt.Font brand = Tokens.serifFor("Umbra", Tokens.BRAND_SIZE,
                    java.awt.Font.BOLD);
            FontMetrics brandMetrics = g.getFontMetrics(brand);
            float baseline = (h - brandMetrics.getHeight()) / 2f + brandMetrics.getAscent();
            float brandWidth = Tokens.drawText(g, "Umbra", brand, Tokens.FG, x, baseline,
                    -0.01f);

            java.awt.Font versionFont = Tokens.serifBold(Tokens.CAPS_SIZE);
            FontMetrics versionMetrics = g.getFontMetrics(versionFont);
            float capsBaseline = (h - versionMetrics.getHeight()) / 2f
                    + versionMetrics.getAscent() + 2f;
            Tokens.drawText(g, "3.0", versionFont, Tokens.FG3,
                    x + brandWidth + 10f, capsBaseline, 0.14f);

            if (seedVisible && !compact) {
                int groupWidth = Math.round(SEED_LABEL_WIDTH) + 8 + SEED_WIDTH;
                int seedX = Math.max(x + 160, (getWidth() - groupWidth) / 2);
                FontMetrics capsMetrics = g.getFontMetrics(Tokens.serifBold(Tokens.CAPS_SIZE));
                float capsY = (h - capsMetrics.getHeight()) / 2f + capsMetrics.getAscent();
                Tokens.drawCaps(g, "Seed", Tokens.FG3, seedX, capsY, Tokens.CAPS_SIZE, 0.18f);
            }
        } finally {
            g.dispose();
        }
    }

    private static Graphics2D probeFont() {
        java.awt.image.BufferedImage image = new java.awt.image.BufferedImage(
                1, 1, java.awt.image.BufferedImage.TYPE_INT_RGB);
        return image.createGraphics();
    }
}
