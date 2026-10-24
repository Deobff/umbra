package io.umbra.gui.ui;

import javax.swing.JPanel;
import java.awt.Dimension;

/**
 * Container for the four statistic cards.
 *
 * <p>It can stack them vertically in the 240px right column (wide window) or
 * lay them out as a four-column strip under the console when the window is
 * narrower than 1100px. Both orientations share the same card instances so no
 * state jumps between layouts.</p>
 */
public class RightColumn extends JPanel {

    public static final int STRIP_HEIGHT = 96;
    public static final int CARD_GAP = 12;

    private final StatCard[] cards;
    private boolean horizontal;

    public RightColumn() {
        super(null);
        setOpaque(false);
        cards = new StatCard[]{
                new StatCard("Classes", StatCard.Format.INTEGER),
                new StatCard("Protected methods", StatCard.Format.INTEGER),
                new StatCard("Encrypted strings", StatCard.Format.INTEGER),
                new StatCard("Elapsed", StatCard.Format.DURATION)
        };
        for (StatCard card : cards) {
            add(card);
        }
        setPreferredSize(new Dimension(240, 600));
    }

    public StatCard[] cards() {
        return cards;
    }

    public void setHorizontal(boolean horizontal) {
        this.horizontal = horizontal;
    }

    public boolean isHorizontal() {
        return horizontal;
    }

    public void reset() {
        for (StatCard card : cards) {
            card.reset();
        }
    }

    public void setAnimationsEnabled(boolean enabled) {
        for (StatCard card : cards) {
            card.setAnimationsEnabled(enabled);
        }
    }

    @Override
    public void doLayout() {
        int w = getWidth();
        int h = getHeight();
        if (horizontal) {
            int cardWidth = (w - CARD_GAP * 3) / 4;
            int x = 0;
            for (StatCard card : cards) {
                card.setBounds(x, 0, cardWidth, h);
                x += cardWidth + CARD_GAP;
            }
            return;
        }
        int cardWidth = Math.max(120, w - 24);
        int available = Math.max(160, h - 16 - 16 - CARD_GAP * 3);
        int cardHeight = available / 4;
        int y = 16;
        for (StatCard card : cards) {
            card.setBounds(0, y, cardWidth, cardHeight);
            y += cardHeight + CARD_GAP;
        }
    }
}
