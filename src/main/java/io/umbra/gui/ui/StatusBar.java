package io.umbra.gui.ui;

import io.umbra.gui.theme.Tokens;

import javax.swing.JComponent;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The 44px bottom status bar.
 *
 * <p>Left: the run state in serif italic while pending/running, switching to a
 * normal-font success green or error red for the "signature" moments. Right:
 * monospace job facts separated by a half-opacity middle dot.</p>
 */
public class StatusBar extends GlassPanel {

    /** Status tone from the specification: pending is italic, results are normal. */
    public enum Tone {
        PENDING,
        SUCCESS,
        ERROR
    }

    private String status = "Waiting to start";
    private Tone tone = Tone.PENDING;
    private List<String> facts = new ArrayList<String>();

    public StatusBar() {
        super(GlassPanel.Variant.STATUS_BAR, 0);
        getAccessibleContext().setAccessibleName("Status bar");
    }

    public void setStatus(String text, Tone tone) {
        this.status = text == null ? "" : text;
        this.tone = tone == null ? Tone.PENDING : tone;
        getAccessibleContext().setAccessibleDescription(this.status);
        repaint();
    }

    public void setFacts(String... segments) {
        facts = segments == null ? new ArrayList<String>() : Arrays.asList(segments);
        repaint();
    }

    public String statusText() {
        return status;
    }

    public Tone tone() {
        return tone;
    }

    public List<String> facts() {
        return new ArrayList<String>(facts);
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        super.paintComponent(graphics);
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();

            Font statusFont = tone == Tone.PENDING
                    ? Tokens.serifFor(status, Tokens.STATUS_SIZE, Font.ITALIC)
                    : Tokens.serifFor(status, Tokens.STATUS_SIZE, Font.PLAIN);
            FontMetrics statusMetrics = g.getFontMetrics(statusFont);
            float baseline = (h - statusMetrics.getHeight()) / 2f + statusMetrics.getAscent();
            Color color = tone == Tone.SUCCESS ? Tokens.SUCCESS
                    : (tone == Tone.ERROR ? Tokens.DANGER : Tokens.FG2);
            Tokens.drawText(g, status, statusFont, color, 24f, baseline,
                    tone == Tone.PENDING ? 0.02f : 0f);

            Font factsFont = Tokens.mono(Tokens.FACTS_SIZE);
            FontMetrics factsMetrics = g.getFontMetrics(factsFont);
            float factsBaseline = (h - factsMetrics.getHeight()) / 2f
                    + factsMetrics.getAscent() + 1f;
            float dotWidth = Tokens.textWidth(g, "\u00b7", factsFont) + 14f;
            float total = 0f;
            for (int i = 0; i < facts.size(); i++) {
                total += Tokens.textWidth(g, facts.get(i), factsFont);
                if (i < facts.size() - 1) {
                    total += dotWidth;
                }
            }
            float x = w - 24f - total;
            for (int i = 0; i < facts.size(); i++) {
                String fact = facts.get(i);
                x += Tokens.drawText(g, fact, factsFont, Tokens.FG3, x, factsBaseline, 0f);
                if (i < facts.size() - 1) {
                    g.setColor(Tokens.alpha(Tokens.FG3, 0.5f));
                    g.setFont(factsFont);
                    g.drawString("\u00b7", x + 7f, factsBaseline);
                    x += dotWidth;
                }
            }
        } finally {
            g.dispose();
        }
    }
}
