package io.umbra.gui.ui;

import io.umbra.gui.theme.Tokens;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.event.ActionListener;

/**
 * The advanced section of the configuration column: native compiler path plus a
 * free-form {@code key=value} editor that can set any advanced option the CLI
 * accepts ({@code string.engine}, {@code vm2.encryptPayload}, ...).
 */
public class AdvancedEditor extends JPanel {

    public static final int HEIGHT = 196;

    private final PathRow compilerRow;
    private final GlassTextArea options;
    private final JScrollPane scroll;

    public AdvancedEditor(String compilerPlaceholder, String optionsPlaceholder,
                          ActionListener browseCompiler) {
        super(null);
        setOpaque(false);
        setPreferredSize(new java.awt.Dimension(Tokens.SIDEBAR_WIDTH - 30, HEIGHT));
        setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, HEIGHT));
        compilerRow = new PathRow("Native compiler", compilerPlaceholder, true,
                "Choose native compiler", "Run a file chooser for the native C compiler",
                browseCompiler);
        add(compilerRow);
        options = new GlassTextArea(optionsPlaceholder, 4);
        options.getAccessibleContext().setAccessibleName("Advanced options");
        options.getAccessibleContext().setAccessibleDescription(
                "One key=value per line; values override the switches above.");
        scroll = new JScrollPane(options);
        Scrollbars.style(scroll);
        add(scroll);
    }

    public JTextField compilerField() {
        return compilerRow.field();
    }

    public GlassTextArea optionsArea() {
        return options;
    }

    public String getOptionsText() {
        return options.getText();
    }

    public void setOptionsText(String text) {
        options.setText(text == null ? "" : text);
        options.setCaretPosition(0);
    }

    @Override
    public void doLayout() {
        int w = getWidth();
        compilerRow.setBounds(0, 0, w, PathRow.HEIGHT);
        compilerRow.doLayout();
        scroll.setBounds(32, 76, w - 44, 108);
        options.setSize(Math.max(40, scroll.getWidth() - 8), options.getPreferredSize().height);
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            FontMetrics metrics = g.getFontMetrics(Tokens.serifBold(Tokens.CAPS_SIZE));
            float baseline = 62f + metrics.getAscent() + 2f;
            Tokens.drawCaps(g, "Advanced options", Tokens.FG3, 32f, baseline,
                    Tokens.CAPS_SIZE, 0.18f);
        } finally {
            g.dispose();
        }
    }
}
