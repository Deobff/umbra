package io.umbra.gui;

import io.umbra.gui.theme.Tokens;
import io.umbra.gui.ui.Buttons;
import io.umbra.gui.ui.PrimaryButton;

import javax.swing.AbstractAction;
import javax.swing.ActionMap;
import javax.swing.BorderFactory;
import javax.swing.InputMap;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.geom.RoundRectangle2D;

/**
 * Small modal dialogs painted in the same warm-paper/serif language as the main
 * window. They are used for overwrite confirmation, configuration errors and
 * short informational notes; long text scrolls.
 *
 * <p>In a headless JVM the methods return the safe default instead of throwing
 * (they are never used by the screenshot self-test).</p>
 */
public final class GuiDialogs {

    private GuiDialogs() {
    }

    /** Shows a confirmation dialog; returns true when the user accepts. */
    public static boolean confirm(Component parent, String title, String message,
                                  String acceptLabel, String cancelLabel) {
        if (GraphicsEnvironment.isHeadless()) {
            return false;
        }
        return show(parent, title, message, acceptLabel, cancelLabel, false);
    }

    /** Shows an error dialog and waits for acknowledgement. */
    public static void error(Component parent, String title, String message) {
        if (GraphicsEnvironment.isHeadless()) {
            System.err.println("[GUI] " + title + ": " + message);
            return;
        }
        show(parent, title, message, "OK", null, true);
    }

    /** Shows an informational dialog and waits for acknowledgement. */
    public static void info(Component parent, String title, String message) {
        if (GraphicsEnvironment.isHeadless()) {
            System.out.println("[GUI] " + title + ": " + message);
            return;
        }
        show(parent, title, message, "OK", null, false);
    }

    private static boolean show(Component parent, String title, String message,
                                String acceptLabel, String cancelLabel, boolean errorTone) {
        Window owner = parent == null ? null : javax.swing.SwingUtilities.getWindowAncestor(parent);
        final JDialog dialog = owner == null
                ? new JDialog() : new JDialog(owner);
        dialog.setUndecorated(true);
        dialog.setModal(true);
        dialog.setResizable(false);
        if (owner != null) {
            dialog.setLocationRelativeTo(owner);
        }
        dialog.setTitle(title);

        final DialogPanel panel = new DialogPanel(title, message, acceptLabel, cancelLabel,
                errorTone, dialog);
        dialog.setContentPane(panel);
        dialog.pack();
        dialog.setLocationRelativeTo(owner);
        bindKeys(dialog.getRootPane(), panel);
        dialog.setVisible(true);
        return panel.accepted();
    }

    private static void bindKeys(JRootPane root, final DialogPanel panel) {
        InputMap input = root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        ActionMap actions = root.getActionMap();
        input.put(KeyStroke.getKeyStroke("ESCAPE"), "umbra.close");
        actions.put("umbra.close", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                panel.reject();
            }
        });
        if (panel.acceptButton() != null) {
            root.setDefaultButton(panel.acceptButton());
        }
    }

    /** The painted dialog sheet. */
    private static final class DialogPanel extends JPanel {

        private final String title;
        private final String message;
        private final String acceptLabel;
        private final String cancelLabel;
        private final boolean errorTone;
        private final JDialog dialog;
        private final JTextArea text;
        private final JScrollPane scroll;
        private final javax.swing.JButton cancel;
        private final PrimaryButton accept;
        private boolean accepted;

        DialogPanel(String title, String message, String acceptLabel, String cancelLabel,
                    boolean errorTone, JDialog dialog) {
            super(null);
            this.title = title == null ? "Umbra" : title;
            this.message = message == null ? "" : message;
            this.acceptLabel = acceptLabel == null ? "OK" : acceptLabel;
            this.cancelLabel = cancelLabel;
            this.errorTone = errorTone;
            this.dialog = dialog;
            setOpaque(true);
            setBackground(Tokens.CANVAS);

            Font messageFont = Tokens.serifFor(this.message, 13f, Font.PLAIN);
            text = new JTextArea(this.message);
            text.setEditable(false);
            text.setOpaque(false);
            text.setLineWrap(true);
            text.setWrapStyleWord(true);
            text.setFont(messageFont);
            text.setForeground(Tokens.FG2);
            text.setBorder(BorderFactory.createEmptyBorder());
            text.setSize(384, Short.MAX_VALUE);
            int preferredHeight = text.getPreferredSize().height;
            int messageHeight = Math.min(230, Math.max(38, preferredHeight));
            if (preferredHeight > 230) {
                scroll = new JScrollPane(text);
                scroll.setBorder(BorderFactory.createEmptyBorder());
                scroll.setOpaque(false);
                scroll.getViewport().setOpaque(false);
                scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
                add(scroll);
            } else {
                scroll = null;
                add(text);
            }

            accept = (PrimaryButton) Buttons.primary(this.acceptLabel, new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    accepted = true;
                    DialogPanel.this.dialog.dispose();
                }
            });
            add(accept);
            if (cancelLabel != null) {
                cancel = Buttons.quiet(cancelLabel, new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        accepted = false;
                        DialogPanel.this.dialog.dispose();
                    }
                });
                add(cancel);
            } else {
                cancel = null;
            }

            int messageWidth = 384;
            int width = 440;
            int buttonsTop = 22 + 28 + messageHeight + 24;
            int height = buttonsTop + 36 + 22;
            setPreferredSize(new Dimension(width, height));
            text.setBounds(28, 56, messageWidth, messageHeight);
            if (scroll != null) {
                scroll.setBounds(28, 56, messageWidth, messageHeight);
            }
            accept.setBounds(width - 28 - 96, height - 22 - 36, 96, 36);
            if (cancel != null) {
                cancel.setBounds(width - 28 - 96 - 10 - 74, height - 22 - 30, 74, 30);
            }
        }

        PrimaryButton acceptButton() {
            return accept;
        }

        boolean accepted() {
            return accepted;
        }

        void reject() {
            accepted = false;
            dialog.dispose();
        }

        @Override
        protected void paintComponent(Graphics graphics) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                Tokens.prepare(g);
                g.setColor(Tokens.CANVAS);
                g.fillRect(0, 0, getWidth(), getHeight());
                RoundRectangle2D.Float sheet = new RoundRectangle2D.Float(
                        0.5f, 0.5f, getWidth() - 1f, getHeight() - 1f, 32f, 32f);
                g.setColor(new Color(255, 255, 255, 246));
                g.fill(sheet);
                g.setColor(Tokens.LINE_STRONG);
                g.setStroke(new java.awt.BasicStroke(1f));
                g.draw(sheet);

                float baseline = 24f + g.getFontMetrics(
                        Tokens.serifBold(17f)).getAscent();
                Tokens.drawText(g, title, Tokens.serifFor(title, 17f, Font.BOLD),
                        Tokens.FG, 28f, baseline, -0.005f);
                if (errorTone) {
                    g.setColor(Tokens.DANGER);
                    g.fill(new RoundRectangle2D.Float(28f, 38f, 26f, 2f, 2f, 2f));
                }
            } finally {
                g.dispose();
            }
        }
    }
}
