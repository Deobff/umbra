package io.umbra.gui;

import io.umbra.gui.ui.ModeOptionsPanel;

import javax.swing.AbstractAction;
import javax.swing.ActionMap;
import javax.swing.InputMap;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.GraphicsEnvironment;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Map;

/**
 * Modal wrapper for {@link ModeOptionsPanel}: the per-mode detailed option
 * editor opened from the Preset group ("Mode options...").
 *
 * <p>Returns {@code null} when the user cancels, otherwise the edited values and
 * the selected mode ("Custom" after any edit).</p>
 */
public final class GuiModeOptionsDialog {

    /** Accepted result of the dialog. */
    public static final class Result {
        public final Map<String, String> values;
        public final String mode;

        Result(Map<String, String> values, String mode) {
            this.values = values;
            this.mode = mode;
        }
    }

    private GuiModeOptionsDialog() {
    }

    /**
     * Opens the dialog and blocks until OK/Cancel.
     *
     * @param parent owning component (used for modality and centring)
     * @param values current detailed values (may be incomplete)
     * @param mode   current mode name
     * @return edited values or {@code null} when cancelled
     */
    public static Result show(Component parent, Map<String, String> values, String mode) {
        if (GraphicsEnvironment.isHeadless()) {
            return null;
        }
        Window owner = parent == null ? null
                : SwingUtilities.getWindowAncestor(parent);
        final JDialog dialog = owner == null ? new JDialog() : new JDialog(owner);
        dialog.setUndecorated(true);
        dialog.setModal(true);
        dialog.setTitle("Mode options");
        final Result[] result = new Result[1];
        final ModeOptionsPanel panel = new ModeOptionsPanel(values, mode,
                new ModeOptionsPanel.Listener() {
                    @Override
                    public void ok(ModeOptionsPanel source) {
                        String error = source.validationError();
                        if (error != null) {
                            GuiDialogs.error(source, "Check the mode options", error);
                            return;
                        }
                        result[0] = new Result(source.values(), source.selectedMode());
                        dialog.dispose();
                    }

                    @Override
                    public void cancel(ModeOptionsPanel source) {
                        dialog.dispose();
                    }
                });
        dialog.setContentPane(panel);
        dialog.setSize(ModeOptionsPanel.SHEET_WIDTH, ModeOptionsPanel.SHEET_HEIGHT);
        dialog.setLocationRelativeTo(owner);
        dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
        dialog.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                dialog.dispose();
            }
        });
        InputMap input = dialog.getRootPane().getInputMap(
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        ActionMap actions = dialog.getRootPane().getActionMap();
        input.put(KeyStroke.getKeyStroke("ESCAPE"), "umbra.mode.cancel");
        actions.put("umbra.mode.cancel", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dialog.dispose();
            }
        });
        dialog.getRootPane().setDefaultButton(panel.okButton());
        dialog.setVisible(true);
        return result[0];
    }
}
