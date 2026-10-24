package io.umbra.gui;

import javax.swing.JFrame;
import java.awt.Dimension;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * Native window shell around {@link GuiRoot}.
 *
 * <p>All layout, painting and behaviour live in the panel so the same UI can be
 * rendered offscreen; this class only provides the OS window, the title, the
 * minimum size and the close confirmation.</p>
 */
public final class GuiFrame extends JFrame {

    private final GuiRoot root;

    public GuiFrame() {
        super("Umbra " + GuiConfig.VERSION);
        boolean animate = !"false".equalsIgnoreCase(
                System.getProperty("umbra.gui.animations", "true"));
        root = new GuiRoot(animate);
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        setContentPane(root);
        setMinimumSize(new Dimension(760, 560));
        setSize(1440, 900);
        setLocationRelativeTo(null);
        root.setCloseHandler(new Runnable() {
            @Override
            public void run() {
                dispose();
            }
        });
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                root.requestClose();
            }
        });
    }

    /** The assembled UI panel (used by the self test). */
    public GuiRoot root() {
        return root;
    }
}
