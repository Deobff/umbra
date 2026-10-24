package io.umbra.gui.ui;

import javax.swing.Action;
import javax.swing.JButton;
import java.awt.event.ActionListener;

/**
 * Public factories for the custom-painted button family so the main GUI
 * package can create quiet and icon buttons without exposing their classes.
 */
public final class Buttons {

    private Buttons() {
    }

    /** A borderless quiet text button (secondary action). */
    public static JButton quiet(String text, ActionListener action) {
        QuietButton button = new QuietButton(text);
        if (action != null) {
            button.addActionListener(action);
        }
        return button;
    }

    /** A 28x28 icon button with a mandatory accessible name. */
    public static JButton icon(int icon, String accessibleName, String tooltip,
                               ActionListener action) {
        IconButton button = new IconButton(icon, accessibleName, tooltip);
        if (action != null) {
            button.addActionListener(action);
        }
        return button;
    }

    /** A primary accent button. */
    public static PrimaryButton primary(String text, ActionListener action) {
        PrimaryButton button = new PrimaryButton(text);
        if (action != null) {
            button.addActionListener(action);
        }
        return button;
    }

    /** Icon constants mirrored from {@link IconButton} for callers. */
    public static final class Icons {
        public static final int FOLDER = IconButton.FOLDER;
        public static final int CLEAR = IconButton.CLEAR;
        public static final int MENU = IconButton.MENU;
        public static final int LOAD = IconButton.LOAD;
        public static final int SAVE = IconButton.SAVE;
        public static final int OPEN = IconButton.OPEN;

        private Icons() {
        }
    }

    /** Unused helper kept to make the Action overload discoverable. */
    public static void bind(JButton button, Action action) {
        if (button != null && action != null) {
            button.setAction(action);
        }
    }
}
