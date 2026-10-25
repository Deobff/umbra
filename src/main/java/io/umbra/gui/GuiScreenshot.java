package io.umbra.gui;

import io.umbra.gui.theme.Tokens;

import javax.imageio.ImageIO;
import javax.swing.JComponent;
import java.awt.Component;
import java.awt.Container;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Deterministic offscreen rendering of the assembled GUI.
 *
 * <p>Both the main window ({@link GuiRoot}) and isolated sheets such as the
 * per-mode option dialog ({@code ModeOptionsPanel}) are plain panels, so they
 * can be laid out and painted into a {@link BufferedImage} without a display or
 * {@code java.awt.Robot}. This is what {@code --screenshot},
 * {@code --options-screenshot} and the layout test use; it works on a headless
 * CI as well as on a desktop.</p>
 */
public final class GuiScreenshot {

    private GuiScreenshot() {
    }

    /** Renders the main window panel tree at the requested size. */
    public static BufferedImage render(GuiRoot root, int width, int height) {
        return renderPanel(root, width, height);
    }

    /** Renders any panel tree at the requested size. */
    public static BufferedImage renderPanel(JComponent panel, int width, int height) {
        int w = Math.max(320, width);
        int h = Math.max(240, height);
        panel.setSize(w, h);
        layoutTree(panel);
        BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        try {
            Tokens.prepare(g);
            panel.paint(g);
        } finally {
            g.dispose();
        }
        return image;
    }

    /** Renders the main window panel tree and writes it as a PNG file. */
    public static void writePng(GuiRoot root, int width, int height, Path file)
            throws IOException {
        writePanel(root, width, height, file);
    }

    /** Renders any panel tree and writes it as a PNG file. */
    public static void writePanel(JComponent panel, int width, int height, Path file)
            throws IOException {
        BufferedImage image = renderPanel(panel, width, height);
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        String name = file.getFileName() == null ? "" : file.getFileName().toString();
        if (name.toLowerCase(java.util.Locale.ROOT).endsWith(".png")) {
            ImageIO.write(image, "png", file.toFile());
        } else {
            ImageIO.write(image, "png", new java.io.File(file.toFile().getAbsolutePath() + ".png"));
        }
    }

    /** Recursively lays out the whole component tree without a native peer. */
    public static void layoutTree(Component component) {
        if (!(component instanceof Container)) {
            return;
        }
        Container container = (Container) component;
        container.doLayout();
        for (Component child : container.getComponents()) {
            layoutTree(child);
        }
    }
}
