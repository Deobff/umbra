package io.umbra.tests;

import io.umbra.gui.GuiModeOptions;
import io.umbra.gui.GuiRoot;
import io.umbra.gui.GuiScreenshot;
import io.umbra.gui.GuiSelfTest;
import io.umbra.gui.ui.ModeOptionsPanel;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

/**
 * Layout and rendering test for the desktop GUI.
 *
 * <p>Runs the shared {@link GuiSelfTest} structural suite (three-column skeleton,
 * responsive breakpoints, accessibility names, preset wiring, option/YAML round
 * trip) and additionally renders the assembled 1440x900 frame to a PNG to prove
 * the offscreen paint path really produces a layered image. Headless-safe.</p>
 */
public final class GuiLayoutTest {

    private static int checks;

    private GuiLayoutTest() {
    }

    public static void main(String[] args) throws Exception {
        int failures = GuiSelfTest.run();
        check(failures == 0, "GuiSelfTest reports no failures (" + failures + " failed)");

        Path temp = Files.createTempDirectory("umbra-gui-layout-");
        String oldHome = System.getProperty("user.home");
        try {
            System.setProperty("user.home", temp.toString());
            GuiRoot root = new GuiRoot(false);
            Path png = temp.resolve("idle-1440x900.png");
            GuiScreenshot.writePng(root, 1440, 900, png);
            check(Files.isRegularFile(png), "screenshot written");
            long size = Files.size(png);
            check(size > 15000, "screenshot is a real rendered image (" + size + " bytes)");
            BufferedImage image = ImageIO.read(png.toFile());
            check(image != null, "screenshot decodes as an image");
            if (image != null) {
                check(image.getWidth() == 1440, "screenshot width is 1440");
                check(image.getHeight() == 900, "screenshot height is 900");
                check(distinctColors(image) > 60, "screenshot has layered colour depth");
                // The corner must be the warm paper canvas (the aurora layers
                // may add a tiny, warm-tinted wash on top of #F6F5F2).
                int corner = image.getRGB(4, 4);
                int alpha = (corner >>> 24) & 0xFF;
                int r = (corner >> 16) & 0xFF;
                int gg = (corner >> 8) & 0xFF;
                int b = corner & 0xFF;
                check(alpha == 255, "screenshot is fully opaque");
                check(r >= gg && gg >= b && r - b >= 0 && r - b <= 14,
                        "warm paper canvas at the corner: #" + Integer.toHexString(corner)
                                + " (expected a warm off-white)");
            }

            // The per-mode detailed options sheet renders offscreen as well.
            ModeOptionsPanel options = new ModeOptionsPanel(
                    GuiModeOptions.defaults("Maximum"), "Maximum", null);
            Path optionsPng = temp.resolve("mode-options-900x700.png");
            GuiScreenshot.writePanel(options, ModeOptionsPanel.SHEET_WIDTH,
                    ModeOptionsPanel.SHEET_HEIGHT, optionsPng);
            check(Files.isRegularFile(optionsPng), "mode options screenshot written");
            long optionsSize = Files.size(optionsPng);
            check(optionsSize > 15000, "mode options screenshot has content ("
                    + optionsSize + " bytes)");
            BufferedImage optionsImage = ImageIO.read(optionsPng.toFile());
            check(optionsImage != null && optionsImage.getWidth() == 900
                            && optionsImage.getHeight() == 700,
                    "mode options screenshot is 900x700");
            check(options.controlCount() >= 100,
                    "mode options panel builds the full control set");
            int integerSpecs = 0;
            for (io.umbra.gui.GuiModeOptions.Spec spec
                    : io.umbra.gui.GuiModeOptions.allSpecs()) {
                if (spec.kind == io.umbra.gui.GuiModeOptions.Kind.INT) {
                    integerSpecs++;
                }
            }
            check(options.sliderCount() == integerSpecs,
                    "every integer option uses a slider (" + options.sliderCount()
                            + "/" + integerSpecs + ")");
            options.scrollToSection("Flow");
            Path sliderPng = temp.resolve("mode-options-sliders.png");
            GuiScreenshot.writePanel(options, io.umbra.gui.ui.ModeOptionsPanel.SHEET_WIDTH,
                    io.umbra.gui.ui.ModeOptionsPanel.SHEET_HEIGHT, sliderPng);
            check(Files.isRegularFile(sliderPng), "slider-heavy sheet renders");
            check(Files.size(sliderPng) > 15000, "slider-heavy sheet has content");
        } finally {
            System.setProperty("user.home", oldHome == null ? "" : oldHome);
            delete(temp);
        }
        System.out.println("GuiLayoutTest: " + checks + " checks passed");
    }

    private static int distinctColors(BufferedImage image) {
        Set<Integer> colors = new HashSet<Integer>();
        for (int y = 0; y < image.getHeight(); y += 5) {
            for (int x = 0; x < image.getWidth(); x += 5) {
                colors.add(Integer.valueOf(image.getRGB(x, y) & 0xFFFFFF));
            }
        }
        return colors.size();
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }

    private static void delete(Path directory) {
        try {
            if (!Files.exists(directory)) {
                return;
            }
            Files.walk(directory)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (Exception ignored) {
                            // Best effort temp cleanup.
                        }
                    });
        } catch (Exception ignored) {
            // Best effort temp cleanup.
        }
    }
}
