package io.umbra.gui.theme;

import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.MultipleGradientPaint;
import java.awt.RadialGradientPaint;
import java.awt.RenderingHints;
import java.awt.geom.Point2D;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;

/**
 * Paints the warm-paper aurora background and provides the blur sampling used
 * by the frosted-glass panels.
 *
 * <p>The background has three layers exactly as specified: a large breathing
 * blue glow fixed above centre, three drifting colour blobs (blue, cyan,
 * violet) and a barely visible vignette. It is rendered once into an offscreen
 * image; every glass panel samples and blurs that image, which is what makes
 * the glass "frosted" instead of a flat white box.</p>
 *
 * <p>Unlike the web specification the layers are static rather than animated:
 * an infinite Swing repaint of a 1440x900 canvas costs CPU for a barely visible
 * effect, and static layers keep {@code --screenshot} deterministic.</p>
 */
public final class Aurora {

    private Aurora() {
    }

    /** Anything that can hand out the painted background image of the window. */
    public interface SurfaceProvider {
        /** Current background image, or {@code null} when not painted yet. */
        BufferedImage surfaceImage();
    }

    /**
     * Renders the layered aurora background.
     *
     * @param width  canvas width in pixels
     * @param height canvas height in pixels
     * @return RGB background image
     */
    public static BufferedImage render(int width, int height) {
        int w = Math.max(1, width);
        int h = Math.max(1, height);
        BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        try {
            Tokens.prepare(g);
            g.setColor(Tokens.CANVAS);
            g.fillRect(0, 0, w, h);

            // Layer 1: breathing glow, centre at 44% height, size 130vmax.
            float glowRadius = Math.max(w, h) * 0.65f;
            radial(g, w, h, w * 0.5f, h * 0.44f, glowRadius,
                    new float[]{0f, 0.30f, 0.58f},
                    new Color[]{
                            Tokens.alpha(Tokens.GLOW_BLUE, 0.065f),
                            Tokens.alpha(Tokens.GLOW_BLUE, 0.020f),
                            Tokens.alpha(Tokens.GLOW_BLUE, 0f)});

            // Layer 2: three drifting blobs. Positions are percentages of the
            // canvas with the blob size centred on that anchor.
            blob(g, w, h, 720f, -0.15f, 0.05f, Tokens.GLOW_BLUE, 0.10f, 0.03f);
            blob(g, w, h, 620f, 0.88f, 0.35f, Tokens.GLOW_CYAN, 0.08f, 0.025f);
            blob(g, w, h, 520f, 0.35f, 0.88f, Tokens.GLOW_VIOLET, 0.07f, 0.02f);
            // Layer 3: vignette. Almost invisible on warm paper; it only keeps
            // the centre of the canvas brighter than the edges.
            float vignette = (float) Math.hypot(w, h) * 0.55f;
            g.setPaint(new RadialGradientPaint(
                    new Point2D.Float(w * 0.5f, h * 0.5f), vignette,
                    new float[]{0.55f, 1f},
                    new Color[]{new Color(0, 0, 0, 0), new Color(0, 0, 0, 6)},
                    MultipleGradientPaint.CycleMethod.NO_CYCLE));
            g.fillRect(0, 0, w, h);
        } finally {
            g.dispose();
        }
        return image;
    }

    private static void radial(Graphics2D g, int canvasW, int canvasH, float cx, float cy,
                               float radius, float[] fractions, Color[] colors) {
        float r = Math.max(1f, radius);
        g.setPaint(new RadialGradientPaint(new Point2D.Float(cx, cy), r, fractions, colors,
                MultipleGradientPaint.CycleMethod.NO_CYCLE));
        // Gradient stops are transparent at the rim, so one full-canvas fill is
        // enough and cannot leak colour past the intended radius.
        g.fillRect(0, 0, canvasW, canvasH);
    }

    private static void blob(Graphics2D g, int canvasW, int canvasH, float size,
                             float anchorX, float anchorY, Color color,
                             float centerAlpha, float midAlpha) {
        float cx = anchorX * canvasW + size / 2f;
        float cy = anchorY * canvasH + size / 2f;
        radial(g, canvasW, canvasH, cx, cy, size / 2f,
                new float[]{0f, 0.35f, 0.70f},
                new Color[]{
                        Tokens.alpha(color, centerAlpha),
                        Tokens.alpha(color, midAlpha),
                        Tokens.alpha(color, 0f)});
    }

    /**
     * Samples the background under a rectangle and blurs it for the frosted
     * glass effect.
     *
     * <p>The blur is a downsample/upsample pair with a saturation boost, which
     * is both fast and visually close to a {@code backdrop-filter} blur at this
     * scale. Missing parts at the canvas edge are filled with the paper colour.</p>
     *
     * @param surface painted background
     * @param x       left edge in surface coordinates
     * @param y       top edge in surface coordinates
     * @param width   sample width
     * @param height  sample height
     * @param radius  requested blur radius in px (the higher, the softer)
     * @return small RGB image ready to be stretched over the panel
     */
    public static BufferedImage sampleBlurred(BufferedImage surface, int x, int y,
                                              int width, int height, int radius) {
        int w = Math.max(1, width);
        int h = Math.max(1, height);
        BufferedImage sample = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = sample.createGraphics();
        try {
            g.setColor(Tokens.CANVAS);
            g.fillRect(0, 0, w, h);
            if (surface != null) {
                g.drawImage(surface, 0, 0, w, h, x, y, x + w, y + h, null);
            }
        } finally {
            g.dispose();
        }
        int factor = Math.max(2, Math.min(12, radius / 2));
        int dw = Math.max(1, Math.round(w / (float) factor));
        int dh = Math.max(1, Math.round(h / (float) factor));
        BufferedImage small = new BufferedImage(dw, dh, BufferedImage.TYPE_INT_RGB);
        Graphics2D sg = small.createGraphics();
        try {
            sg.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                    RenderingHints.VALUE_INTERPOLATION_BILINEAR);
            sg.drawImage(sample, 0, 0, dw, dh, 0, 0, w, h, null);
        } finally {
            sg.dispose();
        }
        saturate(small, 1.8f);
        BufferedImage blurred = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D bg = blurred.createGraphics();
        try {
            bg.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                    RenderingHints.VALUE_INTERPOLATION_BILINEAR);
            bg.drawImage(small, 0, 0, w, h, 0, 0, dw, dh, null);
        } finally {
            bg.dispose();
        }
        return blurred;
    }

    /** Multiplies HSB saturation of every pixel (glass needs 180% saturation). */
    private static void saturate(BufferedImage image, float factor) {
        int w = image.getWidth();
        int h = image.getHeight();
        float[] hsb = new float[3];
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int rgb = image.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int gg = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;
                Color.RGBtoHSB(r, gg, b, hsb);
                hsb[1] = Math.min(1f, hsb[1] * factor);
                int saturated = Color.HSBtoRGB(hsb[0], hsb[1], hsb[2]);
                image.setRGB(x, y, saturated);
            }
        }
    }

    /** Fills a rounded rectangle. */
    public static void fillRoundRect(Graphics2D g, int x, int y, int w, int h, int radius) {
        g.fill(new RoundRectangle2D.Float(x, y, w, h, radius, radius));
    }

    /** Short constant-time no-op used by clients that need a compile anchor. */
    public static void noop() {
        // Intentionally empty.
    }

    /** Composites a translucent white wash; used by the glass panels. */
    public static void whiteWash(Graphics2D g, Color color) {
        g.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER));
        g.setColor(color);
    }
}
