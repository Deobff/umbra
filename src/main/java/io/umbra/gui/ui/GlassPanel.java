package io.umbra.gui.ui;

import io.umbra.gui.theme.Aurora;
import io.umbra.gui.theme.Tokens;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GradientPaint;
import java.awt.Shape;
import java.awt.geom.Line2D;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;

/**
 * A frosted-glass surface.
 *
 * <p>Instead of faking glass with a flat white box, the panel samples the
 * painted aurora background underneath its bounds, blurs and saturates it, then
 * overlays the translucent white wash defined by the visual specification. A
 * 1px inset top highlight supplies the Apple-style "glass edge"; there is no
 * drop shadow anywhere.</p>
 *
 * <p>Glass strength is layered on purpose: toolbars are the most opaque, main
 * cards next, the side column the lightest, exactly as the spec requires.</p>
 */
public class GlassPanel extends JPanel {

    /** Glass variants from the design specification. */
    public enum Variant {
        /** 64px top bar: white 0.72, blur 28. */
        TOOLBAR,
        /** 44px bottom status bar: white 0.72, blur 28. */
        STATUS_BAR,
        /** Centre console: white 0.72 -> 0.55 vertical gradient, blur 32. */
        MAIN,
        /** Statistics card: white 0.70 -> 0.50 gradient, blur 24. */
        STAT,
        /** Left configuration column: white 0.45, blur 24. */
        SIDEBAR,
        /** Narrow-window drawer: white 0.85, blur 36. */
        DRAWER,
        /** Dialog sheet: warm white paper, not glass. */
        PAPER
    }

    private final Variant variant;
    private final int radius;
    private Color outline;

    private BufferedImage blurCache;
    private int cacheWidth = -1;
    private int cacheHeight = -1;
    private int cacheX;
    private int cacheY;
    private BufferedImage cacheSurface;

    public GlassPanel(Variant variant, int radius) {
        this.variant = variant;
        this.radius = radius;
        setOpaque(false);
        setLayout(null);
    }

    public GlassPanel(Variant variant) {
        this(variant, variant == Variant.MAIN || variant == Variant.STAT
                || variant == Variant.PAPER ? Tokens.RADIUS_CARD : 0);
    }

    public Variant variant() {
        return variant;
    }

    /** Overrides the stroke around the panel (drag / running states). */
    public void setOutline(Color color) {
        this.outline = color;
        repaint();
    }

    public void clearOutline() {
        if (outline != null) {
            outline = null;
            repaint();
        }
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();
            if (w <= 0 || h <= 0) {
                return;
            }
            Shape shape = new RoundRectangle2D.Float(0f, 0f, w, h, radius * 2f, radius * 2f);
            BufferedImage surface = surfaceOf();
            if (variant == Variant.PAPER) {
                g.setColor(Tokens.alpha(Color.WHITE, 0.94f));
                g.fill(shape);
            } else {
                paintGlass(g, shape, surface, w, h);
            }
            paintTopHighlight(g, shape, w);
            paintBorder(g, shape, w, h);
        } finally {
            g.dispose();
        }
    }

    private void paintGlass(Graphics2D g, Shape shape, BufferedImage surface, int w, int h) {
        BufferedImage blurred = cachedBlur(surface, w, h);
        if (blurred != null) {
            Shape previous = g.getClip();
            g.clip(shape);
            g.drawImage(blurred, 0, 0, null);
            g.setClip(previous);
        } else {
            g.setColor(Tokens.CANVAS);
            g.fill(shape);
        }
        Shape previous = g.getClip();
        g.clip(shape);
        switch (variant) {
            case TOOLBAR:
            case STATUS_BAR:
                g.setColor(Tokens.alpha(Color.WHITE, 0.72f));
                g.fillRect(0, 0, w, h);
                break;
            case SIDEBAR:
                g.setColor(Tokens.alpha(Color.WHITE, 0.45f));
                g.fillRect(0, 0, w, h);
                break;
            case DRAWER:
                g.setColor(Tokens.alpha(Color.WHITE, 0.85f));
                g.fillRect(0, 0, w, h);
                break;
            case MAIN:
                g.setPaint(new GradientPaint(0f, 0f, Tokens.alpha(Color.WHITE, 0.72f),
                        0f, h, Tokens.alpha(Color.WHITE, 0.55f)));
                g.fillRect(0, 0, w, h);
                break;
            case STAT:
                g.setPaint(new GradientPaint(0f, 0f, Tokens.alpha(Color.WHITE, 0.70f),
                        0f, h, Tokens.alpha(Color.WHITE, 0.50f)));
                g.fillRect(0, 0, w, h);
                break;
            default:
                g.setColor(Tokens.alpha(Color.WHITE, 0.70f));
                g.fillRect(0, 0, w, h);
                break;
        }
        g.setClip(previous);
    }

    private void paintTopHighlight(Graphics2D g, Shape shape, int w) {
        if (variant == Variant.PAPER) {
            return;
        }
        Shape previous = g.getClip();
        g.clip(shape);
        float alpha = variant == Variant.SIDEBAR ? 0.55f : 0.90f;
        g.setColor(Tokens.alpha(Color.WHITE, alpha));
        g.setStroke(new java.awt.BasicStroke(1f));
        g.draw(new Line2D.Float(0f, 0.5f, w, 0.5f));
        g.setClip(previous);
    }

    private void paintBorder(Graphics2D g, Shape shape, int w, int h) {
        if (outline != null) {
            g.setColor(outline);
            g.setStroke(new java.awt.BasicStroke(1f));
            g.draw(new RoundRectangle2D.Float(0.5f, 0.5f, w - 1f, h - 1f,
                    radius * 2f, radius * 2f));
            return;
        }
        switch (variant) {
            case TOOLBAR:
                hairline(g, 0f, h - 0.5f, w, h - 0.5f, Tokens.LINE);
                break;
            case STATUS_BAR:
                hairline(g, 0f, 0.5f, w, 0.5f, Tokens.LINE);
                break;
            case SIDEBAR:
                hairline(g, w - 0.5f, 0f, w - 0.5f, h, Tokens.LINE);
                break;
            case MAIN:
            case STAT:
            case DRAWER:
                g.setColor(new Color(0, 0, 0, 15));
                g.setStroke(new java.awt.BasicStroke(1f));
                g.draw(new RoundRectangle2D.Float(0.5f, 0.5f, w - 1f, h - 1f,
                        radius * 2f, radius * 2f));
                break;
            case PAPER:
                g.setColor(Tokens.LINE_STRONG);
                g.setStroke(new java.awt.BasicStroke(1f));
                g.draw(new RoundRectangle2D.Float(0.5f, 0.5f, w - 1f, h - 1f,
                        radius * 2f, radius * 2f));
                break;
            default:
                break;
        }
    }

    private static void hairline(Graphics2D g, float x1, float y1, float x2, float y2,
                                 Color color) {
        g.setColor(color);
        g.setStroke(new java.awt.BasicStroke(1f));
        g.draw(new Line2D.Float(x1, y1, x2, y2));
    }

    private BufferedImage surfaceOf() {
        Component cursor = getParent();
        while (cursor != null) {
            if (cursor instanceof Aurora.SurfaceProvider) {
                return ((Aurora.SurfaceProvider) cursor).surfaceImage();
            }
            cursor = cursor.getParent();
        }
        return null;
    }

    private BufferedImage cachedBlur(BufferedImage surface, int w, int h) {
        Component provider = getParent();
        while (provider != null && !(provider instanceof Aurora.SurfaceProvider)) {
            provider = provider.getParent();
        }
        java.awt.Point origin = provider == null
                ? new java.awt.Point(0, 0)
                : SwingUtilities.convertPoint(this, 0, 0, provider);
        if (blurCache != null && cacheWidth == w && cacheHeight == h
                && cacheX == origin.x && cacheY == origin.y
                && cacheSurface == surface) {
            return blurCache;
        }
        if (surface == null) {
            return null;
        }
        int radiusPx = variant == Variant.STAT ? 24
                : (variant == Variant.MAIN ? 32 : (variant == Variant.DRAWER ? 36 : 28));
        blurCache = Aurora.sampleBlurred(surface, origin.x, origin.y, w, h, radiusPx);
        cacheWidth = w;
        cacheHeight = h;
        cacheX = origin.x;
        cacheY = origin.y;
        cacheSurface = surface;
        return blurCache;
    }
}
