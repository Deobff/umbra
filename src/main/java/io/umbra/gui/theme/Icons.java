package io.umbra.gui.theme;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.geom.Path2D;

/**
 * Minimal vector icons drawn with Java 2D primitives.
 *
 * <p>The visual specification forbids emoji and coloured icons; these glyphs
 * are monochrome line drawings rendered in {@code --fg-3} / {@code --fg-2} and
 * never used as decoration.</p>
 */
public final class Icons {

    private Icons() {
    }

    /** A folder outline, used for "open output folder" and directory browsing. */
    public static void folder(Graphics2D g, double x, double y, double size, Color color) {
        Graphics2D g2 = stroke(g, color, 1.4f);
        Path2D.Double path = new Path2D.Double();
        double top = y + size * 0.22;
        double bottom = y + size * 0.82;
        path.moveTo(x + size * 0.10, top);
        path.lineTo(x + size * 0.10, bottom);
        path.lineTo(x + size * 0.90, bottom);
        path.lineTo(x + size * 0.90, top + size * 0.10);
        path.lineTo(x + size * 0.52, top + size * 0.10);
        path.lineTo(x + size * 0.45, top);
        path.lineTo(x + size * 0.18, top);
        path.closePath();
        g2.draw(path);
        g2.dispose();
    }

    /** A chevron pointing right at 0 degrees; callers rotate for expansion state. */
    public static void chevron(Graphics2D g, double cx, double cy, double size, Color color) {
        Graphics2D g2 = stroke(g, color, 1.5f);
        Path2D.Double path = new Path2D.Double();
        path.moveTo(cx - size * 0.28, cy - size * 0.45);
        path.lineTo(cx + size * 0.28, cy);
        path.lineTo(cx - size * 0.28, cy + size * 0.45);
        g2.draw(path);
        g2.dispose();
    }

    /** Three horizontal bars (collapsed navigation column). */
    public static void menu(Graphics2D g, double x, double y, double size, Color color) {
        Graphics2D g2 = stroke(g, color, 1.5f);
        double left = x + size * 0.16;
        double right = x + size * 0.84;
        for (int i = 0; i < 3; i++) {
            double yy = y + size * (0.28 + i * 0.22);
            g2.draw(new java.awt.geom.Line2D.Double(left, yy, right, yy));
        }
        g2.dispose();
    }

    /** A clean "x" without any coloured background. */
    public static void close(Graphics2D g, double x, double y, double size, Color color) {
        Graphics2D g2 = stroke(g, color, 1.5f);
        double inset = size * 0.24;
        g2.draw(new java.awt.geom.Line2D.Double(x + inset, y + inset,
                x + size - inset, y + size - inset));
        g2.draw(new java.awt.geom.Line2D.Double(x + size - inset, y + inset,
                x + inset, y + size - inset));
        g2.dispose();
    }

    /** An arrow pointing down into a tray; used by "load configuration". */
    public static void load(Graphics2D g, double x, double y, double size, Color color) {
        Graphics2D g2 = stroke(g, color, 1.4f);
        double cx = x + size / 2;
        g2.draw(new java.awt.geom.Line2D.Double(cx, y + size * 0.16, cx, y + size * 0.62));
        Path2D.Double head = new Path2D.Double();
        head.moveTo(cx - size * 0.16, y + size * 0.46);
        head.lineTo(cx, y + size * 0.64);
        head.lineTo(cx + size * 0.16, y + size * 0.46);
        g2.draw(head);
        g2.draw(new java.awt.geom.Line2D.Double(x + size * 0.18, y + size * 0.78,
                x + size * 0.82, y + size * 0.78));
        g2.dispose();
    }

    /** An arrow pointing up out of a tray; used by "save configuration". */
    public static void save(Graphics2D g, double x, double y, double size, Color color) {
        Graphics2D g2 = stroke(g, color, 1.4f);
        double cx = x + size / 2;
        g2.draw(new java.awt.geom.Line2D.Double(cx, y + size * 0.62, cx, y + size * 0.14));
        Path2D.Double head = new Path2D.Double();
        head.moveTo(cx - size * 0.16, y + size * 0.32);
        head.lineTo(cx, y + size * 0.14);
        head.lineTo(cx + size * 0.16, y + size * 0.32);
        g2.draw(head);
        g2.draw(new java.awt.geom.Line2D.Double(x + size * 0.18, y + size * 0.80,
                x + size * 0.82, y + size * 0.80));
        g2.dispose();
    }

    /** An arrow leaving a box; used by "open output folder". */
    public static void openExternal(Graphics2D g, double x, double y, double size, Color color) {
        Graphics2D g2 = stroke(g, color, 1.4f);
        Path2D.Double box = new Path2D.Double();
        double left = x + size * 0.14;
        double top = y + size * 0.34;
        double bottom = y + size * 0.86;
        double right = x + size * 0.66;
        box.moveTo(right, top);
        box.lineTo(left, top);
        box.lineTo(left, bottom);
        box.lineTo(right, bottom);
        g2.draw(box);
        g2.draw(new java.awt.geom.Line2D.Double(x + size * 0.52, y + size * 0.48,
                x + size * 0.88, y + size * 0.12));
        Path2D.Double arrow = new Path2D.Double();
        arrow.moveTo(x + size * 0.68, y + size * 0.12);
        arrow.lineTo(x + size * 0.88, y + size * 0.12);
        arrow.lineTo(x + size * 0.88, y + size * 0.32);
        g2.draw(arrow);
        g2.dispose();
    }

    private static Graphics2D stroke(Graphics2D g, Color color, float width) {
        Graphics2D g2 = (Graphics2D) g.create();
        Tokens.prepare(g2);
        g2.setColor(color);
        g2.setStroke(new BasicStroke(width, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        return g2;
    }
}
