package io.umbra.gui.theme;

import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.RenderingHints;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Design tokens and type system for the "Apple Books light glass" GUI.
 *
 * <p>Everything visual in the GUI is derived from this class so the look can be
 * changed in one place. The type face is a serif stack (Georgia first) with a
 * CJK fallback chain, plus one monospace stack for the seed field, the log and
 * status-bar facts. No sans-serif UI family is ever selected on purpose.</p>
 *
 * <p>Values mirror the visual specification: warm paper canvas {@code #F6F5F2},
 * Apple ink {@code #1D1D1F}, accent {@code #007AFF}, 16px cards / 10px inputs /
 * 20px pills, 64px top bar, 44px status bar, 280px configuration column and
 * 240px statistics column.</p>
 */
public final class Tokens {

    private Tokens() {
    }

    /* ------------------------------------------------------------ colours */

    public static final Color CANVAS = new Color(0xF6F5F2);
    public static final Color FG = new Color(0x1D1D1F);
    public static final Color FG2 = new Color(0x6E6E73);
    public static final Color FG3 = new Color(0xAEAEB2);
    /** rgba(0,0,0,0.07) */
    public static final Color LINE = new Color(0, 0, 0, 18);
    /** rgba(0,0,0,0.10) */
    public static final Color LINE_STRONG = new Color(0, 0, 0, 26);
    public static final Color ACCENT = new Color(0x007AFF);
    public static final Color DANGER = new Color(0xFF3B30);
    public static final Color SUCCESS = new Color(0x34C759);

    /** Background aurora colours (background layer only, never UI decoration). */
    public static final Color GLOW_BLUE = new Color(41, 151, 255);
    public static final Color GLOW_CYAN = new Color(41, 214, 255);
    public static final Color GLOW_VIOLET = new Color(139, 92, 255);

    /* ------------------------------------------------------------ metrics */

    public static final int TOP_BAR = 64;
    public static final int STATUS_BAR = 44;
    public static final int SIDEBAR_WIDTH = 280;
    public static final int STATS_WIDTH = 240;
    public static final int RADIUS_CARD = 16;
    public static final int RADIUS_CONTROL = 10;
    public static final int RADIUS_PILL = 20;
    public static final int WIDE_BREAKPOINT = 1100;
    public static final int COMPACT_BREAKPOINT = 900;
    public static final int PAD = 16;
    public static final int GAP = 12;

    /* --------------------------------------------------------------- type */

    /** Serif UI stack: Georgia heads English text, Songti/SimSun continue CJK. */
    private static final String[] SERIF_STACK = {
            "Georgia", "Times New Roman", "Songti SC", "STSong", "SimSun"
    };
    /** CJK-only fallbacks, kept serif per the specification. */
    private static final String[] CJK_STACK = {"Songti SC", "STSong", "SimSun"};
    private static final String[] MONO_STACK = {
            "Courier New", "Courier", "Menlo", "Consolas", "Monospaced"
    };

    public static final float BRAND_SIZE = 21f;
    public static final float GROUP_SIZE = 14f;
    public static final float BODY_SIZE = 13f;
    public static final float BUTTON_SIZE = 13.5f;
    public static final float CAPS_SIZE = 10.5f;
    public static final float STAT_SIZE = 30f;
    public static final float STATUS_SIZE = 13.5f;
    public static final float FACTS_SIZE = 11f;

    private static final String serifFamily = pickFamily(SERIF_STACK, Font.SERIF);
    private static final String monoFamily = pickFamily(MONO_STACK, Font.MONOSPACED);
    private static final Set<String> available = new HashSet<String>(
            Arrays.asList(GraphicsEnvironment.getLocalGraphicsEnvironment()
                    .getAvailableFontFamilyNames()));

    /** True when the JVM could load any serif family besides the logical one. */
    public static boolean hasRealSerif() {
        return !Font.SERIF.equals(serifFamily);
    }

    /** True when a physical monospace family (Courier/Consolas/Menlo) exists. */
    public static boolean hasRealMono() {
        return !Font.MONOSPACED.equals(monoFamily);
    }

    private static String pickFamily(String[] stack, String logical) {
        Set<String> names = new HashSet<String>(Arrays.asList(
                GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames()));
        for (String family : stack) {
            if (names.contains(family)) {
                return family;
            }
        }
        return logical;
    }

    public static Font serif(float size) {
        return new Font(serifFamily, Font.PLAIN, 1).deriveFont(size);
    }

    public static Font serifBold(float size) {
        return new Font(serifFamily, Font.BOLD, 1).deriveFont(size);
    }

    public static Font serifItalic(float size) {
        return new Font(serifFamily, Font.ITALIC, 1).deriveFont(size);
    }

    public static Font mono(float size) {
        return new Font(monoFamily, Font.PLAIN, 1).deriveFont(size);
    }

    public static Font monoBold(float size) {
        return new Font(monoFamily, Font.BOLD, 1).deriveFont(size);
    }

    /**
     * Returns a serif font able to display {@code text}. Pure Latin text keeps
     * Georgia; CJK text falls back to the serif CJK chain so mixed labels never
     * render as tofu boxes.
     */
    public static Font serifFor(String text, float size, int style) {
        Font latin = new Font(serifFamily, style, 1).deriveFont(size);
        if (text == null || text.isEmpty() || latin.canDisplayUpTo(text) < 0) {
            return latin;
        }
        for (String cjk : CJK_STACK) {
            if (!available.contains(cjk)) {
                continue;
            }
            Font candidate = new Font(cjk, style, 1).deriveFont(size);
            if (candidate.canDisplayUpTo(text) < 0) {
                return candidate;
            }
        }
        return new Font(Font.SERIF, style, 1).deriveFont(size);
    }

    /** Same fallback discipline for the monospace log/seed text. */
    public static Font monoFor(String text, float size, int style) {
        Font monoFont = new Font(monoFamily, style, 1).deriveFont(size);
        if (text == null || text.isEmpty() || monoFont.canDisplayUpTo(text) < 0) {
            return monoFont;
        }
        for (String cjk : CJK_STACK) {
            if (!available.contains(cjk)) {
                continue;
            }
            Font candidate = new Font(cjk, style, 1).deriveFont(size);
            if (candidate.canDisplayUpTo(text) < 0) {
                return candidate;
            }
        }
        return new Font(Font.SERIF, style, 1).deriveFont(size);
    }

    /* -------------------------------------------------------------- colour */

    public static Color alpha(Color color, float alpha) {
        int a = Math.round(Math.max(0f, Math.min(1f, alpha)) * 255f);
        return new Color(color.getRed(), color.getGreen(), color.getBlue(), a);
    }

    public static Color withAlpha(Color color, int alpha) {
        return new Color(color.getRed(), color.getGreen(), color.getBlue(),
                Math.max(0, Math.min(255, alpha)));
    }

    /** Linear interpolation between two colours ({@code t} in 0..1). */
    public static Color mix(Color from, Color to, float t) {
        float f = Math.max(0f, Math.min(1f, t));
        return new Color(
                Math.round(from.getRed() + (to.getRed() - from.getRed()) * f),
                Math.round(from.getGreen() + (to.getGreen() - from.getGreen()) * f),
                Math.round(from.getBlue() + (to.getBlue() - from.getBlue()) * f),
                Math.round(from.getAlpha() + (to.getAlpha() - from.getAlpha()) * f));
    }

    /* --------------------------------------------------------------- easing */

    /** Decelerating curve close to cubic-bezier(0.16, 1, 0.3, 1); never bounces. */
    public static float easeOut(double t) {
        double x = Math.max(0d, Math.min(1d, t));
        return (float) (1d - Math.pow(1d - x, 3d));
    }

    public static float clamp01(float value) {
        return value < 0f ? 0f : (value > 1f ? 1f : value);
    }

    /* ---------------------------------------------------------------- text */

    /** Renders on a warm paper background with good antialiasing. */
    public static void prepare(Graphics2D g) {
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        g.setRenderingHint(RenderingHints.KEY_FRACTIONALMETRICS,
                RenderingHints.VALUE_FRACTIONALMETRICS_ON);
    }

    /** Width of {@code text} including letter tracking (em units). */
    public static float textWidth(Graphics2D g, String text, Font font, float tracking) {
        if (text == null || text.isEmpty()) {
            return 0f;
        }
        FontMetrics metrics = g.getFontMetrics(font);
        float track = tracking * font.getSize2D();
        float width = 0f;
        for (int i = 0; i < text.length(); i++) {
            width += metrics.charWidth(text.charAt(i));
            if (i < text.length() - 1) {
                width += track;
            }
        }
        return width;
    }

    /** Width of a single line without tracking. */
    public static float textWidth(Graphics2D g, String text, Font font) {
        return textWidth(g, text, font, 0f);
    }

    /** Draws one line with optional letter tracking; returns the advance width. */
    public static float drawText(Graphics2D g, String text, Font font, Color color,
                                 float x, float baseline, float tracking) {
        if (text == null || text.isEmpty()) {
            return 0f;
        }
        g.setFont(font);
        g.setColor(color);
        if (tracking == 0f) {
            g.drawString(text, x, baseline);
            return g.getFontMetrics(font).stringWidth(text);
        }
        FontMetrics metrics = g.getFontMetrics(font);
        float track = tracking * font.getSize2D();
        float cursor = x;
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            g.drawString(String.valueOf(ch), cursor, baseline);
            cursor += metrics.charWidth(ch);
            if (i < text.length() - 1) {
                cursor += track;
            }
        }
        return cursor - x;
    }

    public static void drawCentered(Graphics2D g, String text, Font font, Color color,
                                    float centerX, float baseline, float tracking) {
        float width = textWidth(g, text, font, tracking);
        drawText(g, text, font, color, centerX - width / 2f, baseline, tracking);
    }

    /** Uppercase small-caps label as used for group captions and stat labels. */
    public static void drawCaps(Graphics2D g, String text, Color color, float x, float baseline,
                                float size, float tracking) {
        drawText(g, upper(text), serifFor(text, size, Font.BOLD), color, x, baseline, tracking);
    }

    public static float capsWidth(Graphics2D g, String text, float size, float tracking) {
        return textWidth(g, upper(text), serifFor(text, size, Font.BOLD), tracking);
    }

    public static String upper(String text) {
        return text == null ? "" : text.toUpperCase(Locale.ROOT);
    }

    /** Shortens text with an ellipsis so it fits {@code maxWidth} pixels. */
    public static String ellipsize(Graphics2D g, String text, Font font, float maxWidth) {
        if (text == null) {
            return "";
        }
        if (g.getFontMetrics(font).stringWidth(text) <= maxWidth) {
            return text;
        }
        String ellipsis = "\u2026";
        int low = 0;
        int high = text.length();
        while (low < high) {
            int mid = (low + high + 1) / 2;
            String candidate = text.substring(0, mid) + ellipsis;
            if (g.getFontMetrics(font).stringWidth(candidate) <= maxWidth) {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        return text.substring(0, low) + ellipsis;
    }

    /** Measures text without a live Graphics2D (preferred sizes, layout math). */
    public static float measure(String text, Font font, float tracking) {
        java.awt.image.BufferedImage probe = new java.awt.image.BufferedImage(
                1, 1, java.awt.image.BufferedImage.TYPE_INT_RGB);
        Graphics2D g = probe.createGraphics();
        try {
            return textWidth(g, text, font, tracking);
        } finally {
            g.dispose();
        }
    }

    /**
     * Shortens a path from the left with an ellipsis, keeping the most specific
     * (tail) part visible: {@code …\Umbra\demo\demo.jar}.
     */
    public static String ellipsizeLeft(Graphics2D g, String text, Font font, float maxWidth) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        java.awt.FontMetrics metrics = g.getFontMetrics(font);
        if (metrics.stringWidth(text) <= maxWidth) {
            return text;
        }
        String ellipsis = "\u2026";
        // Candidate width gets shorter as the start index grows, so the first
        // index whose ellipsized suffix fits keeps the longest visible tail.
        int low = 0;
        int high = text.length();
        while (low < high) {
            int mid = (low + high) / 2;
            String candidate = ellipsis + text.substring(mid);
            if (metrics.stringWidth(candidate) <= maxWidth) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }
        return ellipsis + text.substring(low);
    }

    /** Formats milliseconds as a compact human duration: 812 ms, 1.62 s, 12.4 s. */
    public static String duration(long millis) {
        if (millis < 1000L) {
            return millis + " ms";
        }
        double seconds = millis / 1000d;
        if (seconds < 10d) {
            return String.format(Locale.ROOT, "%.2f s", Double.valueOf(seconds));
        }
        if (seconds < 100d) {
            return String.format(Locale.ROOT, "%.1f s", Double.valueOf(seconds));
        }
        return Math.round(seconds) + " s";
    }

    /** Renders the given text with the serif font, picking CJK fallback per line. */
    public static void drawSerif(Graphics2D g, String text, Color color, float x, float baseline,
                                 float size, int style, float tracking) {
        drawText(g, text, serifFor(text, size, style), color, x, baseline, tracking);
    }
}
