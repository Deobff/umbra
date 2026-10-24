package io.umbra.gui.ui;

import io.umbra.gui.theme.Tokens;

import javax.swing.JComponent;
import javax.swing.JScrollPane;
import javax.swing.JViewport;
import javax.swing.Scrollable;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * The central frosted console: quiet header with "Clear" and "Open folder",
 * timestamped monospace log lines, an italic empty state and a drag-and-drop
 * target for the input JAR.
 *
 * <p>The log is a custom-painted view (not a JTextArea) so it can wrap long
 * messages, colour warnings/errors semantically, animate the newest line in and
 * keep the specification's 13px / 1.85 line rhythm.</p>
 */
public class ConsolePanel extends GlassPanel {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final float LOG_SIZE = 13f;
    private static final int LINE_HEIGHT = 24;
    private static final int LINE_GAP = 10;
    private static final int HEADER_HEIGHT = 56;
    private static final int PAD_X = 28;
    private static final int PAD_TOP = 26;

    private final LogView logView = new LogView();
    private final JScrollPane scroll;
    private final QuietButton clear;
    private final IconButton openFolder;

    public ConsolePanel() {
        super(GlassPanel.Variant.MAIN, Tokens.RADIUS_CARD);
        scroll = new JScrollPane(logView);
        Scrollbars.style(scroll);
        scroll.getVerticalScrollBar().setUnitIncrement(LINE_HEIGHT + LINE_GAP);
        add(scroll);
        clear = new QuietButton("Clear");
        clear.getAccessibleContext().setAccessibleName("Clear log");
        clear.getAccessibleContext().setAccessibleDescription(
                "Remove every line from the protection log");
        add(clear);
        openFolder = new IconButton(IconButton.OPEN, "Open output folder",
                "Reveal the protected JAR in the file manager");
        add(openFolder);
        getAccessibleContext().setAccessibleName("Console");
        getAccessibleContext().setAccessibleDescription(
                "Protection log; drop an input JAR here to select it");
    }

    public javax.swing.JButton clearButton() {
        return clear;
    }

    public javax.swing.JButton openFolderButton() {
        return openFolder;
    }

    public LogView logView() {
        return logView;
    }

    public void setAnimationsEnabled(boolean enabled) {
        logView.animations = enabled;
        if (!enabled) {
            logView.settle();
        }
    }

    public void setDragHighlight(boolean active) {
        setOutline(active ? Tokens.alpha(Tokens.ACCENT, 0.55f) : null);
    }

    public void setRunningHighlight(boolean running) {
        if (running) {
            setOutline(Tokens.alpha(Tokens.ACCENT, 0.28f));
        } else {
            clearOutline();
        }
    }

    public void append(String level, String message) {
        logView.append(level, message);
    }

    public void clear() {
        logView.clear();
    }

    public int lineCount() {
        return logView.entryCount();
    }

    public List<LogEntry> entries() {
        return logView.entriesSnapshot();
    }

    @Override
    public void doLayout() {
        int w = getWidth();
        int h = getHeight();
        scroll.setBounds(PAD_X, HEADER_HEIGHT, Math.max(100, w - PAD_X * 2),
                Math.max(60, h - HEADER_HEIGHT - PAD_TOP));
        clear.setBounds(w - PAD_X - 28 - 10 - clear.getPreferredSize().width,
                (HEADER_HEIGHT - 28) / 2, clear.getPreferredSize().width, 28);
        openFolder.setBounds(w - PAD_X - 28, (HEADER_HEIGHT - 28) / 2, 28, 28);
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        super.paintComponent(graphics);
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            FontMetrics metrics = g.getFontMetrics(Tokens.serifBold(Tokens.CAPS_SIZE));
            float baseline = (HEADER_HEIGHT - metrics.getHeight()) / 2f + metrics.getAscent();
            Tokens.drawCaps(g, "Console", Tokens.FG3, PAD_X, baseline, Tokens.CAPS_SIZE, 0.22f);
        } finally {
            g.dispose();
        }
    }

    /** One log line. */
    public static final class LogEntry {
        private final LocalTime time;
        private final String level;
        private final String message;

        LogEntry(LocalTime time, String level, String message) {
            this.time = time;
            this.level = level == null ? "INFO" : level;
            this.message = message == null ? "" : message;
        }

        public LocalTime time() {
            return time;
        }

        public String level() {
            return level;
        }

        public String message() {
            return message;
        }

        public String stamp() {
            return "[" + time.format(TIME) + "]";
        }
    }

    private static final class VisualLine {
        final LogEntry entry;
        final String text;
        final boolean first;

        VisualLine(LogEntry entry, String text, boolean first) {
            this.entry = entry;
            this.text = text;
            this.first = first;
        }
    }

    /** Custom-painted, wrapping log list that tracks the viewport width. */
    public static final class LogView extends JComponent implements Scrollable {

        private final List<LogEntry> entries = new ArrayList<LogEntry>();
        private final List<VisualLine> visuals = new ArrayList<VisualLine>();
        private int wrappedWidth = -1;
        private boolean dirty = true;
        private boolean animations = true;
        private long lastLineAt;
        private Timer lineAnimation;
        private final Font logFont = Tokens.mono(LOG_SIZE);
        private final Font stampFont = Tokens.mono(LOG_SIZE);

        LogView() {
            setOpaque(false);
            getAccessibleContext().setAccessibleName("Protection log");
            getAccessibleContext().setAccessibleDescription(
                    "Timestamped log lines from the protection engine");
            setCursor(Cursor.getDefaultCursor());
        }

        @Override
        public javax.accessibility.AccessibleContext getAccessibleContext() {
            if (accessibleContext == null) {
                accessibleContext = new AccessibleJComponent() {
                    // Anonymous subclass only to obtain a default accessible
                    // context for a custom-painted component.
                };
                accessibleContext.setAccessibleName("Protection log");
            }
            return accessibleContext;
        }

        void append(String level, String message) {
            if (!SwingUtilities.isEventDispatchThread()) {
                final String levelValue = level;
                final String messageValue = message;
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        append(levelValue, messageValue);
                    }
                });
                return;
            }
            LogEntry entry = new LogEntry(LocalTime.now(), level, message);
            entries.add(entry);
            dirty = true;
            lastLineAt = System.currentTimeMillis();
            revalidate();
            repaint();
            scrollToEnd();
            if (animations) {
                startLineAnimation();
            }
        }

        private void startLineAnimation() {
            if (lineAnimation != null) {
                return;
            }
            lineAnimation = new Timer(16, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if (System.currentTimeMillis() - lastLineAt >= 300L) {
                        lineAnimation.stop();
                        lineAnimation = null;
                    }
                    repaint();
                }
            });
            lineAnimation.start();
        }

        void settle() {
            if (lineAnimation != null) {
                lineAnimation.stop();
                lineAnimation = null;
            }
            lastLineAt = 0L;
        }

        void clear() {
            if (!SwingUtilities.isEventDispatchThread()) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        clear();
                    }
                });
                return;
            }
            entries.clear();
            visuals.clear();
            wrappedWidth = -1;
            dirty = true;
            revalidate();
            repaint();
        }

        int entryCount() {
            return entries.size();
        }

        List<LogEntry> entriesSnapshot() {
            return new ArrayList<LogEntry>(entries);
        }

        private void scrollToEnd() {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    if (getParent() instanceof JViewport) {
                        JViewport viewport = (JViewport) getParent();
                        int height = getPreferredSize().height;
                        viewport.setViewPosition(new java.awt.Point(0,
                                Math.max(0, height - viewport.getHeight())));
                    }
                }
            });
        }

        private void rebuild(int width) {
            visuals.clear();
            FontMetrics stampMetrics = probeMetrics(stampFont);
            int stampWidth = stampMetrics.stringWidth("[23:59:59]") + 12;
            int messageWidth = Math.max(60, width - stampWidth);
            for (LogEntry entry : entries) {
                List<String> chunks = wrap(entry.message(), logFont, messageWidth);
                if (chunks.isEmpty()) {
                    chunks.add("");
                }
                for (int i = 0; i < chunks.size(); i++) {
                    visuals.add(new VisualLine(entry, chunks.get(i), i == 0));
                }
            }
            wrappedWidth = width;
            dirty = false;
            revalidate();
        }

        private List<String> wrap(String text, Font font, int maxWidth) {
            List<String> chunks = new ArrayList<String>();
            if (text == null || text.isEmpty()) {
                return chunks;
            }
            StringBuilder line = new StringBuilder();
            for (int i = 0; i < text.length(); i++) {
                char ch = text.charAt(i);
                if (ch == '\n') {
                    chunks.add(line.toString());
                    line.setLength(0);
                    continue;
                }
                line.append(ch);
                if (line.length() > 1 && measureWidth(line.toString(), font) > maxWidth) {
                    // Wrap at the last space when possible to avoid splitting words.
                    int split = line.lastIndexOf(" ");
                    if (split > line.length() / 2) {
                        chunks.add(line.substring(0, split));
                        String rest = line.substring(split + 1);
                        line.setLength(0);
                        line.append(rest);
                    } else {
                        chunks.add(line.substring(0, line.length() - 1));
                        char last = line.charAt(line.length() - 1);
                        line.setLength(0);
                        line.append(last);
                    }
                }
            }
            if (line.length() > 0) {
                chunks.add(line.toString());
            }
            return chunks;
        }

        private FontMetrics probeMetrics(Font font) {
            java.awt.image.BufferedImage image = new java.awt.image.BufferedImage(
                    1, 1, java.awt.image.BufferedImage.TYPE_INT_RGB);
            Graphics2D g = image.createGraphics();
            try {
                return g.getFontMetrics(font);
            } finally {
                g.dispose();
            }
        }

        private float measureWidth(String text, Font font) {
            return Tokens.measure(text, font, 0f);
        }

        @Override
        public Dimension getPreferredSize() {
            int width = getVisibleWidth();
            if (width > 0 && (width != wrappedWidth || dirty)) {
                rebuild(width);
            }
            int lines = Math.max(1, visuals.size());
            return new Dimension(Math.max(80, width), lines * (LINE_HEIGHT + LINE_GAP));
        }

        private int getVisibleWidth() {
            if (getParent() instanceof JViewport) {
                return getParent().getWidth();
            }
            return Math.max(0, getWidth());
        }

        @Override
        protected void paintComponent(Graphics graphics) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                Tokens.prepare(g);
                java.awt.Rectangle visible = getVisibleRect();
                if (visible != null && !visible.isEmpty()) {
                    g.clipRect(visible.x, visible.y, visible.width, visible.height);
                }
                int width = getWidth();
                if (width <= 0) {
                    return;
                }
                if (width != wrappedWidth || dirty) {
                    rebuild(width);
                }
                if (entries.isEmpty()) {
                    paintEmptyState(g, width, getHeight());
                    return;
                }
                FontMetrics stampMetrics = g.getFontMetrics(stampFont);
                int stampWidth = stampMetrics.stringWidth("[23:59:59]") + 12;
                int y = 0;
                for (int i = 0; i < visuals.size(); i++) {
                    VisualLine line = visuals.get(i);
                    int baseline = y + (LINE_HEIGHT - stampMetrics.getHeight()) / 2
                            + stampMetrics.getAscent();
                    float alpha = 1f;
                    if (animations) {
                        long since = System.currentTimeMillis() - lastLineAt;
                        if (since >= 0 && since < 300 && i >= visuals.size() - 1) {
                            float t = since / 300f;
                            alpha = Math.min(1f, t);
                            baseline += Math.round(4f * (1f - t));
                        }
                    }
                    if (line.first) {
                        g.setComposite(java.awt.AlphaComposite.getInstance(
                                java.awt.AlphaComposite.SRC_OVER, alpha));
                        g.setFont(stampFont);
                        g.setColor(Tokens.FG3);
                        g.drawString(line.entry.stamp(), 0f, baseline);
                    }
                    g.setComposite(java.awt.AlphaComposite.getInstance(
                            java.awt.AlphaComposite.SRC_OVER, alpha));
                    Color messageColor = "ERROR".equals(line.entry.level())
                            ? Tokens.DANGER
                            : ("WARN".equals(line.entry.level()) ? Tokens.FG : Tokens.FG2);
                    Tokens.drawText(g, line.text, logFont, messageColor, stampWidth, baseline, 0f);
                    y += LINE_HEIGHT + LINE_GAP;
                }
            } finally {
                g.dispose();
            }
        }

        private void paintEmptyState(Graphics2D g, int width, int height) {
            Font titleFont = Tokens.serifFor("Drop an input JAR here", 13.5f, Font.ITALIC);
            Font hintFont = Tokens.serifFor("or press Ctrl+O to choose one", 13.5f, Font.ITALIC);
            FontMetrics metrics = g.getFontMetrics(titleFont);
            float centerY = height / 2f - 6f;
            float first = centerY + metrics.getAscent() / 2f;
            Tokens.drawCentered(g, "Drop an input JAR here", titleFont, Tokens.FG3,
                    width / 2f, first, 0.02f);
            Tokens.drawCentered(g, "or press Ctrl+O to choose one", hintFont, Tokens.FG3,
                    width / 2f, first + metrics.getHeight() + 4f, 0.02f);
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
            return LINE_HEIGHT + LINE_GAP;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
            return Math.max(LINE_HEIGHT + LINE_GAP, visibleRect.height - LINE_HEIGHT - LINE_GAP);
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            // The italic empty state must sit in the middle of the console, so
            // the view fills the viewport while there are no log lines. Once
            // lines exist the view grows and the scrollbar takes over.
            return entries.isEmpty();
        }
    }
}
