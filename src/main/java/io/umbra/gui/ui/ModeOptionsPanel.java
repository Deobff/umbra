package io.umbra.gui.ui;

import io.umbra.gui.GuiModeOptions;
import io.umbra.gui.theme.Tokens;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JViewport;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The scrollable "Mode options" sheet: a mode chip row plus one section per
 * option family (Names, Strings, Integers &amp; MBA, Flow, Exceptions,
 * Virtualization, Native, Archive, Anti-debug, Anti-analysis, Compatibility,
 * Output).
 *
 * <p>The panel is independent from {@link javax.swing.JDialog} so it can be
 * rendered offscreen by the screenshot/self-test path and asserted headlessly.
 * Values are plain option strings, exactly the representation used by YAML and
 * the CLI {@code --set} option.</p>
 */
public final class ModeOptionsPanel extends JPanel {

    public static final int SHEET_WIDTH = 900;
    public static final int SHEET_HEIGHT = 700;

    /** Notified when the user presses OK or Cancel. */
    public interface Listener {
        void ok(ModeOptionsPanel panel);

        void cancel(ModeOptionsPanel panel);
    }

    private static final int PAD = 24;
    private static final int HEADER_HEIGHT = 138;
    private static final int FOOTER_HEIGHT = 68;

    private final Map<String, String> values = new LinkedHashMap<String, String>();
    private final Map<String, JComponent> controls = new LinkedHashMap<String, JComponent>();
    private final List<Section> sections = new ArrayList<Section>();
    private final JPanel body = new ScrollBody();
    private final JScrollPane scroll;
    private final ModeChips modeChips;
    private final JButton ok;
    private final JButton cancel;
    private final JButton reset;
    private Listener listener;
    private String lastMode = GuiPresetsMode.DEFAULT;
    private boolean refreshing;
    private String hint = "";

    public ModeOptionsPanel(Map<String, String> initialValues, String mode, Listener listener) {
        super(null);
        this.listener = listener;
        setOpaque(true);
        setBackground(Tokens.CANVAS);
        String startMode = normalizeMode(mode);
        if (!"Custom".equals(startMode)) {
            lastMode = startMode;
        }
        values.putAll(GuiModeOptions.defaults("Custom"));
        if (initialValues != null) {
            for (Map.Entry<String, String> entry : initialValues.entrySet()) {
                GuiModeOptions.Spec spec = GuiModeOptions.spec(entry.getKey());
                if (spec != null) {
                    values.put(spec.id, GuiModeOptions.normalize(spec, entry.getValue()));
                }
            }
        }

        body.setOpaque(false);
        body.setLayout(new javax.swing.BoxLayout(body, javax.swing.BoxLayout.Y_AXIS));
        for (GuiModeOptions.Group group : GuiModeOptions.groups()) {
            Section section = new Section(group);
            sections.add(section);
            body.add(section);
            body.add(javax.swing.Box.createVerticalStrut(6));
        }
        body.add(javax.swing.Box.createVerticalStrut(8));
        scroll = new JScrollPane(body);
        Scrollbars.style(scroll);
        scroll.getVerticalScrollBar().setUnitIncrement(28);
        add(scroll);

        modeChips = new ModeChips(startMode, new ModeChips.Listener() {
            @Override
            public void selected(String selectedMode) {
                if (listener != null && !"Custom".equals(selectedMode)) {
                    // Selecting a mode replaces the detailed values with that
                    // mode's CLI-equivalent preset defaults.
                    applyModeDefaults(selectedMode);
                } else {
                    updateMode("Custom");
                }
            }
        });
        add(modeChips);

        ok = Buttons.primary("OK", null);
        ok.getAccessibleContext().setAccessibleName("Apply mode options");
        cancel = Buttons.quiet("Cancel", null);
        cancel.getAccessibleContext().setAccessibleName("Cancel mode options");
        reset = Buttons.quiet("Reset to mode defaults", null);
        reset.getAccessibleContext().setAccessibleName("Reset to mode defaults");
        add(ok);
        add(cancel);
        add(reset);
        bindButtons();
        refreshControls();
        updateMode(startMode);
        getAccessibleContext().setAccessibleName("Mode options");
        getAccessibleContext().setAccessibleDescription(
                "Detailed per-mode protection options; edits switch the mode to Custom.");
        setPreferredSize(new Dimension(SHEET_WIDTH, SHEET_HEIGHT));
        setSize(SHEET_WIDTH, SHEET_HEIGHT);
    }

    private static String normalizeMode(String mode) {
        if (mode == null || mode.trim().isEmpty()) {
            return "Balanced";
        }
        for (String name : GuiPresetsMode.NAMES) {
            if (name.equalsIgnoreCase(mode.trim())) {
                return name;
            }
        }
        return "Custom";
    }

    private void bindButtons() {
        ok.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                if (listener != null) {
                    listener.ok(ModeOptionsPanel.this);
                }
            }
        });
        cancel.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                if (listener != null) {
                    listener.cancel(ModeOptionsPanel.this);
                }
            }
        });
        reset.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                String mode = selectedMode();
                resetToModeDefaults();
                consoleHint("Reset to " + ("Custom".equals(mode) ? lastMode : mode)
                        + " defaults");
            }
        });
    }

    /* --------------------------------------------------------------- values */

    /** Fresh snapshot of every value (normalised). */
    public Map<String, String> values() {
        Map<String, String> copy = new LinkedHashMap<String, String>();
        copy.putAll(values);
        return copy;
    }

    public String value(String id) {
        return values.get(id);
    }

    public void setValue(String id, String value) {
        GuiModeOptions.Spec spec = GuiModeOptions.spec(id);
        if (spec == null) {
            return;
        }
        values.put(spec.id, GuiModeOptions.normalize(spec, value));
        if (!"Custom".equals(selectedMode())) {
            updateMode("Custom");
        }
        refreshControl(spec.id);
    }

    /** Current mode selection ("Custom" after any edit). */
    public String selectedMode() {
        return modeChips.selected();
    }

    public String lastMode() {
        return lastMode;
    }

    public void setMode(String mode) {
        String normalized = normalizeMode(mode);
        if ("Custom".equals(normalized)) {
            updateMode("Custom");
        } else {
            applyModeDefaults(normalized);
        }
    }

    /** Applies one mode's CLI-equivalent defaults to every control. */
    public void applyModeDefaults(String mode) {
        String normalized = normalizeMode(mode);
        if ("Custom".equals(normalized)) {
            updateMode("Custom");
            return;
        }
        Map<String, String> defaults = GuiModeOptions.defaults(normalized);
        values.clear();
        values.putAll(defaults);
        lastMode = normalized;
        refreshControls();
        updateMode(normalized);
    }

    /** Resets controls to the current (or last non-custom) mode defaults. */
    public void resetToModeDefaults() {
        String mode = selectedMode();
        applyModeDefaults("Custom".equals(mode) ? lastMode : mode);
    }

    private void updateMode(String mode) {
        modeChips.setSelected(mode);
        if (!"Custom".equals(mode)) {
            lastMode = mode;
        }
        repaint();
    }

    /** Mode hint text used by the header. */
    public String modeDescription() {
        String mode = selectedMode();
        if ("Custom".equals(mode)) {
            return "Custom \u00b7 edited values are kept for the next run";
        }
        return mode + " defaults \u00b7 edit any control to switch to Custom";
    }

    /** Returns an error message or {@code null} when the values are usable. */
    public String validationError() {
        String seed = values.get("gui.seed");
        if (seed == null || seed.trim().isEmpty()) {
            return "Seed must be a whole number.";
        }
        try {
            Long.parseLong(seed.trim());
        } catch (NumberFormatException e) {
            return "Seed must be a whole number.";
        }
        String mapping = values.get("gui.mapping");
        if (mapping != null && !mapping.trim().isEmpty()
                && mapping.trim().indexOf('\n') >= 0) {
            return "Mapping file path must be a single line.";
        }
        return null;
    }

    /* ------------------------------------------------------------ controls */

    private void refreshControls() {
        for (GuiModeOptions.Spec spec : GuiModeOptions.allSpecs()) {
            refreshControl(spec.id);
        }
        revalidate();
        repaint();
    }

    private void refreshControl(String id) {
        JComponent control = controls.get(id);
        if (control == null) {
            return;
        }
        String value = values.get(id);
        refreshing = true;
        try {
            if (control instanceof BooleanControl) {
                ((BooleanControl) control).setValue("true".equals(value));
            } else if (control instanceof NumberStepper) {
                ((NumberStepper) control).setValueString(value);
            } else if (control instanceof ChipChoice) {
                ((ChipChoice) control).setValue(value);
            } else if (control instanceof GlassTextField) {
                ((GlassTextField) control).setText(value == null ? "" : value);
            }
        } finally {
            refreshing = false;
        }
        control.repaint();
    }

    private JComponent controlFor(GuiModeOptions.Spec spec) {
        switch (spec.kind) {
            case BOOL:
                return new BooleanControl(spec);
            case INT:
                return new NumberStepper(spec);
            case ENUM:
                return new ChipChoice(spec);
            default:
                return new OptionTextField(spec);
        }
    }

    public JComponent control(String id) {
        return controls.get(id);
    }

    public int controlCount() {
        return controls.size();
    }

    public List<String> sectionTitles() {
        List<String> titles = new ArrayList<String>();
        for (Section section : sections) {
            titles.add(section.group.title);
        }
        return titles;
    }

    public JButton okButton() {
        return ok;
    }

    public JButton cancelButton() {
        return cancel;
    }

    public JButton resetButton() {
        return reset;
    }

    public ModeChips modeChips() {
        return modeChips;
    }

    public JScrollPane scrollPane() {
        return scroll;
    }

    /** Scrolls the body so the named section is at the top (QA screenshots). */
    public boolean scrollToSection(String title) {
        int y = 0;
        for (Section section : sections) {
            if (title != null && section.group.title.equalsIgnoreCase(title)) {
                scroll.getViewport().setViewPosition(new java.awt.Point(0, Math.max(0, y)));
                return true;
            }
            y += section.getPreferredSize().height + 6;
        }
        return false;
    }

    public int bodyPreferredHeight() {
        int total = 0;
        for (Section section : sections) {
            total += section.getPreferredSize().height;
        }
        return total;
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    public void consoleHint(String text) {
        // Header hint is paint-only; the dialog shows validation via a dialog.
        hint = text == null ? "" : text;
        repaint();
    }

    /* ---------------------------------------------------------------- layout */

    @Override
    public void doLayout() {
        int w = getWidth();
        int h = getHeight();
        int contentWidth = Math.max(300, w - PAD * 2);
        modeChips.setBounds(PAD, 100, contentWidth, 30);
        scroll.setBounds(PAD, HEADER_HEIGHT, contentWidth,
                Math.max(120, h - HEADER_HEIGHT - FOOTER_HEIGHT));
        int footerY = h - FOOTER_HEIGHT + 14;
        ok.setBounds(w - PAD - 96, footerY, 96, 36);
        int cancelWidth = cancel.getPreferredSize().width;
        cancel.setBounds(w - PAD - 96 - 10 - cancelWidth, footerY + 4, cancelWidth, 28);
        int resetWidth = reset.getPreferredSize().width;
        reset.setBounds(PAD, footerY + 4, resetWidth, 28);
    }

    /* --------------------------------------------------------------- paint */

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        try {
            Tokens.prepare(g);
            int w = getWidth();
            int h = getHeight();
            g.setColor(Tokens.CANVAS);
            g.fillRect(0, 0, w, h);
            RoundRectangle2D.Float sheet = new RoundRectangle2D.Float(
                    0.5f, 0.5f, w - 1f, h - 1f, 32f, 32f);
            g.setColor(new Color(255, 255, 255, 247));
            g.fill(sheet);
            g.setColor(Tokens.LINE_STRONG);
            g.setStroke(new java.awt.BasicStroke(1f));
            g.draw(sheet);
            g.setColor(new Color(255, 255, 255, 235));
            g.draw(new java.awt.geom.Line2D.Float(24f, 1.5f, w - 24f, 1.5f));

            Font titleFont = Tokens.serifFor("Mode options", 20f, Font.BOLD);
            FontMetrics titleMetrics = g.getFontMetrics(titleFont);
            Tokens.drawText(g, "Mode options", titleFont, Tokens.FG, PAD,
                    24f + titleMetrics.getAscent(), -0.005f);
            Font subtitleFont = Tokens.serif(12.5f);
            Tokens.drawText(g, "Each mode presets every control below. "
                            + "Editing a value switches the mode to Custom.",
                    subtitleFont, Tokens.FG2, PAD,
                    24f + titleMetrics.getAscent() + 21f, 0f);
            Tokens.drawCaps(g, "Mode", Tokens.FG3, PAD, 94f, Tokens.CAPS_SIZE, 0.2f);
            Font noteFont = Tokens.serif(12f);
            String note = modeDescription();
            float noteWidth = Tokens.textWidth(g, note, noteFont);
            Tokens.drawText(g, hint.isEmpty() ? note : hint, noteFont, Tokens.FG3,
                    w - PAD - noteWidth - 2f, 94f, 0f);
            // Footer hairline.
            g.setColor(Tokens.LINE);
            g.draw(new java.awt.geom.Line2D.Float(PAD, h - FOOTER_HEIGHT + 2f,
                    w - PAD, h - FOOTER_HEIGHT + 2f));
        } finally {
            g.dispose();
        }
    }

    /* ------------------------------------------------------------ internals */

    /** Scroll content clipped to the visible viewport rectangle. */
    private static final class ScrollBody extends JPanel {
        ScrollBody() {
            setOpaque(false);
        }

        @Override
        protected void paintChildren(Graphics graphics) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                if (getParent() instanceof JViewport) {
                    Rectangle visible = ((JViewport) getParent()).getViewRect();
                    g.clipRect(visible.x, visible.y, visible.width, visible.height);
                }
                super.paintChildren(g);
            } finally {
                g.dispose();
            }
        }
    }

    /** One titled block of option rows. */
    private final class Section extends JPanel {
        final GuiModeOptions.Group group;

        Section(GuiModeOptions.Group group) {
            super(null);
            this.group = group;
            setOpaque(false);
            for (GuiModeOptions.Spec spec : group.specs) {
                JComponent control = controlFor(spec);
                controls.put(spec.id, control);
                add(new OptionRow(spec, control));
            }
            int height = 30 + group.specs.size() * 36 + 8;
            setPreferredSize(new Dimension(SHEET_WIDTH - 70, height));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, height));
            setMinimumSize(new Dimension(200, height));
        }

        @Override
        public void doLayout() {
            int w = getWidth();
            int y = 30;
            int index = 0;
            for (java.awt.Component child : getComponents()) {
                child.setBounds(0, y, w, 36);
                if (child instanceof OptionRow) {
                    ((OptionRow) child).doLayout();
                }
                y += 36;
                index++;
            }
        }

        @Override
        protected void paintComponent(Graphics graphics) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                Tokens.prepare(g);
                Font font = Tokens.serifFor(group.title, Tokens.GROUP_SIZE, Font.BOLD);
                FontMetrics metrics = g.getFontMetrics(font);
                Tokens.drawText(g, group.title, font, Tokens.FG, 16f,
                        20f + metrics.getAscent() * 0.55f, 0.01f);
                g.setColor(Tokens.LINE);
                g.draw(new java.awt.geom.Line2D.Float(16f, 27.5f, getWidth() - 16f, 27.5f));
            } finally {
                g.dispose();
            }
        }
    }

    /** A label + control row (36px). */
    private final class OptionRow extends JPanel {
        private final GuiModeOptions.Spec spec;
        private final JComponent control;

        OptionRow(GuiModeOptions.Spec spec, JComponent control) {
            super(null);
            this.spec = spec;
            this.control = control;
            setOpaque(false);
            add(control);
            control.getAccessibleContext().setAccessibleName(spec.label);
            control.getAccessibleContext().setAccessibleDescription(spec.id + " option");
            getAccessibleContext().setAccessibleName(spec.label);
        }

        @Override
        public void doLayout() {
            int w = getWidth();
            int controlWidth = Math.min(430, Math.max(90, control.getPreferredSize().width));
            int x = w - 24 - controlWidth;
            int controlHeight = Math.min(32, Math.max(24, control.getPreferredSize().height));
            control.setBounds(x, (36 - controlHeight) / 2, controlWidth, controlHeight);
        }

        @Override
        protected void paintComponent(Graphics graphics) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                Tokens.prepare(g);
                int w = getWidth();
                int controlWidth = Math.min(430, Math.max(90, control.getPreferredSize().width));
                float available = w - 24 - controlWidth - 40f;
                String label = Tokens.ellipsize(g, spec.label, Tokens.serif(13f), available);
                FontMetrics metrics = g.getFontMetrics(Tokens.serif(13f));
                float baseline = (36 - metrics.getHeight()) / 2f + metrics.getAscent();
                Tokens.drawText(g, label, Tokens.serifFor(label, 13f, Font.PLAIN),
                        Tokens.FG2, 16f, baseline, 0f);
            } finally {
                g.dispose();
            }
        }
    }

    /* ----------------------------------------------------------- controls */

    /** Boolean control wrapping the shared pill switch. */
    public final class BooleanControl extends JPanel {
        private final PillSwitch pill;
        private final GuiModeOptions.Spec spec;

        BooleanControl(GuiModeOptions.Spec spec) {
            super(null);
            this.spec = spec;
            setOpaque(false);
            pill = new PillSwitch("true".equals(values.get(spec.id)));
            pill.setAnimationsEnabled(false);
            add(pill);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setPreferredSize(new Dimension(48, 26));
            addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    setValue(!pill.isOn());
                    ModeOptionsPanel.this.setValue(BooleanControl.this.spec.id,
                            String.valueOf(pill.isOn()));
                }
            });
            getAccessibleContext().setAccessibleName(spec.label);
        }

        void setValue(boolean on) {
            pill.setOn(on, false);
            repaint();
        }

        public boolean isOn() {
            return pill.isOn();
        }

        @Override
        public void doLayout() {
            pill.setBounds(2, (getHeight() - PillSwitch.HEIGHT) / 2,
                    PillSwitch.WIDTH, PillSwitch.HEIGHT);
        }
    }

    /** Integer stepper with minus/plus zones. */
    public final class NumberStepper extends JPanel {
        private final GuiModeOptions.Spec spec;
        private int number;

        NumberStepper(GuiModeOptions.Spec spec) {
            this.spec = spec;
            setOpaque(false);
            number = parseInt(values.get(spec.id), parseInt(spec.defaultValue, spec.min));
            setPreferredSize(new Dimension(132, 26));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    int delta = e.getX() < getWidth() / 2 ? -1 : 1;
                    int next = clamp(number + delta * Math.max(1, NumberStepper.this.spec.step));
                    ModeOptionsPanel.this.setValue(NumberStepper.this.spec.id,
                            String.valueOf(next));
                }
            });
            getAccessibleContext().setAccessibleName(spec.label);
            setToolTipText(spec.label + " (" + spec.min + ".." + spec.max + ")");
        }

        private int clamp(int value) {
            return Math.max(spec.min, Math.min(spec.max, value));
        }

        void setValueString(String value) {
            number = clamp(parseInt(value, parseInt(spec.defaultValue, spec.min)));
            repaint();
        }

        public int number() {
            return number;
        }

        @Override
        protected void paintComponent(Graphics graphics) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                Tokens.prepare(g);
                int w = getWidth();
                int h = getHeight();
                RoundRectangle2D.Float shape = new RoundRectangle2D.Float(
                        0.5f, 0.5f, w - 1f, h - 1f, 20f, 20f);
                g.setColor(new Color(0, 0, 0, 10));
                g.fill(shape);
                g.setColor(Tokens.LINE);
                g.setStroke(new java.awt.BasicStroke(1f));
                g.draw(shape);
                g.setColor(Tokens.FG2);
                g.setFont(Tokens.serifBold(14f));
                g.drawString("\u2212", 10f, h / 2f + 5f);
                g.drawString("+", w - 18f, h / 2f + 5f);
                String text = String.valueOf(number);
                Font valueFont = Tokens.mono(12.5f);
                FontMetrics metrics = g.getFontMetrics(valueFont);
                Tokens.drawCentered(g, text, valueFont, Tokens.FG, w / 2f,
                        (h - metrics.getHeight()) / 2f + metrics.getAscent(), 0f);
            } finally {
                g.dispose();
            }
        }
    }

    /** Horizontal chip selector for enum values. */
    public final class ChipChoice extends JPanel {
        private final GuiModeOptions.Spec spec;
        private String selected;
        private final List<int[]> bounds = new ArrayList<int[]>();

        ChipChoice(GuiModeOptions.Spec spec) {
            this.spec = spec;
            setOpaque(false);
            selected = values.get(spec.id);
            if (selected == null || !spec.values.contains(selected)) {
                selected = spec.defaultValue;
            }
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    computeBounds();
                    for (int i = 0; i < bounds.size(); i++) {
                        int[] b = bounds.get(i);
                        if (e.getX() >= b[0] && e.getX() <= b[0] + b[2]
                                && e.getY() >= b[1] && e.getY() <= b[1] + b[3]) {
                            ModeOptionsPanel.this.setValue(ChipChoice.this.spec.id,
                                    ChipChoice.this.spec.values.get(i));
                            return;
                        }
                    }
                }
            });
            getAccessibleContext().setAccessibleName(spec.label);
            setToolTipText(spec.label + ": " + join(spec.values));
        }

        void setValue(String value) {
            if (value != null && spec.values.contains(value)) {
                selected = value;
            }
            repaint();
        }

        public String selected() {
            return selected;
        }

        private void computeBounds() {
            bounds.clear();
            Graphics2D g = probe();
            try {
                Font font = Tokens.serif(12f);
                int x = 0;
                for (String value : spec.values) {
                    int width = Math.round(Tokens.textWidth(g, value, font)) + 18;
                    bounds.add(new int[]{x, 0, width, 24});
                    x += width + 4;
                }
            } finally {
                g.dispose();
            }
        }

        @Override
        public Dimension getPreferredSize() {
            computeBounds();
            int total = bounds.isEmpty() ? 80 : bounds.get(bounds.size() - 1)[0]
                    + bounds.get(bounds.size() - 1)[2];
            return new Dimension(Math.max(70, total), 26);
        }

        @Override
        protected void paintComponent(Graphics graphics) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                Tokens.prepare(g);
                computeBounds();
                Font font = Tokens.serif(12f);
                FontMetrics metrics = g.getFontMetrics(font);
                for (int i = 0; i < bounds.size(); i++) {
                    int[] b = bounds.get(i);
                    String value = spec.values.get(i);
                    boolean isSelected = value.equals(selected);
                    RoundRectangle2D.Float shape = new RoundRectangle2D.Float(
                            b[0], b[1] + 1, b[2], b[3], 24f, 24f);
                    if (isSelected) {
                        g.setColor(Tokens.alpha(Color.WHITE, 0.94f));
                        g.fill(shape);
                        g.setColor(Tokens.LINE_STRONG);
                        g.setStroke(new java.awt.BasicStroke(1f));
                        g.draw(shape);
                    } else {
                        g.setColor(new Color(0, 0, 0, 7));
                        g.fill(shape);
                    }
                    float baseline = b[1] + 1 + (b[3] - metrics.getHeight()) / 2f
                            + metrics.getAscent();
                    Tokens.drawCentered(g, value, font, isSelected ? Tokens.FG : Tokens.FG2,
                            b[0] + b[2] / 2f, baseline, 0f);
                }
            } finally {
                g.dispose();
            }
        }
    }

    /** Text control with a placeholder-capable rounded field. */
    public final class OptionTextField extends GlassTextField {
        private final GuiModeOptions.Spec spec;

        OptionTextField(final GuiModeOptions.Spec spec) {
            super("", false);
            this.spec = spec;
            setText(values.get(spec.id) == null ? "" : values.get(spec.id));
            setFont(Tokens.serif(Tokens.BODY_SIZE));
            setPreferredSize(new Dimension(200, 30));
            getAccessibleContext().setAccessibleName(spec.label);
            getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                @Override
                public void insertUpdate(javax.swing.event.DocumentEvent e) {
                    commit();
                }

                @Override
                public void removeUpdate(javax.swing.event.DocumentEvent e) {
                    commit();
                }

                @Override
                public void changedUpdate(javax.swing.event.DocumentEvent e) {
                    commit();
                }

                private void commit() {
                    if (refreshing) {
                        return;
                    }
                    ModeOptionsPanel.this.values.put(spec.id, getText());
                    if (!"Custom".equals(selectedMode())) {
                        updateMode("Custom");
                    }
                }
            });
        }

        public GuiModeOptions.Spec spec() {
            return spec;
        }
    }

    /** Mode chip row (Light / Balanced / Aggressive / Maximum / Nocturne / Custom). */
    public static final class ModeChips extends JPanel {
        public interface Listener {
            void selected(String mode);
        }

        private final List<String> names = GuiModeOptions.modeNames();
        private final List<int[]> bounds = new ArrayList<int[]>();
        private String selected;
        private String hover;
        private final Listener listener;

        ModeChips(String initial, Listener listener) {
            this.selected = initial;
            this.listener = listener;
            setOpaque(false);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            getAccessibleContext().setAccessibleName("Mode");
            addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    computeBounds();
                    for (int i = 0; i < bounds.size(); i++) {
                        int[] b = bounds.get(i);
                        if (e.getX() >= b[0] && e.getX() <= b[0] + b[2]
                                && e.getY() >= b[1] && e.getY() <= b[1] + b[3]) {
                            select(names.get(i));
                            return;
                        }
                    }
                }

                @Override
                public void mouseMoved(MouseEvent e) {
                    String hit = hit(e);
                    if (hit != null ? !hit.equals(hover) : hover != null) {
                        hover = hit;
                        repaint();
                    }
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    hover = null;
                    repaint();
                }
            });
        }

        private String hit(MouseEvent e) {
            computeBounds();
            for (int i = 0; i < bounds.size(); i++) {
                int[] b = bounds.get(i);
                if (e.getX() >= b[0] && e.getX() <= b[0] + b[2]
                        && e.getY() >= b[1] && e.getY() <= b[1] + b[3]) {
                    return names.get(i);
                }
            }
            return null;
        }

        public String selected() {
            return selected;
        }

        public void setSelected(String mode) {
            this.selected = mode;
            repaint();
        }

        private void select(String mode) {
            if (mode.equals(selected) && !"Custom".equals(mode)) {
                return;
            }
            selected = mode;
            repaint();
            if (listener != null) {
                listener.selected(mode);
            }
        }

        private void computeBounds() {
            bounds.clear();
            Graphics2D g = probe();
            try {
                Font font = Tokens.serif(12.5f);
                int x = 0;
                for (String name : names) {
                    int width = Math.round(Tokens.textWidth(g, name, font)) + 22;
                    bounds.add(new int[]{x, 0, width, 28});
                    x += width + 6;
                }
            } finally {
                g.dispose();
            }
        }

        @Override
        public Dimension getPreferredSize() {
            computeBounds();
            int total = bounds.isEmpty() ? 120 : bounds.get(bounds.size() - 1)[0]
                    + bounds.get(bounds.size() - 1)[2];
            return new Dimension(Math.max(120, total), 30);
        }

        @Override
        protected void paintComponent(Graphics graphics) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                Tokens.prepare(g);
                computeBounds();
                Font font = Tokens.serif(12.5f);
                FontMetrics metrics = g.getFontMetrics(font);
                for (int i = 0; i < bounds.size(); i++) {
                    int[] b = bounds.get(i);
                    String name = names.get(i);
                    boolean isSelected = name.equals(selected);
                    boolean isHover = name.equals(hover);
                    RoundRectangle2D.Float shape = new RoundRectangle2D.Float(
                            b[0], b[1], b[2], b[3], 28f, 28f);
                    if (isSelected) {
                        g.setColor(Tokens.alpha(Color.WHITE, 0.94f));
                        g.fill(shape);
                        g.setColor(Tokens.LINE_STRONG);
                        g.setStroke(new java.awt.BasicStroke(1f));
                        g.draw(shape);
                    } else if (isHover) {
                        g.setColor(new Color(0, 0, 0, 7));
                        g.fill(shape);
                    }
                    float baseline = b[1] + (b[3] - metrics.getHeight()) / 2f
                            + metrics.getAscent();
                    Tokens.drawCentered(g, name, font, isSelected ? Tokens.FG : Tokens.FG2,
                            b[0] + b[2] / 2f, baseline, 0f);
                }
            } finally {
                g.dispose();
            }
        }
    }

    /* ------------------------------------------------------------- helpers */

    private static Graphics2D probe() {
        java.awt.image.BufferedImage image = new java.awt.image.BufferedImage(
                1, 1, java.awt.image.BufferedImage.TYPE_INT_RGB);
        return image.createGraphics();
    }

    private static int parseInt(String value, int fallback) {
        try {
            return Integer.parseInt(value == null ? "" : value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static String join(List<String> values) {
        StringBuilder out = new StringBuilder();
        for (String value : values) {
            if (out.length() > 0) {
                out.append(", ");
            }
            out.append(value);
        }
        return out.toString();
    }

    /** Small indirection so this file does not depend on the outer class name. */
    private static final class GuiPresetsMode {
        static final List<String> NAMES = io.umbra.gui.GuiPresets.NAMES;
        static final String DEFAULT = io.umbra.gui.GuiPresets.DEFAULT;

        private GuiPresetsMode() {
        }
    }
}
