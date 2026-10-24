package io.umbra.core.runtime;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;
import java.awt.AWTEvent;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.GradientPaint;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.GridLayout;
import java.awt.LayoutManager;
import java.awt.Point;
import java.awt.RenderingHints;
import java.awt.Toolkit;
import java.awt.event.AWTEventListener;
import java.awt.event.FocusEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

/**
 * Server-backed authorization gate injected into protected programs.
 *
 * <p>This class is a <b>template</b>: Umbra copies its bytecode into the output
 * JAR under a randomized name (see
 * {@code io.umbra.core.runtime.DefaultRuntimeSupport#ensureAuthGate}) and
 * replaces the {@code @@...@@} placeholders below with the configured server
 * URL, software id, window title, cache file, registration flag, timeout and
 * entry-point list. It must stay self-contained (only {@code java.*},
 * {@code javax.swing.*} references) and must not introduce nested classes,
 * because only this single class file is injected.</p>
 *
 * <p>The gate validates a per-software token against the authorization server.
 * When no valid token is cached it either uses the automation system properties
 * ({@code umbra.auth.token/username/password/card/silent}) or shows a modal
 * login / register / card-activation dialog. Authorization failure always ends
 * the protected program with exit code 1.</p>
 */
public final class UmbraAuthGate {

    private static String SERVER = "@@SERVER@@";
    private static String SOFTWARE = "@@SOFTWARE@@";
    private static String TITLE = "@@TITLE@@";
    private static String CACHE = "@@CACHE@@";
    private static String REGISTER = "@@REGISTER@@";
    private static String TIMEOUT = "@@TIMEOUT@@";
    private static String ENTRY = "@@ENTRY@@";

    /** Last authorization failure reason, used for the silent/CI diagnostics line. */
    private static String lastError = "";

    /** Cached machine fingerprint (SHA-256 hex) used for HWID binding. */
    private static String hwidCache;

    /** True when the last server response rejected this machine's fingerprint. */
    private static boolean hwidMismatch;

    private static final Color BG = new Color(0x12, 0x1A, 0x28);
    private static final Color BG_SOFT = new Color(0x0B, 0x0F, 0x17);
    private static final Color FG = new Color(0xE8, 0xF0, 0xFF);
    private static final Color MUTED = new Color(0x8A, 0x9B, 0xB5);
    private static final Color ACCENT = new Color(0x63, 0x66, 0xF1);
    private static final Color CYAN = new Color(0x22, 0xD3, 0xEE);
    private static final Color ERROR = new Color(0xF8, 0x71, 0x71);

    private UmbraAuthGate() {
    }

    /**
     * Entry point called before protected {@code main} methods and configured
     * entry points. Returns normally only after successful authorization.
     */
    public static void guard() {
        final boolean silent = isTrue(System.getProperty("umbra.auth.silent", ""));
        lastError = "";
        hwidMismatch = false;
        try {
            String cached = loadCachedToken();
            if (cached != null) {
                if (validateToken(cached)) {
                    saveToken(cached);
                    return;
                }
            } else if (lastError.isEmpty()) {
                lastError = "no cached token";
            }
            String explicit = System.getProperty("umbra.auth.token", "").trim();
            if (!explicit.isEmpty() && validateToken(explicit)) {
                saveToken(explicit);
                return;
            }
            String username = System.getProperty("umbra.auth.username", "").trim();
            String password = System.getProperty("umbra.auth.password", "");
            if (!username.isEmpty() && !password.isEmpty()) {
                String token = loginToken(username, password);
                if (token == null) {
                    String card = System.getProperty("umbra.auth.card", "").trim();
                    if (!card.isEmpty()) {
                        token = activateToken(username, password, card);
                    }
                }
                if (token != null) {
                    saveToken(token);
                    return;
                }
            }
            if (silent) {
                // silent mode never bypasses server verification: no valid token
                // (or a machine-fingerprint rejection) means the protected program
                // refuses to start.
                System.err.println("UMBRA_AUTH_REQUIRED: "
                        + (hwidMismatch ? "hwid mismatch" : reason()));
                System.exit(1);
                return;
            }
            if (GraphicsEnvironment.isHeadless()) {
                System.err.println("Umbra Auth: authorization required (" + reason() + ")");
                System.exit(1);
                return;
            }
            if (!showDialogAndWait()) {
                System.exit(1);
            }
        } catch (Throwable failure) {
            String detail = failure.getClass().getSimpleName()
                    + (failure.getMessage() == null ? "" : ": " + failure.getMessage());
            if (silent) {
                System.err.println("UMBRA_AUTH_REQUIRED: " + detail);
            } else {
                System.err.println("Umbra Auth: " + detail);
            }
            System.exit(1);
        }
    }

    private static String reason() {
        return lastError == null || lastError.isEmpty() ? "authorization required" : lastError;
    }

    // ------------------------------------------------------------------
    // machine fingerprint (HWID binding)
    // ------------------------------------------------------------------

    /**
     * Stable, non-sensitive machine fingerprint used for HWID binding:
     * SHA-256 over the sorted non-loopback network-interface MAC addresses,
     * hostname ({@code HOSTNAME}/{@code COMPUTERNAME}, then
     * {@link InetAddress#getLocalHost()}), {@code user.name}, {@code os.name}
     * and {@code os.arch} -> 64 lowercase hex chars.
     *
     * <p>{@code -Dumbra.auth.hwid=<value>} overrides the computation (tests and
     * managed environments). The value is cached for the process lifetime; it is
     * never written to the token cache.</p>
     */
    private static String hwid() {
        String override = System.getProperty("umbra.auth.hwid", "").trim();
        if (!override.isEmpty()) {
            return override;
        }
        if (hwidCache != null && !hwidCache.isEmpty()) {
            return hwidCache;
        }
        StringBuilder source = new StringBuilder();
        try {
            TreeSet<String> macs = new TreeSet<String>();
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                try {
                    if (networkInterface == null || networkInterface.isLoopback()) {
                        continue;
                    }
                    byte[] address = networkInterface.getHardwareAddress();
                    if (address == null || address.length == 0) {
                        continue;
                    }
                    StringBuilder hex = new StringBuilder(address.length * 2);
                    for (byte value : address) {
                        int unsigned = value & 0xFF;
                        if (unsigned < 16) {
                            hex.append('0');
                        }
                        hex.append(Integer.toHexString(unsigned));
                    }
                    macs.add(hex.toString());
                } catch (Throwable ignored) {
                    // Interface disappears or cannot be queried: skip it.
                }
            }
            for (String mac : macs) {
                source.append(mac).append('|');
            }
        } catch (Throwable ignored) {
            // No usable network interfaces: the remaining inputs still identify.
        }
        String host = System.getenv("HOSTNAME");
        if (host == null || host.trim().isEmpty()) {
            host = System.getenv("COMPUTERNAME");
        }
        if (host == null || host.trim().isEmpty()) {
            try {
                host = InetAddress.getLocalHost().getHostName();
            } catch (Throwable ignored) {
                host = "";
            }
        }
        source.append("host=").append(host == null ? "" : host.trim()).append('|');
        source.append("user=").append(System.getProperty("user.name", "")).append('|');
        source.append("os=").append(System.getProperty("os.name", "")).append('|');
        source.append("arch=").append(System.getProperty("os.arch", ""));
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(source.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte value : hash) {
                int unsigned = value & 0xFF;
                if (unsigned < 16) {
                    hex.append('0');
                }
                hex.append(Integer.toHexString(unsigned));
            }
            hwidCache = hex.toString();
        } catch (Throwable unavailable) {
            // SHA-256 always exists on Java 8; keep a stable fallback identifier.
            hwidCache = "hwid-unavailable";
        }
        return hwidCache;
    }

    /**
     * Headless helper used by tests/CI: logs in (or activates with a card) and
     * writes the token cache. Never opens a window.
     *
     * @param server    authorization server base URL
     * @param software  software id
     * @param username  user name
     * @param password  password
     * @param card      optional activation card (may be empty)
     * @param cacheFile token cache path (empty for the default location)
     * @return true when a token was obtained and cached
     */
    public static boolean authenticate(String server, String software, String username,
                                       String password, String card, String cacheFile) {
        SERVER = server == null ? "" : server.trim();
        SOFTWARE = software == null ? "" : software.trim();
        CACHE = cacheFile == null ? "" : cacheFile.trim();
        try {
            String token = loginToken(username, password);
            if (token == null && card != null && !card.trim().isEmpty()) {
                token = activateToken(username, password, card.trim());
            }
            if (token != null) {
                saveToken(token);
                return true;
            }
        } catch (Throwable ignored) {
            return false;
        }
        return false;
    }

    /** True when a token is currently valid for this software. */
    public static boolean isAuthorized() {
        try {
            String cached = loadCachedToken();
            return cached != null && validateToken(cached);
        } catch (Throwable ignored) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // server API
    // ------------------------------------------------------------------

    private static boolean validateToken(String token) {
        if (token == null || token.isEmpty()) {
            lastError = "empty token";
            return false;
        }
        Map<String, Object> result = apiPost("/api/auth/session",
                "token=" + encode(token) + "&software=" + encode(SOFTWARE)
                        + "&hwid=" + encode(hwid()));
        if (result == null) {
            lastError = "server unreachable while validating token";
            return false;
        }
        if ("HWID_MISMATCH".equals(string(result, "status"))) {
            hwidMismatch = true;
            lastError = "hwid mismatch";
            return false;
        }
        if ("HWID_REQUIRED".equals(string(result, "status"))) {
            lastError = "hwid required (client error)";
            return false;
        }
        if (Boolean.TRUE.equals(result.get("valid")) && "OK".equals(string(result, "status"))) {
            return true;
        }
        String detail = string(result, "reason");
        if (detail == null || detail.isEmpty()) {
            detail = string(result, "status");
        }
        lastError = "token rejected: " + (detail == null ? "TOKEN_INVALID" : detail);
        return false;
    }

    /** @return token on success, {@code null} when login did not authorize. */
    private static String loginToken(String username, String password) {
        Map<String, Object> result = apiPost("/api/auth/login",
                "username=" + encode(username) + "&password=" + encode(password)
                        + "&software=" + encode(SOFTWARE) + "&hwid=" + encode(hwid()));
        return tokenFrom(result);
    }

    /** @return token on success, {@code null} when activation failed. */
    private static String activateToken(String username, String password, String card) {
        Map<String, Object> result = apiPost("/api/auth/activate",
                "username=" + encode(username) + "&password=" + encode(password)
                        + "&card=" + encode(card) + "&software=" + encode(SOFTWARE)
                        + "&hwid=" + encode(hwid()));
        return tokenFrom(result);
    }

    private static String tokenFrom(Map<String, Object> result) {
        if (result == null) {
            lastError = "server unreachable during login/activation";
            return null;
        }
        if ("HWID_MISMATCH".equals(string(result, "status"))) {
            hwidMismatch = true;
            lastError = "hwid mismatch";
            return null;
        }
        if ("HWID_REQUIRED".equals(string(result, "status"))) {
            lastError = "hwid required (client error)";
            return null;
        }
        if (!Boolean.TRUE.equals(result.get("ok")) || !"OK".equals(string(result, "status"))) {
            lastError = errorText(result);
            return null;
        }
        String token = string(result, "token");
        if (token == null || token.isEmpty()) {
            lastError = "server did not return a token";
            return null;
        }
        return token;
    }

    private static Map<String, Object> apiPost(String path, String form) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(baseServer() + path);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(timeoutMs());
            connection.setReadTimeout(timeoutMs());
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type",
                    "application/x-www-form-urlencoded; charset=UTF-8");
            connection.setRequestProperty("Accept", "application/json");
            byte[] body = form.getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(body.length);
            OutputStream out = connection.getOutputStream();
            try {
                out.write(body);
            } finally {
                out.close();
            }
            int status = connection.getResponseCode();
            InputStream in = status >= HttpURLConnection.HTTP_BAD_REQUEST
                    ? connection.getErrorStream() : connection.getInputStream();
            String text = in == null ? "" : readAll(in);
            Map<String, Object> parsed = parseJsonObject(text);
            if (parsed == null && status >= HttpURLConnection.HTTP_BAD_REQUEST) {
                // The JDK returns a null error stream for some 401 responses (no
                // challenge header). Map the HTTP status to the contract code so the
                // dialog and silent mode can still report a meaningful error.
                parsed = new LinkedHashMap<String, Object>();
                parsed.put("ok", Boolean.FALSE);
                if (status == 401) {
                    parsed.put("status", "INVALID_CREDENTIALS");
                    parsed.put("error", "invalid credentials");
                } else if (status == 429) {
                    parsed.put("status", "RATE_LIMITED");
                    parsed.put("error", "rate limited");
                } else if (status == 403) {
                    parsed.put("status", "FORBIDDEN");
                    parsed.put("error", "forbidden");
                } else {
                    parsed.put("status", "SERVER_ERROR");
                    parsed.put("error", "HTTP " + status);
                }
            }
            return parsed;
        } catch (Throwable networkFailure) {
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static String baseServer() {
        String server = SERVER == null ? "" : SERVER.trim();
        while (server.endsWith("/")) {
            server = server.substring(0, server.length() - 1);
        }
        return server;
    }

    private static int timeoutMs() {
        try {
            int value = Integer.parseInt(TIMEOUT == null ? "" : TIMEOUT.trim());
            return value > 0 ? value : 5000;
        } catch (NumberFormatException ignored) {
            return 5000;
        }
    }

    private static String encode(String value) {
        try {
            return URLEncoder.encode(value == null ? "" : value, "UTF-8");
        } catch (IOException impossible) {
            return "";
        }
    }

    private static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------
    // token cache
    // ------------------------------------------------------------------

    private static String cachePath() {
        // Runtime override first (E2E isolation), then the build-time cache path.
        String runtime = System.getProperty("umbra.auth.cache", "").trim();
        if (!runtime.isEmpty()) {
            return runtime;
        }
        String configured = CACHE == null ? "" : CACHE.trim();
        if (!configured.isEmpty()) {
            return configured;
        }
        String home = System.getProperty("user.home", ".");
        return home + File.separator + ".umbra-auth" + File.separator + SOFTWARE + ".token";
    }

    private static String loadCachedToken() {
        try {
            Path path = Paths.get(cachePath());
            if (!Files.isRegularFile(path)) {
                return null;
            }
            // The cache is keyed by server + software: a token saved for another
            // software (even when E2E tests share one cache path) never validates.
            String cachedServer = null;
            String cachedSoftware = null;
            String token = null;
            for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                int equals = line.indexOf('=');
                if (equals <= 0) {
                    continue;
                }
                String key = line.substring(0, equals).trim();
                String value = line.substring(equals + 1).trim();
                if ("server".equals(key)) {
                    cachedServer = value;
                } else if ("software".equals(key)) {
                    cachedSoftware = value;
                } else if ("token".equals(key)) {
                    token = value;
                }
            }
            if (token == null || token.isEmpty()) {
                return null;
            }
            if (cachedServer != null && !normalize(cachedServer).equals(normalize(baseServer()))) {
                lastError = "cached token belongs to server " + cachedServer;
                return null;
            }
            if (cachedSoftware != null && !cachedSoftware.equals(SOFTWARE)) {
                lastError = "cached token belongs to software " + cachedSoftware;
                return null;
            }
            return token;
        } catch (Throwable unreadable) {
            return null;
        }
    }

    private static void saveToken(String token) {
        try {
            Path path = Paths.get(cachePath());
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            String text = "server=" + baseServer() + "\n"
                    + "software=" + SOFTWARE + "\n"
                    + "token=" + token + "\n";
            Files.write(path, text.getBytes(StandardCharsets.UTF_8));
            try {
                File file = path.toFile();
                file.setReadable(false, false);
                file.setReadable(true, true);
                file.setWritable(false, false);
                file.setWritable(true, true);
            } catch (Throwable ignored) {
                // Windows ignores POSIX-style permissions; best effort only.
            }
        } catch (Throwable ignored) {
            // An unwritable cache must not break authorization.
        }
    }

    private static String normalize(String value) {
        String result = value == null ? "" : value.trim();
        while (result.endsWith("/")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    // ------------------------------------------------------------------
    // interactive dialog (restrained classic style + zh/en internationalization)
    //
    // The template must stay a single class file: panel/field/button chrome is
    // generated as flat ARGB images, and every user-visible string lives in a
    // Swing component refreshed by the UI.
    // ------------------------------------------------------------------

    private static final int TONE_INFO = 0;
    private static final int TONE_ERROR = 1;
    private static final int TONE_OK = 2;

    private static final int STYLE_PRIMARY = 0;
    private static final int STYLE_PRIMARY_HOVER = 1;
    private static final int STYLE_GHOST = 2;
    private static final int STYLE_GHOST_HOVER = 3;

    private static final Color INK_BG = new Color(0x14, 0x11, 0x0D);
    private static final Color INK_PANEL = new Color(0x1C, 0x18, 0x13);
    private static final Color INK_SURFACE_ALT = new Color(0x24, 0x1F, 0x18);
    private static final Color INK_BORDER = new Color(0x32, 0x2B, 0x22);
    private static final Color INK_BORDER_STRONG = new Color(0x45, 0x3B, 0x2E);
    private static final Color INK_TEXT = new Color(0xE9, 0xE1, 0xD2);
    private static final Color INK_MUTED = new Color(0xA2, 0x96, 0x82);
    private static final Color GOLD = new Color(0xC7, 0xA7, 0x6C);
    private static final Color GOLD_STRONG = new Color(0xD8, 0xBC, 0x85);
    private static final Color BRONZE = new Color(0x8A, 0x6A, 0x3B);
    private static final Color BRONZE_DARK = new Color(0x6E, 0x53, 0x29);
    private static final Color PARCHMENT = new Color(0xF6, 0xF1, 0xE7);
    private static final Color DANGER = new Color(0xC8, 0x69, 0x5C);
    private static final Color SUCCESS = new Color(0x8A, 0xA6, 0x7F);

    private static final int DIALOG_WIDTH = 470;
    private static final int DIALOG_HEIGHT = 430;
    private static final int CONTENT_WIDTH = 434;
    private static final int FIELD_WIDTH = CONTENT_WIDTH;
    private static final int FIELD_HEIGHT = 34;
    private static final int BUTTON_WIDTH = CONTENT_WIDTH;
    private static final int BUTTON_HEIGHT = 38;

    /**
     * The gate UI is English-only by product decision (the obfuscator GUI and the
     * admin console keep their own zh/en switches). -Dumbra.auth.lang is no
     * longer used by the dialog.
     */
    private static boolean chinese = false;

    /** Live translators registered by the open dialog (single dialog per process). */
    private static final List<Runnable> TRANSLATORS = new ArrayList<Runnable>();

    private static String lastStatusZh = "";
    private static String lastStatusEn = "";
    private static int lastStatusTone = TONE_INFO;

    private static boolean detectChinese() {
        String lang = System.getProperty("umbra.auth.lang", "").trim().toLowerCase(Locale.ROOT);
        if (lang.startsWith("zh")) {
            return true;
        }
        if (lang.startsWith("en")) {
            return false;
        }
        return Locale.getDefault().getLanguage().toLowerCase(Locale.ROOT).startsWith("zh");
    }

    private static String tr(String zh, String en) {
        return chinese ? zh : en;
    }

    private static void onTranslate(Runnable action) {
        TRANSLATORS.add(action);
    }

    private static void refreshI18n() {
        for (Runnable action : TRANSLATORS) {
            action.run();
        }
    }

    private static boolean showDialogAndWait() {
        final boolean[] granted = {false};
        try {
            SwingUtilities.invokeAndWait(() -> granted[0] = showDialog());
        } catch (Throwable failure) {
            System.err.println("Umbra Auth: unable to show authorization window: "
                    + failure.getClass().getSimpleName());
            return false;
        }
        return granted[0];
    }

    private static boolean showDialog() {
        final boolean[] granted = {false};
        TRANSLATORS.clear();
        lastStatusZh = "";
        lastStatusEn = "";
        lastStatusTone = TONE_INFO;

        final JDialog dialog = new JDialog((java.awt.Frame) null, TITLE, true);
        dialog.setUndecorated(true);
        dialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        try {
            dialog.setBackground(new Color(0, 0, 0, 0));
            dialog.setShape(new RoundRectangle2D.Double(0, 0, DIALOG_WIDTH, DIALOG_HEIGHT, 8, 8));
        } catch (Throwable ignored) {
            // Shape/transparency is best effort on older window managers.
        }

        final Font bodyFont = uiBodyFont(Font.PLAIN, 12);
        final Font bodyBold = uiBodyFont(Font.BOLD, 12);
        final Font smallFont = uiBodyFont(Font.PLAIN, 11);
        final Font brandFont = uiBodyFont(Font.BOLD, 10);
        final Font titleFont = uiSerifFont(Font.PLAIN, 17, TITLE);

        final Map<JButton, Icon[]> hover = new HashMap<JButton, Icon[]>();
        final Map<JButton, Color[]> textHover = new HashMap<JButton, Color[]>();
        final Map<Component, JLabel> fieldFrames = new HashMap<Component, JLabel>();
        final Icon fieldIdle = new ImageIcon(fieldImage(FIELD_WIDTH, FIELD_HEIGHT, false));
        final Icon fieldFocus = new ImageIcon(fieldImage(FIELD_WIDTH, FIELD_HEIGHT, true));

        final JLabel root = new JLabel(new ImageIcon(panelImage(DIALOG_WIDTH, DIALOG_HEIGHT)));
        root.setLayout(new BorderLayout(0, 8));
        root.setBorder(new EmptyBorder(16, 20, 14, 20));

        // Header: wordmark, serif title, thin bronze rule, software line.
        final JLabel brand = styledLabel("UMBRA AUTH", brandFont, GOLD);
        final JLabel title = styledLabel(TITLE, titleFont, INK_TEXT);
        final JPanel rule = new JPanel();
        rule.setOpaque(true);
        rule.setBackground(GOLD);
        rule.setPreferredSize(new Dimension(200, 1));
        rule.setMinimumSize(new Dimension(200, 1));
        rule.setMaximumSize(new Dimension(200, 1));
        final JLabel softwareLabel = styledLabel("", smallFont, INK_MUTED);
        final JPanel brandColumn = transparentPanel(null);
        brandColumn.setLayout(new BoxLayout(brandColumn, BoxLayout.Y_AXIS));
        brandColumn.add(brand);
        brandColumn.add(Box.createVerticalStrut(3));
        brandColumn.add(title);
        brandColumn.add(Box.createVerticalStrut(6));
        brandColumn.add(rule);
        brandColumn.add(Box.createVerticalStrut(4));
        final JPanel header = transparentPanel(new BorderLayout());
        header.add(brandColumn, BorderLayout.CENTER);
        final JButton language = textButton(textHover, "EN", smallFont, GOLD, GOLD_STRONG);
        final JButton close = textButton(textHover, "\u00d7", bodyFont.deriveFont(Font.BOLD, 15f), INK_MUTED, GOLD);
        close.setPreferredSize(new Dimension(24, 24));
        final JPanel headerRight = transparentPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        language.setVisible(false);
        headerRight.add(close);
        header.add(headerRight, BorderLayout.NORTH);

        // Underlined text-style tabs + CardLayout panels (no OS tab chrome).
        final CardLayout cardLayout = new CardLayout();
        final JPanel cardPanel = transparentPanel(cardLayout);
        final String[] cardNames = {"login", "register", "activate"};
        final JButton[] tabButtons = new JButton[3];
        final int[] selectedTab = {0};
        final JPanel tabStrip = transparentPanel(new GridLayout(1, 3, 10, 0));
        for (int i = 0; i < tabButtons.length; i++) {
            tabButtons[i] = tabButton(bodyBold);
            tabStrip.add(tabButtons[i]);
        }

        // Login card.
        final JLabel loginUserCaption = caption(smallFont);
        final JLabel loginPassCaption = caption(smallFont);
        final JTextField loginUser = textField(bodyFont);
        final JPasswordField loginPass = passwordField(bodyFont);
        final JButton loginButton = imageButton(hover, "", BUTTON_WIDTH, BUTTON_HEIGHT, bodyBold,
                STYLE_PRIMARY, STYLE_PRIMARY_HOVER);
        JPanel loginFields = fieldsPanel();
        loginFields.add(loginUserCaption);
        loginFields.add(fieldFrame(loginUser, fieldIdle, fieldFrames));
        loginFields.add(Box.createVerticalStrut(6));
        loginFields.add(loginPassCaption);
        loginFields.add(fieldFrame(loginPass, fieldIdle, fieldFrames));
        cardPanel.add(card(loginFields, loginButton), cardNames[0]);

        // Register card.
        final JLabel regUserCaption = caption(smallFont);
        final JLabel regPassCaption = caption(smallFont);
        final JLabel regConfirmCaption = caption(smallFont);
        final JTextField regUser = textField(bodyFont);
        final JPasswordField regPass = passwordField(bodyFont);
        final JPasswordField regConfirm = passwordField(bodyFont);
        final JButton registerButton = imageButton(hover, "", BUTTON_WIDTH, BUTTON_HEIGHT, bodyBold,
                STYLE_PRIMARY, STYLE_PRIMARY_HOVER);
        JPanel registerFields = fieldsPanel();
        registerFields.add(regUserCaption);
        registerFields.add(fieldFrame(regUser, fieldIdle, fieldFrames));
        registerFields.add(Box.createVerticalStrut(5));
        registerFields.add(regPassCaption);
        registerFields.add(fieldFrame(regPass, fieldIdle, fieldFrames));
        registerFields.add(Box.createVerticalStrut(5));
        registerFields.add(regConfirmCaption);
        registerFields.add(fieldFrame(regConfirm, fieldIdle, fieldFrames));
        cardPanel.add(card(registerFields, registerButton), cardNames[1]);

        // Card activation card.
        final JLabel actUserCaption = caption(smallFont);
        final JLabel actPassCaption = caption(smallFont);
        final JLabel actCardCaption = caption(smallFont);
        final JTextField actUser = textField(bodyFont);
        final JPasswordField actPass = passwordField(bodyFont);
        final JTextField actCard = textField(bodyFont);
        final JButton activateButton = imageButton(hover, "", BUTTON_WIDTH, BUTTON_HEIGHT, bodyBold,
                STYLE_PRIMARY, STYLE_PRIMARY_HOVER);
        JPanel activateFields = fieldsPanel();
        activateFields.add(actUserCaption);
        activateFields.add(fieldFrame(actUser, fieldIdle, fieldFrames));
        activateFields.add(Box.createVerticalStrut(5));
        activateFields.add(actPassCaption);
        activateFields.add(fieldFrame(actPass, fieldIdle, fieldFrames));
        activateFields.add(Box.createVerticalStrut(5));
        activateFields.add(actCardCaption);
        activateFields.add(fieldFrame(actCard, fieldIdle, fieldFrames));
        cardPanel.add(card(activateFields, activateButton), cardNames[2]);

        final JPanel centerStack = transparentPanel(new BorderLayout(0, 8));
        centerStack.add(tabStrip, BorderLayout.NORTH);
        centerStack.add(cardPanel, BorderLayout.CENTER);

        // Status line only: the server URL and software id are intentionally
        // hidden from end users so the gate does not leak deployment details.
        final JLabel status = styledLabel(" ", bodyFont, INK_MUTED);
        final JButton exit = imageButton(hover, "", 104, 30, bodyFont, STYLE_GHOST, STYLE_GHOST_HOVER);
        final JPanel footer = transparentPanel(new BorderLayout());
        footer.add(exit, BorderLayout.EAST);
        final JPanel bottom = transparentPanel(new BorderLayout(0, 5));
        bottom.add(status, BorderLayout.NORTH);
        bottom.add(footer, BorderLayout.SOUTH);

        root.add(header, BorderLayout.NORTH);
        root.add(centerStack, BorderLayout.CENTER);
        root.add(bottom, BorderLayout.SOUTH);
        dialog.setContentPane(root);
        dialog.setSize(DIALOG_WIDTH, DIALOG_HEIGHT);
        dialog.setLocationRelativeTo(null);

        final Runnable showLogin = () -> selectTab(cardPanel, cardLayout, tabButtons, selectedTab,
                bodyBold, 0, cardNames);
        final Runnable showRegister = () -> selectTab(cardPanel, cardLayout, tabButtons, selectedTab,
                bodyBold, 1, cardNames);
        final Runnable showActivate = () -> selectTab(cardPanel, cardLayout, tabButtons, selectedTab,
                bodyBold, 2, cardNames);
        final boolean allowRegister = isTrue(REGISTER);
        tabButtons[0].addActionListener(event -> showLogin.run());
        tabButtons[1].addActionListener(event -> {
            if (allowRegister) {
                showRegister.run();
            }
        });
        tabButtons[2].addActionListener(event -> showActivate.run());
        if (!allowRegister) {
            tabButtons[1].setEnabled(false);
        }

        close.addActionListener(event -> dialog.dispose());
        exit.addActionListener(event -> dialog.dispose());
        language.addActionListener(event -> {
            chinese = !chinese;
            refreshI18n();
        });
        loginButton.addActionListener(event -> attemptLogin(dialog, status, granted, showActivate,
                loginUser.getText().trim(), new String(loginPass.getPassword())));
        registerButton.addActionListener(event -> attemptRegister(status, showActivate, actUser, actPass,
                regUser.getText().trim(), new String(regPass.getPassword()),
                new String(regConfirm.getPassword())));
        activateButton.addActionListener(event -> attemptActivate(dialog, status, granted,
                actUser.getText().trim(), new String(actPass.getPassword()),
                actCard.getText().trim()));

        loginUser.addActionListener(event -> attemptLogin(dialog, status, granted, showActivate,
                loginUser.getText().trim(), new String(loginPass.getPassword())));
        loginPass.addActionListener(event -> attemptLogin(dialog, status, granted, showActivate,
                loginUser.getText().trim(), new String(loginPass.getPassword())));
        regUser.addActionListener(event -> attemptRegister(status, showActivate, actUser, actPass,
                regUser.getText().trim(), new String(regPass.getPassword()),
                new String(regConfirm.getPassword())));
        regPass.addActionListener(event -> attemptRegister(status, showActivate, actUser, actPass,
                regUser.getText().trim(), new String(regPass.getPassword()),
                new String(regConfirm.getPassword())));
        regConfirm.addActionListener(event -> attemptRegister(status, showActivate, actUser, actPass,
                regUser.getText().trim(), new String(regPass.getPassword()),
                new String(regConfirm.getPassword())));
        actUser.addActionListener(event -> attemptActivate(dialog, status, granted,
                actUser.getText().trim(), new String(actPass.getPassword()),
                actCard.getText().trim()));
        actPass.addActionListener(event -> attemptActivate(dialog, status, granted,
                actUser.getText().trim(), new String(actPass.getPassword()),
                actCard.getText().trim()));
        actCard.addActionListener(event -> attemptActivate(dialog, status, granted,
                actUser.getText().trim(), new String(actPass.getPassword()),
                actCard.getText().trim()));

        dialog.getRootPane().registerKeyboardAction(event -> dialog.dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);

        // Register all dynamic strings once; refreshI18n() runs them on toggle.
        onTranslate(() -> {
            brand.setFont(uiBodyFont(Font.BOLD, 10));
            title.setText(TITLE);
            title.setFont(uiSerifFont(Font.PLAIN, 17, TITLE));
            softwareLabel.setText("");
            tabButtons[0].setText("Sign in");
            tabButtons[1].setText("Register");
            tabButtons[2].setText("Activate card");
            styleTabs(tabButtons, selectedTab[0], uiBodyFont(Font.BOLD, 12));
            loginUserCaption.setText("Username");
            loginPassCaption.setText("Password");
            regUserCaption.setText("Username");
            regPassCaption.setText("Password");
            regConfirmCaption.setText("Confirm password");
            actUserCaption.setText("Username");
            actPassCaption.setText("Password");
            actCardCaption.setText("Activate card");
            setFlatButton(hover, loginButton, "Sign in", BUTTON_WIDTH, BUTTON_HEIGHT,
                    uiBodyFont(Font.BOLD, 12), STYLE_PRIMARY, STYLE_PRIMARY_HOVER);
            setFlatButton(hover, registerButton, "Register", BUTTON_WIDTH, BUTTON_HEIGHT,
                    uiBodyFont(Font.BOLD, 12), STYLE_PRIMARY, STYLE_PRIMARY_HOVER);
            setFlatButton(hover, activateButton, "Activate", BUTTON_WIDTH, BUTTON_HEIGHT,
                    uiBodyFont(Font.BOLD, 12), STYLE_PRIMARY, STYLE_PRIMARY_HOVER);
            setFlatButton(hover, exit, "Exit", 104, 30, uiBodyFont(Font.PLAIN, 12),
                    STYLE_GHOST, STYLE_GHOST_HOVER);
            applyStatus(status);
            dialog.setTitle(TITLE);
        });

        // One AWT listener drives window dragging, hover and field focus.
        final Point dragStart = new Point();
        final boolean[] dragging = {false};
        final AWTEventListener uiEvents = event -> {
            if (event instanceof FocusEvent) {
                FocusEvent focus = (FocusEvent) event;
                JLabel frame = fieldFrames.get(focus.getComponent());
                if (frame != null) {
                    frame.setIcon(event.getID() == FocusEvent.FOCUS_GAINED ? fieldFocus : fieldIdle);
                }
                return;
            }
            if (!(event instanceof MouseEvent)) {
                return;
            }
            MouseEvent mouse = (MouseEvent) event;
            Object source = mouse.getSource();
            if (source instanceof Component && SwingUtilities.isDescendingFrom((Component) source, header)) {
                if (mouse.getID() == MouseEvent.MOUSE_PRESSED) {
                    dragStart.setLocation(mouse.getPoint());
                    dragging[0] = true;
                } else if (mouse.getID() == MouseEvent.MOUSE_DRAGGED && dragging[0]) {
                    Point location = dialog.getLocation();
                    dialog.setLocation(location.x + mouse.getX() - dragStart.x,
                            location.y + mouse.getY() - dragStart.y);
                } else if (mouse.getID() == MouseEvent.MOUSE_RELEASED) {
                    dragging[0] = false;
                }
                return;
            }
            if (!(source instanceof JButton)) {
                return;
            }
            JButton button = (JButton) source;
            if (mouse.getID() == MouseEvent.MOUSE_ENTERED) {
                if (indexOf(tabButtons, button) >= 0) {
                    button.setForeground(GOLD);
                } else if (textHover.containsKey(button)) {
                    button.setForeground(textHover.get(button)[1]);
                } else if (hover.containsKey(button)) {
                    button.setIcon(hover.get(button)[1]);
                }
            } else if (mouse.getID() == MouseEvent.MOUSE_EXITED) {
                int tab = indexOf(tabButtons, button);
                if (tab >= 0) {
                    button.setForeground(tab == selectedTab[0] ? INK_TEXT : INK_MUTED);
                } else if (textHover.containsKey(button)) {
                    button.setForeground(textHover.get(button)[0]);
                } else if (hover.containsKey(button)) {
                    button.setIcon(hover.get(button)[0]);
                }
            }
        };
        Toolkit.getDefaultToolkit().addAWTEventListener(uiEvents,
                AWTEvent.MOUSE_EVENT_MASK | AWTEvent.FOCUS_EVENT_MASK);
        try {
            refreshI18n();
            showLogin.run();
            setStatus(status, "Enter your account details", "Enter your account details", TONE_INFO);
            refreshI18n();
            dialog.setVisible(true);
        } finally {
            Toolkit.getDefaultToolkit().removeAWTEventListener(uiEvents);
        }
        return granted[0];
    }

    private static int indexOf(JButton[] buttons, JButton candidate) {
        for (int i = 0; i < buttons.length; i++) {
            if (buttons[i] == candidate) {
                return i;
            }
        }
        return -1;
    }

    // ------------------------------------------------------------------
    // dialog actions (all user-visible text is localized)
    // ------------------------------------------------------------------

    private static void attemptLogin(JDialog dialog, JLabel status, boolean[] granted,
                                     Runnable showActivate, String username, String password) {
        if (username.isEmpty() || password.isEmpty()) {
            setStatus(status, "Username and password are required", "Username and password are required", TONE_INFO);
            return;
        }
        setStatus(status, "Signing in...", "Signing in...", TONE_INFO);
        Map<String, Object> result = apiPost("/api/auth/login",
                "username=" + encode(username) + "&password=" + encode(password)
                        + "&software=" + encode(SOFTWARE) + "&hwid=" + encode(hwid()));
        if (result == null) {
            setStatus(status, "Network or server error, please retry", "Network or server error, please retry", TONE_ERROR);
            return;
        }
        if ("HWID_MISMATCH".equals(string(result, "status"))) {
            hwidMismatch = true;
            setStatus(status, "Hardware ID mismatch", "Hardware ID mismatch", TONE_ERROR);
            return;
        }
        if ("HWID_REQUIRED".equals(string(result, "status"))) {
            setStatus(status, "Hardware ID required (client error)", "Hardware ID required (client error)", TONE_ERROR);
            return;
        }
        if ("OK".equals(string(result, "status")) && string(result, "token") != null) {
            saveToken(string(result, "token"));
            granted[0] = true;
            dialog.dispose();
            return;
        }
        if ("ACTIVATION_REQUIRED".equals(string(result, "status"))) {
            setStatus(status, "This account is not activated for this software; enter a card", "This account is not activated for this software; enter a card", TONE_INFO);
            showActivate.run();
            return;
        }
        setStatus(status, localizedErrorZh(result), localizedErrorEn(result), TONE_ERROR);
    }

    private static void attemptRegister(JLabel status, Runnable showActivate, JTextField actUser,
                                        JPasswordField actPass, String username, String password,
                                        String confirm) {
        if (username.isEmpty() || password.isEmpty()) {
            setStatus(status, "Username and password are required", "Username and password are required", TONE_INFO);
            return;
        }
        if (!password.equals(confirm)) {
            setStatus(status, "Passwords do not match", "Passwords do not match", TONE_ERROR);
            return;
        }
        setStatus(status, "Creating account...", "Creating account...", TONE_INFO);
        Map<String, Object> result = apiPost("/api/auth/register",
                "username=" + encode(username) + "&password=" + encode(password));
        if (result == null) {
            setStatus(status, "Network or server error, please retry", "Network or server error, please retry", TONE_ERROR);
            return;
        }
        if ("REGISTERED".equals(string(result, "status")) || Boolean.TRUE.equals(result.get("ok"))) {
            actUser.setText(username);
            actPass.setText(password);
            showActivate.run();
            setStatus(status, "Registered. Activate with your card", "Registered. Activate with your card", TONE_OK);
            return;
        }
        setStatus(status, localizedErrorZh(result), localizedErrorEn(result), TONE_ERROR);
    }

    private static void attemptActivate(JDialog dialog, JLabel status, boolean[] granted,
                                         String username, String password, String card) {
        if (username.isEmpty() || password.isEmpty() || card.isEmpty()) {
            setStatus(status, "Username, password and card are required", "Username, password and card are required", TONE_INFO);
            return;
        }
        setStatus(status, "Activating...", "Activating...", TONE_INFO);
        Map<String, Object> result = apiPost("/api/auth/activate",
                "username=" + encode(username) + "&password=" + encode(password)
                        + "&card=" + encode(card) + "&software=" + encode(SOFTWARE)
                        + "&hwid=" + encode(hwid()));
        if (result == null) {
            setStatus(status, "Network or server error, please retry", "Network or server error, please retry", TONE_ERROR);
            return;
        }
        if ("HWID_MISMATCH".equals(string(result, "status"))) {
            hwidMismatch = true;
            setStatus(status, "Hardware ID mismatch", "Hardware ID mismatch", TONE_ERROR);
            return;
        }
        if ("HWID_REQUIRED".equals(string(result, "status"))) {
            setStatus(status, "Hardware ID required (client error)", "Hardware ID required (client error)", TONE_ERROR);
            return;
        }
        if ("OK".equals(string(result, "status")) && string(result, "token") != null) {
            saveToken(string(result, "token"));
            granted[0] = true;
            dialog.dispose();
            return;
        }
        setStatus(status, localizedErrorZh(result), localizedErrorEn(result), TONE_ERROR);
    }

    private static void setStatus(JLabel status, String zh, String en, int tone) {
        lastStatusZh = zh == null ? "" : zh;
        lastStatusEn = en == null ? "" : en;
        lastStatusTone = tone;
        applyStatus(status);
    }

    private static void applyStatus(JLabel status) {
        String text = chinese ? lastStatusZh : lastStatusEn;
        status.setText(text == null || text.isEmpty() ? " " : text);
        status.setForeground(lastStatusTone == TONE_ERROR ? DANGER
                : lastStatusTone == TONE_OK ? SUCCESS : INK_MUTED);
    }

    private static String localizedErrorZh(Map<String, Object> result) {
        return localizedErrorEn(result);
    }

    private static String localizedErrorEn(Map<String, Object> result) {
        String code = string(result, "status");
        if ("INVALID_CREDENTIALS".equals(code)) {
            return "Wrong password";
        }
        if ("USERNAME_TAKEN".equals(code)) {
            return "Username already taken";
        }
        if ("CARD_INVALID".equals(code)) {
            return "Invalid activation card";
        }
        if ("CARD_USED".equals(code)) {
            return "Activation card already used";
        }
        if ("CARD_REVOKED".equals(code)) {
            return "Activation card revoked";
        }
        if ("CARD_DISABLED".equals(code)) {
            return "Activation card disabled";
        }
        if ("CARD_SOFTWARE_MISMATCH".equals(code)) {
            return "Card belongs to another software";
        }
        if ("SOFTWARE_UNKNOWN".equals(code)) {
            return "Unknown software";
        }
        if ("SOFTWARE_DISABLED".equals(code)) {
            return "Software disabled";
        }
        if ("RATE_LIMITED".equals(code)) {
            return "Too many requests, please retry later";
        }
        if ("HWID_MISMATCH".equals(code)) {
            return "Hardware ID mismatch";
        }
        String error = string(result, "error");
        return error == null || error.isEmpty() ? "Authorization failed" : error;
    }

    private static String errorText(Map<String, Object> result) {
        String error = string(result, "error");
        if (error != null && !error.isEmpty()) {
            return error;
        }
        String status = string(result, "status");
        return status == null ? "Authorization failed" : status;
    }
    // ------------------------------------------------------------------
    // layout helpers
    // ------------------------------------------------------------------

    private static void selectTab(JPanel cards, CardLayout layout, JButton[] tabs, int[] selected,
                                  Font tabFont, int index, String[] names) {
        selected[0] = index;
        layout.show(cards, names[index]);
        styleTabs(tabs, index, tabFont);
    }

    private static void styleTabs(JButton[] tabs, int selected, Font font) {
        for (int i = 0; i < tabs.length; i++) {
            boolean active = i == selected;
            tabs[i].setFont(font);
            tabs[i].setForeground(active ? INK_TEXT : INK_MUTED);
            tabs[i].setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 0, 2, 0, active ? GOLD : INK_PANEL),
                    new EmptyBorder(7, 10, 5, 10)));
        }
    }

    private static JButton tabButton(Font font) {
        JButton button = new JButton();
        button.setFont(font);
        button.setForeground(INK_MUTED);
        button.setContentAreaFilled(false);
        button.setFocusPainted(false);
        button.setOpaque(false);
        button.setBorderPainted(true);
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 2, 0, INK_PANEL),
                new EmptyBorder(7, 10, 5, 10)));
        return button;
    }

    private static JButton textButton(Map<JButton, Color[]> textHover, String text, Font font,
                                      Color normal, Color hoverColor) {
        JButton button = new JButton(text);
        button.setFont(font);
        button.setForeground(normal);
        button.setContentAreaFilled(false);
        button.setBorderPainted(false);
        button.setFocusPainted(false);
        button.setOpaque(false);
        button.setBorder(new EmptyBorder(2, 6, 2, 6));
        textHover.put(button, new Color[]{normal, hoverColor});
        return button;
    }

    private static JPanel card(JPanel fields, JButton primary) {
        JPanel panel = transparentPanel(new BorderLayout(0, 10));
        panel.setBorder(new EmptyBorder(9, 0, 0, 0));
        panel.add(fields, BorderLayout.NORTH);
        panel.add(primary, BorderLayout.SOUTH);
        return panel;
    }

    private static JPanel fieldsPanel() {
        JPanel panel = transparentPanel(null);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        return panel;
    }

    private static JLabel caption(Font font) {
        JLabel label = styledLabel("", font, INK_MUTED);
        label.setBorder(new EmptyBorder(0, 1, 0, 0));
        return label;
    }

    private static JLabel styledLabel(String text, Font font, Color color) {
        JLabel label = new JLabel(text);
        label.setFont(font);
        label.setForeground(color);
        return label;
    }

    private static JLabel fieldFrame(JTextField field, Icon idle, Map<Component, JLabel> frames) {
        JLabel frame = new JLabel(idle);
        frame.setLayout(new BorderLayout());
        frame.setPreferredSize(new Dimension(FIELD_WIDTH, FIELD_HEIGHT));
        frame.setMinimumSize(new Dimension(FIELD_WIDTH, FIELD_HEIGHT));
        frame.setMaximumSize(new Dimension(FIELD_WIDTH, FIELD_HEIGHT));
        frame.setHorizontalAlignment(JLabel.LEFT);
        frame.setVerticalAlignment(JLabel.CENTER);
        frame.add(field, BorderLayout.CENTER);
        frames.put(field, frame);
        return frame;
    }

    private static JPanel transparentPanel(LayoutManager layout) {
        JPanel panel = layout == null ? new JPanel() : new JPanel(layout);
        panel.setOpaque(false);
        return panel;
    }

    private static JTextField textField(Font font) {
        JTextField field = new JTextField();
        field.setFont(font);
        field.setOpaque(false);
        field.setForeground(INK_TEXT);
        field.setCaretColor(GOLD);
        field.setBorder(new EmptyBorder(7, 10, 7, 10));
        field.setSelectionColor(new Color(0x8A, 0x6A, 0x3B, 120));
        field.setSelectedTextColor(PARCHMENT);
        return field;
    }

    private static JPasswordField passwordField(Font font) {
        JPasswordField field = new JPasswordField();
        field.setFont(font);
        field.setOpaque(false);
        field.setForeground(INK_TEXT);
        field.setCaretColor(GOLD);
        field.setBorder(new EmptyBorder(7, 10, 7, 10));
        field.setSelectionColor(new Color(0x8A, 0x6A, 0x3B, 120));
        field.setSelectedTextColor(PARCHMENT);
        return field;
    }

    private static JButton imageButton(Map<JButton, Icon[]> hover, String text, int width, int height,
                                       Font font, int style, int hoverStyle) {
        JButton button = new JButton();
        button.setPreferredSize(new Dimension(width, height));
        button.setMinimumSize(new Dimension(width, height));
        button.setMaximumSize(new Dimension(width, height));
        button.setContentAreaFilled(false);
        button.setBorderPainted(false);
        button.setFocusPainted(false);
        button.setOpaque(false);
        button.setRolloverEnabled(false);
        setFlatButton(hover, button, text, width, height, font, style, hoverStyle);
        return button;
    }

    private static void setFlatButton(Map<JButton, Icon[]> hover, JButton button, String text,
                                      int width, int height, Font font, int style, int hoverStyle) {
        Icon normal = new ImageIcon(buttonImage(width, height, text, font, style));
        Icon hovered = new ImageIcon(buttonImage(width, height, text, font, hoverStyle));
        button.setIcon(normal);
        hover.put(button, new Icon[]{normal, hovered});
    }

    // ------------------------------------------------------------------
    // fonts
    // ------------------------------------------------------------------

    private static Font uiBodyFont(int style, int size) {
        try {
            java.util.Set<String> families = new java.util.HashSet<String>(java.util.Arrays.asList(
                    GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames()));
            String[] candidates = {"Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI"};
            for (String candidate : candidates) {
                if (families.contains(candidate)) {
                    return new Font(candidate, style, size);
                }
            }
        } catch (Throwable ignored) {
            // Fall through to the logical Dialog font.
        }
        return new Font("Dialog", style, size);
    }

    private static Font uiSerifFont(int style, int size, String sample) {
        try {
            java.util.Set<String> families = new java.util.HashSet<String>(java.util.Arrays.asList(
                    GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames()));
            String[] candidates = containsCjk(sample)
                    ? new String[]{"SimSun", "Songti SC", "Noto Serif CJK SC", "Serif"}
                    : new String[]{"Georgia", "Palatino Linotype", "Times New Roman", "Serif"};
            for (String candidate : candidates) {
                if (families.contains(candidate)) {
                    return new Font(candidate, style, size);
                }
            }
        } catch (Throwable ignored) {
            // Fall through to the logical Serif font.
        }
        return new Font("Serif", style, size);
    }

    private static boolean containsCjk(String text) {
        if (text == null) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if ((c >= 0x4E00 && c <= 0x9FFF) || (c >= 0x3400 && c <= 0x4DBF)) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    // generated classic chrome (flat images; single-class template)
    // ------------------------------------------------------------------

    private static BufferedImage panelImage(int width, int height) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        RoundRectangle2D outer = new RoundRectangle2D.Double(0.5, 0.5, width - 1.0, height - 1.0, 16, 16);
        g.setColor(INK_BORDER);
        g.fill(outer);
        RoundRectangle2D inner = new RoundRectangle2D.Double(1.5, 1.5, width - 3.0, height - 3.0, 14, 14);
        g.setColor(INK_PANEL);
        g.fill(inner);
        g.dispose();
        return image;
    }

    private static BufferedImage fieldImage(int width, int height, boolean focused) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        RoundRectangle2D shape = new RoundRectangle2D.Double(0.5, 0.5, width - 1.0, height - 1.0, 8, 8);
        g.setColor(focused ? INK_SURFACE_ALT : INK_BG);
        g.fill(shape);
        g.setColor(focused ? INK_BORDER_STRONG : INK_BORDER);
        g.draw(shape);
        g.dispose();
        return image;
    }

    private static BufferedImage buttonImage(int width, int height, String text, Font font, int style) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        RoundRectangle2D shape = new RoundRectangle2D.Double(0.5, 0.5, width - 1.0, height - 1.0, 8, 8);
        boolean primary = style == STYLE_PRIMARY || style == STYLE_PRIMARY_HOVER;
        boolean hovered = style == STYLE_PRIMARY_HOVER || style == STYLE_GHOST_HOVER;
        if (primary) {
            g.setColor(hovered ? BRONZE_DARK : BRONZE);
            g.fill(shape);
        } else {
            g.setColor(hovered ? INK_SURFACE_ALT : INK_PANEL);
            g.fill(shape);
            g.setColor(hovered ? INK_BORDER_STRONG : INK_BORDER);
            g.draw(shape);
        }
        if (text != null && !text.isEmpty()) {
            g.setFont(font);
            g.setColor(primary ? PARCHMENT : (hovered ? INK_TEXT : INK_MUTED));
            FontMetrics metrics = g.getFontMetrics();
            int x = Math.max(0, (width - metrics.stringWidth(text)) / 2);
            int y = (height - metrics.getHeight()) / 2 + metrics.getAscent();
            g.drawString(text, x, y);
        }
        g.dispose();
        return image;
    }

    // ------------------------------------------------------------------
    // minimal flat JSON parser (responses are flat per server contract)
    // ------------------------------------------------------------------

    private static Map<String, Object> parseJsonObject(String text) {
        if (text == null) {
            return null;
        }
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        int i = skipWhitespace(text, 0);
        if (i >= text.length() || text.charAt(i) != '{') {
            return null;
        }
        i++;
        int length = text.length();
        while (true) {
            i = skipWhitespace(text, i);
            if (i >= length) {
                return null;
            }
            if (text.charAt(i) == '}') {
                return map;
            }
            if (text.charAt(i) != '"') {
                return null;
            }
            StringBuilder key = new StringBuilder();
            i = parseString(text, i, key);
            if (i < 0) {
                return null;
            }
            i = skipWhitespace(text, i);
            if (i >= length || text.charAt(i) != ':') {
                return null;
            }
            i = skipWhitespace(text, i + 1);
            if (i >= length) {
                return null;
            }
            char first = text.charAt(i);
            Object value;
            if (first == '"') {
                StringBuilder valueText = new StringBuilder();
                i = parseString(text, i, valueText);
                if (i < 0) {
                    return null;
                }
                value = valueText.toString();
            } else if (first == 't' && text.startsWith("true", i)) {
                value = Boolean.TRUE;
                i += 4;
            } else if (first == 'f' && text.startsWith("false", i)) {
                value = Boolean.FALSE;
                i += 5;
            } else if (first == 'n' && text.startsWith("null", i)) {
                value = null;
                i += 4;
            } else if (first == '{' || first == '[') {
                i = skipComposite(text, i);
                value = null;
            } else {
                int start = i;
                while (i < length && "-+.eE0123456789".indexOf(text.charAt(i)) >= 0) {
                    i++;
                }
                if (i == start) {
                    return null;
                }
                value = Double.valueOf(text.substring(start, i));
            }
            map.put(key.toString(), value);
            i = skipWhitespace(text, i);
            if (i < length && text.charAt(i) == ',') {
                i++;
                continue;
            }
            if (i < length && text.charAt(i) == '}') {
                return map;
            }
            return null;
        }
    }

    /** Parses a JSON string starting at the opening quote; returns the next index or -1. */
    private static int parseString(String text, int index, StringBuilder out) {
        int i = index + 1;
        int length = text.length();
        while (i < length) {
            char c = text.charAt(i++);
            if (c == '"') {
                return i;
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (i >= length) {
                return -1;
            }
            char escape = text.charAt(i++);
            switch (escape) {
                case '"':
                case '\\':
                case '/':
                    out.append(escape);
                    break;
                case 'b':
                    out.append('\b');
                    break;
                case 'f':
                    out.append('\f');
                    break;
                case 'n':
                    out.append('\n');
                    break;
                case 'r':
                    out.append('\r');
                    break;
                case 't':
                    out.append('\t');
                    break;
                case 'u':
                    if (i + 4 > length) {
                        return -1;
                    }
                    try {
                        out.append((char) Integer.parseInt(text.substring(i, i + 4), 16));
                    } catch (NumberFormatException invalid) {
                        return -1;
                    }
                    i += 4;
                    break;
                default:
                    return -1;
            }
        }
        return -1;
    }

    private static int skipComposite(String text, int index) {
        int depth = 0;
        int i = index;
        int length = text.length();
        boolean inString = false;
        while (i < length) {
            char c = text.charAt(i++);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{' || c == '[') {
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return i;
    }

    private static int skipWhitespace(String text, int index) {
        int i = index;
        while (i < text.length() && Character.isWhitespace(text.charAt(i))) {
            i++;
        }
        return i;
    }

    private static String string(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value == null ? null : String.valueOf(value);
    }

    private static boolean isTrue(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = value.trim();
        return "true".equalsIgnoreCase(trimmed) || "1".equals(trimmed) || "yes".equalsIgnoreCase(trimmed);
    }

    /** Kept to make the @@ENTRY@@ placeholder observable for diagnostics. */
    static String entryPoints() {
        return ENTRY == null ? "" : ENTRY;
    }
}
