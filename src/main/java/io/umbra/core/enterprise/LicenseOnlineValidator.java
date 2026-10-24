package io.umbra.core.enterprise;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates a signed license against a Umbra License Server.
 *
 * <p>The client posts the license YAML to {@code /api/validate}. The server
 * checks the signature, expiry, required features and revocation state.</p>
 */
public final class LicenseOnlineValidator {

    private static final Pattern VALID = Pattern.compile("\"valid\"\\s*:\\s*(true|false)");
    private static final Pattern REASON = Pattern.compile("\"reason\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");

    private LicenseOnlineValidator() {
    }

    public static Result check(Path licenseFile, String serverUrl) throws IOException {
        return check(new String(Files.readAllBytes(licenseFile), StandardCharsets.UTF_8), serverUrl);
    }

    public static Result check(String licenseYaml, String serverUrl) {
        if (serverUrl == null || serverUrl.trim().isEmpty()) {
            return new Result(false, "No license server configured");
        }
        HttpURLConnection connection = null;
        try {
            URL url = new URL(endpoint(serverUrl));
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(8000);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            String body = "license=" + URLEncoder.encode(licenseYaml, "UTF-8");
            try (OutputStream out = connection.getOutputStream()) {
                out.write(body.getBytes(StandardCharsets.UTF_8));
            }
            int status = connection.getResponseCode();
            String response = read(status >= 400 ? connection.getErrorStream() : connection.getInputStream());
            if (status != 200) {
                return new Result(false, "License server returned HTTP " + status + ": " + response);
            }
            Matcher valid = VALID.matcher(response);
            if (!valid.find()) {
                return new Result(false, "Malformed license server response: " + response);
            }
            boolean ok = Boolean.parseBoolean(valid.group(1));
            String reason = "";
            Matcher reasonMatcher = REASON.matcher(response);
            if (reasonMatcher.find()) {
                reason = unescape(reasonMatcher.group(1));
            }
            return new Result(ok, reason);
        } catch (Exception e) {
            return new Result(false, "Online license check failed: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static String endpoint(String serverUrl) {
        String base = serverUrl.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        if (base.endsWith("/api/validate")) {
            return base;
        }
        return base + "/api/validate";
    }

    private static String read(InputStream in) throws IOException {
        if (in == null) {
            return "";
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String unescape(String value) {
        return value.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n");
    }

    /** Online validation result. */
    public static final class Result {
        private final boolean valid;
        private final String reason;

        public Result(boolean valid, String reason) {
            this.valid = valid;
            this.reason = reason == null ? "" : reason;
        }

        public boolean isValid() { return valid; }
        public String reason() { return reason; }
    }
}
