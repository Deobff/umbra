package io.umbra.core.enterprise;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.Stats;
import io.umbra.core.enterprise.LicenseInfo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

/** Writes machine-readable (JSON) and human-readable (HTML) audit reports. */
public final class AuditReport {

    private AuditReport() {
    }

    public static void write(Path htmlFile, Path jsonFile, UmbraConfig config,
                             EngineResult result, Stats stats, RiskReport risk,
                             LicenseInfo license) throws IOException {
        String generated = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        if (jsonFile != null && !jsonFile.toString().isEmpty()) {
            writeFile(jsonFile, toJson(config, result, stats, risk, license, generated));
        }
        if (htmlFile != null && !htmlFile.toString().isEmpty()) {
            writeFile(htmlFile, toHtml(config, result, stats, risk, license, generated));
        }
    }

    private static void writeFile(Path file, String content) throws IOException {
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));
    }

    public static String toJson(UmbraConfig config, EngineResult result, Stats stats,
                                RiskReport risk, LicenseInfo license, String generated) {
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"tool\": \"umbra\",\n");
        out.append("  \"version\": \"1.0.0\",\n");
        out.append("  \"generated\": ").append(quote(generated)).append(",\n");
        out.append("  \"input\": ").append(quote(config.input().toString())).append(",\n");
        out.append("  \"output\": ").append(quote(config.output().toString())).append(",\n");
        out.append("  \"seed\": ").append(config.seed()).append(",\n");
        out.append("  \"dryRun\": ").append(result.dryRun()).append(",\n");
        out.append("  \"durationMs\": ").append(result.millis()).append(",\n");
        out.append("  \"classes\": ").append(result.classes()).append(",\n");
        out.append("  \"resources\": ").append(result.resources()).append(",\n");
        out.append("  \"stats\": ");
        appendMap(out, stats.snapshot(), 2);
        out.append(",\n  \"passTimes\": ");
        appendMap(out, result.passTimes(), 2);
        out.append(",\n  \"risk\": {\n");
        out.append("    \"serializableClasses\": ").append(risk.serializableClasses()).append(",\n");
        out.append("    \"nativeMethods\": ").append(risk.nativeMethods()).append(",\n");
        out.append("    \"reflectionCallSites\": ").append(risk.reflectionCallSites()).append(",\n");
        out.append("    \"serviceLoaderCallSites\": ").append(risk.serviceLoaderCallSites()).append(",\n");
        out.append("    \"moduleDescriptors\": ").append(risk.moduleDescriptors()).append(",\n");
        out.append("    \"frameworkAnnotations\": ");
        appendIntMap(out, risk.frameworkAnnotations(), 4);
        out.append("\n  },\n");
        out.append("  \"license\": ");
        appendLicense(out, license);
        out.append(",\n  \"suggestions\": [\n");
        for (int i = 0; i < risk.suggestions().size(); i++) {
            out.append("    ").append(quote(risk.suggestions().get(i)));
            if (i + 1 < risk.suggestions().size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("  ]\n}\n");
        return out.toString();
    }

    private static void appendMap(StringBuilder out, Map<String, Long> map, int indent) {
        out.append('{');
        boolean first = true;
        for (Map.Entry<String, Long> e : map.entrySet()) {
            if (!first) {
                out.append(", ");
            }
            first = false;
            out.append(quote(e.getKey())).append(": ").append(e.getValue());
        }
        out.append('}');
    }

    private static void appendIntMap(StringBuilder out, Map<String, Integer> map, int indent) {
        out.append('{');
        boolean first = true;
        for (Map.Entry<String, Integer> e : map.entrySet()) {
            if (!first) {
                out.append(", ");
            }
            first = false;
            out.append(quote(e.getKey())).append(": ").append(e.getValue());
        }
        out.append('}');
    }

    public static String toHtml(UmbraConfig config, EngineResult result, Stats stats,
                                RiskReport risk, LicenseInfo license, String generated) {
        StringBuilder out = new StringBuilder();
        out.append("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n");
        out.append("<title>Umbra Audit</title>\n<style>\n");
        out.append("body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:32px;color:#1f2933;background:#fafbfc}\n");
        out.append("h1{margin:0 0 4px;font-size:26px}h2{margin-top:28px;font-size:18px;border-bottom:1px solid #d9e2ec;padding-bottom:4px}\n");
        out.append(".muted{color:#627d98}.tiles{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}\n");
        out.append(".tile{background:#fff;border:1px solid #d9e2ec;border-radius:8px;padding:12px 16px;min-width:140px}\n");
        out.append(".tile b{display:block;font-size:22px}.tile span{color:#627d98;font-size:12px;text-transform:uppercase;letter-spacing:.04em}\n");
        out.append("table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #d9e2ec;border-radius:8px;overflow:hidden}\n");
        out.append("th,td{padding:8px 10px;border-bottom:1px solid #eef2f6;text-align:left;font-size:13px}th{background:#f0f4f8}\n");
        out.append("code{background:#eef2f6;padding:1px 4px;border-radius:3px;font-size:12px}\n");
        out.append("ul{line-height:1.7}.ok{color:#0b7285}.warn{color:#b44d12}\n");
        out.append("</style></head><body>\n");
        out.append("<h1>Umbra Enterprise Audit</h1>\n");
        out.append("<div class=\"muted\">Generated ").append(escape(generated))
                .append(" · <code>").append(escape(config.input().toString())).append("</code> → <code>")
                .append(escape(config.output().toString())).append("</code> · seed <code>")
                .append(config.seed()).append("</code></div>\n");

        out.append("<div class=\"tiles\">\n");
        tile(out, String.valueOf(result.classes()), "Classes");
        tile(out, String.valueOf(result.resources()), "Resources");
        tile(out, result.millis() + " ms", "Duration");
        tile(out, String.valueOf(risk.reflectionCallSites()), "Reflection sites");
        tile(out, String.valueOf(risk.serializableClasses()), "Serializable");
        tile(out, license == null ? "community" : (license.isValid() ? "enterprise" : "invalid"),
                "License");
        out.append("</div>\n");

        if (license != null) {
            out.append("<h2>License</h2>\n<table><tr><th>Field</th><th>Value</th></tr>\n");
            row(out, "id", license.id());
            row(out, "valid", String.valueOf(license.isValid()));
            row(out, "licensee", license.licensee());
            row(out, "edition", license.edition());
            row(out, "expires", license.expires());
            row(out, "features", String.valueOf(license.features()));
            if (!license.error().isEmpty()) {
                row(out, "error", license.error());
            }
            out.append("</table>\n");
        }

        out.append("<h2>Transformations</h2>\n<table><tr><th>Counter</th><th>Value</th></tr>\n");
        for (Map.Entry<String, Long> e : stats.snapshot().entrySet()) {
            row(out, e.getKey(), String.valueOf(e.getValue()));
        }
        out.append("</table>\n");

        out.append("<h2>Pass timings</h2>\n<table><tr><th>Pass</th><th>Milliseconds</th></tr>\n");
        for (Map.Entry<String, Long> e : result.passTimes().entrySet()) {
            row(out, e.getKey(), String.valueOf(e.getValue()));
        }
        out.append("</table>\n");

        out.append("<h2>Risk scan</h2>\n<table><tr><th>Signal</th><th>Count</th></tr>\n");
        row(out, "Serializable / Externalizable classes", String.valueOf(risk.serializableClasses()));
        row(out, "Native methods", String.valueOf(risk.nativeMethods()));
        row(out, "Reflection call sites", String.valueOf(risk.reflectionCallSites()));
        row(out, "ServiceLoader call sites", String.valueOf(risk.serviceLoaderCallSites()));
        row(out, "Module descriptors", String.valueOf(risk.moduleDescriptors()));
        for (Map.Entry<String, Integer> e : risk.frameworkAnnotations().entrySet()) {
            row(out, "Framework annotation " + e.getKey(), String.valueOf(e.getValue()));
        }
        out.append("</table>\n");

        out.append("<h2>Recommendations</h2>\n<ul>\n");
        for (String suggestion : risk.suggestions()) {
            out.append("<li>").append(escape(suggestion)).append("</li>\n");
        }
        out.append("</ul>\n</body></html>\n");
        return out.toString();
    }

    private static void appendLicense(StringBuilder out, LicenseInfo license) {
        if (license == null) {
            out.append("null");
            return;
        }
        out.append("{\"valid\": ").append(license.isValid())
                .append(", \"id\": ").append(quote(license.id()))
                .append(", \"licensee\": ").append(quote(license.licensee()))
                .append(", \"edition\": ").append(quote(license.edition()))
                .append(", \"expires\": ").append(quote(license.expires()))
                .append(", \"features\": [");
        for (int i = 0; i < license.features().size(); i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append(quote(license.features().get(i)));
        }
        out.append("], \"error\": ").append(quote(license.error())).append('}');
    }

    private static void tile(StringBuilder out, String value, String label) {
        out.append("<div class=\"tile\"><b>").append(escape(value)).append("</b><span>")
                .append(escape(label)).append("</span></div>\n");
    }

    private static void row(StringBuilder out, String key, String value) {
        out.append("<tr><td><code>").append(escape(key)).append("</code></td><td>")
                .append(escape(value)).append("</td></tr>\n");
    }

    private static String quote(String value) {
        return "\"" + escape(value) + "\"";
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }
}
