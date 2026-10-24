package io.umbra.core.config;

import java.util.List;

/**
 * Serializes a {@link UmbraConfig} into the YAML schema understood by
 * {@link ConfigLoader}. Used by the GUI's "Save configuration" action so that
 * GUI-authored settings can be replayed from the command line.
 */
public final class ConfigWriter {

    private ConfigWriter() {
    }

    /**
     * @param config configuration to serialize
     * @return YAML text with a trailing newline
     */
    public static String toYaml(UmbraConfig config) {
        StringBuilder out = new StringBuilder();
        // quote() is mandatory here: a Windows path may contain " #" (which
        // starts a YAML comment) or other plain-scalar special characters, and
        // an unquoted value would be silently truncated on reload.
        line(out, 0, "input", quote(config.input().toString()));
        line(out, 0, "output", quote(config.output().toString()));
        list(out, "libraries", config.libraries().toString().isEmpty()
                ? new String[0]
                : toStrings(config.libraries()));
        list(out, "keep", config.keep().toArray(new String[0]));
        list(out, "softKeep", config.softKeep().toArray(new String[0]));
        line(out, 0, "seed", String.valueOf(config.seed()));
        line(out, 0, "preserveTimestamps", String.valueOf(config.preserveTimestamps()));
        line(out, 0, "dryRun", String.valueOf(config.dryRun()));
        line(out, 0, "preset", quote(config.preset()));
        line(out, 0, "keepPublicApi", String.valueOf(config.keepPublicApi()));
        line(out, 0, "softKeepPublicApi", String.valueOf(config.softKeepPublicApi()));

        UmbraConfig.RenamerOptions r = config.renamer();
        out.append("renamer:\n");
        line(out, 2, "enabled", String.valueOf(r.enabled()));
        line(out, 2, "prefix", quote(r.prefix()));
        line(out, 2, "repackage", String.valueOf(r.repackage()));
        line(out, 2, "repackagePackage", quote(r.repackagePackage()));
        line(out, 2, "renameClasses", String.valueOf(r.renameClasses()));
        line(out, 2, "renameMethods", String.valueOf(r.renameMethods()));
        line(out, 2, "renameFields", String.valueOf(r.renameFields()));
        line(out, 2, "mappingFile", quote(r.mappingFile()));
        line(out, 2, "dictionary", quote(r.dictionary()));
        line(out, 2, "minimumNameLength", String.valueOf(r.minimumNameLength()));
        out.append("  repackageKept:\n");
        for (String kept : r.repackageKept()) {
            out.append("    - ").append(quote(kept)).append('\n');
        }

        UmbraConfig.StringEncryptionOptions s = config.stringEncryption();
        out.append("stringEncryption:\n");
        line(out, 2, "enabled", String.valueOf(s.enabled()));
        line(out, 2, "minLength", String.valueOf(s.minLength()));

        UmbraConfig.IntegerEncryptionOptions i = config.integerEncryption();
        out.append("integerEncryption:\n");
        line(out, 2, "enabled", String.valueOf(i.enabled()));
        line(out, 2, "includeLong", String.valueOf(i.includeLong()));

        UmbraConfig.FlowOptions f = config.flow();
        out.append("flowObfuscation:\n");
        line(out, 2, "enabled", String.valueOf(f.enabled()));
        line(out, 2, "level", quote(f.level()));
        line(out, 2, "maxInstructions", String.valueOf(f.maxInstructions()));
        line(out, 2, "flattening", String.valueOf(f.flattening()));
        if (f.flatteningExclude().isEmpty()) {
            out.append("  flatteningExclude: []\n");
        } else {
            out.append("  flatteningExclude:\n");
            for (String excluded : f.flatteningExclude()) {
                out.append("    - ").append(quote(excluded)).append('\n');
            }
        }

        UmbraConfig.DebugOptions d = config.debug();
        out.append("debugInfo:\n");
        line(out, 2, "enabled", String.valueOf(d.enabled()));
        line(out, 2, "removeSourceFile", String.valueOf(d.removeSourceFile()));
        line(out, 2, "removeLineNumbers", String.valueOf(d.removeLineNumbers()));
        line(out, 2, "removeLocalVariables", String.valueOf(d.removeLocalVariables()));
        line(out, 2, "removeSignatures", String.valueOf(d.removeSignatures()));
        line(out, 2, "removeInnerClasses", String.valueOf(d.removeInnerClasses()));
        line(out, 2, "removeKotlin", String.valueOf(d.removeKotlin()));

        out.append("memberShuffle:\n");
        line(out, 2, "enabled", String.valueOf(config.shuffle().enabled()));

        UmbraConfig.WrapperOptions w = config.invokeWrapper();
        out.append("invokeWrapper:\n");
        line(out, 2, "enabled", String.valueOf(w.enabled()));
        line(out, 2, "maxPerClass", String.valueOf(w.maxPerClass()));

        UmbraConfig.WatermarkOptions wm = config.watermark();
        out.append("watermark:\n");
        line(out, 2, "enabled", String.valueOf(wm.enabled()));
        line(out, 2, "id", quote(wm.id()));

        UmbraConfig.MappingOptions m = config.mapping();
        out.append("mapping:\n");
        line(out, 2, "enabled", String.valueOf(m.enabled()));
        line(out, 2, "file", quote(m.file()));
        line(out, 2, "inputFile", quote(m.inputFile()));

        UmbraConfig.ReportOptions report = config.report();
        out.append("report:\n");
        line(out, 2, "enabled", String.valueOf(report.enabled()));
        line(out, 2, "htmlFile", quote(report.htmlFile()));
        line(out, 2, "jsonFile", quote(report.jsonFile()));

        UmbraConfig.JunkOptions j = config.junk();
        out.append("junkMembers:\n");
        line(out, 2, "enabled", String.valueOf(j.enabled()));
        line(out, 2, "methods", String.valueOf(j.methods()));
        line(out, 2, "fields", String.valueOf(j.fields()));

        out.append("reflection:\n");
        line(out, 2, "enabled", String.valueOf(config.reflection().enabled()));
        line(out, 2, "rewriteClassStrings", String.valueOf(config.reflection().rewriteClassStrings()));

        UmbraConfig.TrimOptions trim = config.trim();
        out.append("trim:\n");
        line(out, 2, "enabled", String.valueOf(trim.enabled()));
        line(out, 2, "removeUnusedPrivateMethods", String.valueOf(trim.removeUnusedPrivateMethods()));
        line(out, 2, "removeUnusedPrivateFields", String.valueOf(trim.removeUnusedPrivateFields()));

        out.append("parameterObfuscation:\n");
        line(out, 2, "enabled", String.valueOf(config.parameterObfuscation().enabled()));

        UmbraConfig.LicenseOptions license = config.license();
        out.append("license:\n");
        line(out, 2, "enabled", String.valueOf(license.enabled()));
        line(out, 2, "file", quote(license.file()));
        line(out, 2, "publicKey", quote(license.publicKey()));
        line(out, 2, "require", String.valueOf(license.require()));
        line(out, 2, "server", quote(license.server()));
        out.append("  features:\n");
        for (String feature : license.requiredFeatures()) {
            out.append("    - ").append(quote(feature)).append('\n');
        }

        out.append("resources:\n");
        line(out, 2, "rewriteContent", String.valueOf(config.resources().rewriteContent()));
        line(out, 2, "obfuscatePaths", String.valueOf(config.resources().obfuscatePaths()));
        out.append("  rewriteDomains:\n");
        for (String domain : config.resources().rewriteDomains()) {
            out.append("    - ").append(quote(domain)).append('\n');
        }

        out.append("referenceObfuscation:\n");
        line(out, 2, "enabled", String.valueOf(config.referenceObfuscation().enabled()));
        line(out, 2, "staticCalls", String.valueOf(config.referenceObfuscation().staticCalls()));
        line(out, 2, "virtualCalls", String.valueOf(config.referenceObfuscation().virtualCalls()));
        line(out, 2, "fields", String.valueOf(config.referenceObfuscation().fields()));
        line(out, 2, "constructors", String.valueOf(config.referenceObfuscation().constructors()));

        out.append("exceptionObfuscation:\n");
        line(out, 2, "enabled", String.valueOf(config.exceptionObfuscation().enabled()));

        UmbraConfig.IncrementalOptions incremental = config.incremental();
        out.append("incremental:\n");
        line(out, 2, "enabled", String.valueOf(incremental.enabled()));
        line(out, 2, "previousOutput", quote(incremental.previousOutput()));
        line(out, 2, "metadataFile", quote(incremental.metadataFile()));

        UmbraConfig.VirtualizationOptions virtualization = config.methodVirtualization();
        out.append("methodVirtualization:\n");
        line(out, 2, "enabled", String.valueOf(virtualization.enabled()));
        line(out, 2, "maxInstructions", String.valueOf(virtualization.maxInstructions()));
        line(out, 2, "maxMethods", String.valueOf(virtualization.maxMethods()));

        UmbraConfig.AntiLlmOptions antiLlm = config.antiLlm();
        out.append("antiLlm:\n");
        line(out, 2, "enabled", String.valueOf(antiLlm.enabled()));
        line(out, 2, "decoyMethodsPerClass", String.valueOf(antiLlm.decoyMethodsPerClass()));
        line(out, 2, "decoyCallSitesPerClass", String.valueOf(antiLlm.decoyCallSitesPerClass()));
        line(out, 2, "wrapperLayers", String.valueOf(antiLlm.wrapperLayers()));
        line(out, 2, "maxWrappedMethodsPerClass", String.valueOf(antiLlm.maxWrappedMethodsPerClass()));
        line(out, 2, "shieldVirtualization", String.valueOf(antiLlm.shieldVirtualization()));

        UmbraConfig.AuthGateOptions gate = config.authGate();
        out.append("authGate:\n");
        line(out, 2, "enabled", String.valueOf(gate.enabled()));
        line(out, 2, "server", quote(gate.server()));
        line(out, 2, "software", quote(gate.software()));
        line(out, 2, "title", quote(gate.title()));
        line(out, 2, "register", String.valueOf(gate.allowRegister()));
        line(out, 2, "cacheFile", quote(gate.cacheFile()));
        line(out, 2, "timeoutMs", String.valueOf(gate.timeoutMs()));
        if (gate.entryPoints().isEmpty()) {
            out.append("  entryPoints: []\n");
        } else {
            out.append("  entryPoints:\n");
            for (String entry : gate.entryPoints()) {
                out.append("    - ").append(quote(entry)).append('\n');
            }
        }

        out.append("protection:\n");
        line(out, 2, "antiDebug", String.valueOf(config.antiDebug()));

        if (!config.options().isEmpty()) {
            out.append("options:\n");
            for (java.util.Map.Entry<String, String> entry : config.options().entrySet()) {
                // Keys are quoted too: --set accepts arbitrary keys and an
                // unquoted key containing ':' would break the YAML mapping.
                out.append("  ").append(quote(entry.getKey())).append(": ")
                        .append(quote(entry.getValue())).append('\n');
            }
        }

        return out.toString();
    }

    private static String[] toStrings(List<java.nio.file.Path> paths) {
        String[] out = new String[paths.size()];
        for (int i = 0; i < paths.size(); i++) {
            out[i] = paths.get(i).toString();
        }
        return out;
    }

    private static void list(StringBuilder out, String key, String[] values) {
        if (values.length == 0) {
            out.append(key).append(": []\n");
            return;
        }
        out.append(key).append(":\n");
        for (String value : values) {
            out.append("  - ").append(quote(value)).append('\n');
        }
    }

    private static void line(StringBuilder out, int indent, String key, String value) {
        for (int i = 0; i < indent; i++) {
            out.append(' ');
        }
        out.append(key).append(": ").append(value).append('\n');
    }

    private static String quote(String value) {
        String escaped = value.replace("\\", "\\\\").replace("\"", "\\\"");
        return "\"" + escaped + "\"";
    }
}
