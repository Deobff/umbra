package io.umbra.tests;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.engine.UmbraVerifier;
import io.umbra.core.util.Log;
import io.umbra.gui.GuiConfig;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

/** Checks that Nocturne can optionally wrap the classic body passes. */
public final class NocturneCompatibleTest {

    private static int checks;

    private NocturneCompatibleTest() {
    }

    public static void main(String[] args) throws Exception {
        Path root = Paths.get("").toAbsolutePath();
        Path input = root.resolve("demo").resolve("demo.jar");
        Path dir = Files.createTempDirectory("umbra-nocturne-compat-");
        try {
            Map<String, String> options = new LinkedHashMap<String, String>();
            options.put("nocturne.enabled", "true");
            options.put("nocturne.compatible", "true");
            options.put("flowObfuscation.enabled", "true");
            options.put("flowObfuscation.flattening", "true");
            options.put("methodVirtualization.enabled", "true");
            options.put("vm2.enabled", "true");
            options.put("mba.enabled", "true");
            options.put("exceptionObfuscation.enabled", "true");
            options.put("antiLlm.enabled", "false");

            Path output = dir.resolve("compatible.jar");
            UmbraConfig compatible = GuiConfig.build(input, output, 808L, options, dir);
            EngineResult result = new UmbraEngine(Log.console(false)).run(compatible, null);
            Map<String, Long> stats = result.stats().snapshot();
            check(stat(stats, "nocturne.methods") > 0, "Nocturne methods present in compatible mode");
            check(stat(stats, "nocturne.variants") > 0, "Nocturne shadows present in compatible mode");
            check(stat(stats, "flow.classes") > 0, "flow ran before Nocturne in compatible mode");
            check(stat(stats, "virtualization.methods") > 0, "VM ran before Nocturne in compatible mode");
            check(stat(stats, "mba.expressions") > 0, "MBA ran before Nocturne in compatible mode");
            check(UmbraVerifier.verify(output).isEmpty(), "compatible output verifies");
            check(run(output).contains("OK"), "compatible output runs and prints OK");

            Map<String, String> exclusiveOptions = new LinkedHashMap<String, String>();
            exclusiveOptions.put("nocturne.enabled", "true");
            exclusiveOptions.put("nocturne.compatible", "false");
            exclusiveOptions.put("flowObfuscation.enabled", "true");
            exclusiveOptions.put("methodVirtualization.enabled", "true");
            Path exclusiveOut = dir.resolve("exclusive.jar");
            UmbraConfig exclusive = GuiConfig.build(input, exclusiveOut, 809L, exclusiveOptions, dir);
            EngineResult exclusiveResult = new UmbraEngine(Log.console(false)).run(exclusive, null);
            Map<String, Long> exclusiveStats = exclusiveResult.stats().snapshot();
            check(stat(exclusiveStats, "nocturne.methods") > 0, "exclusive Nocturne methods present");
            check(stat(exclusiveStats, "flow.classes") == 0, "exclusive mode leaves flow disabled");
            check(stat(exclusiveStats, "virtualization.methods") == 0,
                    "exclusive mode leaves VM disabled");
            check(UmbraVerifier.verify(exclusiveOut).isEmpty(), "exclusive output verifies");
            check(run(exclusiveOut).contains("OK"), "exclusive output runs and prints OK");
        } finally {
            delete(dir);
        }
        System.out.println("NocturneCompatibleTest: " + checks + " checks passed");
    }

    private static long stat(Map<String, Long> stats, String key) {
        Long value = stats.get(key);
        return value == null ? 0L : value.longValue();
    }

    private static String run(Path jar) throws Exception {
        Process process = new ProcessBuilder("java", "-jar", jar.toString())
                .redirectErrorStream(true).start();
        StringBuilder out = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append('\n');
            }
        }
        int exit = process.waitFor();
        check(exit == 0, "protected jar exits 0 (exit was " + exit + ")");
        return out.toString();
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }

    private static void delete(Path directory) {
        try {
            if (!Files.exists(directory)) {
                return;
            }
            Files.walk(directory)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (IOException ignored) {
                            // Best effort temp cleanup.
                        }
                    });
        } catch (IOException ignored) {
            // Best effort temp cleanup.
        }
    }
}
