package io.umbra.tests;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.engine.UmbraVerifier;
import io.umbra.core.runtime.UmbraCantrip;
import io.umbra.core.util.Log;
import io.umbra.gui.GuiConfig;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

/** Checks the Cantrip dialect VM2 payload layer and its interpreter. */
public final class CantripTest {

    private static int checks;

    private CantripTest() {
    }

    public static void main(String[] args) throws Exception {
        int[] direct = UmbraCantrip.run(new String[]{"~7;.~-3;.", "~42;."});
        check(direct.length == 3, "interpreter emitted three values");
        check(direct[0] == 7 && direct[1] == -3 && direct[2] == 42,
                "interpreter reconstructed signed dialect literals");
        int[] loop = UmbraCantrip.run(new String[]{"~3;[-]."});
        check(loop.length == 1 && loop[0] == 0, "interpreter loop semantics");

        // P0-3: the sealed second layer substitutes the dialect syntax through a
        // per-build opcode table and ChaCha20-encrypts the program text.
        String[] plain = new String[]{"~7;.~-3;.", "~42;."};
        String[] sealed = UmbraCantrip.seal(plain, 0x5EED1234);
        check(!sealed[0].contains("~") && !sealed[0].contains(";"),
                "sealed chunks hide the dialect syntax");
        int[] decoded = UmbraCantrip.runSealed(sealed, 0x5EED1234);
        check(decoded.length == 3 && decoded[0] == 7 && decoded[1] == -3 && decoded[2] == 42,
                "sealed chunks round-trip to the same values");
        int[] wrongKey = null;
        try {
            wrongKey = UmbraCantrip.runSealed(sealed, 0x11112222);
        } catch (RuntimeException expected) {
            wrongKey = null;
        }
        check(wrongKey == null || wrongKey.length != 3 || wrongKey[0] != 7,
                "a wrong dialect key does not reproduce the values");
        check(UmbraCantrip.decode(sealed, 0x5EED1234)[0].contains("~"),
                "unsealing exposes the dialect text again");

        Path root = Paths.get("").toAbsolutePath();
        Path input = root.resolve("demo").resolve("demo.jar");
        Path dir = Files.createTempDirectory("umbra-cantrip-test-");
        try {
            Map<String, String> options = new LinkedHashMap<String, String>();
            options.put("methodVirtualization.enabled", "true");
            options.put("vm2.enabled", "true");
            options.put("cantrip.enabled", "true");
            options.put("cantrip.level", "1");
            options.put("flowObfuscation.enabled", "false");
            options.put("exceptionObfuscation.enabled", "false");
            options.put("antiLlm.enabled", "false");
            Path output = dir.resolve("cantrip.jar");
            UmbraConfig config = GuiConfig.build(input, output, 912L, options, dir);
            EngineResult result = new UmbraEngine(Log.console(false)).run(config, null);
            Map<String, Long> stats = result.stats().snapshot();
            check(stat(stats, "virtualization.methods") > 0, "VM2 virtualized methods");
            check(stat(stats, "cantrip.programs") > 0, "Cantrip programs generated");
            check(stat(stats, "cantrip.values") > 0, "Cantrip reconstructed values");
            check(stat(stats, "cantrip.sealed") > 0, "Cantrip programs are sealed by default");
            check(UmbraVerifier.verify(output).isEmpty(), "Cantrip output verifies");
            check(run(output).contains("OK"), "Cantrip output runs and prints OK");
        } finally {
            delete(dir);
        }
        System.out.println("CantripTest: " + checks + " checks passed");
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
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
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
                        } catch (Exception ignored) {
                            // Best effort temp cleanup.
                        }
                    });
        } catch (Exception ignored) {
            // Best effort temp cleanup.
        }
    }
}
