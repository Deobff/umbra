package io.umbra.tests;

import io.umbra.core.config.UmbraConfig;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Checks that {@code --set <typed section>.*} reaches the typed configuration
 * sections instead of only landing in the generic option map.
 *
 * <p>The engine reads the typed sections ({@code renamer()}, {@code flow()}, ...)
 * while {@code --set} writes the option map, so the CLI translates the typed keys
 * during its own assembly ({@link UmbraConfig#applyTypedOverrides}). The order is
 * preset &lt; {@code --set} &lt; explicit switches, and a derived configuration
 * (nocturne's exclusive mode) must still be able to tighten a section afterwards —
 * that last part is why the translation is not part of the constructor.</p>
 */
public final class TypedSetTest {

    private static int checks;

    private TypedSetTest() {
    }

    public static void main(String[] args) throws Exception {
        testMappingHelper();
        testDerivedConfigurationStaysStrict();
        testUntouchedSections();
        testCliEndToEnd();
        testCliPriority();
        System.out.println("TypedSetTest: " + checks + " checks passed");
    }

    private static void testMappingHelper() throws Exception {
        Map<String, String> sets = new LinkedHashMap<String, String>();
        sets.put("renamer.enabled", "false");
        sets.put("flowObfuscation.level", "aggressive");
        sets.put("flowObfuscation.maxInstructions", "1234");
        sets.put("stringEncryption.minLength", "5");
        sets.put("antiLlm.decoyMethodsPerClass", "7");
        sets.put("classEncryption.enabled", "true");

        UmbraConfig.Builder builder = baseBuilder()
                .renamer(new UmbraConfig.RenamerOptions(true, "", false, "", true, true, true,
                        "umbra-mapping.txt", "abcdefghijklmnopqrstuvwxyz", 1))
                .flow(new UmbraConfig.FlowOptions(true, "light", 8000));
        // Same two steps as the CLI: every --set key lands in the option map, then
        // the typed keys are translated into the typed sections.
        for (Map.Entry<String, String> entry : sets.entrySet()) {
            builder.option(entry.getKey(), entry.getValue());
        }
        UmbraConfig.applyTypedOverrides(builder, sets);
        UmbraConfig config = builder.build();

        check(!config.renamer().enabled(),
                "renamer.enabled=false reaches the typed renamer section");
        check("aggressive".equals(config.flow().level()),
                "flowObfuscation.level reaches flow().level()");
        check(config.flow().maxInstructions() == 1234,
                "flowObfuscation.maxInstructions reaches flow().maxInstructions()");
        check(config.stringEncryption().minLength() == 5,
                "stringEncryption.minLength reaches stringEncryption().minLength()");
        check(config.antiLlm().decoyMethodsPerClass() == 7,
                "antiLlm.decoyMethodsPerClass reaches antiLlm().decoyMethodsPerClass()");
        // classEncryption has no typed section: the pass reads the option map, so
        // the value must stay readable exactly as before.
        check(config.optionBool("classEncryption.enabled", false),
                "classEncryption.enabled stays readable through optionBool()");
        check("false".equals(config.option("renamer.enabled", "")),
                "the --set key itself stays in the option map");
    }

    /**
     * Regression guard for nocturne's exclusive mode: a configuration derived from
     * a base whose option map still holds {@code flowObfuscation.*} must be able to
     * switch the typed section off. A constructor-level override reopened it.
     */
    private static void testDerivedConfigurationStaysStrict() throws Exception {
        UmbraConfig.Builder builder = baseBuilder()
                .flow(new UmbraConfig.FlowOptions(true, "light", 8000));
        Map<String, String> sets = new LinkedHashMap<String, String>();
        sets.put("flowObfuscation.enabled", "true");
        UmbraConfig.applyTypedOverrides(builder, sets);
        builder.option("flowObfuscation.enabled", "true");
        UmbraConfig base = builder.build();
        check(base.flow().enabled(), "--set flowObfuscation.enabled=true enables flow");

        UmbraConfig strict = base.toBuilder()
                .flow(new UmbraConfig.FlowOptions(false, base.flow().level(),
                        base.flow().maxInstructions(), false))
                .build();
        check(!strict.flow().enabled(),
                "a derived configuration can still disable a typed section");
        check(strict.optionBool("flowObfuscation.enabled", false),
                "the inherited option key is still present in the derived config");
    }

    private static void testUntouchedSections() throws Exception {
        UmbraConfig.Builder plain = baseBuilder()
                .flow(new UmbraConfig.FlowOptions(true, "light", 8000));
        UmbraConfig.applyTypedOverrides(plain, null);
        UmbraConfig.applyTypedOverrides(plain, new LinkedHashMap<String, String>());
        Map<String, String> unrelated = new LinkedHashMap<String, String>();
        unrelated.put("flow.aggressive", "true");
        unrelated.put("string.strength", "3");
        unrelated.put("renamer.unknownKnob", "x");
        unrelated.put("renamer.minimumNameLength", "not-a-number");
        UmbraConfig.applyTypedOverrides(plain, unrelated);
        UmbraConfig config = plain.build();

        check("light".equals(config.flow().level()),
                "flow.aggressive is a different namespace and leaves flow().level() at light");
        check(config.flow().maxInstructions() == 8000, "typed flow ceiling is unchanged");
        check(config.renamer().enabled(), "typed renamer stays enabled without renamer.enabled");
        check(config.renamer().minimumNameLength() == 1,
                "a malformed typed value keeps the typed setter's value");
        check(config.options().isEmpty(),
                "applyTypedOverrides never adds keys to the option map");

        UmbraConfig defaults = baseBuilder().build();
        check(defaults.renamer().enabled() && defaults.stringEncryption().enabled()
                        && defaults.flow().enabled() && defaults.shuffle().enabled()
                        && defaults.junk().enabled() && defaults.watermark().enabled(),
                "an untouched builder keeps every typed default");
    }

    private static void testCliEndToEnd() throws Exception {
        Path root = findProjectRoot();
        check(root != null, "demo/demo.jar is available for the CLI end-to-end check");
        if (root == null) {
            return;
        }
        Path demo = root.resolve("demo").resolve("demo.jar");
        Path dir = Files.createTempDirectory("umbra-typed-set-");
        try {
            Path kept = dir.resolve("demo-typed-set.jar");
            String cliOut = runIn(dir, javaBinary(), "-cp", absoluteClasspath(),
                    "io.umbra.cli.Main",
                    "-i", demo.toString(),
                    "-o", kept.toString(),
                    "--set", "renamer.enabled=false",
                    "--seed", "4242");
            check(Files.exists(kept), "CLI wrote the protected jar: " + tail(cliOut));
            check(entries(kept).contains("demo/Main.class"),
                    "--set renamer.enabled=false keeps the original class names");
            check(runIn(dir, javaBinary(), "-jar", kept.toString()).contains("OK"),
                    "jar protected with renaming disabled still runs and prints OK");

            // Control case: without the option the renamer still runs, so the
            // assertion above cannot pass for the wrong reason.
            Path renamed = dir.resolve("demo-default.jar");
            runIn(dir, javaBinary(), "-cp", absoluteClasspath(),
                    "io.umbra.cli.Main",
                    "-i", demo.toString(),
                    "-o", renamed.toString(),
                    "--seed", "4242");
            check(!entries(renamed).contains("demo/Main.class"),
                    "default protection still renames classes (control case)");
        } finally {
            delete(dir);
        }
    }

    private static void testCliPriority() throws Exception {
        Path root = findProjectRoot();
        if (root == null) {
            return;
        }
        Path demo = root.resolve("demo").resolve("demo.jar");
        Path dir = Files.createTempDirectory("umbra-typed-priority-");
        try {
            // --set must beat the preset: maximum flattens every renamed class into
            // one package, and the mapping file shows which package won.
            Path presetMapping = dir.resolve("preset-mapping.txt");
            runIn(dir, javaBinary(), "-cp", absoluteClasspath(), "io.umbra.cli.Main",
                    "-i", demo.toString(), "-o", dir.resolve("preset-only.jar").toString(),
                    "--preset", "maximum", "--mapping", presetMapping.toString(),
                    "--seed", "4242");
            String flattened = mappingLine(presetMapping, "demo/Main");
            check(flattened != null && !flattened.contains("-> demo/"),
                    "the maximum preset repackages every renamed class (" + flattened + ")");

            Path presetSetMapping = dir.resolve("preset-set-mapping.txt");
            runIn(dir, javaBinary(), "-cp", absoluteClasspath(), "io.umbra.cli.Main",
                    "-i", demo.toString(), "-o", dir.resolve("preset-set.jar").toString(),
                    "--preset", "maximum",
                    "--set", "renamer.repackage=false",
                    "--mapping", presetSetMapping.toString(),
                    "--seed", "4242");
            String keptPackage = mappingLine(presetSetMapping, "demo/Main");
            check(keptPackage != null && keptPackage.contains("-> demo/"),
                    "--set renamer.repackage=false overrides the maximum preset ("
                            + keptPackage + ")");

            // --no-flow must beat --set, and --set must beat the default.
            String flowOn = runIn(dir, javaBinary(), "-cp", absoluteClasspath(),
                    "io.umbra.cli.Main", "-i", demo.toString(),
                    "-o", dir.resolve("flow-on.jar").toString(),
                    "--set", "flowObfuscation.enabled=true", "--seed", "4242");
            check(flowOn.contains("flow-obfuscation"),
                    "--set flowObfuscation.enabled=true runs the flow pass");
            String flowSetOff = runIn(dir, javaBinary(), "-cp", absoluteClasspath(),
                    "io.umbra.cli.Main", "-i", demo.toString(),
                    "-o", dir.resolve("flow-set-off.jar").toString(),
                    "--set", "flowObfuscation.enabled=false", "--seed", "4242");
            check(!flowSetOff.contains("flow-obfuscation"),
                    "--set flowObfuscation.enabled=false disables the flow pass");
            String flowNoFlow = runIn(dir, javaBinary(), "-cp", absoluteClasspath(),
                    "io.umbra.cli.Main", "-i", demo.toString(),
                    "-o", dir.resolve("flow-no-flow.jar").toString(),
                    "--no-flow", "--set", "flowObfuscation.enabled=true",
                    "--seed", "4242");
            check(!flowNoFlow.contains("flow-obfuscation"),
                    "--no-flow wins over --set flowObfuscation.enabled=true");

            // The translation is CLI-only: a typed key inside a YAML options: block
            // stays inert, while the YAML typed section still decides its value.
            Path inertJar = dir.resolve("options-inert.jar");
            Path inertYaml = dir.resolve("options-inert.yml");
            Files.write(inertYaml, ("input: " + slash(demo)
                    + "\noutput: " + slash(inertJar)
                    + "\noptions:\n  renamer.enabled: \"false\"\n").getBytes(StandardCharsets.UTF_8));
            runIn(dir, javaBinary(), "-cp", absoluteClasspath(), "io.umbra.cli.Main",
                    "-c", inertYaml.toString());
            check(!entries(inertJar).contains("demo/Main.class"),
                    "a typed key in a YAML options: block does not reach the typed section");

            Path typedJar = dir.resolve("typed-off.jar");
            Path typedYaml = dir.resolve("typed-off.yml");
            Files.write(typedYaml, ("input: " + slash(demo)
                    + "\noutput: " + slash(typedJar)
                    + "\nrenamer:\n  enabled: false\n").getBytes(StandardCharsets.UTF_8));
            runIn(dir, javaBinary(), "-cp", absoluteClasspath(), "io.umbra.cli.Main",
                    "-c", typedYaml.toString());
            check(entries(typedJar).contains("demo/Main.class"),
                    "the YAML renamer: section still decides its own value");
        } finally {
            delete(dir);
        }
    }

    private static UmbraConfig.Builder baseBuilder() {
        return new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"));
    }

    /** Absolute path with forward slashes, safe inside a YAML scalar. */
    private static String slash(Path path) {
        return path.toAbsolutePath().toString().replace('\\', '/');
    }

    /** The mapping line for {@code original}, or {@code null} when it is absent. */
    private static String mappingLine(Path mapping, String original) throws Exception {
        if (!Files.isRegularFile(mapping)) {
            return null;
        }
        String prefix = original + " -> ";
        for (String line : Files.readAllLines(mapping, StandardCharsets.UTF_8)) {
            if (line.startsWith(prefix)) {
                return line.trim();
            }
        }
        return null;
    }

    private static Set<String> entries(Path jar) throws Exception {
        Set<String> names = new LinkedHashSet<String>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            Enumeration<? extends ZipEntry> items = zip.entries();
            while (items.hasMoreElements()) {
                names.add(items.nextElement().getName());
            }
        }
        return names;
    }

    private static String runIn(Path directory, String... command) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(directory.toFile());
        builder.redirectErrorStream(true);
        Process process = builder.start();
        StringBuilder out = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append('\n');
            }
        }
        int exit = process.waitFor();
        check(exit == 0, command[0] + " exited 0 (exit was " + exit + "): " + tail(out.toString()));
        return out.toString();
    }

    private static String javaBinary() {
        return Paths.get(System.getProperty("java.home"), "bin", "java").toString();
    }

    /** Absolute classpath so subprocesses can run from a temp working directory. */
    private static String absoluteClasspath() {
        String raw = System.getProperty("java.class.path");
        StringBuilder result = new StringBuilder();
        for (String entry : raw.split(File.pathSeparator)) {
            if (entry.isEmpty()) {
                continue;
            }
            File file = new File(entry);
            if (!file.isAbsolute()) {
                file = new File(System.getProperty("user.dir"), entry);
            }
            if (result.length() > 0) {
                result.append(File.pathSeparatorChar);
            }
            result.append(file.getAbsolutePath());
        }
        return result.toString();
    }

    private static Path findProjectRoot() {
        Path dir = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && dir != null; i++) {
            if (Files.exists(dir.resolve("demo").resolve("demo.jar"))) {
                return dir;
            }
            dir = dir.getParent();
        }
        return null;
    }

    private static String tail(String output) {
        String text = output.trim();
        return text.length() <= 400 ? text : text.substring(text.length() - 400);
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
