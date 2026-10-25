package io.umbra.tests;

import io.umbra.cli.InspectTool;
import io.umbra.core.config.ConfigException;
import io.umbra.core.config.ConfigLoader;
import io.umbra.core.config.ConfigWriter;
import io.umbra.core.config.Presets;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.config.YamlParser;
import io.umbra.core.enterprise.LicenseTool;
import io.umbra.gui.GuiConfig;
import io.umbra.gui.GuiPrefs;
import io.umbra.gui.GuiPresets;
import io.umbra.gui.GuiSwitches;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * WS8 audit regression suite (plain main, JDK 8, no external dependencies).
 *
 * <p>Every check corresponds to an edge case audited for Umbra 3.1. The
 * configuration/YAML and in-process checks cover the bugs fixed during the
 * audit (ConfigWriter path quoting, YamlParser tabs/BOM/single quotes,
 * ConfigLoader empty paths, GUI headless/usage exits, CLI license gate). The
 * CLI/GUI checks run the real entry points in a child JVM and assert the
 * documented exit codes 0/1/2/3. See {@code docs/AUDIT-3.1.md} for the
 * findings table this suite locks down.</p>
 */
public final class AuditTest {

    private static final List<String> failures = new ArrayList<String>();
    private static int checks;
    private static Path root;
    private static Path work;
    private static Path demo;

    private AuditTest() {
    }

    public static void main(String[] args) throws Exception {
        long started = System.currentTimeMillis();
        root = locateRoot();
        work = Files.createTempDirectory("umbra-audit-test-");
        demo = root.resolve("demo").resolve("demo.jar");
        try {
            run("yaml-parser-edges", new TestCase() {
                @Override
                public void run() throws Exception {
                    testYamlParserEdges();
                }
            });
            run("yaml-config-load", new TestCase() {
                @Override
                public void run() throws Exception {
                    testConfigLoadingEdges();
                }
            });
            run("config-round-trip", new TestCase() {
                @Override
                public void run() throws Exception {
                    testConfigRoundTrip();
                }
            });
            run("gui-config-round-trip", new TestCase() {
                @Override
                public void run() throws Exception {
                    testGuiConfigRoundTrip();
                }
            });
            run("gui-prefs", new TestCase() {
                @Override
                public void run() throws Exception {
                    testGuiPrefs();
                }
            });
            run("inspect-edges", new TestCase() {
                @Override
                public void run() throws Exception {
                    testInspectEdges();
                }
            });
            run("cli-parsing", new TestCase() {
                @Override
                public void run() throws Exception {
                    testCliParsing();
                }
            });
            run("cli-paths-and-outputs", new TestCase() {
                @Override
                public void run() throws Exception {
                    testCliPathsAndOutputs();
                }
            });
            run("cli-license-gate", new TestCase() {
                @Override
                public void run() throws Exception {
                    testCliLicenseGate();
                }
            });
            run("cli-artifacts", new TestCase() {
                @Override
                public void run() throws Exception {
                    testCliArtifacts();
                }
            });
            run("gui-entry", new TestCase() {
                @Override
                public void run() throws Exception {
                    testGuiEntry();
                }
            });
        } finally {
            delete(work);
        }
        long elapsed = System.currentTimeMillis() - started;
        System.out.println("AuditTest: " + checks + " checks, " + failures.size()
                + " failure(s) in " + elapsed + " ms");
        if (!failures.isEmpty()) {
            for (String failure : failures) {
                System.err.println("FAIL: " + failure);
            }
            throw new AssertionError(failures.size() + " audit check(s) failed");
        }
    }

    /* --------------------------------------------------------------- YAML */

    private static void testYamlParserEdges() throws Exception {
        // BOM: the parser must strip a UTF-8 BOM itself (license files and
        // plugins call it directly; ConfigLoader strips it separately).
        Map<String, Object> bom = YamlParser.parse("\uFEFFrenamer:\n  enabled: false\n");
        check(bom.containsKey("renamer"), "YamlParser strips a UTF-8 BOM from the first key");
        check(Boolean.FALSE.equals(asMap(bom.get("renamer")).get("enabled")),
                "YamlParser BOM document keeps the first section's value");

        // Tabs are one character but four indent columns; the content must not
        // be chopped (previously "\tinput: x" parsed as key "ut").
        Map<String, Object> tabbed = YamlParser.parse("renamer:\n\tenabled: false\n\tprefix: \"t\"\n");
        Map<String, Object> tabRenamer = asMap(tabbed.get("renamer"));
        check(Boolean.FALSE.equals(tabRenamer.get("enabled")),
                "tab-indented YAML keeps the renamer.enabled value");
        check("t".equals(tabRenamer.get("prefix")), "tab-indented YAML keeps the renamer.prefix value");
        check(!tabbed.containsKey("amer"), "tab indentation does not chop the key name");

        // Single-quoted scalars are literal in YAML: a Windows path must keep
        // its backslashes ('C:\new\file' is not a newline).
        Map<String, Object> single = YamlParser.parse("prefix: 'C:\\new\\file'\n");
        check("C:\\new\\file".equals(single.get("prefix")),
                "single-quoted scalar keeps backslashes literal");
        Map<String, Object> escapedQuote = YamlParser.parse("prefix: 'it''s'\n");
        check("it's".equals(escapedQuote.get("prefix")),
                "single-quoted '' escape becomes a quote");
        // Double-quoted scalars still decode escapes.
        Map<String, Object> doubleQuoted = YamlParser.parse("prefix: \"a\\nb\"\n");
        check(String.valueOf(doubleQuoted.get("prefix")).indexOf('\n') >= 0,
                "double-quoted scalar still decodes \\n");

        // Empty document and duplicate keys (documented deterministic value).
        check(YamlParser.parse("").isEmpty(), "empty YAML is an empty mapping");
        check(YamlParser.parse("# only a comment\n").isEmpty(), "comment-only YAML is empty");
        Map<String, Object> duplicate = asMap(YamlParser.parse(
                "renamer:\n  enabled: true\n  enabled: false\n").get("renamer"));
        check(Boolean.FALSE.equals(duplicate.get("enabled")),
                "duplicate YAML keys deterministically use the last value");

        // Quoted keys with a colon, inline lists with quoted commas.
        Map<String, Object> quotedKey = YamlParser.parse("\"a: b\": 1\n");
        check(quotedKey.containsKey("a: b"), "quoted mapping key may contain ':'");
        Object listValue = YamlParser.parse("keep: [a, \"b, c\", 'd']\n").get("keep");
        List<?> inline = (List<?>) listValue;
        check(inline.size() == 3, "inline list with quoted comma has three items");
        check("b, c".equals(inline.get(1)), "inline list keeps a comma inside quotes");
        check("d".equals(inline.get(2)), "inline list keeps a single-quoted item");

        // CRLF normalisation.
        Map<String, Object> crlf = YamlParser.parse("renamer:\r\n  enabled: false\r\n");
        check(Boolean.FALSE.equals(asMap(crlf.get("renamer")).get("enabled")),
                "CRLF line endings parse like LF");
    }

    private static void testConfigLoadingEdges() throws Exception {
        // Tab-indented configuration file (editors may indent with tabs).
        Path tabConfig = write("tabs.yml", "input: \"in.jar\"\noutput: \"out.jar\"\n"
                + "renamer:\n\tenabled: false\n\tprefix: \"tab\"\n");
        UmbraConfig tabbedConfig = ConfigLoader.load(tabConfig);
        check(tabbedConfig.input().getFileName().toString().equals("in.jar"),
                "tab-indented config resolves input");
        check(!tabbedConfig.renamer().enabled(), "tab-indented config applies renamer.enabled");
        check("tab".equals(tabbedConfig.renamer().prefix()),
                "tab-indented config applies renamer.prefix");

        // BOM-prefixed config file.
        Path bomConfig = write("bom.yml", "\uFEFFinput: \"in.jar\"\noutput: \"out.jar\"\n");
        UmbraConfig bomLoaded = ConfigLoader.load(bomConfig);
        check(bomLoaded.input().getFileName().toString().equals("in.jar"),
                "BOM-prefixed config file loads");

        // A single-quoted Windows path in a typed section survives.
        Path quotedConfig = write("quoted.yml", "input: \"in.jar\"\noutput: \"out.jar\"\n"
                + "renamer:\n  mappingFile: 'C:\\new\\mapping.txt'\n");
        check(quotedConfig != null, "quoted config fixture written");
        UmbraConfig quoted = ConfigLoader.load(quotedConfig);
        check("C:\\new\\mapping.txt".equals(quoted.renamer().mappingFile()),
                "single-quoted Windows path keeps its backslashes");

        // Unknown sections/keys are ignored, not rejected.
        Path unknown = write("unknown.yml", "input: \"in.jar\"\noutput: \"out.jar\"\n"
                + "unknownSection:\n  foo: bar\n");
        ConfigLoader.load(unknown);
        check(true, "unknown configuration keys are ignored");

        // Empty input/output values are missing keys, not the config directory.
        Path emptyInput = write("empty-input.yml", "input:\noutput: \"out.jar\"\n");
        try {
            ConfigLoader.load(emptyInput);
            check(false, "empty input value must be reported as a missing key");
        } catch (ConfigException expected) {
            check(expected.getMessage().contains("input"),
                    "empty input value reports the missing input key: " + expected.getMessage());
        }

        // Integer overflow in a typed section silently falls back to the
        // documented default (safe default, recorded as an accepted risk).
        Path overflow = write("overflow.yml", "input: \"in.jar\"\noutput: \"out.jar\"\n"
                + "junkMembers:\n  methods: 99999999999\n");
        check(ConfigLoader.load(overflow).junk().methods() == 2,
                "overflowing int option falls back to the safe default");

        // Unknown preset is still a clear configuration error.
        try {
            Presets.apply(new UmbraConfig.Builder().input(Paths.get("in.jar"))
                    .output(Paths.get("out.jar")).build(), "not-a-preset");
            check(false, "unknown preset must be rejected");
        } catch (ConfigException expected) {
            check(expected.getMessage().contains("Unknown preset"), "unknown preset message");
        }
    }

    /* ------------------------------------------------------------- config */

    private static void testConfigRoundTrip() throws Exception {
        Path base = work.resolve("round-trip");
        Files.createDirectories(base);
        Path input = base.resolve("a #1").resolve("app.jar");
        Path output = base.resolve("b #2").resolve("app obf.jar");
        Path library = base.resolve("lib #3.jar");
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("custom:key", "value with \"quotes\" and \\ backslash");
        options.put("string.engine", "rc4");
        options.put("empty.value", "");
        UmbraConfig config = new UmbraConfig.Builder()
                .input(input)
                .output(output)
                .addLibrary(library)
                .keep(Arrays.asList("com.example.**", "**Main"))
                .seed(20261024L)
                .options(options)
                .build();
        String yaml = ConfigWriter.toYaml(config);
        check(yaml.contains("input: \""), "ConfigWriter quotes the input path");
        check(yaml.contains("output: \""), "ConfigWriter quotes the output path");
        Path file = write("round-trip.yml", yaml);
        UmbraConfig loaded = ConfigLoader.load(file);
        check(loaded.input().equals(input), "quoted input path round-trips (contains ' #')");
        check(loaded.output().equals(output), "quoted output path round-trips (contains ' #')");
        check(loaded.libraries().size() == 1 && loaded.libraries().get(0).equals(library),
                "library path with ' #' round-trips");
        check(loaded.keep().equals(config.keep()), "keep rules round-trip");
        check(loaded.seed() == 20261024L, "seed round-trips");
        check("value with \"quotes\" and \\ backslash".equals(
                        loaded.option("custom:key", "<missing>")),
                "advanced option key with ':' and quoted value round-trips");
        check("".equals(loaded.option("empty.value", "<missing>")),
                "empty advanced option value round-trips");
        check("rc4".equals(loaded.option("string.engine", "<missing>")),
                "ordinary advanced option round-trips");
    }

    private static void testGuiConfigRoundTrip() throws Exception {
        Path app = work.resolve("gui-app.jar");
        Files.copy(demo, app);
        Path output = work.resolve("gui #out").resolve("app-obf.jar");
        Path mapping = work.resolve("gui-mapping.txt");
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("string.engine", "rc4");
        options.put("custom.key", "a, b");
        options.put("layout.multiRelease", "flatten");
        options.put("empty.value", "");
        UmbraConfig config = GuiConfig.build(app, output, 4242L, options, mapping);
        String yaml = GuiConfig.toYaml(config);
        Path file = write("gui.yml", yaml);
        UmbraConfig loaded = ConfigLoader.load(file);
        check(loaded.seed() == 4242L, "GUI config YAML round-trip keeps the seed");
        check(loaded.input().equals(app), "GUI config YAML round-trip keeps the input");
        check(loaded.output().equals(output), "GUI config YAML round-trip keeps a ' #' output path");
        check("rc4".equals(loaded.option("string.engine", "")),
                "GUI advanced option survives the YAML round-trip");
        check("a, b".equals(loaded.option("custom.key", "")),
                "GUI option value with a comma survives the YAML round-trip");
        check("flatten".equals(loaded.option("layout.multiRelease", "")),
                "GUI layout option survives the YAML round-trip");
        check("".equals(loaded.option("empty.value", "<missing>")),
                "GUI empty option value survives the YAML round-trip");
        check(GuiSwitches.fromConfig(loaded).equals(GuiSwitches.fromConfig(config)),
                "GUI toggle states survive the YAML round-trip");
        check(GuiConfig.validate(app, output) == null, "GUI validate accepts a fresh output path");
        check(GuiConfig.validate(app, app) != null, "GUI validate rejects input == output");
        check(GuiConfig.validate(app, work.resolve("not-a-jar.zip")) != null,
                "GUI validate rejects a non-jar output");

        // SpotBugs MS_MUTABLE_COLLECTION: the shared public preset-name list is
        // read by the GUI panels and must not be mutable by callers. set() is
        // the operation Arrays.asList allows (add/remove throw anyway), so it
        // is the one that proves the unmodifiable contract.
        boolean mutable;
        try {
            GuiPresets.NAMES.set(0, "Injected");
            mutable = true;
        } catch (UnsupportedOperationException expected) {
            mutable = false;
        }
        check(!mutable, "GuiPresets.NAMES must be immutable");
        if (mutable) {
            GuiPresets.NAMES.set(0, "Light");
        }
        check(GuiPresets.NAMES.size() == 6 && "Light".equals(GuiPresets.NAMES.get(0))
                        && "Balanced".equals(GuiPresets.NAMES.get(1)),
                "GuiPresets.NAMES keeps the six preset names in order");
    }

    private static void testGuiPrefs() throws Exception {
        String oldHome = System.getProperty("user.home");
        Path home = work.resolve("fake-home");
        Files.createDirectories(home);
        System.setProperty("user.home", home.toString());
        try {
            Path prefsFile = home.resolve(".umbra").resolve("gui.properties");
            Files.createDirectories(prefsFile.getParent());
            // Malformed unicode escape: Properties.load throws, the GUI must
            // fall back to defaults instead of failing to start.
            Files.write(prefsFile, "seed=\\uZZZZ\npreset=Light\n".getBytes(StandardCharsets.UTF_8));
            GuiPrefs corrupted = GuiPrefs.load();
            check(corrupted.seed() == 23303L, "corrupt preferences fall back to the default seed");
            check(GuiPresetsDefault.equals(corrupted.preset()),
                    "corrupt preferences fall back to the default preset");
            corrupted.setSeed(777L);
            corrupted.setPreset("Maximum");
            corrupted.rememberInput(home.resolve("somewhere").resolve("app.jar"));
            corrupted.save();
            GuiPrefs reloaded = GuiPrefs.load();
            check(reloaded.seed() == 777L, "preferences remember the seed after save");
            check("Maximum".equals(reloaded.preset()), "preferences remember the preset after save");
            check(reloaded.lastInputDir() != null && reloaded.lastInputDir().endsWith("somewhere"),
                    "preferences remember the last input directory");
            // Saving twice must stay atomic and readable.
            reloaded.setSeed(778L);
            reloaded.save();
            check(GuiPrefs.load().seed() == 778L, "preferences save is repeatable");
        } finally {
            System.setProperty("user.home", oldHome == null ? "" : oldHome);
        }
    }

    /* ------------------------------------------------------------- inspect */

    private static void testInspectEdges() throws Exception {
        Path duplicate = work.resolve("duplicate-entry.jar");
        writeDuplicateEntryJar(duplicate, "demo/Main.class", new byte[] { 1, 2, 3, 4 });
        InspectTool.Report report = InspectTool.analyze(duplicate);
        check(report.duplicateEntries == 1, "duplicate archive entries are counted");
        check(report.duplicateNames.contains("demo/Main.class"),
                "duplicate entry name is reported");
        // Inspection counts archive entries, so the duplicated class is counted
        // twice even though the protection writer keeps the first occurrence.
        check(report.transformableClasses == 2,
                "duplicate jar reports both class entries (entry-level count)");
        check(report.warnings.toString().contains("duplicate"), "duplicate entries produce a warning");

        Path empty = work.resolve("empty.zip");
        writeEmptyZip(empty);
        InspectTool.Report emptyReport = InspectTool.analyze(empty);
        check(emptyReport.transformableClasses == 0, "empty archive has no transformable classes");
        check(emptyReport.warnings.toString().contains("no transformable class entries"),
                "empty archive warns that no classes were found");

        Path resourcesOnly = work.resolve("resources-only.jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(resourcesOnly))) {
            out.putNextEntry(new ZipEntry("data/one.txt"));
            out.write("one".getBytes(StandardCharsets.UTF_8));
            out.closeEntry();
            out.putNextEntry(new ZipEntry("data/two.txt"));
            out.write("two".getBytes(StandardCharsets.UTF_8));
            out.closeEntry();
        }
        InspectTool.Report resources = InspectTool.analyze(resourcesOnly);
        check(resources.transformableClasses == 0 && resources.resources == 2,
                "resources-only archive counts only resources");
        check(resources.warnings.toString().contains("nothing to transform"),
                "resources-only archive warns that there is nothing to transform");

        Path corrupt = write("corrupt.jar", "this is not a zip file");
        try {
            InspectTool.analyze(corrupt);
            check(false, "corrupt archive must throw");
        } catch (java.util.zip.ZipException expected) {
            check(true, "corrupt archive throws ZipException");
        }
    }

    /* ----------------------------------------------------------- CLI parse */

    private static void testCliParsing() throws Exception {
        Path input = work.resolve("parse-app.jar");
        Files.copy(demo, input);
        Path output = work.resolve("parse-out.jar");

        Result version = cli("--version");
        check(version.exit == 0 && version.output.contains("Umbra "), "--version exits 0");

        Result help = cli("-h");
        check(help.exit == 0 && help.output.contains("--inspect"), "-h exits 0 and prints usage");

        Result unknown = cli("--bogus-option");
        check(unknown.exit == 1 && unknown.output.contains("Unknown argument"),
                "unknown argument exits 1 with a clear message");

        Result missingValue = cli("-i");
        check(missingValue.exit == 1 && missingValue.output.contains("Missing value for -i"),
                "missing option value exits 1 with a clear message");

        Result missingSet = cli("--set");
        check(missingSet.exit == 1 && missingSet.output.contains("Missing value for --set"),
                "missing --set value exits 1");

        Result emptyKey = cli("--set", "=value", "-i", input.toString(), "-o", output.toString(),
                "--dry-run");
        check(emptyKey.exit == 1 && emptyKey.output.contains("--set expects key=value"),
                "--set with an empty key exits 1");

        Result emptyValue = cli("--set", "vm2.enabled=", "-i", input.toString(),
                "-o", output.toString(), "--dry-run");
        check(emptyValue.exit == 0, "--set with an empty value is accepted");

        Result equalsValue = cli("--set", "custom.eq=a=b=c", "-i", input.toString(),
                "-o", output.toString(), "--dry-run");
        check(equalsValue.exit == 0, "--set value may contain '='");

        Result duplicate = cli("--set", "vm2.enabled=true", "--set", "vm2.enabled=false",
                "-i", input.toString(), "-o", output.toString(), "--dry-run");
        check(duplicate.exit == 0, "duplicate --set keys use the last value without failing");

        Result dashD = cli("-D", "vm2.enabled=true", "-i", input.toString(),
                "-o", output.toString(), "--dry-run");
        check(dashD.exit == 0, "-D key=value alias works");

        Result missingDiff = cli("--diff-mapping", root.resolve("demo").resolve("umbra-mapping.txt")
                .toString());
        check(missingDiff.exit == 1 && missingDiff.output.contains("Missing value for --diff-mapping"),
                "--diff-mapping with one path exits 1");

        Result badSeed = cli("-i", input.toString(), "-o", output.toString(), "--seed", "abc");
        check(badSeed.exit == 1 && badSeed.output.contains("Invalid number for --seed"),
                "non-numeric --seed exits 1 with a clear message");

        Result badInt = cli("-i", input.toString(), "-o", output.toString(),
                "--virtualize-max-instructions", "abc");
        check(badInt.exit == 1 && badInt.output.contains("Invalid integer for --virtualize-max-instructions"),
                "non-numeric integer option exits 1 with a clear message");

        Result badConfig = cli("-c", work.resolve("missing-config.yml").toString());
        check(badConfig.exit == 1 && badConfig.output.contains("Configuration file not found"),
                "missing config file exits 1 with a clear message");

        Result noPaths = cli("-i", input.toString());
        check(noPaths.exit == 1 && noPaths.output.contains("-o <output> are required"),
                "input without output exits 1");
    }

    /* ------------------------------------------------------ CLI paths/runs */

    private static void testCliPathsAndOutputs() throws Exception {
        Path input = work.resolve("run-app.jar");
        Files.copy(demo, input);
        Path dryOutput = work.resolve("dry-run-out.jar");
        Result dryRun = cli("--dry-run", "-i", input.toString(), "-o", dryOutput.toString());
        check(dryRun.exit == 0, "--dry-run succeeds");
        check(!Files.exists(dryOutput), "--dry-run writes no output JAR");

        Result dryRunNoOutput = cli("-i", input.toString(), "--dry-run");
        check(dryRunNoOutput.exit == 0, "--dry-run works without -o");

        // A filesystem-root input has no file name: the dry-run placeholder
        // output must not NPE, the run must fail cleanly as a non-regular file.
        Path rootPath = Paths.get("").toAbsolutePath().getRoot();
        if (rootPath != null) {
            Result rootInput = cli("-i", rootPath.toString(), "--dry-run");
            check(rootInput.exit == 1 && rootInput.output.contains("not a regular file"),
                    "dry-run with a filesystem-root input exits 1 with a clear message");
        }

        // Input == output is rejected unless --allow-in-place is explicit.
        Path source = work.resolve("source.jar");
        Files.copy(demo, source);
        byte[] sourceHash = hash(source);
        Result same = cli("-i", source.toString(), "-o", source.toString());
        check(same.exit == 1 && same.output.contains("Output must be different"),
                "output == input exits 1");
        Result inPlaceDry = cli("-i", source.toString(), "-o", source.toString(),
                "--allow-in-place", "--dry-run");
        check(inPlaceDry.exit == 0, "--allow-in-place permits an in-place dry run");
        check(Arrays.equals(sourceHash, hash(source)), "in-place dry run leaves the input untouched");

        // Paths with spaces and non-ASCII names.
        Path spaced = work.resolve("app with space \u00fc \u6d4b\u8bd5.jar");
        Files.copy(demo, spaced);
        Path spacedOut = work.resolve("out with space \u00fc.jar");
        Result spacedRun = cli("--dry-run", "-i", spaced.toString(), "-o", spacedOut.toString());
        check(spacedRun.exit == 0, "input/output paths with spaces and non-ASCII characters work");

        // Relative paths resolve against the process working directory.
        Result relativeRun = cli("--dry-run", "-i", "demo/demo.jar",
                "-o", "build-qa/audit/relative-dry-run-out.jar");
        check(relativeRun.exit == 0, "relative input/output paths work");

        // Config without input fails clearly when loaded strictly.
        Path noInput = write("no-input.yml", "renamer:\n  enabled: true\n");
        Result noInputRun = cli("--dry-run", "-c", noInput.toString());
        check(noInputRun.exit == 1
                        && noInputRun.output.contains("Missing required configuration key: input"),
                "config without input exits 1 with a clear message");

        // Real protection run (light preset) with all report artifacts.
        Path output = work.resolve("protected.jar");
        Path mapping = work.resolve("mapping.txt");
        Path reportHtml = work.resolve("report.html");
        Path reportJson = work.resolve("report.json");
        Path compatJson = work.resolve("compat.json");
        Result protect = cli("-i", input.toString(), "-o", output.toString(),
                "--preset", "light", "--seed", "11", "--verify",
                "--mapping", mapping.toString(),
                "--report", reportHtml.toString(),
                "--report-json", reportJson.toString(),
                "--compat-report", compatJson.toString());
        check(protect.exit == 0, "light-preset protection run succeeds");
        check(protect.output.contains("Verification: OK"), "protected output passes JVM verification");
        check(Files.isRegularFile(output), "protection run writes the output JAR");
        check(Files.isRegularFile(mapping), "protection run writes the mapping file");
        check(Files.isRegularFile(reportHtml) && read(reportHtml).contains("<html"),
                "protection run writes the HTML report");
        check(Files.isRegularFile(reportJson) && read(reportJson).trim().startsWith("{"),
                "protection run writes the JSON report");
        check(Files.isRegularFile(compatJson)
                        && read(compatJson).contains("\"kind\": \"compat-report\""),
                "protection run writes the compatibility report");

        // The mapping diff tool reads two mapping files.
        Result diff = cli("--diff-mapping",
                root.resolve("demo").resolve("umbra-mapping.txt").toString(), mapping.toString());
        check(diff.exit == 0 && diff.output.contains("mapping diff"),
                "--diff-mapping compares two mapping files");

        // The watermark tracer finds the mark embedded by the run.
        Result watermark = cli("--trace-watermark", output.toString());
        check(watermark.exit == 0 && watermark.output.contains("UMBRA|"),
                "--trace-watermark finds the Umbra watermark");
        Result noWatermark = cli("--trace-watermark", input.toString());
        check(noWatermark.exit == 0 && noWatermark.output.contains("No Umbra watermark found"),
                "--trace-watermark reports an unmarked JAR");

        // Corrupt / empty inputs are reported without a stack trace.
        Path corrupt = write("bad.jar", "not a zip");
        Result corruptRun = cli("-i", corrupt.toString(), "-o", work.resolve("bad-out.jar").toString());
        check(corruptRun.exit == 1 && corruptRun.output.contains("not a readable JAR"),
                "corrupt input JAR exits 1 with a clear message");
        Result corruptInspect = cli("--inspect", "-i", corrupt.toString());
        check(corruptInspect.exit == 1 && corruptInspect.output.contains("not a readable JAR"),
                "--inspect on a corrupt JAR exits 1 with a clear message");
        Result inspectNoInput = cli("--inspect");
        check(inspectNoInput.exit == 1 && inspectNoInput.output.contains("--inspect requires -i"),
                "--inspect without an input exits 1");

        // Inspection JSON is valid JSON and is written to a missing directory.
        Path inspectJson = work.resolve("inspect-dir").resolve("sub").resolve("inspect.json");
        Result inspect = cli("--inspect", "-i", input.toString(),
                "--inspect-json", inspectJson.toString());
        check(inspect.exit == 0, "--inspect exits 0 for a readable JAR");
        check(Files.isRegularFile(inspectJson), "--inspect-json creates missing parent directories");
        String inspectText = read(inspectJson);
        check(inspectText.trim().startsWith("{") && inspectText.contains("\"layout\""),
                "--inspect-json writes a JSON document with the layout field");
    }

    /* ------------------------------------------------------- license gate */

    private static void testCliLicenseGate() throws Exception {
        Licenses licenses = makeLicenses(work.resolve("licenses"));
        Path input = work.resolve("license-app.jar");
        Files.copy(demo, input);
        Path output = work.resolve("license-out.jar");

        Result requireNoLicense = cli("-i", input.toString(), "-o", output.toString(),
                "--dry-run", "--require-license");
        check(requireNoLicense.exit == 3,
                "--require-license without a license exits 3 (was: silent or wrong code)");

        Result missingLicense = cli("-i", input.toString(), "-o", output.toString(),
                "--dry-run", "--require-license", "--license",
                work.resolve("missing.lic").toString());
        check(missingLicense.exit == 3 && missingLicense.output.contains("License error"),
                "missing license file exits 3 with a License error");

        Result valid = cli("-i", input.toString(), "-o", output.toString(), "--dry-run",
                "--require-license", "--license", licenses.audit.toString(),
                "--license-key", licenses.publicKey.toString());
        check(valid.exit == 0 && valid.output.contains("License:"),
                "valid required license exits 0 and is logged");

        Result featurePresent = cli("-i", input.toString(), "-o", output.toString(), "--dry-run",
                "--require-feature", "audit", "--license", licenses.audit.toString(),
                "--license-key", licenses.publicKey.toString());
        check(featurePresent.exit == 0, "licensed feature satisfies --require-feature");

        Result featureMissing = cli("-i", input.toString(), "-o", output.toString(), "--dry-run",
                "--require-feature", "policy", "--license", licenses.audit.toString(),
                "--license-key", licenses.publicKey.toString());
        check(featureMissing.exit == 3
                        && featureMissing.output.contains("does not include required feature"),
                "unlicensed --require-feature exits 3");

        Result featureNoLicense = cli("-i", input.toString(), "-o", output.toString(),
                "--dry-run", "--require-feature", "audit");
        check(featureNoLicense.exit == 3,
                "--require-feature without any license exits 3 (was: silently ignored)");

        // A license supplied by the configuration file must be enforced when
        // --require-license is passed on the command line.
        Path configWithLicense = write("license-config.yml",
                "input: \"" + escape(input) + "\"\noutput: \"" + escape(output) + "\"\n"
                        + "license:\n  enabled: true\n  file: \"" + escape(licenses.audit) + "\"\n"
                        + "  publicKey: \"" + escape(licenses.publicKey) + "\"\n"
                        + "  require: true\n");
        Result configLicense = cli("--dry-run", "--require-license", "-c", configWithLicense.toString());
        check(configLicense.exit == 0 && configLicense.output.contains("License:"),
                "config-supplied license satisfies --require-license (was: exit 3 before reading config)");

        // The public key and require flag from the config survive a --license
        // override on the command line.
        Result override = cli("--dry-run", "-c", configWithLicense.toString(),
                "--license", licenses.audit.toString());
        check(override.exit == 0, "config public key survives a --license override");
        check(!override.output.contains("Public key not provided"),
                "config public key is used for the overridden license (was: dropped)");

        Result downgrade = cli("--dry-run", "-c", configWithLicense.toString(),
                "--license", licenses.unsigned.toString(),
                "--license-key", licenses.publicKey.toString());
        check(downgrade.exit == 3,
                "config license.require is preserved when --license overrides the file");
    }

    /* ----------------------------------------------------------- artifacts */

    private static void testCliArtifacts() throws Exception {
        Path input = work.resolve("artifact-app.jar");
        Files.copy(demo, input);
        Path output = work.resolve("artifact-out.jar");
        Result inspectResources = cli("--inspect", "-i",
                work.resolve("resources-only.jar").toString());
        check(inspectResources.exit == 0
                        && inspectResources.output.contains("nothing to transform"),
                "--inspect reports a resources-only archive");

        // In-place protection is explicit and produces a valid protected JAR.
        Path inPlace = work.resolve("in-place.jar");
        Files.copy(demo, inPlace);
        Result inPlaceRun = cli("-i", inPlace.toString(), "-o", inPlace.toString(),
                "--allow-in-place", "--preset", "light", "--seed", "5");
        check(inPlaceRun.exit == 0, "--allow-in-place protection run succeeds");
        try (ZipFile zip = new ZipFile(inPlace.toFile())) {
            check(zip.size() > 0, "in-place output is a readable JAR");
        }
        check(!Arrays.equals(hash(inPlace), hash(demo)), "in-place output actually replaced the input");

        // dry-run never writes the mapping file either.
        Path dryMapping = work.resolve("dry-mapping.txt");
        Result dryRun = cli("--dry-run", "-i", input.toString(), "-o", output.toString(),
                "--mapping", dryMapping.toString());
        check(dryRun.exit == 0 && !Files.exists(dryMapping),
                "--dry-run writes no mapping file");

        // A report path that cannot be written is a warning after a successful
        // run, not a failure of the protection run itself.
        Result compatFailure = cli("--dry-run", "-i", input.toString(), "-o", output.toString(),
                "--compat-report", work.toString());
        check(compatFailure.exit == 0
                        && compatFailure.output.contains("Warning: compatibility report not written"),
                "unwritable --compat-report path is a warning after a successful run");
    }

    /* ------------------------------------------------------------ GUI exit */

    private static void testGuiEntry() throws Exception {
        Result headlessMain = runChild("io.umbra.cli.Main", true);
        check(headlessMain.exit == 1 && headlessMain.output.contains("requires a graphical desktop"),
                "GUI on a headless JVM exits 1 (was: 0)");

        Result headlessGui = runChild("io.umbra.gui.GuiMain", true);
        check(headlessGui.exit == 1, "GuiMain headless exit code is 1");

        Path png = work.resolve("gui-audit.png");
        Result screenshot = runChild("io.umbra.cli.Main", true,
                "--gui", "--screenshot", png.toString(), "--width", "320", "--height", "240");
        check(screenshot.exit == 0, "--gui forwards --screenshot and exits 0");
        check(Files.isRegularFile(png), "--gui --screenshot writes the PNG");
        if (Files.isRegularFile(png)) {
            BufferedImage image = ImageIO.read(png.toFile());
            check(image != null && image.getWidth() == 320 && image.getHeight() == 240,
                    "--screenshot uses the requested dimensions");
        }

        Result missingScreenshot = runChild("io.umbra.gui.GuiMain", true, "--screenshot");
        check(missingScreenshot.exit == 2
                        && missingScreenshot.output.contains("Missing value for --screenshot"),
                "GUI missing --screenshot value exits 2 with a clear message");

        Result unknown = runChild("io.umbra.gui.GuiMain", true, "--bogus-option");
        check(unknown.exit == 2 && unknown.output.contains("Unknown argument: --bogus-option"),
                "GUI unknown argument exits 2 with a clear message");
    }

    /* ------------------------------------------------------------- helpers */

    private static final String GuiPresetsDefault = "Balanced";

    private interface TestCase {
        void run() throws Exception;
    }

    private static void run(String name, TestCase test) {
        try {
            test.run();
        } catch (Throwable error) {
            failures.add(name + " crashed: " + error);
            if (!(error instanceof AssertionError)) {
                error.printStackTrace();
            }
        }
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            failures.add(message);
        }
    }

    private static Path locateRoot() {
        Path current = Paths.get("").toAbsolutePath().normalize();
        while (current != null) {
            if (Files.isRegularFile(current.resolve("demo").resolve("demo.jar"))) {
                return current;
            }
            current = current.getParent();
        }
        throw new IllegalStateException("run AuditTest from the Umbra repository root "
                + "(demo/demo.jar not found from " + Paths.get("").toAbsolutePath() + ")");
    }

    private static Path write(String name, String content) throws IOException {
        Path file = work.resolve(name);
        if (file.getParent() != null) {
            Files.createDirectories(file.getParent());
        }
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));
        return file;
    }

    private static String read(Path file) throws IOException {
        return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    }

    private static String escape(Path path) {
        return path.toAbsolutePath().toString().replace("\\", "\\\\");
    }

    private static byte[] hash(Path file) throws IOException {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            return digest.digest(Files.readAllBytes(file));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : new LinkedHashMap<String, Object>();
    }

    private static final class Result {
        final int exit;
        final String output;

        Result(int exit, String output) {
            this.exit = exit;
            this.output = output == null ? "" : output;
        }
    }

    private static Result cli(String... args) throws Exception {
        return runChild("io.umbra.cli.Main", true, args);
    }

    private static Result runChild(String mainClass, boolean headless, String... args)
            throws Exception {
        List<String> command = new ArrayList<String>();
        command.add(javaExecutable());
        if (headless) {
            command.add("-Djava.awt.headless=true");
        }
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(mainClass);
        for (String arg : args) {
            command.add(arg);
        }
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(root.toFile());
        builder.redirectErrorStream(true);
        final Process process = builder.start();
        // Drain the child's output on a separate thread: waiting for the
        // process first would deadlock as soon as the child fills the pipe
        // buffer (the usage text alone is larger than it).
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Thread reader = new Thread(new Runnable() {
            @Override
            public void run() {
                try (InputStream in = process.getInputStream()) {
                    byte[] chunk = new byte[8192];
                    int read;
                    while ((read = in.read(chunk)) >= 0) {
                        buffer.write(chunk, 0, read);
                    }
                } catch (IOException ignored) {
                    // The child was killed; keep whatever was buffered.
                }
            }
        }, "audit-child-reader");
        reader.setDaemon(true);
        reader.start();
        boolean finished = process.waitFor(180L, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
        }
        reader.join(5000L);
        String output = new String(buffer.toByteArray(), StandardCharsets.UTF_8);
        if (!finished) {
            return new Result(-1, output + "\n[timeout]");
        }
        return new Result(process.exitValue(), output);
    }

    private static String javaExecutable() {
        String home = System.getProperty("java.home");
        boolean windows = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT)
                .contains("win");
        File executable = new File(home, "bin" + File.separator + "java" + (windows ? ".exe" : ""));
        return executable.getAbsolutePath();
    }

    private static Licenses makeLicenses(Path directory) throws Exception {
        Files.createDirectories(directory);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        Path privateKey = directory.resolve("private.pem");
        Path publicKey = directory.resolve("public.pem");
        Files.write(privateKey, LicenseTool.pem("PRIVATE KEY", pair.getPrivate().getEncoded()));
        Files.write(publicKey, LicenseTool.pem("PUBLIC KEY", pair.getPublic().getEncoded()));
        Path unsigned = directory.resolve("license-unsigned.yml");
        Files.write(unsigned, ("id: audit-fixture\nlicensee: Umbra Audit\nedition: enterprise\n"
                + "expires: 2030-12-31\nfeatures:\n  - audit\n")
                .getBytes(StandardCharsets.UTF_8));
        Path signed = directory.resolve("license-audit.yml");
        LicenseTool.sign(unsigned, privateKey, signed);
        Path bad = directory.resolve("license-unsigned-out.yml");
        Files.write(bad, ("id: audit-bad\nlicensee: Umbra Audit\nedition: enterprise\n"
                + "expires: 2030-12-31\nfeatures:\n  - audit\n")
                .getBytes(StandardCharsets.UTF_8));
        return new Licenses(publicKey, signed, bad);
    }

    private static final class Licenses {
        final Path publicKey;
        final Path audit;
        final Path unsigned;

        Licenses(Path publicKey, Path audit, Path unsigned) {
            this.publicKey = publicKey;
            this.audit = audit;
            this.unsigned = unsigned;
        }
    }

    /* ------------------------------------------------- raw ZIP edge fixture */

    private static void writeEmptyZip(Path file) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeLe32(out, 0x06054b50L);
        writeLe16(out, 0);
        writeLe16(out, 0);
        writeLe16(out, 0);
        writeLe16(out, 0);
        writeLe32(out, 0);
        writeLe32(out, 0);
        writeLe16(out, 0);
        Files.write(file, out.toByteArray());
    }

    /** Writes a STORED-entry ZIP containing the same name twice (ZipOutputStream rejects it). */
    private static void writeDuplicateEntryJar(Path file, String name, byte[] data)
            throws IOException {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        CRC32 crc = new CRC32();
        crc.update(data);
        long crcValue = crc.getValue();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long[] offsets = new long[2];
        for (int i = 0; i < 2; i++) {
            offsets[i] = out.size();
            writeLe32(out, 0x04034b50L);
            writeLe16(out, 20);
            writeLe16(out, 0);
            writeLe16(out, 0);
            writeLe16(out, 0);
            writeLe16(out, 0);
            writeLe32(out, crcValue);
            writeLe32(out, data.length);
            writeLe32(out, data.length);
            writeLe16(out, nameBytes.length);
            writeLe16(out, 0);
            out.write(nameBytes);
            out.write(data);
        }
        long centralStart = out.size();
        for (int i = 0; i < 2; i++) {
            writeLe32(out, 0x02014b50L);
            writeLe16(out, 20);
            writeLe16(out, 20);
            writeLe16(out, 0);
            writeLe16(out, 0);
            writeLe16(out, 0);
            writeLe16(out, 0);
            writeLe32(out, crcValue);
            writeLe32(out, data.length);
            writeLe32(out, data.length);
            writeLe16(out, nameBytes.length);
            writeLe16(out, 0);
            writeLe16(out, 0);
            writeLe16(out, 0);
            writeLe16(out, 0);
            writeLe32(out, 0);
            writeLe32(out, offsets[i]);
            out.write(nameBytes);
        }
        long centralSize = out.size() - centralStart;
        writeLe32(out, 0x06054b50L);
        writeLe16(out, 0);
        writeLe16(out, 0);
        writeLe16(out, 2);
        writeLe16(out, 2);
        writeLe32(out, centralSize);
        writeLe32(out, centralStart);
        writeLe16(out, 0);
        Files.write(file, out.toByteArray());
    }

    private static void writeLe16(ByteArrayOutputStream out, long value) {
        out.write((int) (value & 0xFF));
        out.write((int) ((value >>> 8) & 0xFF));
    }

    private static void writeLe32(ByteArrayOutputStream out, long value) {
        out.write((int) (value & 0xFF));
        out.write((int) ((value >>> 8) & 0xFF));
        out.write((int) ((value >>> 16) & 0xFF));
        out.write((int) ((value >>> 24) & 0xFF));
    }

    private static void delete(Path directory) {
        if (directory == null || !Files.exists(directory)) {
            return;
        }
        try {
            Files.walk(directory)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (Exception ignored) {
                            // Best-effort temp cleanup.
                        }
                    });
        } catch (Exception ignored) {
            // Best-effort temp cleanup.
        }
    }
}
