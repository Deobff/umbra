package io.umbra.tests;

import io.umbra.core.config.ConfigLoader;
import io.umbra.core.config.UmbraConfig;
import io.umbra.gui.GuiConfig;
import io.umbra.gui.GuiSwitches;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Self-test for the desktop GUI's configuration logic: output-path defaults,
 * validation, the 3.0 advanced options, mapping-file resolution and the YAML
 * round trip the GUI's Save/Load actions rely on.
 */
public final class GuiConfigTest {

    private static int checks;

    private GuiConfigTest() {
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("umbra-gui-test-");
        try {
            check("3.1.0".equals(GuiConfig.VERSION), "GUI version is 3.1.0");

            Path input = dir.resolve("app.jar");
            Files.write(input, new byte[0]);
            Path output = dir.resolve("app-obf.jar");

            check(GuiConfig.defaultOutput(input).endsWith("app-obf.jar"),
                    "default output name is next to the input");
            check(GuiConfig.defaultOutput(null).isEmpty(), "no input gives no default output");

            check(GuiConfig.validate(input, output) == null, "valid paths accepted");
            check(GuiConfig.validate(dir.resolve("missing.jar"), output) != null,
                    "missing input rejected");
            check(GuiConfig.validate(input, dir.resolve("app.zip")) != null,
                    "non-jar output rejected");
            check(GuiConfig.validate(input, input) != null, "input == output rejected");
            check(GuiConfig.validate(input, dir) != null, "directory output rejected");

            Map<String, String> options = new LinkedHashMap<String, String>();
            options.put("renamer.enabled", "true");
            options.put("stringEncryption.enabled", "true");
            options.put("integerEncryption.enabled", "false");
            options.put("flowObfuscation.enabled", "true");
            options.put("methodVirtualization.enabled", "true");
            options.put("vm2.enabled", "true");
            options.put("decompilerNoise.enabled", "true");
            options.put("decompilerNoise.level", "3");
            options.put("classEncryption.enabled", "true");
            options.put("classEncryption.resources", "true");
            options.put("integrity.enabled", "true");
            options.put("antiDebug.level", "2");
            options.put("nocturne.enabled", "true");
            options.put("minecraft.enabled", "false");

            UmbraConfig config = GuiConfig.build(input, output, 4242L, options, dir);
            check(config.input().equals(input), "input propagated");
            check(config.output().equals(output), "output propagated");
            check(config.seed() == 4242L, "seed propagated");
            check("3".equals(config.option("decompilerNoise.level", "")), "noise level propagated");
            check("true".equals(config.option("classEncryption.enabled", "")), "class encryption propagated");
            check("true".equals(config.option("classEncryption.resources", "")), "resource encryption propagated");
            check("true".equals(config.option("integrity.enabled", "")), "integrity propagated");
            check("true".equals(config.option("nocturne.enabled", "")), "nocturne propagated");
            check("false".equals(config.option("minecraft.enabled", "")), "minecraft switch propagated");
            check(config.antiDebug(), "anti-debug enabled for level 2");
            check("2".equals(config.option("antiDebug.level", "")), "anti-debug level propagated");
            check("true".equals(config.option("antiDebug.nativeGuard", "")), "native guard implied");
            check(config.methodVirtualization().enabled(), "virtualization enabled");
            check(config.integerEncryption().enabled() == false, "integer encryption disabled");

            Path keepOutput = dir.resolve("keep.jar");
            Map<String, String> keepOptions = new LinkedHashMap<String, String>();
            keepOptions.put("keepPublicApi", "true");
            keepOptions.put("antiDebug.level", "0");
            UmbraConfig keep = GuiConfig.build(input, keepOutput, 1L, keepOptions, dir);
            check(keep.keepPublicApi(), "keep public API propagated");
            check(!keep.antiDebug(), "anti-debug disabled at level 0");
            check("0".equals(keep.option("antiDebug.level", "")), "level 0 stored");

            // 3.0 option surface: the GUI sends these; defaults stay conservative.
            check("true".equals(keep.option("layout.springBoot", "")),
                    "Spring Boot layout defaults on");
            check("true".equals(keep.option("layout.war", "")), "WAR layout defaults on");
            check("preserve".equals(keep.option("layout.multiRelease", "")),
                    "multi-release layout defaults to preserve");
            check("auto".equals(keep.option("layout.moduleInfo", "")),
                    "module-info handling defaults to auto");
            check("false".equals(keep.option("typeConfusion.enabled", "")),
                    "type confusion defaults off");
            check("false".equals(keep.option("reflectionGate.enabled", "")),
                    "reflection gate defaults off");
            check("false".equals(keep.option("flow.aggressive", "")),
                    "aggressive flow defaults off");
            check("true".equals(keep.option("string.stackTraceHide", "")),
                    "stack-trace hiding defaults on");
            check("true".equals(keep.option("string.wipe", "")),
                    "decrypted-string wiping defaults on");
            check("auto".equals(keep.option("string.engine", "")),
                    "string engine defaults to auto");
            check("true".equals(keep.option("vm2.fusion", "")), "VM2 fusion defaults on");
            check("true".equals(keep.option("native.antiDump", "")),
                    "native anti-dump defaults on");

            Map<String, String> explicit = new LinkedHashMap<String, String>();
            explicit.put("typeConfusion.enabled", "true");
            explicit.put("layout.springBoot", "false");
            explicit.put("layout.multiRelease", "flatten");
            explicit.put("string.engine", "rc4");
            explicit.put("flow.aggressive", "true");
            UmbraConfig explicitConfig = GuiConfig.build(input, dir.resolve("explicit.jar"),
                    7L, explicit, dir);
            check("true".equals(explicitConfig.option("typeConfusion.enabled", "")),
                    "explicit optional pass enabled");
            check("false".equals(explicitConfig.option("layout.springBoot", "")),
                    "explicit layout flag respected");
            check("flatten".equals(explicitConfig.option("layout.multiRelease", "")),
                    "explicit multi-release mode respected");
            check("rc4".equals(explicitConfig.option("string.engine", "")),
                    "explicit string engine respected");
            check("true".equals(explicitConfig.option("flow.aggressive", "")),
                    "explicit aggressive flow respected");

            // Mapping path resolution: a directory gets umbra-mapping.txt, a
            // *.txt path is used verbatim.
            UmbraConfig dirMapping = GuiConfig.build(input, dir.resolve("m.jar"), 1L,
                    new LinkedHashMap<String, String>(), dir);
            check(dirMapping.mapping().file().equals(
                            dir.resolve("umbra-mapping.txt").toAbsolutePath().toString()),
                    "directory mapping target resolves to umbra-mapping.txt");
            check(dirMapping.renamer().mappingFile().equals(dirMapping.mapping().file()),
                    "renamer and mapping sections agree");
            Path mappingFile = dir.resolve("stable-mapping.txt");
            UmbraConfig fileMapping = GuiConfig.build(input, dir.resolve("m2.jar"), 1L,
                    new LinkedHashMap<String, String>(), mappingFile);
            check(fileMapping.mapping().file().equals(mappingFile.toAbsolutePath().toString()),
                    "explicit mapping file used verbatim");

            // YAML round trip, as used by the GUI's Save/Load buttons.
            String yaml = GuiConfig.toYaml(config);
            check(yaml.contains("layout.springBoot"), "saved YAML contains 3.0 layout options");
            check(yaml.contains("options:"), "saved YAML contains the advanced option section");
            Path yamlFile = dir.resolve("gui.yml");
            Files.write(yamlFile, yaml.getBytes(StandardCharsets.UTF_8));
            UmbraConfig reloaded = ConfigLoader.load(yamlFile);
            check(reloaded.seed() == 4242L, "YAML round trip keeps the seed");
            check(reloaded.input().equals(input), "YAML round trip keeps the input");
            check(GuiSwitches.fromConfig(reloaded).equals(GuiSwitches.fromConfig(config)),
                    "toggle states survive the YAML round trip");
            check(GuiSwitches.advancedOverrides(reloaded).containsKey("classEncryption.enabled")
                            || "true".equals(reloaded.option("classEncryption.enabled", "")),
                    "advanced options survive the YAML round trip");

            // Preset maps must be complete and detectable.
            check(GuiSwitches.defaults().size() == GuiSwitches.allToggles().size(),
                    "every toggle has a default");
            check("Balanced".equals(io.umbra.gui.GuiPresets.detect(
                            io.umbra.gui.GuiPresets.states("Balanced"))),
                    "Balanced preset is detectable");
            check("Light".equals(io.umbra.gui.GuiPresets.detect(
                            io.umbra.gui.GuiPresets.states("Light"))),
                    "Light preset is detectable");
            check("Balanced".equals(io.umbra.gui.GuiPresets.detect(GuiSwitches.defaults())),
                    "catalogue defaults equal the Balanced preset");
        } finally {
            delete(dir);
        }
        System.out.println("GuiConfigTest: " + checks + " checks passed");
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
