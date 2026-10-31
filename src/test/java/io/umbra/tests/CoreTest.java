package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.ConfigLoader;
import io.umbra.core.config.ConfigWriter;
import io.umbra.core.config.Presets;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.pass.impl.FieldInitializationPass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Cipher;
import io.umbra.core.util.Log;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

/**
 * Plain-main test harness. The build script compiles everything under
 * {@code src/test/java} and runs each {@code *Test} class; a non-zero exit code
 * marks the build failed, so no JUnit dependency is required.
 */
public final class CoreTest {

    private static int checks;

    private CoreTest() {
    }

    public static void main(String[] args) throws Exception {
        testDefaults();
        testOptionMap();
        testYamlRoundTrip();
        testCipherRoundTrip();
        testNameGeneratorDeterminism();
        testPresetCeilings();
        testFieldInitializationBeforeReturn();
        System.out.println("CoreTest: " + checks + " checks passed");
    }

    /**
     * Static constants moved into {@code <clinit>} must be assigned before the
     * terminal {@code RETURN}: appending them after it turns every assignment into
     * dead code, and the field silently keeps its default value.
     */
    private static void testFieldInitializationBeforeReturn() throws Exception {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = "probe/Consts";
        node.superName = "java/lang/Object";
        node.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "TEXT", "Ljava/lang/String;", null, "hello"));
        node.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "COUNT", "J", null, Long.valueOf(7L)));
        ClassWriter writer = new ClassWriter(0);
        node.accept(writer);
        byte[] bytes = writer.toByteArray();
        ClassPool pool = new ClassPool();
        pool.putClass(node.name + ".class", bytes, node);
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        PassContext context = new PassContext(
                new UmbraConfig.Builder().input(Paths.get("in.jar")).output(Paths.get("out.jar"))
                        .seed(11L).build(),
                pool, hierarchy,
                new DefaultRuleSet(new java.util.ArrayList<String>(),
                        new java.util.ArrayList<String>(), false, false),
                new DefaultRuntimeSupport(), new MappingSet(), new Stats(), new Log(null, false),
                new Random(11L), ProgressListener.NONE);
        new FieldInitializationPass().run(context);
        MethodNode clinit = null;
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name)) {
                clinit = method;
            }
        }
        check(clinit != null, "field-initialization creates a class initializer");
        int putstatic = -1;
        int ret = -1;
        for (int i = 0; i < clinit.instructions.size(); i++) {
            AbstractInsnNode insn = clinit.instructions.get(i);
            if (insn.getOpcode() == Opcodes.PUTSTATIC) {
                putstatic = i;
            }
            if (insn.getOpcode() == Opcodes.RETURN) {
                ret = i;
            }
        }
        check(putstatic >= 0 && ret > putstatic,
                "moved constants initialize before the terminal RETURN");
        check(context.stats().snapshot().get("constants.moved").longValue() == 2L,
                "both constants were moved into <clinit>");
    }

    /**
     * The instruction ceilings are eligibility thresholds, and they scale with the
     * preset tier. A single shared value made {@code light} as expensive per method
     * as {@code maximum} on large methods, which defeats the point of picking a
     * cheaper tier.
     */
    private static void testPresetCeilings() throws Exception {
        UmbraConfig light = Presets.apply(baseConfig(), "light");
        UmbraConfig balanced = Presets.apply(baseConfig(), "balanced");
        UmbraConfig maximum = Presets.apply(baseConfig(), "maximum");

        check(light.flow().maxInstructions() == 2000, "light flow ceiling is 2000");
        check(balanced.flow().maxInstructions() == 4000, "balanced flow ceiling is 4000");
        check(maximum.flow().maxInstructions() == 8000, "maximum flow ceiling is 8000");

        check(light.methodVirtualization().maxInstructions() == 1000,
                "light virtualization ceiling is 1000");
        check(balanced.methodVirtualization().maxInstructions() == 2000,
                "balanced virtualization ceiling is 2000");
        check(maximum.methodVirtualization().maxInstructions() == 4000,
                "maximum virtualization ceiling is 4000");

        check("2000".equals(balanced.option("vm2.maxInstructions", "")),
                "balanced vm2 ceiling is 2000");
        check("4000".equals(maximum.option("vm2.maxInstructions", "")),
                "maximum vm2 ceiling is 4000");

        check("400".equals(light.option("native.maxInstructions", "")),
                "light native ceiling is 400");
        check("800".equals(balanced.option("native.maxInstructions", "")),
                "balanced native ceiling is 800");
        check("1600".equals(maximum.option("native.maxInstructions", "")),
                "maximum native ceiling is 1600");

        check(light.flow().maxInstructions() < balanced.flow().maxInstructions()
                        && balanced.flow().maxInstructions() < maximum.flow().maxInstructions(),
                "flow ceiling increases with the tier");
        check(light.methodVirtualization().maxInstructions()
                        < balanced.methodVirtualization().maxInstructions()
                        && balanced.methodVirtualization().maxInstructions()
                        < maximum.methodVirtualization().maxInstructions(),
                "virtualization ceiling increases with the tier");
    }

    private static UmbraConfig baseConfig() throws Exception {
        return new UmbraConfig.Builder()
                .input(java.nio.file.Paths.get("in.jar"))
                .output(java.nio.file.Paths.get("out.jar"))
                .seed(424242L)
                .build();
    }

    private static void testDefaults() throws Exception {
        UmbraConfig config = new UmbraConfig.Builder()
                .input(java.nio.file.Paths.get("in.jar"))
                .output(java.nio.file.Paths.get("out.jar"))
                .build();
        check(config.seed() != 0, "default seed is set");
        check(config.stringEncryption().enabled(), "string encryption on by default");
        check(config.renamer().enabled(), "renamer on by default");
        check(config.options().isEmpty(), "option map starts empty");
        check(!config.optionBool("vm2.enabled", false), "unknown feature options are off by default");
    }

    private static void testOptionMap() throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        options.put("native.compiler", "C:/gcc.exe");
        options.put("mba.depth", "3");
        UmbraConfig config = new UmbraConfig.Builder()
                .input(java.nio.file.Paths.get("in.jar"))
                .output(java.nio.file.Paths.get("out.jar"))
                .options(options)
                .option("string.strength", "3")
                .build();
        check(config.optionBool("vm2.enabled", false), "vm2 option parsed");
        check("C:/gcc.exe".equals(config.option("native.compiler", "")), "string option parsed");
        check(config.optionInt("mba.depth", 0) == 3, "int option parsed");
        check(config.optionInt("mba.depth", -1) == 3, "int option parsed twice");
        check("3".equals(config.option("string.strength", "")), "single option added");
        check(config.toBuilder().build().optionBool("vm2.enabled", false), "options survive toBuilder");

        UmbraConfig direct = new UmbraConfig.Builder()
                .input(java.nio.file.Paths.get("in.jar"))
                .output(java.nio.file.Paths.get("out.jar"))
                .option("empty.value", "")
                .build();
        check("".equals(direct.option("empty.value", "x")), "empty value preserved");
    }

    private static void testYamlRoundTrip() throws Exception {
        Path dir = Files.createTempDirectory("umbra-config-test");
        try {
            Path input = dir.resolve("in.jar");
            Path output = dir.resolve("out.jar");
            Files.write(input, new byte[] { 1, 2, 3 });
            Map<String, String> options = new LinkedHashMap<String, String>();
            options.put("vm2.enabled", "true");
            options.put("vm2.trys", "true");
            options.put("native.enabled", "false");
            UmbraConfig config = new UmbraConfig.Builder()
                    .input(input)
                    .output(output)
                    .seed(20261023L)
                    .options(options)
                    .addLibrary(dir.resolve("lib.jar"))
                    .build();
            String yaml = ConfigWriter.toYaml(config);
            check(yaml.contains("vm2.enabled"), "options written to YAML");
            Path file = dir.resolve("umbra.yml");
            Files.write(file, yaml.getBytes(StandardCharsets.UTF_8));
            UmbraConfig loaded = ConfigLoader.load(file);
            check(loaded.seed() == 20261023L, "seed round-trips");
            check(loaded.optionBool("vm2.trys", false), "bool option round-trips");
            check(!loaded.optionBool("native.enabled", true), "false option round-trips");
            check(loaded.option("native.enabled", "").equals("false"), "option string round-trips");
            check(loaded.libraries().size() == 1, "libraries round-trip");
            check(loaded.input().toString().endsWith("in.jar"), "input round-trips");
        } finally {
            deleteRecursively(dir);
        }
    }

    private static void testCipherRoundTrip() {
        StringBuilder wide = new StringBuilder();
        for (int i = 0; i < 512; i++) {
            wide.append('a');
        }
        String[] samples = { "Hello, Umbra!", "Unicode sample \\u00e9\\u00fc", "", "x", wide.toString() };
        long[] keys = { 1L, 0x9E3779B97F4A7C15L, -42L, Long.MIN_VALUE, Long.MAX_VALUE };
        for (String sample : samples) {
            for (long key : keys) {
                String payload = Cipher.encrypt(sample, key);
                check(payload != null, "cipher produced a payload");
                check(Cipher.decrypt(payload, key).equals(sample), "cipher round-trip for length " + sample.length());
            }
        }
    }

    private static void testNameGeneratorDeterminism() {
        NameGenerator a = new NameGenerator(new Random(7), "");
        NameGenerator b = new NameGenerator(new Random(7), "");
        for (int i = 0; i < 32; i++) {
            String first = a.random(6);
            String second = b.random(6);
            check(first.equals(second), "name generator deterministic");
            check(first.length() == 6, "name generator honours length");
        }
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }

    private static void deleteRecursively(Path path) {
        try {
            if (!Files.exists(path)) {
                return;
            }
            Files.walk(path)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (java.io.IOException ignored) {
                            // best effort
                        }
                    });
        } catch (java.io.IOException ignored) {
            // best effort
        }
    }
}
