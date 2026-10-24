package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.engine.UmbraVerifier;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.DecompilerNoisePass;
import io.umbra.core.pass.impl.noise.ClassNoise;
import io.umbra.core.pass.impl.noise.NoiseBudget;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Log;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Plain-main tests for the decompiler-noise pass.
 *
 * <p>Builds classes with the ASM tree API, applies {@link ClassNoise}, serializes
 * them through the production writer and then loads/links/executes them to prove
 * the metadata noise is JVM-legal. The end-to-end part obfuscates
 * {@code demo/demo.jar} at every level, runs the output on JDK 8/21/26 and
 * records how CFR copes (level 1 must stay useful, level 3 must visibly
 * degrade).</p>
 */
public final class DecompilerNoiseTest {

    private static final String TARGET = "noisetest/Target";
    private static final String TARGET_BINARY = "noisetest.Target";

    private static int checks;

    private DecompilerNoiseTest() {
    }

    public static void main(String[] args) throws Exception {
        testLevelsMetadataAndJvm();
        testDeterminism();
        testSkipRulesAndStats();
        testDemoJarEndToEnd();
        System.out.println("DecompilerNoiseTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------- unit tests

    private static void testLevelsMetadataAndJvm() throws Exception {
        for (int level = 1; level <= ClassNoise.LEVEL_HOSTILE; level++) {
            ClassNode node = targetClass(TARGET);
            int perClass = ClassNoise.perClassBudget(level);
            NoiseBudget budget = new NoiseBudget(perClass, ClassNoise.globalBudget(level));
            ClassNoise.Result result = ClassNoise.apply(node, level, new Random(1000L + level),
                    budget, false);

            check(result.attributes > 0, "level " + level + ": attributes added");
            check(result.bytes > 0, "level " + level + ": bytes charged");
            check(result.bytes <= perClass, "level " + level + ": per-class budget respected");
            check((level >= 3) == hasClassAttribute(node, "Code"),
                    "level " + level + ": class-level Code trap only at level 3");
            check(node.sourceDebug != null, "level " + level + ": SourceDebugExtension noise");
            check(node.methods.get(0).localVariables != null
                            || node.methods.get(0).maxLocals <= 0,
                    "level " + level + ": local variable table rewritten");
            check(node.methods.get(0).parameters != null, "level " + level + ": MethodParameters noise");

            byte[] bytes = serialize(node);
            check(bytes.length > 100, "level " + level + ": class serializes");
            ClassNode parsed = new ClassNode();
            new ClassReader(bytes).accept(parsed, 0);
            check(TARGET.equals(parsed.name), "level " + level + ": output parses");
            check(parsed.methods.size() == 3, "level " + level + ": methods preserved");

            Class<?> type = defineClass(TARGET_BINARY, bytes);
            check(((Integer) type.getMethod("compute", int.class).invoke(null, 41)).intValue() == 42,
                    "level " + level + ": compute(41) == 42");
            check("hi".equals(type.getMethod("greet", String.class).invoke(null, "hi")),
                    "level " + level + ": greet");
            check(((Long) type.getMethod("multi", long.class).invoke(null, 41L)).longValue() == 42L,
                    "level " + level + ": multi(41) == 42");
            check(type.getDeclaredMethods().length == 3, "level " + level + ": methods reflectable");
            check(type.getDeclaredFields().length == 1, "level " + level + ": fields reflectable");
            if (level >= 2) {
                check(genericReflectionFails(type),
                        "level " + level + ": bogus signatures break generic reflection");
            } else {
                check(!genericReflectionFails(type), "level 1: generic reflection still works");
            }
            if (level >= 3) {
                check(declaresFakeException(type), "level 3: fake declared exception visible");
            }
        }
        check(ClassNoise.apply(null, 1, new Random(1), new NoiseBudget(10, 10), false).attributes == 0,
                "null class is a no-op");
    }

    private static void testDeterminism() throws Exception {
        byte[] first = serializeNoise(3, 424242L);
        byte[] second = serializeNoise(3, 424242L);
        byte[] different = serializeNoise(3, 424243L);
        check(Arrays.equals(first, second), "same seed produces byte-identical output");
        check(!Arrays.equals(first, different), "different seed changes the noise");
        check(Arrays.equals(serializeNoise(1, 7L), serializeNoise(1, 7L)),
                "level 1 is deterministic too");
    }

    private static void testSkipRulesAndStats() throws Exception {
        UmbraConfig config = new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"))
                .option("decompilerNoise.level", "3")
                .build();
        ClassPool pool = new ClassPool();
        ClassNode normal = targetClass("demo/Normal");
        ClassNode frozen = targetClass("demo/Frozen");
        ClassNode generated = targetClass("demo/Generated");
        ClassNode kept = targetClass("demo/Kept");
        ClassNode bodySkip = targetClass("demo/BodySkip");
        pool.putClass("demo/Normal.class", new byte[0], normal);
        pool.putClass("demo/Frozen.class", new byte[0], frozen);
        pool.freeze("demo/Frozen");
        pool.addGenerated(generated);
        pool.putClass("demo/Kept.class", new byte[0], kept);
        pool.putClass("demo/BodySkip.class", new byte[0], bodySkip);

        DefaultRuleSet rules = new DefaultRuleSet(
                Collections.singletonList("demo/Kept"), Collections.<String>emptyList(), false, false);
        rules.addBodySkipGlob("demo/BodySkip");
        Stats stats = new Stats();
        PassContext context = new PassContext(config, pool, new Hierarchy(), rules,
                new DefaultRuntimeSupport(), new MappingSet(), stats, new Log(null, false),
                new Random(7), ProgressListener.NONE);

        DecompilerNoisePass pass = new DecompilerNoisePass();
        check("decompiler-noise".equals(pass.name()), "pass name is stable");
        check(pass.order() == 35, "pass order stays 35");
        check(pass.enabled(context), "pass is enabled by default");
        pass.run(context);

        check(hasAnyAttribute(normal), "normal class receives noise");
        check(!hasAnyAttribute(frozen), "frozen class is skipped");
        check(!hasAnyAttribute(generated), "generated class is skipped");
        check(!hasAnyAttribute(kept), "kept class is skipped");
        check(!hasAnyAttribute(bodySkip), "body-skip (mixin/target) class is skipped");

        Map<String, Long> snapshot = stats.snapshot();
        check(snapshot.containsKey("noise.level") && snapshot.get("noise.level").longValue() == 3,
                "noise.level stat");
        check(snapshot.containsKey("noise.classes") && snapshot.get("noise.classes").longValue() == 1,
                "only the transformable class is counted");
        check(snapshot.get("noise.attributes").longValue() > 0, "noise.attributes stat");
        check(snapshot.get("noise.bytes").longValue() > 0, "noise.bytes stat");

        UmbraConfig disabled = new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"))
                .option("decompilerNoise.enabled", "false")
                .build();
        PassContext offContext = new PassContext(disabled, new ClassPool(), new Hierarchy(), rules,
                new DefaultRuntimeSupport(), new MappingSet(), new Stats(), new Log(null, false),
                new Random(7), ProgressListener.NONE);
        check(!pass.enabled(offContext), "pass can be disabled");

        // Level clamping keeps hostile values safe.
        check(ClassNoise.clampLevel(0) == 1, "level 0 clamps to 1");
        check(ClassNoise.clampLevel(9) == 3, "level 9 clamps to 3");
    }

    // ---------------------------------------------------------- end to end

    private static void testDemoJarEndToEnd() throws Exception {
        Path root = findProjectRoot();
        if (root == null) {
            System.out.println("DecompilerNoiseTest: demo/demo.jar not found, skipping end-to-end checks");
            return;
        }
        Path demoJar = root.resolve("demo").resolve("demo.jar");
        Path dir = Files.createTempDirectory("umbra-noise-test");
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();

        // The engine runs in-process (same classes this test was compiled
        // against), so no child-process classpath is involved at all: only the
        // produced jar is started as a subprocess later.
        Path baseline = dir.resolve("demo-noise-off.jar");
        EngineResult baselineResult = runEngine(demoJar, baseline, false, 1);
        check(Files.exists(baseline), "baseline jar produced");
        check(!baselineResult.stats().snapshot().containsKey("noise.classes"),
                "baseline run has no noise stats");

        Path[] jars = new Path[ClassNoise.LEVEL_HOSTILE + 1];
        for (int level = 1; level <= ClassNoise.LEVEL_HOSTILE; level++) {
            Path out = dir.resolve("demo-noise-" + level + ".jar");
            jars[level] = out;
            EngineResult result = runEngine(demoJar, out, true, level);
            check(Files.exists(out), "level " + level + ": output jar produced");
            Map<String, Long> stats = result.stats().snapshot();
            check(stats.get("noise.level").longValue() == level, "level " + level + ": noise.level stat");
            check(stats.get("noise.classes").longValue() > 0, "level " + level + ": noise.classes stat");
            check(stats.get("noise.attributes").longValue() > 0, "level " + level + ": noise.attributes stat");
            check(stats.get("noise.bytes").longValue() > 0, "level " + level + ": noise.bytes stat");
            check(UmbraVerifier.verify(out).isEmpty(),
                    "level " + level + ": every class still links (JVM verifier)");
            String run = runIn(dir, java, "-jar", out.toString());
            check(run.contains("OK"), "level " + level + ": demo runs on JDK 8: " + tail(run));
            check(Files.size(out) > Files.size(demoJar), "level " + level + ": jar grew");
            check(!Arrays.equals(Files.readAllBytes(baseline), Files.readAllBytes(out)),
                    "level " + level + ": noise changes the archive");
        }
        check(Files.size(jars[3]) > Files.size(jars[1]), "level 3 is larger than level 1");
        check(Files.size(baseline) < Files.size(jars[1]), "level 1 grows the archive over baseline");

        // Same seed -> identical archive (engine-level determinism).
        Path repeat = dir.resolve("demo-noise-1-repeat.jar");
        runEngine(demoJar, repeat, true, 1);
        check(sha256(jars[1]).equals(sha256(repeat)),
                "engine output is deterministic for the same seed");

        // JDK 21 / 26 load, link and execute the hostile level.
        for (String candidate : new String[] {
                "C:\\Program Files\\Java\\jdk-21.0.10\\bin\\java.exe",
                "C:\\Program Files\\Java\\jdk-26.0.1\\bin\\java.exe",
                "C:\\Program Files\\Zulu\\zulu-21\\bin\\java.exe"
        }) {
            if (!Files.exists(Paths.get(candidate))) {
                continue;
            }
            String run = runIn(dir, candidate, "-jar", jars[3].toString());
            check(run.contains("OK"), "level 3 runs on " + candidate + ": " + tail(run));
        }

        // CFR: level 1 must stay usable, level 3 must visibly lose classes.
        Path cfr = root.resolve("qa").resolve("tools").resolve("cfr-0.152.jar");
        if (!Files.exists(cfr)) {
            System.out.println("DecompilerNoiseTest: CFR not found, skipping decompiler checks");
            return;
        }
        int cfrLevel1 = runCfr(java, cfr, jars[1], dir.resolve("cfr-1"));
        int cfrLevel3 = runCfr(java, cfr, jars[3], dir.resolve("cfr-3"));
        check(cfrLevel1 > 5, "level 1: CFR still decompiles the demo (" + cfrLevel1 + " files)");
        check(cfrLevel3 < cfrLevel1,
                "level 3: CFR output degraded (" + cfrLevel3 + " vs " + cfrLevel1 + " files)");
        check(cfrLevel3 * 2 < cfrLevel1,
                "level 3: CFR loses the majority of classes (" + cfrLevel3 + "/" + cfrLevel1 + ")");
    }

    private static int runCfr(String java, Path cfr, Path jar, Path outDir) throws Exception {
        if (!Files.exists(outDir.getParent())) {
            Files.createDirectories(outDir.getParent());
        }
        if (Files.exists(outDir)) {
            deleteRecursively(outDir);
        }
        runIn(outDir.getParent(), java, "-jar", cfr.toString(), jar.toString(),
                "--outputdir", outDir.toString(), "--silent", "true");
        if (!Files.exists(outDir)) {
            return 0;
        }
        int count = 0;
        java.util.stream.Stream<Path> stream = Files.walk(outDir);
        try {
            count = (int) stream.filter(path -> path.toString().endsWith(".java")
                    && Files.isRegularFile(path)).count();
        } finally {
            stream.close();
        }
        return count;
    }

    /**
     * Runs the whole obfuscation pipeline in-process. Deliberately avoids a
     * child JVM for the CLI: the test must not depend on the parent test
     * runner's classpath or working directory, which differ between build
     * directories and concurrent shared builds.
     */
    private static EngineResult runEngine(Path input, Path output, boolean noiseEnabled, int level)
            throws Exception {
        UmbraConfig config = new UmbraConfig.Builder()
                .input(input)
                .output(output)
                .seed(424242L)
                .option("decompilerNoise.enabled", Boolean.toString(noiseEnabled))
                .option("decompilerNoise.level", Integer.toString(level))
                .build();
        return new UmbraEngine(new Log(null, false)).run(config, ProgressListener.NONE);
    }

    // -------------------------------------------------------- class synthesis

    private static ClassNode targetClass(String name) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = name;
        node.superName = "java/lang/Object";
        node.fields.add(new FieldNode(Opcodes.ACC_PRIVATE, "counter", "I", null, null));
        node.methods.add(method("compute", "(I)I",
                new VarInsnNode(Opcodes.ILOAD, 0),
                new InsnNode(Opcodes.ICONST_1),
                new InsnNode(Opcodes.IADD),
                new InsnNode(Opcodes.IRETURN)));
        node.methods.add(method("greet", "(Ljava/lang/String;)Ljava/lang/String;",
                new VarInsnNode(Opcodes.ALOAD, 0),
                new InsnNode(Opcodes.ARETURN)));
        node.methods.add(method("multi", "(J)J",
                new VarInsnNode(Opcodes.LLOAD, 0),
                new InsnNode(Opcodes.LCONST_1),
                new InsnNode(Opcodes.LADD),
                new InsnNode(Opcodes.LRETURN)));
        // Real max_locals so the local-variable-table noise is actually applied;
        // the writer still recomputes them from the final code.
        node.methods.get(0).maxLocals = 1;
        node.methods.get(1).maxLocals = 1;
        node.methods.get(2).maxLocals = 2;
        return node;
    }

    private static MethodNode method(String name, String desc, AbstractInsnNode... instructions) {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                name, desc, null, null);
        for (AbstractInsnNode instruction : instructions) {
            method.instructions.add(instruction);
        }
        return method;
    }

    private static byte[] serialize(ClassNode node) {
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        return UmbraClassWriter.toBytes(node, hierarchy);
    }

    private static byte[] serializeNoise(int level, long seed) {
        ClassNode node = targetClass(TARGET);
        ClassNoise.apply(node, level, new Random(seed),
                new NoiseBudget(ClassNoise.perClassBudget(level), ClassNoise.globalBudget(level)), false);
        return serialize(node);
    }

    private static Class<?> defineClass(final String name, final byte[] bytes) throws Exception {
        ClassLoader loader = new ClassLoader(DecompilerNoiseTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String requested) throws ClassNotFoundException {
                if (name.equals(requested)) {
                    return defineClass(requested, bytes, 0, bytes.length);
                }
                throw new ClassNotFoundException(requested);
            }
        };
        return Class.forName(name, true, loader);
    }

    private static boolean genericReflectionFails(Class<?> type) {
        try {
            for (java.lang.reflect.Method method : type.getDeclaredMethods()) {
                method.getGenericParameterTypes();
                method.getGenericReturnType();
            }
            type.getGenericSuperclass();
            return false;
        } catch (Throwable expected) {
            return true;
        }
    }

    private static boolean declaresFakeException(Class<?> type) {
        for (java.lang.reflect.Method method : type.getDeclaredMethods()) {
            for (Class<?> exception : method.getExceptionTypes()) {
                if (exception.getName().equals("java.lang.RuntimeException")
                        || exception.getName().equals("java.lang.Exception")
                        || exception.getName().equals("java.lang.Error")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean hasClassAttribute(ClassNode node, String type) {
        if (node.attrs == null) {
            return false;
        }
        for (Attribute attribute : node.attrs) {
            if (type.equals(attribute.type)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasAnyAttribute(ClassNode node) {
        if (node.attrs != null && !node.attrs.isEmpty()) {
            return true;
        }
        for (MethodNode method : node.methods) {
            if (method.attrs != null && !method.attrs.isEmpty()) {
                return true;
            }
        }
        for (FieldNode field : node.fields) {
            if (field.attrs != null && !field.attrs.isEmpty()) {
                return true;
            }
        }
        return node.sourceDebug != null;
    }

    // --------------------------------------------------------------- helpers

    private static String runIn(Path directory, String... command) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(directory.toFile());
        builder.redirectErrorStream(true);
        Process process = builder.start();
        String output = readAll(process.getInputStream());
        int code = process.waitFor();
        check(code == 0, "command exited 0 (" + command[0] + "...): " + tail(output));
        return output;
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

    private static String sha256(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(Files.readAllBytes(file));
        StringBuilder out = new StringBuilder(hash.length * 2);
        for (byte value : hash) {
            out.append(String.format("%02x", Integer.valueOf(value & 0xFF)));
        }
        return out.toString();
    }

    private static String readAll(InputStream in) throws IOException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return new String(out.toByteArray(), "UTF-8");
        } finally {
            in.close();
        }
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        List<Path> paths;
        java.util.stream.Stream<Path> stream = Files.walk(path);
        try {
            paths = new java.util.ArrayList<Path>();
            stream.forEach(paths::add);
        } finally {
            stream.close();
        }
        Collections.sort(paths, Collections.reverseOrder());
        for (Path entry : paths) {
            Files.deleteIfExists(entry);
        }
    }

    private static String tail(String value) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        return trimmed.length() <= 1200 ? trimmed : trimmed.substring(trimmed.length() - 1200);
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}
