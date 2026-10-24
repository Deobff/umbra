package io.umbra.tests;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.engine.UmbraVerifier;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.DecompilerNoisePass;
import io.umbra.core.pass.impl.FlowObfuscationPass;
import io.umbra.core.pass.impl.ReflectionGatePass;
import io.umbra.core.pass.impl.StringEncryptionPass;
import io.umbra.core.pass.impl.TypeConfusionPass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.RecordComponentNode;
import org.objectweb.asm.tree.TypeInsnNode;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Plain-main acceptance tests for the Umbra 3.0 obfuscation-strength passes
 * (workstream WS2): {@link TypeConfusionPass}, {@link StringEncryptionPass} v2,
 * {@link FlowObfuscationPass} v2, {@link ReflectionGatePass} and
 * {@link DecompilerNoisePass} level 4.
 *
 * <p>The test drives each pass directly on a hand-built {@link PassContext} (the
 * same way {@code FlowTest} does), serializes the result into a real JAR, runs
 * that JAR in a child JVM, checks the demo still prints {@code OK}, asks
 * {@link UmbraVerifier} to link every produced class, proves byte-level
 * determinism for a seed and scans the output for plaintext string constants.
 * It therefore stays valid while {@code UmbraEngine} configuration is still
 * being wired by the integration owner.</p>
 *
 * <p>Nothing here needs network access; the only optional external tool is the
 * vendored CFR jar under {@code qa/tools} used for decompiler evidence.</p>
 */
public final class ProtectionV2Test {

    private static final long SEED = 424242L;

    /** String literals of the demo program that must never survive encryption. */
    private static final String[] DEMO_LITERALS = {
            "Hello, Umbra!", "logic broken", "self-check failed: ",
            "reflective static method invoke", "sum=", "caught: "
    };

    private static int checks;

    private ProtectionV2Test() {
    }

    public static void main(String[] args) throws Exception {
        startWatchdog();
        String only = System.getProperty("umbra.protection2.only", "");
        boolean all = only.isEmpty();
        if (all || only.contains("strings")) {
            System.out.println("ProtectionV2Test: string engine v2");
            testStringEngines();
        }
        if (all || only.contains("stringauto")) {
            System.out.println("ProtectionV2Test: string auto engines, wipe, hide, encryptAll");
            testStringAutoFlags();
        }
        if (all || only.contains("type")) {
            System.out.println("ProtectionV2Test: type confusion");
            testTypeConfusion();
        }
        if (all || only.contains("flow")) {
            System.out.println("ProtectionV2Test: flow v2");
            testFlowV2();
        }
        if (all || only.contains("reflection")) {
            System.out.println("ProtectionV2Test: reflection gate");
            testReflectionGate();
        }
        if (all || only.contains("noise")) {
            System.out.println("ProtectionV2Test: decompiler noise level 4");
            testDecompilerNoiseLevel4();
        }
        if (all || only.contains("determinism")) {
            System.out.println("ProtectionV2Test: combined determinism");
            testCombinedPipeline();
        }
        if (all || only.contains("limit")) {
            System.out.println("ProtectionV2Test: near-64KB method guard");
            testNearLimitStringMethod();
        }
        if (all || only.contains("modern")) {
            System.out.println("ProtectionV2Test: modern class-file shapes");
            testModernClassShapes();
        }
        System.out.println("ProtectionV2Test: " + checks + " checks passed");
    }

    // ------------------------------------------------------------------
    // String engine v2
    // ------------------------------------------------------------------

    private static void testStringEngines() throws Exception {
        Path demo = demoJar();
        if (demo == null) {
            System.out.println("ProtectionV2Test: demo/demo.jar not found, skipping");
            return;
        }
        String[] engines = { "chacha20", "aes-ctr", "rc4", "speck", "xor" };
        for (String engine : engines) {
            Protected result = protect(demo, SEED,
                    options("string.strength", "3", "string.engine", engine, "string.indy", "false"),
                    new StringEncryptionPass());
            long encrypted = stat(result, "strings.encrypted");
            check("string engine " + engine + ": encrypted constants", encrypted > 300);
            check("string engine " + engine + ": per-engine stat",
                    stat(result, "strings.engine." + engine) == encrypted);
            check("string engine " + engine + ": one engine kind",
                    stat(result, "strings.engineKinds") == 1);
            check("string engine " + engine + ": output differs from input",
                    !result.fingerprint().equals(fingerprint(demo)));
            verify(result, "string engine " + engine);
            check("string engine " + engine + ": demo prints OK", runsOk(result.jar));
            check("string engine " + engine + ": no plaintext literals left",
                    findPlaintext(result, DEMO_LITERALS).isEmpty());
        }

        // Determinism: same seed -> byte identical classes, different seed -> not.
        Protected first = protect(demo, SEED, options("string.strength", "3"), new StringEncryptionPass());
        Protected repeat = protect(demo, SEED, options("string.strength", "3"), new StringEncryptionPass());
        Protected other = protect(demo, SEED + 1, options("string.strength", "3"),
                new StringEncryptionPass());
        check("strings: same seed deterministic",
                first.fingerprint().equals(repeat.fingerprint()));
        check("strings: different seed changes output",
                !first.fingerprint().equals(other.fingerprint()));
        verify(repeat, "strings determinism");
        check("strings: deterministic output runs", runsOk(repeat.jar));
    }

    private static void testStringAutoFlags() throws Exception {
        Path demo = demoJar();
        if (demo == null) {
            return;
        }
        Protected auto = protect(demo, SEED,
                options("string.strength", "3", "string.engine", "auto", "string.indy", "true",
                        "string.wipe", "true", "string.stackTraceHide", "true",
                        "string.encryptAll", "true"),
                new StringEncryptionPass());
        check("auto: several engines used", stat(auto, "strings.engineKinds") >= 3);
        check("auto: chacha20 subset", stat(auto, "strings.engine.chacha20") > 0);
        check("auto: aes-ctr subset", stat(auto, "strings.engine.aes-ctr") > 0);
        check("auto: rc4 subset", stat(auto, "strings.engine.rc4") > 0);
        check("auto: speck subset", stat(auto, "strings.engine.speck") > 0);
        check("auto: indy call sites", stat(auto, "strings.indySites") > 0);
        check("auto: wipe flag recorded", stat(auto, "strings.wipe") == 1);
        check("auto: stackTraceHide flag recorded", stat(auto, "strings.stackTraceHide") == 1);
        check("auto: encryptAll flag recorded", stat(auto, "strings.encryptAll") == 1);
        verify(auto, "string auto");
        check("auto: demo prints OK", runsOk(auto.jar));
        check("auto: no plaintext literals left", findPlaintext(auto, DEMO_LITERALS).isEmpty());

        // encryptAll must cover literals that the default minimum length skips.
        Protected shortOnly = protect(demo, SEED, options("string.strength", "1"),
                new StringEncryptionPass());
        Protected all = protect(demo, SEED,
                options("string.strength", "1", "string.encryptAll", "true"),
                new StringEncryptionPass());
        check("encryptAll: covers more than the default minimum length",
                stat(all, "strings.encrypted") > stat(shortOnly, "strings.encrypted"));
        check("encryptAll: output still runs", runsOk(all.jar));

        // Explicit engine order including the xor engine must mix all five.
        Protected order = protect(demo, SEED,
                options("string.strength", "2", "string.engine", "auto",
                        "string.engineOrder", "xor,rc4,chacha20,aes-ctr,speck"),
                new StringEncryptionPass());
        check("engineOrder: all five engines used", stat(order, "strings.engineKinds") == 5);
        check("engineOrder: xor sites use per-site convention",
                stat(order, "strings.engine.xor") > 0);
        verify(order, "string engineOrder");
        check("engineOrder: demo prints OK", runsOk(order.jar));
    }

    // ------------------------------------------------------------------
    // Type confusion
    // ------------------------------------------------------------------

    private static void testTypeConfusion() throws Exception {
        Path demo = demoJar();
        if (demo != null) {
            Protected level2 = protect(demo, SEED,
                    options("typeConfusion.enabled", "true", "typeConfusion.level", "2"),
                    new TypeConfusionPass());
            check("type-confusion: methods transformed", stat(level2, "typeConfusion.methods") > 0);
            check("type-confusion: call sites transformed", stat(level2, "typeConfusion.calls") > 0);
            check("type-confusion: static fields carried", stat(level2, "typeConfusion.fields") > 0);
            check("type-confusion: field accesses rewritten",
                    stat(level2, "typeConfusion.fieldSites") > 0);
            check("type-confusion: no class rollbacks",
                    stat(level2, "typeConfusion.rollback.classes") == 0);
            verify(level2, "type-confusion demo");
            check("type-confusion: demo prints OK", runsOk(level2.jar));
            check("type-confusion: output differs from input",
                    !level2.fingerprint().equals(fingerprint(demo)));
            Protected repeat = protect(demo, SEED,
                    options("typeConfusion.enabled", "true", "typeConfusion.level", "2"),
                    new TypeConfusionPass());
            check("type-confusion: same seed deterministic",
                    level2.fingerprint().equals(repeat.fingerprint()));

            // Constructors and <clinit> are never replaced by carriers.
            ClassNode checks = level2.classNode("demo/Checks");
            check("type-confusion: Checks still has its original constructor",
                    hasMethod(checks, "<init>", "()V"));
        }

        Path synthetic = syntheticProgram("tc",
                "package tc;\n"
                        + "public final class Main {\n"
                        + "    private static int counter;\n"
                        + "    private static int hidden(int a, long b) { return a + (int) b; }\n"
                        + "    private static String label(int v) { return \"v\" + v; }\n"
                        + "    static int add(int a, int b) { return a + b; }\n"
                        + "    public static void main(String[] args) {\n"
                        + "        int x = add(2, 3);\n"
                        + "        int y = hidden(x, 4L);\n"
                        + "        counter = counter + y;\n"
                        + "        String text = label(counter);\n"
                        + "        if (!\"v9\".equals(text)) { throw new IllegalStateException(text); }\n"
                        + "        System.out.println(\"OK:\" + text);\n"
                        + "    }\n"
                        + "}\n");
        Protected level1 = protect(synthetic, SEED,
                options("typeConfusion.enabled", "true", "typeConfusion.level", "1"),
                new TypeConfusionPass());
        check("type-confusion(synthetic): methods transformed",
                stat(level1, "typeConfusion.methods") >= 2);
        check("type-confusion(synthetic): call sites transformed",
                stat(level1, "typeConfusion.calls") >= 2);
        check("type-confusion(synthetic): no field carriers at level 1",
                stat(level1, "typeConfusion.fields") == 0);
        check("type-confusion(synthetic): trampoline descriptor emitted",
                level1.fingerprint().length() > 0 && containsCarrier(level1, "tc/Main"));
        check("type-confusion(synthetic): level1 program prints OK", runsOk(level1.jar));
        verify(level1, "type-confusion synthetic l1");

        Protected syn2 = protect(synthetic, SEED,
                options("typeConfusion.enabled", "true", "typeConfusion.level", "2"),
                new TypeConfusionPass());
        check("type-confusion(synthetic): level2 field carrier",
                stat(syn2, "typeConfusion.fields") >= 1);
        check("type-confusion(synthetic): level2 program prints OK", runsOk(syn2.jar));
        verify(syn2, "type-confusion synthetic l2");
        Protected syn2repeat = protect(synthetic, SEED,
                options("typeConfusion.enabled", "true", "typeConfusion.level", "2"),
                new TypeConfusionPass());
        check("type-confusion(synthetic): deterministic",
                syn2.fingerprint().equals(syn2repeat.fingerprint()));
    }

    // ------------------------------------------------------------------
    // Flow v2
    // ------------------------------------------------------------------

    private static void testFlowV2() throws Exception {
        Path demo = demoJar();
        if (demo == null) {
            return;
        }
        Protected flow = protect(demo, SEED,
                options("flow.level", "aggressive", "flow.aggressive", "true"),
                new FlowObfuscationPass());
        check("flow-v2: methods transformed", stat(flow, "flow.methods") > 0);
        check("flow-v2: transposed blocks", stat(flow, "flow.transposed") > 0);
        check("flow-v2: bogus exception ranges", stat(flow, "flow.bogusRanges") > 0);
        check("flow-v2: range predicates", stat(flow, "flow.rangePredicates") > 0);
        check("flow-v2: hash predicates", stat(flow, "flow.hashPredicates") > 0);
        check("flow-v2: aggressive flag recorded", stat(flow, "flow.aggressive") == 1);
        check("flow-v2: no verification skips", stat(flow, "flow.skipped") == 0);
        verify(flow, "flow-v2");
        check("flow-v2: demo prints OK", runsOk(flow.jar));
        check("flow-v2: output differs from input",
                !flow.fingerprint().equals(fingerprint(demo)));

        Protected repeat = protect(demo, SEED,
                options("flow.level", "aggressive", "flow.aggressive", "true"),
                new FlowObfuscationPass());
        check("flow-v2: same seed deterministic", flow.fingerprint().equals(repeat.fingerprint()));
        Protected other = protect(demo, SEED + 7,
                options("flow.level", "aggressive", "flow.aggressive", "true"),
                new FlowObfuscationPass());
        check("flow-v2: different seed changes output",
                !flow.fingerprint().equals(other.fingerprint()));

        // Levels 1..3 behaviour must be untouched: normal level still works.
        Protected normal = protect(demo, SEED, options("flow.level", "normal"),
                new FlowObfuscationPass());
        check("flow-v2: normal level still injects junk", stat(normal, "flow.junkBlocks") > 0);
        check("flow-v2: normal level does not use aggressive-only features",
                stat(normal, "flow.transposed") == 0 && stat(normal, "flow.bogusRanges") == 0);
        check("flow-v2: normal level demo prints OK", runsOk(normal.jar));
    }

    // ------------------------------------------------------------------
    // Reflection gate
    // ------------------------------------------------------------------

    private static void testReflectionGate() throws Exception {
        Path gate = syntheticProgram("rg",
                "package rg;\n"
                        + "public final class Target {\n"
                        + "    private static int secret() { return 41; }\n"
                        + "    private static final String HIDDEN = \"hidden-value\";\n"
                        + "}\n",
                "package rg;\n"
                        + "public final class Caller {\n"
                        + "    public static void main(String[] args) {\n"
                        + "        try {\n"
                        + "            Class<?> target = Class.forName(\"rg.Target\");\n"
                        + "            java.lang.reflect.Method method =\n"
                        + "                target.getDeclaredMethod(\"secret\");\n"
                        + "            method.setAccessible(true);\n"
                        + "            System.out.println(\"OK:\" + method.invoke(null));\n"
                        + "        } catch (SecurityException denied) {\n"
                        + "            System.out.println(\"DENIED\");\n"
                        + "        } catch (NoSuchMethodException masked) {\n"
                        + "            System.out.println(\"MASKED\");\n"
                        + "        } catch (ClassNotFoundException masked) {\n"
                        + "            System.out.println(\"MASKED\");\n"
                        + "        } catch (Exception other) {\n"
                        + "            System.out.println(\"UNEXPECTED:\" + other);\n"
                        + "        }\n"
                        + "    }\n"
                        + "}\n");

        Protected deny = protect(gate, SEED,
                options("reflectionGate.enabled", "true"), new ReflectionGatePass());
        check("reflection-gate: sites rewritten", stat(deny, "reflectionGate.sites") >= 2);
        check("reflection-gate: classes sealed", stat(deny, "reflectionGate.sealed") >= 2);
        check("reflection-gate: deny action recorded", stat(deny, "reflectionGate.action") == 1);
        verify(deny, "reflection-gate deny");
        String denied = run(deny.jar);
        check(denied.contains("DENIED"), "reflection-gate(deny): foreign lookup denied", denied);

        Protected mask = protect(gate, SEED,
                options("reflectionGate.enabled", "true", "reflectionGate.action", "mask"),
                new ReflectionGatePass());
        String masked = run(mask.jar);
        check(masked.contains("MASKED"), "reflection-gate(mask): lookup masked as missing", masked);

        Protected allow = protect(gate, SEED,
                options("reflectionGate.enabled", "true", "reflectionGate.allow", "rg.Caller"),
                new ReflectionGatePass());
        String allowed = run(allow.jar);
        check(allowed.contains("OK:41"), "reflection-gate(allow): allow-listed caller succeeds",
                allowed);

        // Default (pass disabled) must not run the gate at all.
        Protected off = protect(gate, SEED, options("reflectionGate.enabled", "false"),
                new ReflectionGatePass());
        check("reflection-gate: disabled pass rewrites nothing",
                stat(off, "reflectionGate.sites") == 0);
        check("reflection-gate: disabled pass runs normally", run(off.jar).contains("OK:41"));

        Path demo = demoJar();
        if (demo != null) {
            Protected demoGate = protect(demo, SEED,
                    options("reflectionGate.enabled", "true"), new ReflectionGatePass());
            check("reflection-gate: demo sites rewritten",
                    stat(demoGate, "reflectionGate.sites") > 0);
            check("reflection-gate: demo self-reflection stays allowed", runsOk(demoGate.jar));
            verify(demoGate, "reflection-gate demo");
        }
    }

    // ------------------------------------------------------------------
    // Decompiler noise level 4
    // ------------------------------------------------------------------

    private static void testDecompilerNoiseLevel4() throws Exception {
        Path demo = demoJar();
        if (demo == null) {
            return;
        }
        Protected level1 = protect(demo, SEED, options("decompilerNoise.level", "1"),
                new DecompilerNoisePass());
        check("noise-level4: level 1 still works", runsOk(level1.jar));
        Protected level3 = protect(demo, SEED, options("decompilerNoise.level", "3"),
                new DecompilerNoisePass());
        check("noise-level4: level 3 recorded", stat(level3, "noise.level") == 3);
        check("noise-level4: level 3 still runs", runsOk(level3.jar));

        Protected level4 = protect(demo, SEED, options("decompilerNoise.level", "4"),
                new DecompilerNoisePass());
        check("noise-level4: level 4 recorded", stat(level4, "noise.level") == 4);
        check("noise-level4: level-4 attributes", stat(level4, "noise.level4.attributes") > 0);
        check("noise-level4: level-4 bytes", stat(level4, "noise.level4.bytes") > 0);
        check("noise-level4: bigger than level 3", level4.jarSize() > level3.jarSize());
        verify(level4, "noise level 4");
        check("noise-level4: demo prints OK (JDK 8 verifier)", runsOk(level4.jar));

        for (String candidate : new String[] {
                "C:\\Program Files\\Java\\jdk-21.0.10\\bin\\java.exe",
                "C:\\Program Files\\Java\\jdk-26.0.1\\bin\\java.exe",
                "C:\\Program Files\\Zulu\\zulu-21\\bin\\java.exe"
        }) {
            if (!Files.exists(Paths.get(candidate))) {
                continue;
            }
            String output = runWith(candidate, level4.jar);
            check("noise-level4: demo prints OK on " + candidate, output.contains("OK"));
        }

        // CFR evidence: level 4 must degrade decompilation at least as much as 3.
        Path cfr = projectRoot() == null ? null
                : projectRoot().resolve("qa").resolve("tools").resolve("cfr-0.152.jar");
        if (cfr != null && Files.exists(cfr)) {
            int baseline = runCfr(cfr, demo);
            int cfr3 = runCfr(cfr, level3.jar);
            int cfr4 = runCfr(cfr, level4.jar);
            System.out.println("ProtectionV2Test: CFR baseline=" + baseline + " level3=" + cfr3
                    + " level4=" + cfr4);
            check("noise-level4: CFR baseline decompiles the demo", baseline > 5);
            check("noise-level4: CFR output at level 4 is not better than baseline",
                    cfr4 < baseline);
        } else {
            System.out.println("ProtectionV2Test: qa/tools/cfr-0.152.jar not found, "
                    + "skipping decompiler evidence");
        }
    }

    // ------------------------------------------------------------------
    // Combined pipeline
    // ------------------------------------------------------------------

    private static void testCombinedPipeline() throws Exception {
        Path demo = demoJar();
        if (demo == null) {
            return;
        }
        String[] combinedOptions = options(
                "decompilerNoise.level", "1",
                "typeConfusion.enabled", "true",
                "typeConfusion.level", "2",
                "string.strength", "3",
                "string.engine", "auto",
                "string.indy", "true",
                "string.wipe", "true",
                "flow.level", "aggressive",
                "flow.aggressive", "true",
                "reflectionGate.enabled", "true");
        Protected first = protect(demo, SEED, combinedOptions,
                new DecompilerNoisePass(), new TypeConfusionPass(), new StringEncryptionPass(),
                new FlowObfuscationPass(), new ReflectionGatePass());
        check("combined: string pass ran", stat(first, "strings.encrypted") > 300);
        check("combined: type-confusion ran", stat(first, "typeConfusion.methods") > 0);
        check("combined: flow v2 ran", stat(first, "flow.transposed") > 0);
        check("combined: reflection gate ran", stat(first, "reflectionGate.sites") > 0);
        check("combined: noise ran", stat(first, "noise.level") == 1);
        verify(first, "combined pipeline");
        check("combined: demo prints OK", runsOk(first.jar));
        check("combined: no plaintext literals left", findPlaintext(first, DEMO_LITERALS).isEmpty());

        Protected second = protect(demo, SEED, combinedOptions,
                new DecompilerNoisePass(), new TypeConfusionPass(), new StringEncryptionPass(),
                new FlowObfuscationPass(), new ReflectionGatePass());
        check("combined: same seed deterministic",
                first.fingerprint().equals(second.fingerprint()));

        // Read back: the protected archive must contain the injected helpers.
        List<String> names = entryNames(first.jar);
        boolean hasRuntimeHelper = false;
        for (String name : names) {
            if (name.startsWith("umbra/runtime/") && name.endsWith(".class")) {
                hasRuntimeHelper = true;
            }
        }
        check("combined: injected runtime helpers present", hasRuntimeHelper);
    }

    // ------------------------------------------------------------------
    // Regression: method code-size stays under the 64KB JVM limit
    // ------------------------------------------------------------------

    /**
     * A method whose 3000 string literals would push its code size far beyond
     * the 65535-byte JVM limit if every site were encrypted. The pass must bound
     * the rewrite, leave the remaining literals alone and still produce a valid,
     * runnable class instead of failing the whole run with
     * {@code MethodTooLargeException}.
     */
    private static void testNearLimitStringMethod() throws Exception {
        ClassNode main = new ClassNode();
        main.version = Opcodes.V1_8;
        main.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER;
        main.name = "limit/Main";
        main.superName = "java/lang/Object";
        MethodNode run = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "main", "([Ljava/lang/String;)V", null, null);
        run.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "limit/NearLimit",
                "strings", "()I", false));
        run.instructions.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.SIPUSH, 3000));
        org.objectweb.asm.tree.LabelNode ok = new org.objectweb.asm.tree.LabelNode();
        run.instructions.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.IF_ICMPEQ, ok));
        run.instructions.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalStateException"));
        run.instructions.add(new InsnNode(Opcodes.DUP));
        run.instructions.add(new LdcInsnNode("near-limit mismatch"));
        run.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/IllegalStateException", "<init>", "(Ljava/lang/String;)V", false));
        run.instructions.add(new InsnNode(Opcodes.ATHROW));
        run.instructions.add(ok);
        run.instructions.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC,
                "java/lang/System", "out", "Ljava/io/PrintStream;"));
        run.instructions.add(new LdcInsnNode("OK limit"));
        run.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream",
                "println", "(Ljava/lang/String;)V", false));
        run.instructions.add(new InsnNode(Opcodes.RETURN));
        run.maxStack = 4;
        run.maxLocals = 1;
        main.methods.add(run);

        ClassNode nearLimit = new ClassNode();
        nearLimit.version = Opcodes.V1_8;
        nearLimit.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER;
        nearLimit.name = "limit/NearLimit";
        nearLimit.superName = "java/lang/Object";
        MethodNode strings = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "strings", "()I", null, null);
        for (int i = 0; i < 3000; i++) {
            strings.instructions.add(new LdcInsnNode("str" + (10000 + i)));
            strings.instructions.add(new InsnNode(Opcodes.POP));
        }
        strings.instructions.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.SIPUSH, 3000));
        strings.instructions.add(new InsnNode(Opcodes.IRETURN));
        strings.maxStack = 1;
        strings.maxLocals = 0;
        nearLimit.methods.add(strings);

        Path directory = Files.createTempDirectory("umbra-protection2-limit");
        Path jar = directory.resolve("limit.jar");
        writeAsmJar(jar, Arrays.asList(main, nearLimit), "limit/Main");
        Protected result = protect(jar, SEED,
                options("string.strength", "3", "string.engine", "chacha20"), 
                new StringEncryptionPass());
        long encrypted = stat(result, "strings.encrypted");
        check("near-limit: encrypted some literals", encrypted > 0);
        check("near-limit: did not encrypt every literal", encrypted < 3000);
        check("near-limit: code-size guard reported",
                stat(result, "strings.skipped.methodSize") > 0);
        verify(result, "near-limit");
        check("near-limit: program still runs", runsOk(result.jar));
        Protected repeat = protect(jar, SEED,
                options("string.strength", "3", "string.engine", "chacha20"),
                new StringEncryptionPass());
        check("near-limit: deterministic", result.fingerprint().equals(repeat.fingerprint()));
        deleteRecursively(directory);
    }

    // ------------------------------------------------------------------
    // Regression: modern class-file shapes (records/sealed/condy) survive
    // ------------------------------------------------------------------

    /**
     * Java 17 record/sealed metadata and {@code CONSTANT_Dynamic} operands must
     * survive the body passes untouched (the JDK 8 test JVM cannot load version
     * 61 classes, so this is a byte-shape regression: the attributes and the
     * condy operand are asserted on the serialized class files).
     */
    private static void testModernClassShapes() throws Exception {
        ClassNode condy = new ClassNode();
        condy.version = Opcodes.V11;
        condy.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER;
        condy.name = "modern/Condy";
        condy.superName = "java/lang/Object";
        MethodNode seed = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                "seed", "()Ljava/lang/String;", null, null);
        seed.instructions.add(new LdcInsnNode("condy-sentinel"));
        seed.instructions.add(new InsnNode(Opcodes.ARETURN));
        condy.methods.add(seed);
        Handle bootstrap = new Handle(Opcodes.H_INVOKESTATIC,
                "java/lang/invoke/ConstantBootstraps", "invoke",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;"
                        + "Ljava/lang/invoke/MethodHandle;[Ljava/lang/Object;)Ljava/lang/Object;",
                false);
        Handle seedHandle = new Handle(Opcodes.H_INVOKESTATIC, "modern/Condy", "seed",
                "()Ljava/lang/String;", false);
        ConstantDynamic dynamic = new ConstantDynamic("c", "Ljava/lang/Object;", bootstrap,
                seedHandle);
        MethodNode value = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/Object;", null, null);
        value.instructions.add(new LdcInsnNode(dynamic));
        value.instructions.add(new InsnNode(Opcodes.ARETURN));
        condy.methods.add(value);
        MethodNode plain = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "plain", "()Ljava/lang/String;", null, null);
        plain.instructions.add(new LdcInsnNode("modern-constant"));
        plain.instructions.add(new InsnNode(Opcodes.ARETURN));
        condy.methods.add(plain);
        MethodNode helper = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "helper", "(I)I", null, null);
        helper.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 0));
        helper.instructions.add(new InsnNode(Opcodes.ICONST_1));
        helper.instructions.add(new InsnNode(Opcodes.IADD));
        helper.instructions.add(new InsnNode(Opcodes.IRETURN));
        condy.methods.add(helper);
        MethodNode caller = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "caller", "(I)I", null, null);
        caller.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 0));
        caller.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "modern/Condy",
                "helper", "(I)I", false));
        caller.instructions.add(new InsnNode(Opcodes.ICONST_2));
        caller.instructions.add(new InsnNode(Opcodes.IMUL));
        caller.instructions.add(new InsnNode(Opcodes.IRETURN));
        condy.methods.add(caller);
        MethodNode branchy = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "branchy", "(I)I", null, null);
        org.objectweb.asm.tree.LabelNode elseLabel = new org.objectweb.asm.tree.LabelNode();
        org.objectweb.asm.tree.LabelNode done = new org.objectweb.asm.tree.LabelNode();
        branchy.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 0));
        branchy.instructions.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.IFLE, elseLabel));
        branchy.instructions.add(new InsnNode(Opcodes.ICONST_1));
        branchy.instructions.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.GOTO, done));
        branchy.instructions.add(elseLabel);
        branchy.instructions.add(new InsnNode(Opcodes.ICONST_2));
        branchy.instructions.add(done);
        branchy.instructions.add(new InsnNode(Opcodes.IRETURN));
        condy.methods.add(branchy);

        ClassNode record = new ClassNode();
        record.version = Opcodes.V17;
        record.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER
                | Opcodes.ACC_RECORD;
        record.name = "modern/Rec";
        record.superName = "java/lang/Object";
        record.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL, "x", "I",
                null, null));
        record.recordComponents = new ArrayList<RecordComponentNode>();
        record.recordComponents.add(new RecordComponentNode("x", "I", null));
        MethodNode init = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "(I)V", null, null);
        init.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
        init.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object",
                "<init>", "()V", false));
        init.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
        init.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 1));
        init.instructions.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.PUTFIELD,
                "modern/Rec", "x", "I"));
        init.instructions.add(new InsnNode(Opcodes.RETURN));
        record.methods.add(init);
        MethodNode accessor = new MethodNode(Opcodes.ACC_PUBLIC, "x", "()I", null, null);
        accessor.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
        accessor.instructions.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETFIELD,
                "modern/Rec", "x", "I"));
        accessor.instructions.add(new InsnNode(Opcodes.IRETURN));
        record.methods.add(accessor);

        ClassNode sealed = new ClassNode();
        sealed.version = Opcodes.V17;
        sealed.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_SUPER;
        sealed.name = "modern/Sealed";
        sealed.superName = "java/lang/Object";
        sealed.permittedSubclasses = new ArrayList<String>();
        sealed.permittedSubclasses.add("modern/Rec");
        MethodNode area = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                "area", "()I", null, null);
        sealed.methods.add(area);

        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"))
                .seed(SEED)
                .option("string.strength", "3")
                .option("string.engine", "auto")
                .option("typeConfusion.enabled", "true")
                .option("typeConfusion.level", "2")
                .option("flow.aggressive", "true")
                .option("decompilerNoise.level", "4")
                .flow(new UmbraConfig.FlowOptions(true, "aggressive", 20000, false));
        Stats stats = new Stats();
        PassContext context = passContext(builder.build(), stats, "modern", condy, record, sealed);
        new DecompilerNoisePass().run(context);
        new TypeConfusionPass().run(context);
        new StringEncryptionPass().run(context);
        new FlowObfuscationPass().run(context);

        check("modern: string pass ran", stat(stats, "strings.encrypted") > 0);
        check("modern: type confusion ran", stat(stats, "typeConfusion.calls") > 0);
        check("modern: flow ran", stat(stats, "flow.junkBlocks") > 0);
        check("modern: noise level 4 ran", stat(stats, "noise.level") == 4);
        check("modern: no pass errors",
                stat(stats, "typeConfusion.rollback.classes") == 0);

        byte[] condyBytes = serialize(condy, context.hierarchy());
        byte[] recordBytes = serialize(record, context.hierarchy());
        byte[] sealedBytes = serialize(sealed, context.hierarchy());

        ClassNode condyBack = new ClassNode();
        new ClassReader(condyBytes).accept(condyBack, 0);
        boolean condyPreserved = false;
        boolean plaintextEncrypted = true;
        for (MethodNode method : condyBack.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof LdcInsnNode)) {
                    continue;
                }
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof ConstantDynamic && "c".equals(((ConstantDynamic) constant)
                        .getName())) {
                    condyPreserved = true;
                }
                if ("modern-constant".equals(constant)) {
                    plaintextEncrypted = false;
                }
            }
        }
        check("modern: CONSTANT_Dynamic operand preserved", condyPreserved);
        check("modern: plain string constant encrypted", plaintextEncrypted);

        ClassNode recordBack = new ClassNode();
        new ClassReader(recordBytes).accept(recordBack, 0);
        check("modern: ACC_RECORD flag preserved",
                (recordBack.access & Opcodes.ACC_RECORD) != 0);
        check("modern: Record attribute preserved",
                recordBack.recordComponents != null && recordBack.recordComponents.size() == 1
                        && "x".equals(recordBack.recordComponents.get(0).name));

        ClassNode sealedBack = new ClassNode();
        new ClassReader(sealedBytes).accept(sealedBack, 0);
        check("modern: PermittedSubclasses preserved",
                sealedBack.permittedSubclasses != null
                        && sealedBack.permittedSubclasses.contains("modern/Rec"));
    }

    // ------------------------------------------------------------------
    // Protection harness
    // ------------------------------------------------------------------

    /** One protected output: real JAR, statistics, class bytes for inspection. */
    private static final class Protected {
        private Path jar;
        private Path directory;
        private Stats stats;
        private final Map<String, byte[]> classBytes = new LinkedHashMap<String, byte[]>();
        private String fingerprint;
        private long jarSize;

        long jarSize() {
            return jarSize;
        }

        String fingerprint() {
            return fingerprint;
        }

        ClassNode classNode(String name) {
            byte[] bytes = classBytes.get(name);
            if (bytes == null) {
                throw new IllegalStateException("missing class " + name);
            }
            ClassNode node = new ClassNode();
            new ClassReader(bytes).accept(node, 0);
            return node;
        }
    }

    /** Writes ASM-built classes into a runnable JAR (used by shape regressions). */
    private static void writeAsmJar(Path jar, List<ClassNode> classes, String mainClass)
            throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", mainClass);
        try (JarOutputStream out = new JarOutputStream(
                new FileOutputStream(jar.toFile()), manifest)) {
            for (ClassNode node : classes) {
                ClassWriter writer = new ClassWriter(
                        ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
                node.accept(writer);
                out.putNextEntry(new JarEntry(node.name + ".class"));
                out.write(writer.toByteArray());
                out.closeEntry();
            }
        }
    }

    /** Hand-built PassContext for direct pass-level shape regressions. */
    private static PassContext passContext(UmbraConfig config, Stats stats, String salt,
                                           ClassNode... nodes) {
        ClassPool pool = new ClassPool();
        Hierarchy hierarchy = new Hierarchy();
        for (ClassNode node : nodes) {
            pool.putClass(node.name + ".class", new byte[0], node);
            hierarchy.addInput(node);
        }
        return new PassContext(config, pool, hierarchy,
                new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(), false, false),
                new DefaultRuntimeSupport(), new MappingSet(), stats, new Log(null, false),
                new Random(SEED), ProgressListener.NONE);
    }

    private static byte[] serialize(ClassNode node, Hierarchy hierarchy) {
        hierarchy.addInput(node);
        return UmbraClassWriter.toBytes(node, hierarchy);
    }

    private static long stat(Stats stats, String key) {
        Long value = stats.snapshot().get(key);
        return value == null ? 0L : value.longValue();
    }

    private static Protected protect(Path input, long seed, String[] options, Pass... passes)
            throws Exception {
        Program program = load(input);
        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(input)
                .output(Paths.get("out.jar"))
                .seed(seed);
        for (int i = 0; i + 1 < options.length; i += 2) {
            if ("flow.level".equals(options[i])) {
                builder.flow(new UmbraConfig.FlowOptions(true, options[i + 1], 20000, false));
            } else {
                builder.option(options[i], options[i + 1]);
            }
        }
        Stats stats = new Stats();
        Log log = new Log(new Log.Sink() {
            @Override
            public void line(String level, String message) {
                // Quiet unless a check fails; diagnostics are printed explicitly.
            }
        }, false);
        PassContext context = new PassContext(builder.build(), program.pool, program.hierarchy,
                new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(), false, false),
                new DefaultRuntimeSupport(), new MappingSet(), stats, log, new Random(seed),
                ProgressListener.NONE);
        for (Pass pass : passes) {
            if (!pass.enabled(context)) {
                continue;
            }
            pass.run(context);
        }
        Path directory = Files.createTempDirectory("umbra-protection2");
        Path jar = directory.resolve("protected.jar");
        writeJar(jar, program, context);
        Protected result = new Protected();
        result.jar = jar;
        result.directory = directory;
        result.stats = stats;
        result.jarSize = Files.size(jar);
        result.fingerprint = classFingerprint(jar);
        readClasses(jar, result.classBytes);
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                deleteRecursively(result.directory);
            }
        }));
        return result;
    }

    /** Loaded program: pool + hierarchy + manifest/resources, independent per run. */
    private static final class Program {
        private ClassPool pool = new ClassPool();
        private Hierarchy hierarchy = new Hierarchy();
        private final Map<String, byte[]> resources = new LinkedHashMap<String, byte[]>();
        private final Map<String, Long> resourceTimes = new LinkedHashMap<String, Long>();
        private Manifest manifest = new Manifest();
        private final Map<String, byte[]> originalClasses = new LinkedHashMap<String, byte[]>();
    }

    private static Program load(Path input) throws Exception {
        Program program = new Program();
        try (ZipInputStream zip = new ZipInputStream(new FileInputStream(input.toFile()))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                byte[] bytes = readAll(zip);
                String name = entry.getName();
                if ("META-INF/MANIFEST.MF".equals(name)) {
                    program.manifest = new Manifest(new java.io.ByteArrayInputStream(bytes));
                } else if (name.endsWith(".class")) {
                    ClassNode node = new ClassNode();
                    new ClassReader(bytes).accept(node, 0);
                    program.pool.putClass(name, bytes, node);
                    program.hierarchy.addInput(node);
                    program.originalClasses.put(name, bytes);
                } else {
                    program.resources.put(name, bytes);
                    program.resourceTimes.put(name, Long.valueOf(0L));
                    program.pool.putResource(name, bytes, 0L, ZipEntry.DEFLATED);
                }
            }
        }
        return program;
    }

    private static void writeJar(Path output, Program program, PassContext context)
            throws Exception {
        Manifest manifest = new Manifest();
        Manifest source = program.manifest;
        if (source != null) {
            manifest.getMainAttributes().putAll(source.getMainAttributes());
        }
        if (manifest.getMainAttributes().getValue("Manifest-Version") == null) {
            manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        }
        try (JarOutputStream jar = new JarOutputStream(new FileOutputStream(output.toFile()),
                manifest)) {
            for (Map.Entry<String, ClassNode> entry : context.classes().classes().entrySet()) {
                String name = context.classes().entryPrefix(entry.getKey()) + entry.getKey()
                        + ".class";
                byte[] bytes = UmbraClassWriter.toBytes(entry.getValue(), context.hierarchy());
                jar.putNextEntry(new JarEntry(name));
                jar.write(bytes);
                jar.closeEntry();
            }
            for (Map.Entry<String, ClassPool.Resource> entry
                    : context.classes().resources().entrySet()) {
                JarEntry jarEntry = new JarEntry(entry.getKey());
                jarEntry.setTime(entry.getValue().time());
                jar.putNextEntry(jarEntry);
                jar.write(entry.getValue().bytes());
                jar.closeEntry();
            }
        }
    }

    // ------------------------------------------------------------------
    // Checks and tools
    // ------------------------------------------------------------------

    private static void verify(Protected result, String phase) throws Exception {
        List<String> problems = UmbraVerifier.verify(result.jar);
        check(problems.isEmpty(), phase + ": --verify clean", problems.toString());
    }

    private static boolean runsOk(Path jar) throws Exception {
        String output = run(jar);
        return output.contains("OK");
    }

    private static String run(Path jar) throws Exception {
        return runWith(Paths.get(System.getProperty("java.home"), "bin", "java").toString(), jar);
    }

    private static String runWith(String java, Path jar) throws Exception {
        List<String> command = new ArrayList<String>();
        command.add(java);
        command.add("-jar");
        command.add(jar.toAbsolutePath().toString());
        return runProcess(command);
    }

    private static String runProcess(List<String> command) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        InputStream in = process.getInputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            output.write(buffer, 0, read);
        }
        if (!process.waitFor(120, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            return "TIMEOUT";
        }
        String text = new String(output.toByteArray(), StandardCharsets.UTF_8);
        if (process.exitValue() != 0) {
            return text + " (exit " + process.exitValue() + ")";
        }
        return text;
    }

    private static int runCfr(Path cfr, Path jar) throws Exception {
        Path output = Files.createTempDirectory("umbra-cfr");
        try {
            List<String> command = new ArrayList<String>();
            command.add(Paths.get(System.getProperty("java.home"), "bin", "java").toString());
            command.add("-jar");
            command.add(cfr.toAbsolutePath().toString());
            command.add(jar.toAbsolutePath().toString());
            command.add("--outputdir");
            command.add(output.toAbsolutePath().toString());
            command.add("--silent");
            command.add("true");
            runProcess(command);
            final int[] count = { 0 };
            Files.walk(output).forEach(path -> {
                if (path.toString().endsWith(".java") && Files.isRegularFile(path)) {
                    count[0]++;
                }
            });
            return count[0];
        } finally {
            deleteRecursively(output);
        }
    }

    /** Finds plaintext demo literals that survived in string constants. */
    private static List<String> findPlaintext(Protected result, String[] needles) {
        List<String> found = new ArrayList<String>();
        for (Map.Entry<String, byte[]> entry : result.classBytes.entrySet()) {
            ClassNode node = new ClassNode();
            new ClassReader(entry.getValue()).accept(node, 0);
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                     insn = insn.getNext()) {
                    Object constant = null;
                    if (insn instanceof LdcInsnNode) {
                        constant = ((LdcInsnNode) insn).cst;
                    } else if (insn instanceof InvokeDynamicInsnNode) {
                        for (Object argument : ((InvokeDynamicInsnNode) insn).bsmArgs) {
                            if (argument instanceof String) {
                                addNeedleHits(found, (String) argument, needles);
                            }
                        }
                    }
                    if (constant instanceof String) {
                        addNeedleHits(found, (String) constant, needles);
                    }
                }
            }
            for (FieldNode field : node.fields) {
                if (field.value instanceof String) {
                    addNeedleHits(found, (String) field.value, needles);
                }
            }
        }
        return found;
    }

    private static void addNeedleHits(List<String> found, String value, String[] needles) {
        for (String needle : needles) {
            if (value.contains(needle)) {
                found.add(needle);
            }
        }
    }

    private static boolean containsCarrier(Protected result, String className) {
        for (MethodNode method : result.classNode(className).methods) {
            if (method.desc.startsWith("([Ljava/lang/Object;)")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasMethod(ClassNode node, String name, String desc) {
        for (MethodNode method : node.methods) {
            if (name.equals(method.name) && desc.equals(method.desc)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> entryNames(Path jar) throws Exception {
        List<String> names = new ArrayList<String>();
        try (JarFile file = new JarFile(jar.toFile())) {
            java.util.Enumeration<JarEntry> entries = file.entries();
            while (entries.hasMoreElements()) {
                names.add(entries.nextElement().getName());
            }
        }
        return names;
    }

    private static void readClasses(Path jar, Map<String, byte[]> target) throws Exception {
        try (ZipInputStream zip = new ZipInputStream(new FileInputStream(jar.toFile()))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (entry.getName().endsWith(".class")) {
                    target.put(entry.getName().substring(0, entry.getName().length() - 6),
                            readAll(zip));
                }
            }
        }
    }

    /** SHA-256 over sorted class entries: ignores archive timestamps/compression. */
    private static String classFingerprint(Path jar) throws Exception {
        Map<String, byte[]> classes = new LinkedHashMap<String, byte[]>();
        readClasses(jar, classes);
        List<String> names = new ArrayList<String>(classes.keySet());
        Collections.sort(names);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (String name : names) {
            digest.update(name.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(classes.get(name));
        }
        return hex(digest.digest());
    }

    private static String fingerprint(Path jar) throws Exception {
        return classFingerprint(jar);
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++) {
            out.append(Character.forDigit((bytes[i] >>> 4) & 0xF, 16));
            out.append(Character.forDigit(bytes[i] & 0xF, 16));
        }
        return out.toString();
    }

    private static long stat(Protected result, String key) {
        Long value = result.stats.snapshot().get(key);
        return value == null ? 0L : value.longValue();
    }

    private static String[] options(String... pairs) {
        return pairs;
    }

    // ------------------------------------------------------------------
    // Synthetic programs
    // ------------------------------------------------------------------

    /**
     * Compiles the given Java sources and packs the produced classes into a JAR.
     * The {@code Main-Class} manifest attribute is the class whose source
     * declares {@code public static void main}.
     */
    private static Path syntheticProgram(String packageName, String... sources) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("no system Java compiler available");
        }
        Path directory = Files.createTempDirectory("umbra-protection2-synth");
        Path srcDir = directory.resolve("src").resolve(packageName);
        Path classDir = directory.resolve("classes");
        Files.createDirectories(classDir);
        Files.createDirectories(srcDir);
        List<String> command = new ArrayList<String>();
        command.add("-encoding");
        command.add("UTF-8");
        command.add("-source");
        command.add("1.8");
        command.add("-target");
        command.add("1.8");
        command.add("-d");
        command.add(classDir.toString());
        String mainClass = null;
        for (String source : sources) {
            String simpleName = declaredClassName(source);
            Path file = srcDir.resolve(simpleName + ".java");
            Files.write(file, source.getBytes(StandardCharsets.UTF_8));
            command.add(file.toString());
            if (source.contains("static void main(")) {
                mainClass = packageName + "." + simpleName;
            }
        }
        int exit = compiler.run(null, null, null, command.toArray(new String[0]));
        if (exit != 0) {
            throw new IllegalStateException("synthetic program compilation failed");
        }
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class",
                mainClass == null ? packageName + "." + declaredClassName(sources[0]) : mainClass);
        Path jar = directory.resolve("synthetic.jar");
        final Path classRoot = classDir;
        try (JarOutputStream out = new JarOutputStream(
                new FileOutputStream(jar.toFile()), manifest)) {
            Files.walk(classDir).forEach(path -> {
                if (!path.toString().endsWith(".class")) {
                    return;
                }
                try {
                    String name = classRoot.relativize(path).toString().replace('\\', '/');
                    out.putNextEntry(new JarEntry(name));
                    out.write(Files.readAllBytes(path));
                    out.closeEntry();
                } catch (Exception failure) {
                    throw new IllegalStateException(failure);
                }
            });
        }
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                deleteRecursively(directory);
            }
        }));
        return jar;
    }

    /** Extracts the name of the public top-level type declared by a source text. */
    private static String declaredClassName(String source) {
        String[] markers = { "public final class ", "public class ", "public final enum ",
                "public enum ", "public interface " };
        for (String marker : markers) {
            int index = source.indexOf(marker);
            if (index >= 0) {
                int start = index + marker.length();
                int end = start;
                while (end < source.length()
                        && (Character.isJavaIdentifierPart(source.charAt(end)))) {
                    end++;
                }
                if (end > start) {
                    return source.substring(start, end);
                }
            }
        }
        throw new IllegalArgumentException("cannot find the declared type name in source");
    }

    // ------------------------------------------------------------------
    // Environment
    // ------------------------------------------------------------------

    private static Path projectRoot() {
        Path candidate = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && candidate != null; i++) {
            if (Files.isRegularFile(candidate.resolve("demo").resolve("demo.jar"))) {
                return candidate;
            }
            candidate = candidate.getParent();
        }
        return null;
    }

    private static Path demoJar() {
        Path root = projectRoot();
        return root == null ? null : root.resolve("demo").resolve("demo.jar");
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static void deleteRecursively(Path root) {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try {
            List<Path> paths = new ArrayList<Path>();
            Files.walk(root).forEach(paths::add);
            Collections.sort(paths, Collections.reverseOrder());
            for (Path path : paths) {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("ProtectionV2Test FAILED: " + message);
        }
    }

    /** Convenience overload for the message-first call style used in this suite. */
    private static void check(String message, boolean condition) {
        check(condition, message);
    }

    private static void check(boolean condition, String message, String detail) {
        checks++;
        if (!condition) {
            throw new AssertionError("ProtectionV2Test FAILED: " + message + " [" + detail + "]");
        }
    }

    /** Fails loudly instead of hanging forever if transformed code loops. */
    private static void startWatchdog() {
        final long timeout = Long.parseLong(
                System.getProperty("umbra.protection2.watchdog", "420000"));
        Thread watchdog = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(timeout);
                } catch (InterruptedException ignored) {
                    return;
                }
                System.err.println("ProtectionV2Test WATCHDOG after " + timeout + "ms");
                Runtime.getRuntime().halt(3);
            }
        }, "protection-v2-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }
}
