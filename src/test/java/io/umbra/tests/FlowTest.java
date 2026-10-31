package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.ControlFlowFlatteningPass;
import io.umbra.core.pass.impl.ExceptionObfuscationPass;
import io.umbra.core.pass.impl.FlowObfuscationPass;
import io.umbra.core.pass.impl.MbaPass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Flow/MBA control-flow protection tests.
 *
 * <p>Plain-main test harness (no JUnit): the build runs every {@code *Test}
 * class and a non-zero exit fails the build.</p>
 *
 * <p>The class synthesises Java 8 methods with ASM, runs the MBA, flow,
 * flattening and exception passes on them, checks the produced class with
 * {@link CheckClassAdapter} and the real JVM verifier (by defining and
 * invoking it), and compares every result with a plain Java reference
 * implementation. The demo JAR is then obfuscated with the CLI and executed end
 * to end for both {@code normal} and {@code aggressive} flow levels.</p>
 */
public final class FlowTest {

    private static final String TARGET = "test/FlowTarget";
    private static final String TARGET_DOTTED = "test.FlowTarget";

    private static int checks;

    private FlowTest() {
    }

    public static void main(String[] args) throws Exception {
        startWatchdog();
        String only = System.getProperty("umbra.flowtest.only", "");
        boolean all = only.isEmpty();
        if (all || only.contains("identities")) {
            testMbaIdentities();
        }
        if (all || only.contains("mba")) {
            System.out.println("FlowTest: mba pass");
            testMbaPass();
        }
        if (all || only.contains("flow")) {
            System.out.println("FlowTest: flow obfuscation");
            testFlowObfuscation();
            System.out.println("FlowTest: flow reordering");
            testFlowReordering();
        }
        if (all || only.contains("flatten")) {
            System.out.println("FlowTest: flattening");
            testFlattening();
        }
        if (all || only.contains("combined")) {
            System.out.println("FlowTest: combined");
            testEverythingCombined();
        }
        if (all || only.contains("democlasses")) {
            System.out.println("FlowTest: demo classes (flow + flatten only)");
            testDemoClassesSerialize();
        }
        if (all || only.contains("determinism")) {
            System.out.println("FlowTest: determinism");
            testDeterminism();
        }
        if (all || only.equals("demo")) {
            System.out.println("FlowTest: demo jar");
            testDemoJar();
        }
        System.out.println("FlowTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------ identities

    /** Fails loudly instead of hanging forever if transformed code loops. */
    private static void startWatchdog() {
        final long timeout = Long.parseLong(System.getProperty("umbra.flowtest.watchdog", "60000"));
        Thread watchdog = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(timeout);
                } catch (InterruptedException ignored) {
                    return;
                }
                System.err.println("FlowTest WATCHDOG after " + timeout + "ms");
                Map<Thread, StackTraceElement[]> traces = Thread.getAllStackTraces();
                for (Map.Entry<Thread, StackTraceElement[]> entry : traces.entrySet()) {
                    System.err.println("THREAD " + entry.getKey().getName());
                    for (StackTraceElement element : entry.getValue()) {
                        System.err.println("  at " + element);
                    }
                }
                Runtime.getRuntime().halt(3);
            }
        }, "flow-test-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    private static void testMbaIdentities() {
        Random random = new Random(0x5A17L);
        for (int i = 0; i < 20000; i++) {
            int a = random.nextInt();
            int b = random.nextInt();
            check(((a | b) + (a & b)) == a + b, "int add identity");
            check(((a | b) - (a & b)) == (a ^ b), "int xor identity");
            check(((a & ~b) - (~a & b)) == a - b, "int sub identity");
            check(((a | b) - (a ^ b)) == (a & b), "int and identity");
            check(((a & b) + (a ^ b)) == (a | b), "int or identity");
            check((((a * (a + 1)) & 1) == 0), "int parity identity");
            check(((a | 1) != 0), "int or-one identity");
            long x = random.nextLong();
            long y = random.nextLong();
            check(((x | y) + (x & y)) == x + y, "long add identity");
            check(((x | y) - (x & y)) == (x ^ y), "long xor identity");
            check(((x & ~y) - (~x & y)) == x - y, "long sub identity");
            check(((x | y) - (x ^ y)) == (x & y), "long and identity");
            check(((x & y) + (x ^ y)) == (x | y), "long or identity");
            check((((x * (x + 1)) & 1L) == 0L), "long parity identity");
        }
    }

    // ---------------------------------------------------------------- MBA pass

    private static void testMbaPass() throws Exception {
        ClassNode node = target();
        byte[] original = serialize(node);
        if (System.getProperty("umbra.flowtest.dump") != null) {
            Files.write(Paths.get(System.getProperty("umbra.flowtest.dump")), original);
        }
        assertArithmetic(verifyAndLoad(original, "baseline"));
        PassContext context = context(original, node, 101L, false);
        new MbaPass().run(context);
        byte[] transformed = serialize(node, context.hierarchy());
        if (System.getProperty("umbra.flowtest.dump") != null) {
            Files.write(Paths.get(System.getProperty("umbra.flowtest.dump") + ".mba"), transformed);
        }
        Class<?> type = verifyAndLoad(transformed, "mba");
        assertArithmetic(type);
        check(context.stats().snapshot().get("mba.expressions").longValue() > 0, "mba rewrote expressions");
        check(context.stats().snapshot().get("mba.constants").longValue() > 0, "mba rewrote constants");
    }

    // ------------------------------------------------------- flow obfuscation

    private static void testFlowObfuscation() throws Exception {
        ClassNode node = target();
        byte[] original = serialize(node);
        PassContext context = context(original, node, 202L, false);
        new FlowObfuscationPass().run(context);
        Class<?> type = verifyAndLoad(serialize(node, context.hierarchy()), "flow");
        assertAll(type);
        Stats stats = context.stats();
        check(stats.snapshot().get("flow.predicates").longValue() > 0, "flow inserted predicates");
        check(stats.snapshot().get("flow.branches.inverted").longValue() > 0, "flow inverted branches");
        check(stats.snapshot().get("flow.junkBlocks").longValue() > 0, "flow inserted junk");
    }

    private static void testFlowReordering() throws Exception {
        ClassNode node = target();
        byte[] original = serialize(node);
        PassContext context = context(original, node, 505L, false, true);
        new FlowObfuscationPass().run(context);
        Class<?> type = verifyAndLoad(serialize(node, context.hierarchy()), "reorder");
        // The full behavioural matrix runs against the rescheduled bytecode: block
        // scheduling must not change a single result.
        assertAll(type);
        Long moved = context.stats().snapshot().get("flow.reordered.blocks");
        check(moved != null && moved.longValue() > 0, "flow rescheduled basic blocks");
        check(context.stats().snapshot().get("flow.skipped").longValue() == 0,
                "every rescheduled method still verified");
    }

    // ------------------------------------------------------------ flattening

    private static void testFlattening() throws Exception {
        ClassNode node = target();
        byte[] original = serialize(node);
        PassContext context = context(original, node, 303L, true);
        new ControlFlowFlatteningPass().run(context);
        byte[] transformed = serialize(node, context.hierarchy());
        Class<?> type = verifyAndLoad(transformed, "flatten");
        assertAll(type);
        Stats stats = context.stats();
        check(stats.snapshot().get("flow.flattened.methods").longValue() > 0, "flattened at least one method");
        check(stats.snapshot().get("flow.flattened.tryCatch").longValue() > 0, "flattened a try/catch method");
        check(stats.snapshot().get("flow.flattened.blocks").longValue() > 10, "flattened many blocks");
        Long stackSkips = stats.snapshot().get("flow.flattened.skipped.stack");
        check(stackSkips != null && stackSkips.longValue() > 0,
                "skipped method with non-empty stack at a jump target");
        Long blockSkips = stats.snapshot().get("flow.flattened.skipped.blocks");
        check(blockSkips != null && blockSkips.longValue() > 0, "skipped trivial try/catch method");
        // The flattening must actually make the dispatcher visible: at least one
        // class must contain a tableswitch over the state variable.
        check(countSwitches(transformed) > 1, "flattened code contains dispatcher switches");
    }

    private static void testEverythingCombined() throws Exception {
        ClassNode node = target();
        byte[] original = serialize(node);
        PassContext context = context(original, node, 404L, true);
        new MbaPass().run(context);
        new FlowObfuscationPass().run(context);
        new ControlFlowFlatteningPass().run(context);
        new ExceptionObfuscationPass().run(context);
        byte[] combinedBytes = serialize(node, context.hierarchy());
        if (System.getProperty("umbra.flowtest.dump") != null) {
            Files.write(Paths.get(System.getProperty("umbra.flowtest.dump") + ".combined"), combinedBytes);
        }
        Class<?> type = verifyAndLoad(combinedBytes, "combined");
        assertAll(type);
        Stats stats = context.stats();
        check(stats.snapshot().get("exceptions.wrapped").longValue() > 0, "exception pass wrapped methods");
        check(stats.snapshot().get("exceptions.fakeThrows").longValue() > 0, "exception pass added fake throws");
    }

    /**
     * Runs flow + flattening over every class of the real demo JAR and forces
     * {@code COMPUTE_FRAMES} serialization. This surfaces ASM frame-computation
     * crashes (including internal NPEs) in the test rather than in a full run.
     */
    private static void testDemoClassesSerialize() throws Exception {
        Path root = findProjectRoot();
        if (root == null) {
            System.out.println("FlowTest: demo/demo.jar not found, skipping demo-class serialization check");
            return;
        }
        Path jar = root.resolve("demo").resolve("demo.jar");
        ClassPool pool = new ClassPool();
        Hierarchy hierarchy = new Hierarchy();
        List<ClassNode> classes = new ArrayList<ClassNode>();
        java.util.zip.ZipFile zip = new java.util.zip.ZipFile(jar.toFile());
        try {
            java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                java.util.zip.ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }
                byte[] bytes = readBytes(zip.getInputStream(entry));
                ClassNode node = read(bytes);
                pool.putClass(entry.getName(), bytes, node);
                hierarchy.addInput(node);
                classes.add(node);
            }
        } finally {
            zip.close();
        }
        check(!classes.isEmpty(), "demo jar contains classes");
        {
            UmbraConfig config = new UmbraConfig.Builder()
                    .input(jar)
                    .output(Paths.get("out.jar"))
                    .seed(333L)
                    .flow(new UmbraConfig.FlowOptions(true, "light", 8000, true))
                    .build();
            PassContext context = new PassContext(config, pool, hierarchy,
                    new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(), false, false),
                    new DefaultRuntimeSupport(), new MappingSet(), new Stats(),
                    new Log(null, false), new Random(333L), ProgressListener.NONE);
            new FlowObfuscationPass().run(context);
            new ControlFlowFlatteningPass().run(context);
            int serialized = 0;
            for (ClassNode node : classes) {
                try {
                    UmbraClassWriter.toBytes(node, hierarchy);
                    serialized++;
                } catch (Throwable failure) {
                    diagnoseFailingMethod(node, hierarchy, failure);
                    check(false, "demo class " + node.name + " does not serialize after flow+flatten: "
                            + failure);
                }
            }
            check(serialized == classes.size(), "all demo classes serialize");
            check(context.stats().snapshot().get("flow.flattened.methods").longValue() > 0,
                    "demo classes were flattened");
        }
    }

    private static void diagnoseFailingMethod(ClassNode node, final Hierarchy hierarchy,
                                              Throwable failure) {
        System.out.println("FlowTest: serialization failure in " + node.name + ": " + failure);
        for (final MethodNode method : node.methods) {
            ClassNode mini = new ClassNode();
            mini.version = node.version;
            mini.access = node.access;
            mini.name = node.name;
            mini.superName = node.superName;
            mini.interfaces = node.interfaces;
            mini.methods.add(method);
            try {
                ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
                    @Override
                    protected String getCommonSuperClass(String a, String b) {
                        return hierarchy.getCommonSuperClass(a, b);
                    }
                };
                mini.accept(writer);
            } catch (Throwable methodFailure) {
                System.out.println("FlowTest:   method " + method.name + method.desc
                        + " insns=" + method.instructions.size() + " -> " + methodFailure);
            }
        }
    }

    private static void testDeterminism() throws Exception {
        byte[] original = serialize(target());
        ClassNode first = read(original);
        ClassNode second = read(original);
        PassContext a = context(original, first, 505L, true);
        PassContext b = context(original, second, 505L, true);
        runPipeline(a);
        runPipeline(b);
        diagnoseFrames(first);
        byte[] firstBytes = serialize(first, a.hierarchy());
        byte[] secondBytes = serialize(second, b.hierarchy());
        check(java.util.Arrays.equals(firstBytes, secondBytes),
                "the same seed produces byte-identical output");
        verifyAndLoad(firstBytes, "determinism");
    }

    private static void runPipeline(PassContext context) {
        new MbaPass().run(context);
        new FlowObfuscationPass().run(context);
        new ControlFlowFlatteningPass().run(context);
        new ExceptionObfuscationPass().run(context);
    }

    private static boolean hasStateDispatcher(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LdcInsnNode && "state".equals(((LdcInsnNode) insn).cst)) {
                AbstractInsnNode cursor = insn.getNext();
                for (int i = 0; i < 8 && cursor != null; i++, cursor = cursor.getNext()) {
                    if (cursor instanceof TypeInsnNode
                            && "java/lang/IllegalStateException".equals(((TypeInsnNode) cursor).desc)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** Prints the method whose frames cannot be computed (diagnostic only). */
    private static void diagnoseFrames(ClassNode node) {
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        for (final MethodNode method : node.methods) {
            ClassNode mini = new ClassNode();
            mini.version = node.version;
            mini.access = node.access;
            mini.name = node.name;
            mini.superName = node.superName;
            mini.interfaces = node.interfaces;
            mini.methods.add(method);
            try {
                ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
                    @Override
                    protected String getCommonSuperClass(String a, String b) {
                        return hierarchy.getCommonSuperClass(a, b);
                    }
                };
                mini.accept(writer);
            } catch (Throwable failure) {
                System.out.println("FlowTest: frame computation failed for " + method.name + method.desc
                        + " insns=" + method.instructions.size() + " maxLocals=" + method.maxLocals
                        + " tryBlocks=" + (method.tryCatchBlocks == null ? 0 : method.tryCatchBlocks.size())
                        + " dispatcher=" + hasStateDispatcher(method)
                        + " -> " + failure);
            }
        }
    }

    // -------------------------------------------------------- expected values

    private static void assertArithmetic(Class<?> type) throws Exception {
        int[][] pairs = {
                { 0, 0 }, { 1, -1 }, { Integer.MIN_VALUE, Integer.MAX_VALUE },
                { 123456789, -987654321 }, { -5, 7 }, { 0x7FFFFFFF, 1 }
        };
        for (int[] pair : pairs) {
            check(((Integer) call(type, "add", new Class<?>[] { int.class, int.class }, pair[0], pair[1]))
                    .intValue() == pair[0] + pair[1], "add(" + pair[0] + "," + pair[1] + ")");
            check(((Integer) call(type, "sub", new Class<?>[] { int.class, int.class }, pair[0], pair[1]))
                    .intValue() == pair[0] - pair[1], "sub(" + pair[0] + "," + pair[1] + ")");
            check(((Integer) call(type, "xor", new Class<?>[] { int.class, int.class }, pair[0], pair[1]))
                    .intValue() == (pair[0] ^ pair[1]), "xor(" + pair[0] + "," + pair[1] + ")");
            check(((Integer) call(type, "and", new Class<?>[] { int.class, int.class }, pair[0], pair[1]))
                    .intValue() == (pair[0] & pair[1]), "and(" + pair[0] + "," + pair[1] + ")");
            check(((Integer) call(type, "or", new Class<?>[] { int.class, int.class }, pair[0], pair[1]))
                    .intValue() == (pair[0] | pair[1]), "or(" + pair[0] + "," + pair[1] + ")");
        }
        long[][] longs = {
                { 0L, 0L }, { 1L, -1L }, { Long.MIN_VALUE, Long.MAX_VALUE },
                { 1234567890123L, -99L }
        };
        for (long[] pair : longs) {
            long actual = ((Long) call(type, "longMix", new Class<?>[] { long.class, long.class },
                    pair[0], pair[1])).longValue();
            long expected = refLongMixLong(pair[0], pair[1]);
            check(actual == expected, "longMix(" + pair[0] + "," + pair[1] + ") got " + actual
                    + " expected " + expected);
        }
        check(((Integer) call(type, "constants", new Class<?>[0])).intValue() == refConstants(),
                "constant materialisation");
        check(((Long) call(type, "longConstants", new Class<?>[0])).longValue() == refLongConstants(),
                "long constant materialisation");
    }

    private static void assertAll(Class<?> type) throws Exception {
        assertArithmetic(type);
        for (int n : new int[] { 1, 2, 3, 7, 27 }) {
            check(((Integer) call(type, "collatz", new Class<?>[] { int.class }, n)).intValue() == refCollatz(n),
                    "collatz(" + n + ")");
        }
        for (int v : new int[] { 0, 1, 2, 3, 4, -1, 100 }) {
            check(((Integer) call(type, "switchy", new Class<?>[] { int.class }, v)).intValue() == refSwitchy(v),
                    "switchy(" + v + ")");
        }
        for (int v : new int[] { 0, 1, 5, 100 }) {
            check(((Integer) call(type, "sumLoop", new Class<?>[] { int.class }, v)).intValue() == v * (v + 1) / 2,
                    "sumLoop(" + v + ")");
        }
        for (int v : new int[] { 1, 2, 0, 5, -3 }) {
            check(refTryCatch(v).equals(call(type, "tryCatchString", new Class<?>[] { int.class }, v)),
                    "tryCatchString(" + v + ")");
        }
        for (int v : new int[] { 1, 0, 5, -1 }) {
            check(((Integer) call(type, "tryFinally", new Class<?>[] { int.class }, v)).intValue() == refTryFinally(v),
                    "tryFinally(" + v + ")");
        }
        for (int v : new int[] { 1, -1, 0 }) {
            check(((Integer) call(type, "stackAtMerge", new Class<?>[] { int.class }, v)).intValue()
                    == (v > 0 ? 100 : 200), "stackAtMerge(" + v + ")");
        }
        for (int v : new int[] { 5, 0 }) {
            check(((Integer) call(type, "throwing", new Class<?>[] { int.class }, v)).intValue() == v * 2,
                    "throwing(" + v + ")");
        }
        for (int v : new int[] { 0, 1, 7, 49, 50, -3 }) {
            check(((Integer) call(type, "bigSwitch", new Class<?>[] { int.class }, v)).intValue() == refBigSwitch(v),
                    "bigSwitch(" + v + ")");
        }
        try {
            call(type, "throwing", new Class<?>[] { int.class }, -1);
            check(false, "throwing(-1) must throw");
        } catch (InvocationTargetException e) {
            check(e.getCause() instanceof IllegalArgumentException, "original exception type preserved");
            check("neg".equals(e.getCause().getMessage()), "original exception message preserved");
        }
    }

    /** Method returns {@code long}; reference implementation. */
    private static long refLongMixLong(long a, long b) {
        long s = a + b;
        long d = a - b;
        long x = s ^ d;
        x &= (a | b);
        x += (a ^ b);
        return x;
    }

    private static int refConstants() {
        int value = 0;
        value += Integer.MIN_VALUE;
        value += -1;
        value += 127;
        value += 128;
        value += -129;
        value += 32767;
        value += 40000;
        value += -70000;
        value += 123456789;
        value += 0x7FFFFFFF;
        return value;
    }

    private static long refLongConstants() {
        long value = 0L;
        value += Long.MIN_VALUE;
        value += 1234567890123L;
        value += -42L;
        value += 0x7FFFFFFFFFFFL;
        return value;
    }

    private static int refCollatz(int n) {
        int steps = 0;
        while (n != 1) {
            if ((n & 1) == 0) {
                n = n / 2;
            } else {
                n = n * 3 + 1;
            }
            steps++;
            if (steps > 100000) {
                throw new IllegalStateException();
            }
        }
        return steps;
    }

    private static int refSwitchy(int a) {
        switch (a) {
            case 0: return 10;
            case 1: return 11;
            case 2: return 15;
            case 3: return a * 7;
            default: return -1;
        }
    }

    private static int refBigSwitch(int a) {
        if (a < 0 || a >= 50) {
            return -1;
        }
        return a * 3 + 1;
    }

    private static String refTryCatch(int x) {
        try {
            return Integer.toString(100 / x);
        } catch (ArithmeticException e) {
            return "div0";
        }
    }

    private static int refTryFinally(int a) {
        int value;
        try {
            value = 100 / a;
        } catch (ArithmeticException e) {
            value = -1;
        }
        value += 1000;
        return value;
    }

    // ------------------------------------------------------------- demo jar

    private static void testDemoJar() throws Exception {
        Path root = findProjectRoot();
        if (root == null) {
            System.out.println("FlowTest: demo/demo.jar not found, skipping end-to-end demo check");
            return;
        }
        Path outputDir = Files.createTempDirectory("umbra-flow-test");
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        String classpath = absoluteClasspath();
        Path normalJar = outputDir.resolve("demo-flow-normal.jar");
        String cliOut = runIn(outputDir, java, "-cp", classpath, "io.umbra.cli.Main",
                "-i", root.resolve("demo/demo.jar").toString(),
                "-o", normalJar.toString(),
                "--flatten",
                "--set", "mba.enabled=true",
                "--set", "mba.depth=3",
                "--set", "flowObfuscation.level=normal",
                "--set", "exceptionObfuscation.enabled=true",
                "--verify",
                "--seed", "777");
        check(Files.exists(normalJar), "demo obfuscation produced an output jar: " + tail(cliOut));
        String runOut = runIn(outputDir, java, "-jar", normalJar.toString());
        check(runOut.contains("OK"), "demo (normal flow) prints OK: " + tail(runOut));

        Path aggressiveJar = outputDir.resolve("demo-flow-aggressive.jar");
        runIn(outputDir, java, "-cp", classpath, "io.umbra.cli.Main",
                "-i", root.resolve("demo/demo.jar").toString(),
                "-o", aggressiveJar.toString(),
                "--flatten",
                "--set", "mba.enabled=true",
                "--set", "mba.depth=4",
                "--set", "flowObfuscation.level=aggressive",
                "--set", "exceptionObfuscation.enabled=true",
                "--set", "exception.level=3",
                "--verify",
                "--seed", "778");
        String aggressiveOut = runIn(outputDir, java, "-jar", aggressiveJar.toString());
        check(aggressiveOut.contains("OK"), "demo (aggressive flow) prints OK: " + tail(aggressiveOut));
    }

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

    // ------------------------------------------------------- class synthesis

    private static ClassNode target() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = TARGET;
        node.superName = "java/lang/Object";
        node.methods.add(binary("add", Opcodes.IADD));
        node.methods.add(binary("sub", Opcodes.ISUB));
        node.methods.add(binary("xor", Opcodes.IXOR));
        node.methods.add(binary("and", Opcodes.IAND));
        node.methods.add(binary("or", Opcodes.IOR));
        node.methods.add(longMix());
        node.methods.add(constants());
        node.methods.add(longConstants());
        node.methods.add(collatz());
        node.methods.add(switchy());
        node.methods.add(sumLoop());
        node.methods.add(tryCatchString());
        node.methods.add(tryFinally());
        node.methods.add(stackAtMerge());
        node.methods.add(throwing());
        node.methods.add(bigSwitch());
        return node;
    }

    private static MethodNode method(String name, String desc) {
        return new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, desc, null, null);
    }

    private static MethodNode binary(String name, int opcode) {
        MethodNode method = method(name, "(II)I");
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new InsnNode(opcode));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 2;
        return method;
    }

    private static MethodNode longMix() {
        MethodNode method = method("longMix", "(JJ)J");
        InsnList insns = method.instructions;
        insns.add(new VarInsnNode(Opcodes.LLOAD, 0));
        insns.add(new VarInsnNode(Opcodes.LLOAD, 2));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new VarInsnNode(Opcodes.LLOAD, 0));
        insns.add(new VarInsnNode(Opcodes.LLOAD, 2));
        insns.add(new InsnNode(Opcodes.LSUB));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, 0));
        insns.add(new VarInsnNode(Opcodes.LLOAD, 2));
        insns.add(new InsnNode(Opcodes.LOR));
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new VarInsnNode(Opcodes.LLOAD, 0));
        insns.add(new VarInsnNode(Opcodes.LLOAD, 2));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new InsnNode(Opcodes.LRETURN));
        return method;
    }

    private static MethodNode constants() {
        MethodNode method = method("constants", "()I");
        InsnList insns = method.instructions;
        insns.add(new LdcInsnNode(Integer.valueOf(Integer.MIN_VALUE)));
        int[] values = { -1, 127, 128, -129, 32767, 40000, -70000, 123456789, 0x7FFFFFFF };
        for (int value : values) {
            AsmUtil.pushInt(insns, value);
            insns.add(new InsnNode(Opcodes.IADD));
        }
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode longConstants() {
        MethodNode method = method("longConstants", "()J");
        InsnList insns = method.instructions;
        insns.add(new LdcInsnNode(Long.valueOf(Long.MIN_VALUE)));
        long[] values = { 1234567890123L, -42L, 0x7FFFFFFFFFFFL };
        for (long value : values) {
            insns.add(new LdcInsnNode(Long.valueOf(value)));
            insns.add(new InsnNode(Opcodes.LADD));
        }
        insns.add(new InsnNode(Opcodes.LRETURN));
        return method;
    }

    private static MethodNode collatz() {
        MethodNode method = method("collatz", "(I)I");
        InsnList insns = method.instructions;
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode odd = new LabelNode();
        LabelNode increment = new LabelNode();
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 1));
        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, end));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new JumpInsnNode(Opcodes.IFNE, odd));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.ICONST_2));
        insns.add(new InsnNode(Opcodes.IDIV));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 0));
        insns.add(new JumpInsnNode(Opcodes.GOTO, increment));
        insns.add(odd);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.ICONST_3));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 0));
        insns.add(increment);
        insns.add(new IincInsnNode(1, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));
        insns.add(end);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode switchy() {
        MethodNode method = method("switchy", "(I)I");
        InsnList insns = method.instructions;
        LabelNode defaultLabel = new LabelNode();
        LabelNode case0 = new LabelNode();
        LabelNode case1 = new LabelNode();
        LabelNode case2 = new LabelNode();
        LabelNode case3 = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new TableSwitchInsnNode(0, 3, defaultLabel, case0, case1, case2, case3));
        insns.add(case0);
        insns.add(new LdcInsnNode(Integer.valueOf(10)));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(case1);
        insns.add(new LdcInsnNode(Integer.valueOf(11)));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(case2);
        insns.add(new LdcInsnNode(Integer.valueOf(15)));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(case3);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new LdcInsnNode(Integer.valueOf(7)));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(defaultLabel);
        insns.add(new InsnNode(Opcodes.ICONST_M1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode sumLoop() {
        MethodNode method = method("sumLoop", "(I)I");
        InsnList insns = method.instructions;
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 1));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 2));
        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 2));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGT, end));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 2));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 1));
        insns.add(new IincInsnNode(2, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));
        insns.add(end);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode tryCatchString() {
        MethodNode method = method("tryCatchString", "(I)Ljava/lang/String;");
        InsnList insns = method.instructions;
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        insns.add(start);
        insns.add(new LdcInsnNode(Integer.valueOf(100)));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.IDIV));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                "toString", "(I)Ljava/lang/String;", false));
        insns.add(new InsnNode(Opcodes.ARETURN));
        insns.add(end);
        insns.add(handler);
        insns.add(new VarInsnNode(Opcodes.ASTORE, 1));
        insns.add(new LdcInsnNode("div0"));
        insns.add(new InsnNode(Opcodes.ARETURN));
        method.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
        method.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, "java/lang/ArithmeticException"));
        method.maxLocals = 2;
        return method;
    }

    private static MethodNode tryFinally() {
        MethodNode method = method("tryFinally", "(I)I");
        InsnList insns = method.instructions;
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        LabelNode normal = new LabelNode();
        insns.add(start);
        insns.add(new LdcInsnNode(Integer.valueOf(100)));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.IDIV));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 1));
        insns.add(end);
        insns.add(new JumpInsnNode(Opcodes.GOTO, normal));
        insns.add(handler);
        insns.add(new VarInsnNode(Opcodes.ASTORE, 2));
        insns.add(new InsnNode(Opcodes.ICONST_M1));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 1));
        insns.add(normal);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new LdcInsnNode(Integer.valueOf(1000)));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 1));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        method.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
        method.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, "java/lang/ArithmeticException"));
        method.maxLocals = 3;
        return method;
    }

    private static MethodNode stackAtMerge() {
        MethodNode method = method("stackAtMerge", "(I)I");
        InsnList insns = method.instructions;
        LabelNode elseLabel = new LabelNode();
        LabelNode end = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new JumpInsnNode(Opcodes.IFLE, elseLabel));
        insns.add(new LdcInsnNode(Integer.valueOf(100)));
        insns.add(new JumpInsnNode(Opcodes.GOTO, end));
        insns.add(elseLabel);
        insns.add(new LdcInsnNode(Integer.valueOf(200)));
        insns.add(end);
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode throwing() {
        MethodNode method = method("throwing", "(I)I");
        InsnList insns = method.instructions;
        LabelNode negative = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new JumpInsnNode(Opcodes.IFLT, negative));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.ICONST_2));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(negative);
        insns.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalArgumentException"));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new LdcInsnNode("neg"));
        insns.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/IllegalArgumentException",
                "<init>", "(Ljava/lang/String;)V", false));
        insns.add(new InsnNode(Opcodes.ATHROW));
        return method;
    }

    private static MethodNode bigSwitch() {
        MethodNode method = method("bigSwitch", "(I)I");
        InsnList insns = method.instructions;
        LabelNode defaultLabel = new LabelNode();
        LabelNode[] cases = new LabelNode[50];
        for (int i = 0; i < cases.length; i++) {
            cases[i] = new LabelNode();
        }
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new TableSwitchInsnNode(0, cases.length - 1, defaultLabel, cases));
        for (int i = 0; i < cases.length; i++) {
            insns.add(cases[i]);
            insns.add(new LdcInsnNode(Integer.valueOf(i * 3 + 1)));
            insns.add(new InsnNode(Opcodes.IRETURN));
        }
        insns.add(defaultLabel);
        insns.add(new InsnNode(Opcodes.ICONST_M1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    // ------------------------------------------------------------ infrastructure

    private static PassContext context(byte[] originalBytes, ClassNode node, long seed, boolean flattening) {
        return context(originalBytes, node, seed, flattening, false);
    }

    private static PassContext context(byte[] originalBytes, ClassNode node, long seed,
                                       boolean flattening, boolean reorder) {
        try {
            UmbraConfig config = new UmbraConfig.Builder()
                    .input(Paths.get("in.jar"))
                    .output(Paths.get("out.jar"))
                    .seed(seed)
                    .flow(new UmbraConfig.FlowOptions(true, "aggressive", 20000, flattening))
                    .exceptionObfuscation(new UmbraConfig.ExceptionOptions(true))
                    .option("mba.enabled", "true")
                    .option("mba.depth", System.getProperty("umbra.flowtest.depth", "3"))
                    .option("mba.maxPerMethod", "400")
                    .option("exception.level", "3")
                    .option("flow.maxBlocks", "512")
                    .option("flow.reorder", String.valueOf(reorder))
                    .build();
            ClassPool pool = new ClassPool();
            pool.putClass(node.name + ".class", originalBytes, node);
            Hierarchy hierarchy = new Hierarchy();
            hierarchy.addInput(node);
            DefaultRuleSet rules = new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(),
                    false, false);
            return new PassContext(config, pool, hierarchy, rules, new DefaultRuntimeSupport(),
                    new MappingSet(), new Stats(), new Log(null, false), new Random(seed),
                    ProgressListener.NONE);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static byte[] serialize(ClassNode node) {
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        return UmbraClassWriter.toBytes(node, hierarchy);
    }

    private static byte[] serialize(ClassNode node, Hierarchy hierarchy) {
        hierarchy.addInput(node);
        return UmbraClassWriter.toBytes(node, hierarchy);
    }

    private static Class<?> verifyAndLoad(byte[] bytes, String phase) {
        StringWriter writer = new StringWriter();
        CheckClassAdapter.verify(new ClassReader(bytes), false, new PrintWriter(writer));
        String errors = writer.toString();
        check(errors.isEmpty(), "CheckClassAdapter (" + phase + "): " + errors);
        final Map<String, byte[]> classes = new HashMap<String, byte[]>();
        classes.put(TARGET_DOTTED, bytes);
        ClassLoader loader = new ClassLoader(FlowTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] data = classes.get(name);
                if (data != null) {
                    return defineClass(name, data, 0, data.length);
                }
                return super.findClass(name);
            }
        };
        try {
            Class<?> type = Class.forName(TARGET_DOTTED, true, loader);
            type.getDeclaredMethods();
            return type;
        } catch (ClassNotFoundException e) {
            throw new AssertionError("Cannot load transformed class", e);
        }
    }

    private static int countSwitches(byte[] bytes) {
        ClassNode node = read(bytes);
        int count = 0;
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof TableSwitchInsnNode || insn instanceof LookupSwitchInsnNode) {
                    count++;
                }
            }
        }
        return count;
    }

    private static Object call(Class<?> type, String name, Class<?>[] signature, Object... args)
            throws Exception {
        Method method = type.getDeclaredMethod(name, signature);
        method.setAccessible(true);
        return method.invoke(null, args);
    }

    private static String readAll(InputStream in) throws java.io.IOException {
        return new String(readBytes(in), StandardCharsets.UTF_8);
    }

    private static byte[] readBytes(InputStream in) throws java.io.IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
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
