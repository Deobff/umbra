package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.ClassInitOrderPass;
import io.umbra.core.pass.impl.FlowIntsPass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.util.CheckClassAdapter;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.FileObject;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileManager;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

/**
 * Self-test for the flow-ints and class-init-order ports.
 *
 * <p>Fixtures are compiled with the platform javac into memory, so the bytecode
 * under test is real javac output (dense switches, loop headers, duplicated
 * finally blocks, exception ranges) instead of hand-written instruction lists
 * that accidentally avoid every hard shape. Every transformed class is checked
 * with {@link CheckClassAdapter}, defined in a throw-away class loader and
 * compared method by method against the untransformed baseline, including the
 * exception each call throws.</p>
 *
 * <p>Covered: state chaining across if/else, loops, both switch kinds, early
 * returns, nested try/catch/finally, long constants (including the split-mask
 * shape), array lengths and {@code new} dimensions (which must NOT be rewritten),
 * the runtime-table path, the decoy-switch advance, the two-phase "no orphan
 * field" rule, determinism for a fixed seed, and the whole class-init-order
 * surface: dependency edges, cycle reporting, topological order, conservative
 * {@code reorderClinit} and {@code ConstantValue} hoisting.</p>
 */
public final class FlowIntsClassInitTest {

    private static int checks;

    private static final String TARGET = "test.FlowIntsTarget";

    private static final String TARGET_SOURCE =
            "package test;\n"
            + "public class FlowIntsTarget {\n"
            + "  public static int arith(int a, int b) {\n"
            + "    int r;\n"
            + "    if (a > b) { r = a * 3 + 7; } else { r = b * 5 - 11; }\n"
            + "    if (r % 2 == 0) { r += 1000003; }\n"
            + "    return r;\n"
            + "  }\n"
            + "  public static int loopy(int n) {\n"
            + "    int sum = 0;\n"
            + "    for (int i = 0; i < n; i++) {\n"
            + "      if (i % 3 == 0) { sum += i * 13; } else { sum -= i * 7; }\n"
            + "    }\n"
            + "    while (sum > 1000000) { sum /= 3; }\n"
            + "    return sum;\n"
            + "  }\n"
            + "  public static int switcher(int v) {\n"
            + "    switch (v) {\n"
            + "      case 0: return 1000003;\n"
            + "      case 1: return 1000033;\n"
            + "      case 2: return 1000037;\n"
            + "      case 3: return 1000039;\n"
            + "      default: break;\n"
            + "    }\n"
            + "    switch (v) {\n"
            + "      case 100000: return 7;\n"
            + "      case 200000: return 11;\n"
            + "      case 300000: return 13;\n"
            + "      default: return -1000003;\n"
            + "    }\n"
            + "  }\n"
            + "  public static int early(int v) {\n"
            + "    if (v < 0) { return -1000003; }\n"
            + "    if (v == 0) { return 1000033; }\n"
            + "    int acc = v;\n"
            + "    while (acc > 100) { acc -= 37; if (acc == 101) { return 1000037; } }\n"
            + "    return acc * 1000003;\n"
            + "  }\n"
            + "  public static String tryNest(int v) {\n"
            + "    try {\n"
            + "      try { return Integer.toString(1000003 / v); }\n"
            + "      finally { if (v == 2) { throw new IllegalStateException(\"two\"); } }\n"
            + "    } catch (ArithmeticException e) { return \"div0-\" + 1000033; }\n"
            + "    catch (IllegalStateException e) { return \"state-\" + 1000037; }\n"
            + "  }\n"
            + "  public static int bigConstants() {\n"
            + "    int v = 0;\n"
            + "    v += 123456789; v += 2147483647; v += -559038737; v += 305419896;\n"
            + "    v += 2000000000; v += -2000000000; v += 1073741824; v += 999999999;\n"
            + "    return v;\n"
            + "  }\n"
            + "  public static long longish(long v) {\n"
            + "    long a = 1234567890123L;\n"
            + "    long b = -998877665544L;\n"
            + "    if (v > 0) { return a ^ v; }\n"
            + "    return b + v;\n"
            + "  }\n"
            + "  public static int arrayLoop() {\n"
            + "    int[] slots = new int[14];\n"
            + "    for (int i = 0; i < 14; i++) {\n"
            + "      slots[i] = i * 7 + 3;\n"
            + "    }\n"
            + "    int sum = 0;\n"
            + "    for (int i = 0; i < slots.length; i++) {\n"
            + "      sum += slots[i] + (i % 3);\n"
            + "    }\n"
            + "    return sum;\n"
            + "  }\n"
            + "  public static int arrayish(int n) {\n"
            + "    int[] a = new int[n];\n"
            + "    int[][] b = new int[2][3];\n"
            + "    a[0] = 1000003;\n"
            + "    return a.length + b.length + b[1].length + 1000033;\n"
            + "  }\n"
            + "  public static int mixed(int v) {\n"
            + "    int t;\n"
            + "    switch (v & 7) {\n"
            + "      case 0: t = 11; break;\n"
            + "      case 1: t = 22; break;\n"
            + "      default: t = 33; break;\n"
            + "    }\n"
            + "    try { t += 1000003 / (v - 3); } catch (ArithmeticException e) { t = -1000033; }\n"
            + "    return t + 1000037;\n"
            + "  }\n"
            + "}\n";

    private FlowIntsClassInitTest() {
    }

    public static void main(String[] args) throws Exception {
        startWatchdog();
        System.out.println("FlowIntsClassInitTest: flow ints");
        testFlowInts();
        System.out.println("FlowIntsClassInitTest: flow ints (adjacent labels / empty block)");
        testFlowIntsAdjacentLabels();
        System.out.println("FlowIntsClassInitTest: flow ints (decoy switch)");
        testFlowIntsConfused();
        System.out.println("FlowIntsClassInitTest: flow ints (rollback / two phase)");
        testFlowIntsTwoPhase();
        System.out.println("FlowIntsClassInitTest: flow ints (determinism)");
        testFlowIntsDeterminism();
        System.out.println("FlowIntsClassInitTest: class init order (report)");
        testClassInitReport();
        System.out.println("FlowIntsClassInitTest: class init order (reorderClinit)");
        testClassInitReorder();
        System.out.println("FlowIntsClassInitTest: class init order (hoist)");
        testClassInitHoist();
        System.out.println("FlowIntsClassInitTest: " + checks + " checks passed");
    }

    private static void startWatchdog() {
        final long timeout = Long.parseLong(System.getProperty("umbra.flowints.watchdog", "180000"));
        Thread watchdog = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(timeout);
                } catch (InterruptedException ignored) {
                    return;
                }
                System.err.println("FlowIntsClassInitTest WATCHDOG after " + timeout + "ms");
                Runtime.getRuntime().halt(3);
            }
        }, "flowints-test-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    // ---------------------------------------------------------------- fixtures

    private static Map<String, byte[]> compileFlowTarget() throws Exception {
        Map<String, String> sources = new LinkedHashMap<String, String>();
        sources.put(TARGET, TARGET_SOURCE);
        return compile(sources);
    }

    private static Map<String, byte[]> compileOrderFixtures() throws Exception {
        Map<String, String> sources = new LinkedHashMap<String, String>();
        sources.put("test.cioa.C",
                "package test.cioa;\n"
                + "public class C {\n"
                + "  public static int cz = 11;\n"
                + "  public static int cdoubled = cz + 3;\n"
                + "}\n");
        sources.put("test.cioa.B",
                "package test.cioa;\n"
                + "public class B {\n"
                + "  public static int by = 7;\n"
                + "  public static int bcopy = C.cz + 1;\n"
                + "}\n");
        sources.put("test.cioa.A",
                "package test.cioa;\n"
                + "public class A {\n"
                + "  public static int ax = 5;\n"
                + "  public static int aderived = B.by + 1;\n"
                + "  public static Object tag = String.valueOf(123);\n"
                + "}\n");
        sources.put("test.cioa.P",
                "package test.cioa;\n"
                + "public class P {\n"
                + "  public static int pv = 1;\n"
                + "  public static int pfrom = Q.qv + 1;\n"
                + "}\n");
        sources.put("test.cioa.Q",
                "package test.cioa;\n"
                + "public class Q {\n"
                + "  public static int qv = 2;\n"
                + "  public static int qfrom = P.pv + 1;\n"
                + "}\n");
        sources.put("test.ciod.H",
                "package test.ciod;\n"
                + "public class H {\n"
                + "  public static int hi = 42;\n"
                + "  public static String hs = \"hey\";\n"
                + "  public static long hl = 9000000000L;\n"
                + "  public static int hread = hi + 1;\n"
                + "}\n");
        return compile(sources);
    }

    // ---------------------------------------------------------------- flow ints

    private static void testFlowInts() throws Exception {
        Map<String, byte[]> compiled = compileFlowTarget();
        ClassPool baselinePool = pool(compiled);
        ClassNode baselineNode = baselinePool.getClass("test/FlowIntsTarget");
        byte[] baselineBytes = serialize(baselineNode, hierarchy(compiled));
        Class<?> baseline = defineAll(compiled, TARGET);

        Map<String, byte[]> once = compileFlowTarget();
        ClassPool transformedPool = pool(once);
        Hierarchy hierarchy = hierarchy(once);
        PassContext context = context(transformedPool, hierarchy, 0x5EEDF10BL,
                new String[] {
                        "flowInts.enabled", "true",
                        "flowInts.includeLong", "true",
                        "flowInts.rate", "100",
                        "flowInts.tablePairs", "2048",
                        "flowInts.debugAssert", "true"
                });
        new FlowIntsPass().run(context);
        ClassNode transformedNode = transformedPool.getClass("test/FlowIntsTarget");
        byte[] transformedBytes = serialize(transformedNode, hierarchy);
        Class<?> transformed = verifyAndLoad(transformedBytes, TARGET, "flowInts");
        assertSameBehaviour(baseline, transformed);

        Stats stats = context.stats();
        long sites = value(stats, "flowInts.sites");
        check(sites > 0L, "flowInts rewrote constant sites (" + sites + ")");
        check(value(stats, "flowInts.longSites") > 0L, "flowInts rewrote long constants");
        check(value(stats, "flowInts.states") > 0L, "flowInts wrote state updates");
        check(value(stats, "flowInts.methods") > 0L, "flowInts touched methods");
        check(value(stats, "flowInts.classes") > 0L, "flowInts touched the class");
        check(value(stats, "flowInts.joins") > 0L, "flowInts saw if/else join points");
        check(value(stats, "flowInts.runtimePairs") > 0L, "flowInts used the runtime table");
        check(value(stats, "flowInts.skip.rollback") == 0L, "flowInts rolled nothing back");
        check(value(stats, "flowInts.blocked") == 0L,
                "flowInts refused no method for a missing anchor");
        long merges = value(stats, "flowInts.skipped.merge");
        long states = value(stats, "flowInts.states");
        check(merges <= states, "merge reseeds (" + merges + ") never exceed state writes ("
                + states + ")");
        check(!transformedNode.fields.isEmpty(), "flowInts added the state table field");
        check(countIntArrayFields(transformedNode) > 0, "flowInts table is an int[]");

        // Literal constants are counted on a run without the diagnostic guards:
        // the guards push the expected value back as a literal, which would hide
        // the drop the transform is supposed to produce.
        ClassNode plainNode = read(runFlowInts(compileFlowTarget(), 0x5EEDF10BL));
        MethodNode bigBefore = method(baselineNode, "bigConstants");
        MethodNode bigAfter = method(plainNode, "bigConstants");
        int before = countLdcInt(bigBefore);
        int after = countLdcInt(bigAfter);
        check(before >= 8, "baseline bigConstants carries 8 literal ints (" + before + ")");
        check(after < before / 2, "literal int constants dropped (" + before + " -> " + after + ")");
        check(!hasLdcValue(bigAfter, 123456789) && !hasLdcValue(bigAfter, 2147483647)
                        && !hasLdcValue(bigAfter, -559038737),
                "distinctive constants no longer appear as literals");

        MethodNode arrayish = method(transformedNode, "arrayish");
        check(hasMultiArrayDimensions(arrayish), "array dimensions keep their literal sizes");
        check(value(stats, "flowInts.skipped") > 0L, "flowInts skipped the reserved constants");

        ClassNode reread = read(transformedBytes);
        int grew = 0;
        for (int i = 0; i < reread.methods.size(); i++) {
            MethodNode grownMethod = reread.methods.get(i);
            if (grownMethod.name.startsWith("<")) {
                continue;
            }
            MethodNode originalMethod = method(baselineNode, grownMethod.name);
            if (realSize(originalMethod) < realSize(grownMethod)) {
                grew++;
            }
        }
        check(grew >= 8, "most methods grew with the state arithmetic (" + grew + ")");
        check(baselineBytes.length > 0, "baseline serialised");
    }

    /**
     * Two leaders next to each other make a block with no real instruction. The
     * planner must treat it as transparent: the runtime carries the predecessor's
     * value straight through, so the successor has to anchor or advance from that
     * value. This is the shape that broke on the demo jar (a missing anchor meant
     * a planned state advance never happened and the successor materialised a
     * constant from the wrong state).
     */
    private static void testFlowIntsAdjacentLabels() throws Exception {
        ClassNode baselineNode = adjacentLabelClass();
        byte[] baselineBytes = serialize(baselineNode, new Hierarchy());
        Class<?> baseline = defineSingle(baselineNode.name, baselineBytes);

        ClassNode node = adjacentLabelClass();
        byte[] original = serialize(node, new Hierarchy());
        ClassPool pool = new ClassPool();
        pool.putClass(node.name + ".class", original, node);
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        PassContext context = context(pool, hierarchy, 0xAD7ACE70L,
                new String[] {
                        "flowInts.enabled", "true",
                        "flowInts.rate", "100",
                        "flowInts.inherit", "0",
                        "flowInts.tablePairs", "2048",
                        "flowInts.debugAssert", "true"
                });
        new FlowIntsPass().run(context);
        byte[] bytes = serialize(node, hierarchy);
        Class<?> transformed = defineSingle(node.name, bytes);
        check(value(context.stats(), "flowInts.sites") > 0L,
                "the adjacent-label method was rewritten");
        check(value(context.stats(), "flowInts.blocked") == 0L,
                "no method was refused for a missing anchor");
        for (int a = 0; a < 2; a++) {
            for (int b = 0; b < 2; b++) {
                String expected = call(baseline, "pick", new Class<?>[] { int.class, int.class },
                        Integer.valueOf(a), Integer.valueOf(b));
                String actual = call(transformed, "pick", new Class<?>[] { int.class, int.class },
                        Integer.valueOf(a), Integer.valueOf(b));
                check(expected.equals(actual), "pick(" + a + "," + b + ") expected " + expected
                        + " but got " + actual);
            }
        }
    }

    /** A method whose block layout contains a label-only block. */
    private static ClassNode adjacentLabelClass() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = "test/FlowIntsAdjacent";
        node.superName = "java/lang/Object";
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "pick", "(II)I", null, null);
        InsnList insns = method.instructions;
        LabelNode first = new LabelNode();
        LabelNode second = new LabelNode();
        LabelNode join = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new JumpInsnNode(Opcodes.IFNE, first));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, second));
        insns.add(new LdcInsnNode(Integer.valueOf(1000003)));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 2));
        insns.add(new JumpInsnNode(Opcodes.GOTO, join));
        insns.add(first);
        insns.add(second);
        insns.add(new LdcInsnNode(Integer.valueOf(2000003)));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 2));
        insns.add(join);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 2));
        insns.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 3;
        node.methods.add(method);
        return node;
    }

    private static void testFlowIntsConfused() throws Exception {
        Map<String, byte[]> compiled = compileFlowTarget();
        Class<?> baseline = defineAll(compiled, TARGET);

        Map<String, byte[]> once = compileFlowTarget();
        ClassPool pool = pool(once);
        Hierarchy hierarchy = hierarchy(once);
        PassContext context = context(pool, hierarchy, 0xC0FFEE77L,
                new String[] {
                        "flowInts.enabled", "true",
                        "flowInts.includeLong", "true",
                        "flowInts.confuse", "true",
                        "flowInts.confusePercent", "100",
                        "flowInts.inherit", "20",
                        "flowInts.tablePairs", "2048"
                });
        new FlowIntsPass().run(context);
        ClassNode node = pool.getClass("test/FlowIntsTarget");
        byte[] bytes = serialize(node, hierarchy);
        Class<?> transformed = verifyAndLoad(bytes, TARGET, "flowInts-confused");
        assertSameBehaviour(baseline, transformed);
        check(countLookupSwitches(read(bytes)) > 0, "decoy switches were emitted");
        check(value(context.stats(), "flowInts.states") > 0L, "confused run still writes states");
    }

    private static void testFlowIntsTwoPhase() throws Exception {
        Map<String, byte[]> compiled = compileFlowTarget();
        ClassPool pool = pool(compiled);
        Hierarchy hierarchy = hierarchy(compiled);
        ClassNode node = pool.getClass("test/FlowIntsTarget");
        List<FieldNode> fieldsBefore = new ArrayList<FieldNode>(node.fields);
        byte[] clinitBefore = clinitBytes(node);
        PassContext context = context(pool, hierarchy, 11L,
                new String[] {
                        "flowInts.enabled", "true",
                        "flowInts.rate", "0"
                });
        new FlowIntsPass().run(context);
        check(value(context.stats(), "flowInts.sites") == 0L, "rate=0 rewrites nothing");
        check(node.fields.size() == fieldsBefore.size(), "rate=0 leaves no orphan table field");
        byte[] clinitAfter = clinitBytes(node);
        check(Arrays.equals(clinitBefore, clinitAfter), "rate=0 leaves the initialiser alone");

        // A method the verifier rejects must be skipped, and the class must stay writable.
        Map<String, byte[]> second = compileFlowTarget();
        ClassPool brokenPool = pool(second);
        Hierarchy brokenHierarchy = hierarchy(second);
        ClassNode broken = brokenPool.getClass("test/FlowIntsTarget");
        MethodNode brokenMethod = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "broken", "()I", null, null);
        brokenMethod.instructions.add(new InsnNode(Opcodes.ICONST_0));
        brokenMethod.instructions.add(new InsnNode(Opcodes.ICONST_1));
        brokenMethod.instructions.add(new InsnNode(Opcodes.IADD));
        brokenMethod.instructions.add(new InsnNode(Opcodes.ARETURN));
        brokenMethod.maxStack = 2;
        broken.methods.add(brokenMethod);
        int brokenSizeBefore = brokenMethod.instructions.size();
        PassContext brokenContext = context(brokenPool, brokenHierarchy, 12L,
                new String[] {
                        "flowInts.enabled", "true",
                        "flowInts.rate", "100"
                });
        new FlowIntsPass().run(brokenContext);
        check(value(brokenContext.stats(), "flowInts.skipped") >= 1L,
                "the unverifiable method was skipped");
        check(brokenMethod.instructions.size() == brokenSizeBefore,
                "the skipped method kept its bytes");
        byte[] written = serialize(broken, brokenHierarchy);
        check(written.length > 0, "the class still serialises with a skipped method");
        check(countIntArrayFields(broken) > 0, "the surviving methods still got their table");
    }

    private static void testFlowIntsDeterminism() throws Exception {
        Map<String, byte[]> first = compileFlowTarget();
        Map<String, byte[]> second = compileFlowTarget();
        byte[] a = runFlowInts(first, 0xA11CE5L);
        byte[] b = runFlowInts(second, 0xA11CE5L);
        check(Arrays.equals(a, b), "the same seed produces byte-identical flow-ints output");
        byte[] c = runFlowInts(compileFlowTarget(), 0xA11CE6L);
        check(!Arrays.equals(a, c), "a different seed produces different flow-ints output");
    }

    private static byte[] runFlowInts(Map<String, byte[]> compiled, long seed) throws Exception {
        ClassPool pool = pool(compiled);
        Hierarchy hierarchy = hierarchy(compiled);
        PassContext context = context(pool, hierarchy, seed,
                new String[] {
                        "flowInts.enabled", "true",
                        "flowInts.includeLong", "true",
                        "flowInts.tablePairs", "2048"
                });
        new FlowIntsPass().run(context);
        return serialize(pool.getClass("test/FlowIntsTarget"), hierarchy);
    }

    // ------------------------------------------------------------ init order

    private static void testClassInitReport() throws Exception {
        PassContext context = orderContext(compileOrderFixtures(), 0x0DE101L, "report");
        new ClassInitOrderPass().run(context);
        ClassPool pool = context.classes();
        check(value(context.stats(), "classInitOrder.edges") > 0L, "dependency edges found");
        check(value(context.stats(), "classInitOrder.cycles") == 1L, "exactly one cycle found");
        String cycles = pool.getMeta("classInitOrder.cycle");
        check(cycles != null && cycles.contains("test/cioa/P") && cycles.contains("test/cioa/Q"),
                "the P<->Q cycle is reported: " + cycles);
        String order = pool.getMeta("classInitOrder.order");
        check(order != null, "a topological order is published");
        int rankC = rankOf(order, "test/cioa/C");
        int rankB = rankOf(order, "test/cioa/B");
        int rankA = rankOf(order, "test/cioa/A");
        check(rankC >= 0 && rankB >= 0 && rankA >= 0, "A, B and C are all in the order");
        check(rankC < rankB, "C is initialised before B (" + rankC + " < " + rankB + ")");
        check(rankB < rankA, "B is initialised before A (" + rankB + " < " + rankA + ")");
        check(value(context.stats(), "classInitOrder.reordered") == 0L,
                "report touches no bytecode");
        check(value(context.stats(), "classInitOrder.hoisted") == 0L,
                "report hoists nothing");
    }

    private static void testClassInitReorder() throws Exception {
        Map<String, byte[]> compiled = compileOrderFixtures();
        Class<?> baseline = defineAll(compiled, "test.cioa.A");
        PassContext context = orderContext(compiled, 0x0DE102L, "reorderClinit");
        new ClassInitOrderPass().run(context);
        check(value(context.stats(), "classInitOrder.reordered") > 0L,
                "reorderClinit moved independent statements");
        check(value(context.stats(), "classInitOrder.skip.rollback") == 0L,
                "no initialiser needed a rollback");
        Map<String, byte[]> out = new LinkedHashMap<String, byte[]>();
        Hierarchy hierarchy = hierarchy(compiled);
        for (ClassNode node : context.classes().classes().values()) {
            byte[] bytes = serialize(node, hierarchy);
            verifyBytes(node.name, bytes);
            out.put(node.name.replace('/', '.'), bytes);
        }
        Class<?> transformed = defineAll(out, "test.cioa.A");
        check(readInt(transformed, "ax") == readInt(baseline, "ax"), "ax survives reordering");
        check(readInt(transformed, "aderived") == readInt(baseline, "aderived"),
                "aderived survives reordering");
        check(String.valueOf(readObject(transformed, "tag")).equals(
                String.valueOf(readObject(baseline, "tag"))), "tag survives reordering");
        check(readInt(transformed, "ax") == 5 && readInt(transformed, "aderived") == 8,
                "reordered values are still 5 / 8");
        Class<?> c = defineAll(out, "test.cioa.C");
        check(readInt(c, "cdoubled") == 14, "C.cdoubled keeps its value");
    }

    private static void testClassInitHoist() throws Exception {
        Map<String, byte[]> compiled = compileOrderFixtures();
        Class<?> baseline = defineAll(compiled, "test.ciod.H");
        int baselineInsns = clinitSize(read(compiled.get("test.ciod.H")));

        PassContext context = orderContext(compiled, 0x0DE103L, "hoist");
        new ClassInitOrderPass().run(context);
        check(value(context.stats(), "classInitOrder.hoisted") >= 2L,
                "constant initialisers were hoisted (" + value(context.stats(),
                        "classInitOrder.hoisted") + ")");
        ClassNode node = context.classes().getClass("test/ciod/H");
        int afterInsns = clinitSize(node);
        check(afterInsns < baselineInsns, "the initialiser shrank (" + baselineInsns + " -> "
                + afterInsns + ")");
        FieldNode hi = field(node, "hi");
        FieldNode hs = field(node, "hs");
        FieldNode hl = field(node, "hl");
        check(hi != null && hi.value == null, "the field read by the initialiser was not hoisted");
        check(hs != null && "hey".equals(hs.value), "the String constant became a ConstantValue");
        check(hl != null && Long.valueOf(9000000000L).equals(hl.value),
                "the long constant became a ConstantValue");

        byte[] bytes = serialize(node, hierarchy(compiled));
        verifyBytes("test/ciod/H", bytes);
        Map<String, byte[]> out = new LinkedHashMap<String, byte[]>();
        out.put(node.name.replace('/', '.'), bytes);
        Class<?> transformed = defineAll(out, "test.ciod.H");
        check(readInt(transformed, "hi") == readInt(baseline, "hi"), "hi keeps its value");
        check(readInt(transformed, "hread") == readInt(baseline, "hread"), "hread keeps its value");
        check(String.valueOf(readObject(transformed, "hs")).equals("hey"), "hs keeps its value");
        check(((Long) readObject(transformed, "hl")).longValue() == 9000000000L,
                "hl keeps its value");
    }

    // ------------------------------------------------------------- assertions

    private static void assertSameBehaviour(Class<?> baseline, Class<?> transformed)
            throws Exception {
        int compared = 0;
        for (int i = 0; i < INT_TARGETS.length; i++) {
            String name = INT_TARGETS[i];
            int[] values = INT_INPUTS[i];
            boolean binary = BINARY_TARGETS.contains(name);
            for (int v = 0; v < values.length; v++) {
                String expected;
                String actual;
                if (binary) {
                    expected = call(baseline, name, new Class<?>[] { int.class, int.class },
                            Integer.valueOf(values[v]), Integer.valueOf(3));
                    actual = call(transformed, name, new Class<?>[] { int.class, int.class },
                            Integer.valueOf(values[v]), Integer.valueOf(3));
                } else {
                    expected = call(baseline, name, new Class<?>[] { int.class },
                            Integer.valueOf(values[v]));
                    actual = call(transformed, name, new Class<?>[] { int.class },
                            Integer.valueOf(values[v]));
                }
                check(expected.equals(actual), name + "(" + values[v] + ") expected " + expected
                        + " but got " + actual);
                compared++;
            }
        }

        String baselineNoArgs = call(baseline, "bigConstants", new Class<?>[0]);
        String transformedNoArgs = call(transformed, "bigConstants", new Class<?>[0]);
        check(baselineNoArgs.equals(transformedNoArgs), "bigConstants matches");
        compared++;

        String baselineLoop = call(baseline, "arrayLoop", new Class<?>[0]);
        String transformedLoop = call(transformed, "arrayLoop", new Class<?>[0]);
        check("692".equals(baselineLoop), "arrayLoop reference value is 692 (" + baselineLoop + ")");
        check(baselineLoop.equals(transformedLoop), "arrayLoop(14 slots, iinc index) matches: "
                + baselineLoop + " vs " + transformedLoop);

        long[] longs = { 0L, 1L, -1L, Long.MAX_VALUE, Long.MIN_VALUE, 1234567890123L };
        for (int i = 0; i < longs.length; i++) {
            String expected = call(baseline, "longish", new Class<?>[] { long.class },
                    Long.valueOf(longs[i]));
            String actual = call(transformed, "longish", new Class<?>[] { long.class },
                    Long.valueOf(longs[i]));
            check(expected.equals(actual), "longish(" + longs[i] + ") expected " + expected
                    + " but got " + actual);
            compared++;
        }
        check(compared >= 45, "compared a meaningful number of calls (" + compared + ")");
    }

    private static final List<String> BINARY_TARGETS = Arrays.asList("arith");

    private static final String[] INT_TARGETS = {
            "arith", "loopy", "switcher", "early", "tryNest", "arrayish", "mixed"
    };

    private static final int[][] INT_INPUTS = {
            { 5, 3, 0, -7, 1000003 },
            { 0, 1, 10, 137, 10000 },
            { 0, 1, 2, 3, 4, 100000, 200000, 300000, -1 },
            { -5, 0, 1, 101, 102, 1000, 100000 },
            { 0, 1, 2, 3, 7, -3 },
            { 0, 1, 5, 17 },
            { 0, 1, 3, 4, 7, 15, 100 }
    };

    private static String call(Class<?> type, String name, Class<?>[] signature, Object... args)
            throws Exception {
        Method method = type.getDeclaredMethod(name, signature);
        method.setAccessible(true);
        try {
            Object result = method.invoke(null, args);
            if (result instanceof String) {
                return "S:" + result;
            }
            return String.valueOf(result);
        } catch (InvocationTargetException failure) {
            Throwable cause = failure.getCause();
            return "EX:" + cause.getClass().getName() + ":" + cause.getMessage();
        }
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }

    private static long value(Stats stats, String key) {
        Long found = stats.snapshot().get(key);
        return found == null ? -1L : found.longValue();
    }

    // ------------------------------------------------------------- utilities

    private static Map<String, byte[]> compile(Map<String, String> sources) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("no system Java compiler: the flow-ints self-test "
                    + "compiles its fixtures with javac");
        }
        List<String[]> attempts = new ArrayList<String[]>();
        attempts.add(new String[] { "-g:none", "--release", "8" });
        attempts.add(new String[] { "-g:none" });
        String lastError = "";
        for (int attempt = 0; attempt < attempts.size(); attempt++) {
            Map<String, byte[]> out = new LinkedHashMap<String, byte[]>();
            DiagnosticCollector<JavaFileObject> diagnostics =
                    new DiagnosticCollector<JavaFileObject>();
            StandardJavaFileManager standard = compiler.getStandardFileManager(
                    diagnostics, Locale.ROOT, StandardCharsets.UTF_8);
            final Map<String, ByteArrayOutputStream> buffers =
                    new LinkedHashMap<String, ByteArrayOutputStream>();
            JavaFileManager manager = new ForwardingJavaFileManager<StandardJavaFileManager>(
                    standard) {
                @Override
                public JavaFileObject getJavaFileForOutput(Location location, final String className,
                                                           JavaFileObject.Kind kind,
                                                           FileObject sibling) {
                    final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    buffers.put(className, buffer);
                    return new SimpleJavaFileObject(
                            URI.create("bytes:///" + className.replace('.', '/') + kind.extension),
                            kind) {
                        @Override
                        public OutputStream openOutputStream() {
                            return buffer;
                        }
                    };
                }
            };
            List<JavaFileObject> units = new ArrayList<JavaFileObject>();
            for (Map.Entry<String, String> entry : sources.entrySet()) {
                final String code = entry.getValue();
                units.add(new SimpleJavaFileObject(
                        URI.create("string:///" + entry.getKey().replace('.', '/')
                                + JavaFileObject.Kind.SOURCE.extension),
                        JavaFileObject.Kind.SOURCE) {
                    @Override
                    public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                        return code;
                    }
                });
            }
            List<String> options = Arrays.asList(attempts.get(attempt));
            boolean ok = compiler.getTask(null, manager, diagnostics, options, null, units).call();
            try {
                manager.close();
            } catch (java.io.IOException ignored) {
                // closing the in-memory manager cannot fail meaningfully
            }
            if (!ok) {
                StringBuilder errors = new StringBuilder();
                for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
                    errors.append(diagnostic).append(' ');
                }
                lastError = errors.toString();
                continue;
            }
            for (Map.Entry<String, ByteArrayOutputStream> entry : buffers.entrySet()) {
                out.put(entry.getKey(), entry.getValue().toByteArray());
            }
            return out;
        }
        throw new IllegalStateException("fixture compilation failed: " + lastError);
    }

    private static ClassPool pool(Map<String, byte[]> compiled) {
        ClassPool pool = new ClassPool();
        for (Map.Entry<String, byte[]> entry : compiled.entrySet()) {
            ClassNode node = read(entry.getValue());
            pool.putClass(entry.getKey().replace('.', '/') + ".class", entry.getValue(), node);
        }
        return pool;
    }

    private static Hierarchy hierarchy(Map<String, byte[]> compiled) {
        Hierarchy hierarchy = new Hierarchy();
        for (byte[] bytes : compiled.values()) {
            hierarchy.addInput(read(bytes));
        }
        return hierarchy;
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static byte[] serialize(ClassNode node, Hierarchy hierarchy) {
        hierarchy.addInput(node);
        return UmbraClassWriter.toBytes(node, hierarchy);
    }

    private static PassContext context(ClassPool pool, Hierarchy hierarchy, long seed,
                                       String[] options) {
        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"))
                .seed(seed);
        for (int i = 0; i + 1 < options.length; i += 2) {
            builder.option(options[i], options[i + 1]);
        }
        UmbraConfig config;
        try {
            config = builder.build();
        } catch (Exception failure) {
            throw new IllegalStateException("cannot build the test configuration", failure);
        }
        return new PassContext(config, pool, hierarchy,
                new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(), false, false),
                new DefaultRuntimeSupport(), new MappingSet(), new Stats(),
                new Log(null, false), new Random(seed), ProgressListener.NONE);
    }

    private static PassContext orderContext(Map<String, byte[]> compiled, long seed,
                                            String action) {
        ClassPool pool = pool(compiled);
        Hierarchy hierarchy = hierarchy(compiled);
        return context(pool, hierarchy, seed,
                new String[] {
                        "classInitOrder.enabled", "true",
                        "classInitOrder.action", action,
                        "classInitOrder.maxDepth", "64"
                });
    }

    private static void verifyBytes(String internalName, byte[] bytes) {
        StringWriter writer = new StringWriter();
        CheckClassAdapter.verify(new ClassReader(bytes), false, new PrintWriter(writer));
        String errors = writer.toString();
        check(errors.isEmpty(), "CheckClassAdapter (" + internalName + "): " + errors);
    }

    private static Class<?> verifyAndLoad(byte[] bytes, String dottedName, String phase)
            throws Exception {
        verifyBytes(dottedName, bytes);
        Map<String, byte[]> map = new LinkedHashMap<String, byte[]>();
        map.put(dottedName, bytes);
        return defineAll(map, dottedName);
    }

    private static Class<?> defineAll(Map<String, byte[]> classes, String dottedName)
            throws Exception {
        final Map<String, byte[]> copy = new LinkedHashMap<String, byte[]>(classes);
        final ClassLoader loader = new ClassLoader(FlowIntsClassInitTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] data = copy.get(name);
                if (data != null) {
                    return defineClass(name, data, 0, data.length);
                }
                return super.findClass(name);
            }
        };
        return Class.forName(dottedName, true, loader);
    }

    private static Class<?> defineSingle(String internalName, byte[] bytes) throws Exception {
        String dotted = internalName.replace('/', '.');
        Map<String, byte[]> map = new LinkedHashMap<String, byte[]>();
        map.put(dotted, bytes);
        return defineAll(map, dotted);
    }

    private static MethodNode method(ClassNode node, String name) {
        for (int i = 0; i < node.methods.size(); i++) {
            MethodNode method = node.methods.get(i);
            if (method.name.equals(name)) {
                return method;
            }
        }
        throw new IllegalStateException("no method " + name + " in " + node.name);
    }

    private static FieldNode field(ClassNode node, String name) {
        for (int i = 0; i < node.fields.size(); i++) {
            FieldNode field = node.fields.get(i);
            if (field.name.equals(name)) {
                return field;
            }
        }
        return null;
    }

    private static int countIntArrayFields(ClassNode node) {
        int count = 0;
        for (int i = 0; i < node.fields.size(); i++) {
            FieldNode field = node.fields.get(i);
            if ("[I".equals(field.desc) && (field.access & Opcodes.ACC_STATIC) != 0) {
                count++;
            }
        }
        return count;
    }

    private static int countLdcInt(MethodNode method) {
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer) {
                count++;
            }
        }
        return count;
    }

    private static boolean hasLdcValue(MethodNode method, int value) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof LdcInsnNode) {
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof Integer && ((Integer) constant).intValue() == value) {
                    return true;
                }
            }
        }
        return false;
    }

    private static long countSmallIntPushes(MethodNode method) {
        long count = 0L;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
                count++;
            } else if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
                count++;
            }
        }
        return count;
    }

    private static int realSize(MethodNode method) {
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn.getOpcode() >= 0) {
                count++;
            }
        }
        return count;
    }

    private static int countLookupSwitches(ClassNode node) {
        int count = 0;
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof LookupSwitchInsnNode) {
                    count++;
                }
            }
        }
        return count;
    }

    private static boolean hasMultiArrayDimensions(MethodNode method) {
        AbstractInsnNode[] insns = method.instructions.toArray();
        for (int i = 0; i < insns.length; i++) {
            if (insns[i].getOpcode() != Opcodes.MULTIANEWARRAY) {
                continue;
            }
            int ones = 0;
            for (int k = i - 1; k >= 0; k--) {
                int opcode = insns[k].getOpcode();
                if (opcode < 0) {
                    continue;
                }
                if (opcode == Opcodes.ICONST_2 || opcode == Opcodes.ICONST_3
                        || opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
                    ones++;
                    continue;
                }
                break;
            }
            if (ones >= 2) {
                return true;
            }
        }
        return false;
    }

    private static byte[] clinitBytes(ClassNode node) {
        MethodNode clinit = null;
        for (int i = 0; i < node.methods.size(); i++) {
            if ("<clinit>".equals(node.methods.get(i).name)) {
                clinit = node.methods.get(i);
                break;
            }
        }
        if (clinit == null) {
            return new byte[0];
        }
        ClassNode mini = new ClassNode();
        mini.version = node.version;
        mini.access = node.access;
        mini.name = node.name;
        mini.superName = node.superName;
        mini.interfaces = node.interfaces;
        mini.methods.add(clinit);
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(mini);
        return UmbraClassWriter.toBytes(mini, hierarchy);
    }

    private static int clinitSize(ClassNode node) {
        for (int i = 0; i < node.methods.size(); i++) {
            MethodNode method = node.methods.get(i);
            if ("<clinit>".equals(method.name)) {
                int count = 0;
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                     insn = insn.getNext()) {
                    if (insn.getOpcode() >= 0) {
                        count++;
                    }
                }
                return count;
            }
        }
        return 0;
    }

    private static int rankOf(String order, String internalName) {
        String[] parts = order.split(",");
        for (int i = 0; i < parts.length; i++) {
            if (parts[i].equals(internalName)) {
                return i;
            }
        }
        return -1;
    }

    private static int readInt(Class<?> type, String name) throws Exception {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        return field.getInt(null);
    }

    private static Object readObject(Class<?> type, String name) throws Exception {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(null);
    }
}
