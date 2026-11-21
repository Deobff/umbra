package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.BodyOptimizePass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * Plain-main tests for {@link BodyOptimizePass}: dead code, repeated int
 * constants and write-only locals.
 *
 * <p>Each scenario builds one synthetic class with ASM, runs the pass on its own
 * {@link ClassPool} (so the statistics of one scenario are not polluted by
 * another), serialises the result with {@link UmbraClassWriter}, checks it with
 * {@link CheckClassAdapter}, defines it in a fresh class loader and compares every
 * returned value with a plain Java reference implementation.</p>
 */
public final class BodyOptimizeTest {

    private static int checks;

    private BodyOptimizeTest() {
    }

    public static void main(String[] args) throws Exception {
        startWatchdog();
        testDeadCode();
        testDeadClinit();
        testIntReuse();
        testUnusedLocals();
        testMixedMethod();
        testDeterminism();
        testJsrSkip();
        System.out.println("BodyOptimizeTest: " + checks + " checks passed");
    }

    private static void startWatchdog() {
        final long timeout = Long.parseLong(System.getProperty("umbra.bodyopt.watchdog", "120000"));
        Thread watchdog = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(timeout);
                } catch (InterruptedException ignored) {
                    return;
                }
                System.err.println("BodyOptimizeTest WATCHDOG after " + timeout + "ms");
                Runtime.getRuntime().halt(3);
            }
        }, "body-optimize-test-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    // ------------------------------------------------------------------
    // 1. dead code
    // ------------------------------------------------------------------

    private static void testDeadCode() throws Exception {
        ClassNode node = newClass("test/DeadTarget");
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "deadCode", "(I)I", null, null);
        node.methods.add(method);
        addConstructor(node);
        method.maxStack = 2;
        method.maxLocals = 2;

        LabelNode nonZero = new LabelNode();
        LabelNode deadStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode handler = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new JumpInsnNode(Opcodes.IFNE, nonZero));
        method.instructions.add(new InsnNode(Opcodes.ICONST_2));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(nonZero);
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        // Everything below is unreachable: seven real instructions in one run.
        method.instructions.add(deadStart);
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        method.instructions.add(new InsnNode(Opcodes.POP));
        method.instructions.add(new InsnNode(Opcodes.NOP));
        method.instructions.add(new InsnNode(Opcodes.NOP));
        method.instructions.add(tryEnd);
        method.instructions.add(handler);
        method.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
        method.instructions.add(new InsnNode(Opcodes.ICONST_4));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.tryCatchBlocks.add(new TryCatchBlockNode(deadStart, tryEnd, handler,
                "java/lang/Exception"));

        Run run = run(node);
        eq(7L, stat(run.stats, "bodyOptimize.deadInstructions"), "dead instructions");
        eq(1L, stat(run.stats, "bodyOptimize.deadBlocks"), "dead blocks");
        eq(1L, stat(run.stats, "bodyOptimize.methods"), "optimized methods");
        eq(0L, stat(run.stats, "bodyOptimize.skip.rollback"), "no rollback");
        check(method.tryCatchBlocks.isEmpty(), "dead handler entry dropped");

        Class<?> type = verifyAndLoad(node, "test.DeadTarget", "dead-code");
        eq(2, invoke(type, "deadCode", new Class<?>[] { int.class }, 0), "deadCode(0)");
        eq(1, invoke(type, "deadCode", new Class<?>[] { int.class }, 5), "deadCode(5)");
        eq(1, invoke(type, "deadCode", new Class<?>[] { int.class }, -3), "deadCode(-3)");
    }

    /**
     * A {@code <clinit>} is swept like any other body: the pass must not treat class
     * initializers as untouchable.
     */
    private static void testDeadClinit() throws Exception {
        ClassNode node = newClass("test/ClinitTarget");
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "flag", "I", null, null));
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.maxStack = 1;
        clinit.maxLocals = 0;
        clinit.instructions.add(new InsnNode(Opcodes.ICONST_1));
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, "test/ClinitTarget", "flag", "I"));
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 9));
        clinit.instructions.add(new InsnNode(Opcodes.POP));
        clinit.instructions.add(new InsnNode(Opcodes.NOP));
        node.methods.add(clinit);

        Run run = run(node);
        eq(3L, stat(run.stats, "bodyOptimize.deadInstructions"), "clinit dead instructions");
        eq(1L, stat(run.stats, "bodyOptimize.deadBlocks"), "clinit dead blocks");
        eq(3, clinit.instructions.size(), "clinit keeps only its three instructions");

        Class<?> type = verifyAndLoad(node, "test.ClinitTarget", "dead-clinit");
        eq(1, ((Integer) type.getField("flag").get(null)).intValue(), "clinit still runs");
    }

    // ------------------------------------------------------------------
    // 2. int constant reuse
    // ------------------------------------------------------------------

    private static void testIntReuse() throws Exception {
        ClassNode node = newClass("test/ConstTarget");
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "consts", "(I)I", null, null);
        node.methods.add(method);
        addConstructor(node);
        method.maxStack = 2;
        method.maxLocals = 1;

        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        for (int i = 0; i < 5; i++) {
            method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 100));
            method.instructions.add(new InsnNode(Opcodes.IADD));
        }
        method.instructions.add(new InsnNode(Opcodes.IRETURN));

        Run run = run(node);
        eq(1L, stat(run.stats, "bodyOptimize.intReuse"), "hoisted constants");
        eq(5L, stat(run.stats, "bodyOptimize.intSites"), "rewritten sites");
        eq(2, method.maxLocals, "one new local");

        int pushSites = count(method, Opcodes.BIPUSH, 100);
        eq(1, pushSites, "single BIPUSH 100 left (the prologue)");
        int reads = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() == Opcodes.ILOAD && ((VarInsnNode) insn).var == 1) {
                reads++;
            }
        }
        eq(5, reads, "five reads of the reused local");

        Class<?> type = verifyAndLoad(node, "test.ConstTarget", "int-reuse");
        int[] inputs = new int[] { 0, 1, -1, 12345, Integer.MIN_VALUE, Integer.MAX_VALUE };
        for (int i = 0; i < inputs.length; i++) {
            eq(inputs[i] + 500, invoke(type, "consts", new Class<?>[] { int.class }, inputs[i]),
                    "consts(" + inputs[i] + ")");
        }
    }

    // ------------------------------------------------------------------
    // 3. unused locals
    // ------------------------------------------------------------------

    private static void testUnusedLocals() throws Exception {
        ClassNode node = newClass("test/LocalTarget");
        addConstructor(node);

        MethodNode unused = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "unused", "(I)I", null, null);
        unused.maxStack = 1;
        unused.maxLocals = 3;
        unused.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        unused.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 5));
        unused.instructions.add(new VarInsnNode(Opcodes.ISTORE, 1));
        unused.instructions.add(new LdcInsnNode("hello"));
        unused.instructions.add(new VarInsnNode(Opcodes.ASTORE, 2));
        unused.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        unused.instructions.add(new InsnNode(Opcodes.IRETURN));
        node.methods.add(unused);

        // The store keeps a value produced by a call, so the pair must survive.
        MethodNode kept = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "kept", "(I)I", null, null);
        kept.maxStack = 2;
        kept.maxLocals = 2;
        kept.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        kept.instructions.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        kept.instructions.add(new InsnNode(Opcodes.DUP));
        kept.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/StringBuilder", "<init>", "()V", false));
        kept.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
        kept.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        kept.instructions.add(new InsnNode(Opcodes.IRETURN));
        node.methods.add(kept);

        Run run = run(node);
        eq(2L, stat(run.stats, "bodyOptimize.localsRemoved"), "cleaned locals");
        eq(0L, stat(run.stats, "bodyOptimize.skip.rollback"), "no rollback");
        check(countStore(unused, 1) == 0, "write-only int local removed");
        check(countStore(unused, 2) == 0, "write-only ref local removed");
        eq(1, countStore(kept, 1), "store behind a call kept");

        Class<?> type = verifyAndLoad(node, "test.LocalTarget", "unused-locals");
        eq(7, invoke(type, "unused", new Class<?>[] { int.class }, 7), "unused(x)");
        eq(9, invoke(type, "kept", new Class<?>[] { int.class }, 9), "kept(x)");
    }

    // ------------------------------------------------------------------
    // 4. try/catch + loops + switch
    // ------------------------------------------------------------------

    private static void testMixedMethod() throws Exception {
        ClassNode node = newClass("test/MixedTarget");
        addConstructor(node);
        node.methods.add(mixedMethod());

        // diagnostic: the hand-built method must verify before the pass touches it
        verifyAndLoad(copyOf(node), "test.MixedTarget", "mixed-baseline");
        Run run = run(node);
        eq(0L, stat(run.stats, "bodyOptimize.skip.rollback"), "mixed method verified");

        Class<?> type = verifyAndLoad(node, "test.MixedTarget", "mixed");
        int[][] dataSets = new int[][] {
                new int[] { 1, 2, 3, 4 },
                new int[] { 0, 0, 0 },
                new int[] { 5 },
                new int[] { 9, 8, 7, 6, 5 },
                new int[0],
                new int[] { -1, -2, -3, -4 }
        };
        int[] lengths = new int[] { 4, 3, 1, 5, 0, 4 };
        for (int i = 0; i < dataSets.length; i++) {
            int expected = mixedReference(dataSets[i], lengths[i]);
            int actual = ((Integer) invoke(type, "mixed",
                    new Class<?>[] { int[].class, int.class }, dataSets[i], lengths[i])).intValue();
            eq(expected, actual, "mixed(" + Arrays.toString(dataSets[i]) + ", " + lengths[i] + ")");
        }
        eq(-1, ((Integer) invoke(type, "mixed",
                new Class<?>[] { int[].class, int.class }, null, 1)).intValue(), "mixed(null, 1)");
        eq(-1, mixedReference(null, 1), "reference mixed(null, 1)");
    }

    private static MethodNode mixedMethod() {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "mixed", "([II)I", null, null);
        method.maxStack = 3;
        method.maxLocals = 5;
        LabelNode tryStart = new LabelNode();
        LabelNode loop = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode handler = new LabelNode();
        LabelNode caseZero = new LabelNode();
        LabelNode caseOne = new LabelNode();
        LabelNode other = new LabelNode();
        LabelNode afterSwitch = new LabelNode();
        LabelNode noContinue = new LabelNode();
        LabelNode ret = new LabelNode();

        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 2));
        method.instructions.add(tryStart);
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 3));
        method.instructions.add(loop);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 3));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPGE, tryEnd));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 3));
        method.instructions.add(new InsnNode(Opcodes.IALOAD));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 4));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 4));
        method.instructions.add(new InsnNode(Opcodes.ICONST_3));
        method.instructions.add(new InsnNode(Opcodes.IREM));
        method.instructions.add(new LookupSwitchInsnNode(other,
                new int[] { 0, 1 }, new LabelNode[] { caseZero, caseOne }));

        method.instructions.add(caseZero);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 2));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IADD));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 2));
        method.instructions.add(new JumpInsnNode(Opcodes.GOTO, afterSwitch));

        method.instructions.add(caseOne);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 2));
        method.instructions.add(new InsnNode(Opcodes.ICONST_2));
        method.instructions.add(new InsnNode(Opcodes.IADD));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 2));
        method.instructions.add(new JumpInsnNode(Opcodes.GOTO, afterSwitch));

        method.instructions.add(other);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 2));
        method.instructions.add(new InsnNode(Opcodes.ICONST_3));
        method.instructions.add(new InsnNode(Opcodes.IADD));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 2));

        method.instructions.add(afterSwitch);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 3));
        method.instructions.add(new InsnNode(Opcodes.ICONST_2));
        method.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPNE, noContinue));
        method.instructions.add(new IincInsnNode(3, 1));
        method.instructions.add(new JumpInsnNode(Opcodes.GOTO, loop));

        method.instructions.add(noContinue);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 2));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 3));
        method.instructions.add(new InsnNode(Opcodes.IADD));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 2));
        method.instructions.add(new IincInsnNode(3, 1));
        method.instructions.add(new JumpInsnNode(Opcodes.GOTO, loop));

        method.instructions.add(tryEnd);
        method.instructions.add(new JumpInsnNode(Opcodes.GOTO, ret));
        method.instructions.add(handler);
        method.instructions.add(new InsnNode(Opcodes.POP));
        method.instructions.add(new InsnNode(Opcodes.ICONST_M1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(ret);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 2));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.tryCatchBlocks.add(new TryCatchBlockNode(tryStart, tryEnd, handler,
                "java/lang/RuntimeException"));
        return method;
    }

    private static int mixedReference(int[] data, int n) {
        int sum = 0;
        try {
            int i = 0;
            while (i < n) {
                int value = data[i];
                switch (value % 3) {
                    case 0:
                        sum += 1;
                        break;
                    case 1:
                        sum += 2;
                        break;
                    default:
                        sum += 3;
                        break;
                }
                if (i == 2) {
                    i++;
                    continue;
                }
                sum += i;
                i++;
            }
        } catch (RuntimeException failure) {
            return -1;
        }
        return sum;
    }

    // ------------------------------------------------------------------
    // 5. determinism and JSR/RET
    // ------------------------------------------------------------------

    private static void testDeterminism() throws Exception {
        ClassNode first = deterministicNode();
        ClassNode second = deterministicNode();
        run(first);
        run(second);
        byte[] a = serialize(first);
        byte[] b = serialize(second);
        check(Arrays.equals(a, b), "same seed produces identical bytes");
    }

    private static ClassNode deterministicNode() {
        ClassNode node = newClass("test/DetTarget");
        addConstructor(node);
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "(I)I", null, null);
        method.maxStack = 2;
        method.maxLocals = 2;
        LabelNode join = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new JumpInsnNode(Opcodes.IFEQ, join));
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 42));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(join);
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 42));
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 42));
        method.instructions.add(new InsnNode(Opcodes.IADD));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        node.methods.add(method);
        return node;
    }

    private static void testJsrSkip() throws Exception {
        ClassNode node = newClass("test/JsrTarget");
        node.version = Opcodes.V1_5;
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "legacy", "(I)I", null, null);
        method.maxStack = 2;
        method.maxLocals = 2;
        LabelNode subroutine = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new JumpInsnNode(Opcodes.JSR, subroutine));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(subroutine);
        method.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
        method.instructions.add(new IincInsnNode(0, 1));
        method.instructions.add(new VarInsnNode(Opcodes.RET, 1));
        node.methods.add(method);
        int before = method.instructions.size();

        Run run = run(node);
        eq(1L, stat(run.stats, "bodyOptimize.skip.jsr"), "jsr methods skipped");
        eq(0L, stat(run.stats, "bodyOptimize.methods"), "no method touched");
        eq(before, method.instructions.size(), "jsr method unchanged");
    }

    // ------------------------------------------------------------------
    // harness
    // ------------------------------------------------------------------

    private static final class Run {
        private final PassContext context;
        private final Stats stats;

        private Run(PassContext context, Stats stats) {
            this.context = context;
            this.stats = stats;
        }
    }

    private static Run run(ClassNode node) throws Exception {
        UmbraConfig config = new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"))
                .seed(0x5A17L)
                .option("bodyOptimize.enabled", "true")
                .option("bodyOptimize.deadCode", "true")
                .option("bodyOptimize.intReuse", "true")
                .option("bodyOptimize.unusedLocals", "true")
                .option("bodyOptimize.intReuseThreshold", "2")
                .build();
        ClassPool pool = new ClassPool();
        pool.putClass(node.name + ".class", new byte[0], node);
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        DefaultRuleSet rules = new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(),
                false, false);
        Stats stats = new Stats();
        PassContext context = new PassContext(config, pool, hierarchy, rules,
                new DefaultRuntimeSupport(), new MappingSet(), stats,
                new Log(null, false), new Random(0x5A17L), ProgressListener.NONE);
        new BodyOptimizePass().run(context);
        return new Run(context, stats);
    }

    private static ClassNode copyOf(ClassNode node) {
        ClassNode copy = newClass(node.name);
        copy.version = node.version;
        copy.access = node.access;
        copy.superName = node.superName;
        copy.sourceFile = node.sourceFile;
        for (int i = 0; i < node.methods.size(); i++) {
            copy.methods.add(copyMethod(node.methods.get(i)));
        }
        return copy;
    }

    private static MethodNode copyMethod(MethodNode original) {
        return io.umbra.core.pass.impl.flow.MethodGate.copy(original);
    }

    private static ClassNode newClass(String name) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER;
        node.name = name;
        node.superName = "java/lang/Object";
        node.sourceFile = "BodyOptTarget.java";
        return node;
    }

    private static void addConstructor(ClassNode node) {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        method.maxStack = 1;
        method.maxLocals = 1;
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        node.methods.add(method);
    }

    private static byte[] serialize(ClassNode node) {
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        return UmbraClassWriter.toBytes(node, hierarchy);
    }

    private static Class<?> verifyAndLoad(ClassNode node, final String dotted, String phase)
            throws Exception {
        byte[] bytes = serialize(node);
        StringWriter writer = new StringWriter();
        PrintWriter print = new PrintWriter(writer);
        CheckClassAdapter.verify(new ClassReader(bytes),
                BodyOptimizeTest.class.getClassLoader(), false, print);
        String errors = writer.toString();
        check(errors.isEmpty(), "CheckClassAdapter (" + phase + "): " + errors.trim());
        final byte[] data = bytes;
        final Map<String, byte[]> classes = new HashMap<String, byte[]>();
        classes.put(dotted, data);
        ClassLoader loader = new ClassLoader(BodyOptimizeTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] bytesFor = classes.get(name);
                if (bytesFor != null) {
                    return defineClass(name, bytesFor, 0, bytesFor.length);
                }
                return super.findClass(name);
            }
        };
        try {
            return Class.forName(dotted, true, loader);
        } catch (ClassNotFoundException failure) {
            throw new AssertionError("cannot load " + dotted, failure);
        }
    }

    private static int invoke(Class<?> owner, String name, Class<?>[] parameterTypes, Object... args)
            throws Exception {
        Method method = owner.getMethod(name, parameterTypes);
        try {
            Object result = method.invoke(null, args);
            return ((Integer) result).intValue();
        } catch (InvocationTargetException failure) {
            throw failure;
        }
    }

    private static int count(MethodNode method, int opcode, int operand) {
        int found = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() != opcode) {
                continue;
            }
            if (insn instanceof IntInsnNode && ((IntInsnNode) insn).operand == operand) {
                found++;
            }
        }
        return found;
    }

    private static int countStore(MethodNode method, int slot) {
        int found = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode >= Opcodes.ISTORE && opcode <= Opcodes.ASTORE
                    && ((VarInsnNode) insn).var == slot) {
                found++;
            }
        }
        return found;
    }

    private static long stat(Stats stats, String key) {
        Long value = stats.snapshot().get(key);
        return value == null ? 0L : value.longValue();
    }

    private static void eq(long expected, long actual, String message) {
        check(expected == actual, message + ": expected " + expected + " but was " + actual);
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("BodyOptimizeTest: " + message);
        }
    }
}
