package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.OpaquePass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Tests for the opaque-predicate pass (the reference implementation port).
 *
 * <p>Synthesises six methods - arithmetic, if/else, loop, try/catch, table
 * switch, early return - and, for every renderer x seed combination, runs the
 * pass, verifies the produced class with {@link CheckClassAdapter}, defines it
 * in a real JVM and compares every result with a plain Java reference. Then it
 * checks the statistics, the determinism of a repeated run, and the two
 * rollback paths (a JSR/RET method that makes the class unserializable, and a
 * method over the block budget).</p>
 */
public final class OpaqueTest {

    private static final String TARGET = "test/OpaqueTarget";
    private static final String TARGET_DOTTED = "test.OpaqueTarget";

    private static final String[] RENDERERS = {
            "conditional", "switch", "exception", "unconditional", "internal"
    };

    private static final String[] SEEDS = {
            "static", "enhanced", "exception", "switch", "internal"
    };

    private static int checks;

    private OpaqueTest() {
    }

    public static void main(String[] args) throws Exception {
        startWatchdog();
        testOptIn();
        testBaseline();
        testCombinations();
        testDeterminism();
        testRate();
        testDeadCodeFlag();
        testRuntimeTablesOff();
        testTableBudget();
        testRollbackJsr();
        testBlockBudget();
        System.out.println("OpaqueTest: " + checks + " checks passed");
    }

    private static void startWatchdog() {
        final long timeout = Long.parseLong(System.getProperty("umbra.opaquetest.watchdog", "240000"));
        Thread watchdog = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(timeout);
                } catch (InterruptedException ignored) {
                    return;
                }
                System.err.println("OpaqueTest WATCHDOG after " + timeout + "ms");
                Runtime.getRuntime().halt(3);
            }
        }, "opaque-test-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    /** The pass has to be opt-in: nothing may change unless the option asks for it. */
    private static void testOptIn() throws Exception {
        ClassNode node = target();
        byte[] original = serialize(node);
        PassContext off = context(original, node, 1L, "conditional", "static", null, false);
        check(!new OpaquePass().enabled(off), "opaque pass is off by default");
        PassContext on = context(original, node, 1L, "conditional", "static", null, true);
        check(new OpaquePass().enabled(on), "opaque pass turns on with opaque.enabled");
        OpaquePass pass = new OpaquePass();
        check(pass.order() == 88, "opaque pass keeps order 88");
        check("opaque".equals(pass.name()), "opaque pass name");
    }

    /** Untransformed class first, then the transformed one, both against the reference. */
    private static void testBaseline() throws Exception {
        ClassNode node = target();
        byte[] original = serialize(node);
        Class<?> baseline = verifyAndLoad(original, "baseline");
        assertBehaviour(baseline, "baseline");

        PassContext context = context(original, node, 3131L, "unconditional", "enhanced", null);
        new OpaquePass().run(context);
        byte[] transformed = serialize(node, context.hierarchy());
        Class<?> after = verifyAndLoad(transformed, "baseline/transformed");
        assertBehaviour(after, "baseline/transformed");
        check(original.length != transformed.length || !Arrays.equals(original, transformed),
                "baseline: transformed bytes differ");
    }

    /** Every renderer x seed combination on the six synthetic methods. */
    private static void testCombinations() throws Exception {
        String only = System.getProperty("umbra.opaquetest.only", "");
        for (String renderer : RENDERERS) {
            StringBuilder line = new StringBuilder();
            for (String seedName : SEEDS) {
                if (!only.isEmpty() && !only.equals(renderer + "/" + seedName)) {
                    continue;
                }
                int before = checks;
                runCombination(renderer, seedName);
                line.append(' ').append(seedName).append('=').append(checks - before);
            }
            if (line.length() > 0) {
                System.out.println("OpaqueTest: renderer " + renderer + " ->" + line);
            }
        }
    }

    private static void runCombination(String renderer, String seedName) throws Exception {
        String phase = renderer + "/" + seedName;
        ClassNode node = target();
        byte[] original = serialize(node);
        PassContext context = context(original, node, 8801L, renderer, seedName, null);
        new OpaquePass().run(context);
        byte[] transformed = serialize(node, context.hierarchy());

        check(!Arrays.equals(original, transformed), phase + ": class bytes changed; stats="
                + new LinkedHashMap<String, Long>(context.stats().snapshot()));
        Class<?> type = verifyAndLoad(transformed, phase);
        assertBehaviour(type, phase);

        check(stat(context, "opaque.methods") == 7, phase + ": every method transformed");
        check(stat(context, "opaque.blocks") >= 7, phase + ": guards emitted");
        check(stat(context, "opaque.setters") >= 7, phase + ": seed setters emitted");
        check(stat(context, "opaque.skipped.stack") == 0, phase + ": no block skipped for stack");
        check(stat(context, "opaque.skipped.blocks") == 0, phase + ": no block skipped");
        check(stat(context, "opaque.skip.rollback") == 0, phase + ": no rollback");
        check(stat(context, "opaque.renderers." + renderer) >= 7, phase + ": renderer counter");
        check(stat(context, "opaque.seed." + seedName) == 7, phase + ": seed counter");
        check(stat(context, "opaque.runtimePairs") > 0, phase + ": edge masks via runtime table");
        check(stat(context, "opaque.skipped.handlers") >= 1,
                phase + ": the try/catch handler block is skipped on purpose");

        // Structural evidence: the helper (and, for enhanced, the parity fields).
        // Only the internal seed inlines the XOR; every other seed, and the internal
        // guard shape regardless of the seed, needs the per-class helper.
        boolean wantsHelper = !"internal".equals(seedName) || "internal".equals(renderer);
        check(helperCount(node) == (wantsHelper ? 1 : 0), phase + ": helper count, got "
                + helperCount(node) + " in " + describe(node));
        if ("enhanced".equals(seedName)) {
            check(intStaticFields(node) == 2, phase + ": parity field pair materialised");
        }
        // Guard shapes: internal always calls the helper, exception always registers a handler.
        if ("internal".equals(renderer)) {
            check(callsHelper(node), phase + ": internal guards call the helper");
        }
        if ("exception".equals(renderer)) {
            check(handlerCount(node) > 0, phase + ": exception guards registered handlers");
        }
        if ("switch".equals(renderer)) {
            check(tableSwitchCount(node) > 0, phase + ": switch guards emitted tableswitch");
        }
        // The rolling state must live in a fresh slot above the original frame.
        check(usesExtraLocal(node), phase + ": rolling state uses a new local slot");
    }

    /** Same seed, two runs, byte-identical output. */
    private static void testDeterminism() throws Exception {
        byte[] first = runMixed(4242L);
        byte[] second = runMixed(4242L);
        check(Arrays.equals(first, second), "same seed produces identical bytes");

        ClassNode node = target();
        byte[] original = serialize(node);
        PassContext context = context(original, node, 4242L, "mix", "mix", null);
        new OpaquePass().run(context);
        check(stat(context, "opaque.methods") == 7, "mixed shapes still cover every method");
        Map<String, Long> statsBefore = new LinkedHashMap<String, Long>(context.stats().snapshot());
        ClassNode again = target();
        PassContext repeat = context(serialize(again), again, 4242L, "mix", "mix", null);
        new OpaquePass().run(repeat);
        check(statsBefore.equals(new LinkedHashMap<String, Long>(repeat.stats().snapshot())),
                "same seed produces identical statistics");
        assertBehaviour(verifyAndLoad(serialize(again, repeat.hierarchy()), "mix"), "mix");
    }

    private static byte[] runMixed(long seed) throws Exception {
        ClassNode node = target();
        PassContext context = context(serialize(node), node, seed, "mix", "mix", null);
        new OpaquePass().run(context);
        return serialize(node, context.hierarchy());
    }

    /** {@code opaque.rate} thins the guards out without breaking anything. */
    private static void testRate() throws Exception {
        ClassNode full = target();
        PassContext fullContext = context(serialize(full), full, 515L, "conditional", "static", null);
        new OpaquePass().run(fullContext);

        ClassNode sparse = target();
        Map<String, String> extra = new HashMap<String, String>();
        extra.put("opaque.rate", "40");
        PassContext sparseContext = context(serialize(sparse), sparse, 515L, "conditional", "static",
                extra);
        new OpaquePass().run(sparseContext);

        check(stat(sparseContext, "opaque.blocks") > 0, "rate 40 still emits guards");
        check(stat(sparseContext, "opaque.blocks") < stat(fullContext, "opaque.blocks"),
                "rate 40 emits fewer guards than rate 100");
        check(stat(sparseContext, "opaque.skipped.rate") > 0, "rate 40 counts the blocks it skipped");
        check(stat(sparseContext, "opaque.skip.rollback") == 0, "rate 40 does not roll anything back");
        assertBehaviour(verifyAndLoad(serialize(sparse, sparseContext.hierarchy()), "rate40"),
                "rate40");
    }

    /** {@code opaque.deadCode=false} drops the junk payload but keeps every guard. */
    private static void testDeadCodeFlag() throws Exception {
        ClassNode loud = target();
        PassContext loudContext = context(serialize(loud), loud, 616L, "conditional", "static", null);
        new OpaquePass().run(loudContext);

        ClassNode quiet = target();
        Map<String, String> extra = new HashMap<String, String>();
        extra.put("opaque.deadCode", "false");
        PassContext quietContext = context(serialize(quiet), quiet, 616L, "conditional", "static",
                extra);
        new OpaquePass().run(quietContext);

        check(stat(quietContext, "opaque.blocks") == stat(loudContext, "opaque.blocks"),
                "deadCode=false keeps the same number of guards");
        check(instructionTotal(quiet) < instructionTotal(loud),
                "deadCode=false removes the junk payload");
        assertBehaviour(verifyAndLoad(serialize(quiet, quietContext.hierarchy()), "nodead"),
                "nodead");
    }

    /** With the runtime table switched off every mask becomes a plain constant, and it still runs. */
    private static void testRuntimeTablesOff() throws Exception {
        ClassNode node = target();
        Map<String, String> extra = new HashMap<String, String>();
        extra.put("flow.runtimeTables", "false");
        PassContext context = context(serialize(node), node, 8181L, "switch", "enhanced", extra);
        new OpaquePass().run(context);

        check(stat(context, "opaque.runtimePairs") == 0, "no table pairs without the runtime table");
        check(stat(context, "opaque.plainConstants") > 0, "every mask degrades to a constant");
        check(stat(context, "opaque.methods") == 7, "degraded build still covers every method");
        assertBehaviour(verifyAndLoad(serialize(node, context.hierarchy()), "notable"), "notable");
    }

    /** An exhausted {@code opaque.tablePairs} budget degrades to plain constants and is counted. */
    private static void testTableBudget() throws Exception {
        ClassNode node = target();
        Map<String, String> extra = new HashMap<String, String>();
        extra.put("opaque.tablePairs", "4");
        PassContext context = context(serialize(node), node, 717L, "conditional", "static", extra);
        new OpaquePass().run(context);

        check(stat(context, "opaque.runtimePairs") > 0, "table budget is used before it runs out");
        check(stat(context, "opaque.plainConstants") > 0,
                "over-budget masks degrade to plain constants and are counted");
        check(stat(context, "opaque.blocks") >= 7, "degraded masks still guard every block");
        assertBehaviour(verifyAndLoad(serialize(node, context.hierarchy()), "tablebudget"),
                "tablebudget");
    }

    /**
     * A JSR/RET method cannot be carried through ASM's frame computation, so the
     * class has to be rolled back as a whole and still write.
     */
    private static void testRollbackJsr() throws Exception {
        ClassNode node = target();
        node.version = Opcodes.V1_5;
        node.methods.add(jsrMethod());
        byte[] original = serialize(node);
        PassContext context = context(original, node, 9911L, "conditional", "static", null);
        new OpaquePass().run(context);

        check(stat(context, "opaque.skip.rollback") == 1, "JSR class rolled back exactly once");
        check(stat(context, "opaque.methods") == 0, "no method counted after the rollback");
        check(helperCount(node) == 0, "helper method dropped by the rollback");
        check(intStaticFields(node) == 0, "no loader fields left behind");
        check(methodCount(node) == 8, "method list restored");
        check(instructionCount(node, "arith") == 8, "method body restored byte for byte");
        check(containsJsr(node), "the JSR/RET method itself was skipped");

        byte[] written = serialize(node);
        check(written != null && written.length > 0, "rolled-back class still serializes");
        Class<?> type = load(written);
        check(callInt2(type, "arith", 3, 4) == 3 * 31 + 4 - 7, "restored method still runs");
        check(callInt(type, "tryCatch", 0) == -1, "restored handler still runs");
    }

    /** A method over {@code opaque.maxBlocks} is skipped; its class is kept and works. */
    private static void testBlockBudget() throws Exception {
        ClassNode node = target();
        node.methods.add(chain());
        byte[] original = serialize(node);
        Map<String, String> extra = new HashMap<String, String>();
        extra.put("opaque.maxBlocks", "16");
        PassContext context = context(original, node, 7717L, "unconditional", "switch", extra);
        new OpaquePass().run(context);

        check(stat(context, "opaque.skipped.blocks") >= 16, "over-budget method skipped");
        check(stat(context, "opaque.skip.rollback") == 0, "the class itself is kept");
        check(stat(context, "opaque.methods") == 7, "the small methods are still transformed");
        check(instructionCount(node, "chain") == chainOriginalSize, "skipped method kept its body");

        Class<?> type = verifyAndLoad(serialize(node, context.hierarchy()), "budget");
        assertBehaviour(type, "budget");
        for (int i = 0; i < 40; i += 7) {
            check(callInt(type, "chain", i) == i * 3, "chain(" + i + ") after the skip");
        }
        check(callInt(type, "chain", 40) == -1, "chain default case after the skip");
    }

    // ---------------------------------------------------------------- reference

    private static void assertBehaviour(Class<?> type, String phase) throws Exception {
        int[] left = { 1, 0, -5, Integer.MAX_VALUE, 123456, 7, -1 };
        int[] right = { 2, 0, 7, 1, -98765, -7, 9 };
        for (int i = 0; i < left.length; i++) {
            int a = left[i];
            int b = right[i];
            check(callInt2(type, "arith", a, b) == a * 31 + b - 7, phase + " arith(" + a + "," + b + ")");
        }
        int[] branchInputs = { 5, 0, -3, Integer.MIN_VALUE, 1, -1, 1000 };
        for (int a : branchInputs) {
            check(callInt(type, "branch", a) == (a > 0 ? a + 1 : -a), phase + " branch(" + a + ")");
        }
        int[] loopInputs = { 0, 1, 10, 100, -5 };
        for (int n : loopInputs) {
            int expected = 0;
            for (int i = 1; i <= n; i++) {
                expected += i;
            }
            check(callInt(type, "loop", n) == expected, phase + " loop(" + n + ")");
        }
        int[] divInputs = { 0, 5, -7, 100, 3 };
        for (int a : divInputs) {
            check(callInt(type, "tryCatch", a) == (a == 0 ? -1 : 100 / a), phase + " tryCatch(" + a + ")");
        }
        for (int a = -1; a <= 5; a++) {
            check(callInt(type, "switcher", a) == switchReference(a), phase + " switcher(" + a + ")");
        }
        int[] earlyInputs = { -1, 0, 7, Integer.MIN_VALUE, 3, -100 };
        for (int a : earlyInputs) {
            int expected = a < 0 ? -2 : (a == 0 ? 0 : a * 2);
            check(callInt(type, "early", a) == expected, phase + " early(" + a + ")");
        }
        long[] wideLeft = { 1L, 0L, -7L, 1000000000000L, Long.MAX_VALUE };
        long[] wideRight = { 2L, 0L, 3L, -5L, -1L };
        for (int i = 0; i < wideLeft.length; i++) {
            long a = wideLeft[i];
            long b = wideRight[i];
            check(callLong2(type, "wide", a, b) == a * 3L + b,
                    phase + " wide(" + a + "," + b + ")");
        }
    }

    private static int switchReference(int value) {
        switch (value) {
            case 0: return 10;
            case 1: return 20;
            case 2: return 30;
            case 3: return 40;
            default: return -1;
        }
    }

    // ------------------------------------------------------------------- target

    private static ClassNode target() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = TARGET;
        node.superName = "java/lang/Object";
        node.methods = new ArrayList<MethodNode>();
        node.fields = new ArrayList<FieldNode>();
        node.methods.add(arith());
        node.methods.add(branch());
        node.methods.add(loop());
        node.methods.add(tryCatch());
        node.methods.add(switcher());
        node.methods.add(early());
        node.methods.add(wide());
        return node;
    }

    private static MethodNode method(String name, String desc, int maxLocals, int maxStack) {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, desc, null, null);
        method.maxLocals = maxLocals;
        method.maxStack = maxStack;
        return method;
    }

    private static MethodNode arith() {
        MethodNode method = method("arith", "(II)I", 2, 3);
        InsnList insns = method.instructions;
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new IntInsnNode(Opcodes.BIPUSH, 31));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        insns.add(new InsnNode(Opcodes.ISUB));
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode branch() {
        MethodNode method = method("branch", "(I)I", 2, 2);
        InsnList insns = method.instructions;
        LabelNode otherwise = new LabelNode();
        LabelNode end = new LabelNode();
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 1));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new JumpInsnNode(Opcodes.IFLE, otherwise));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, end));
        insns.add(otherwise);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.INEG));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 1));
        insns.add(end);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode loop() {
        MethodNode method = method("loop", "(I)I", 3, 2);
        InsnList insns = method.instructions;
        LabelNode condition = new LabelNode();
        LabelNode end = new LabelNode();
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 1));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 2));
        insns.add(condition);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 2));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGT, end));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 2));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 1));
        insns.add(new IincInsnNode(2, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, condition));
        insns.add(end);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode tryCatch() {
        MethodNode method = method("tryCatch", "(I)I", 2, 2);
        InsnList insns = method.instructions;
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        insns.add(start);
        insns.add(new IntInsnNode(Opcodes.BIPUSH, 100));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.IDIV));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(end);
        insns.add(handler);
        insns.add(new VarInsnNode(Opcodes.ASTORE, 1));
        insns.add(new InsnNode(Opcodes.ICONST_M1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        method.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
        method.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler,
                "java/lang/ArithmeticException"));
        return method;
    }

    private static MethodNode switcher() {
        MethodNode method = method("switcher", "(I)I", 1, 1);
        InsnList insns = method.instructions;
        LabelNode fallback = new LabelNode();
        LabelNode[] cases = new LabelNode[4];
        for (int i = 0; i < cases.length; i++) {
            cases[i] = new LabelNode();
        }
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new TableSwitchInsnNode(0, 3, fallback, cases));
        for (int i = 0; i < cases.length; i++) {
            insns.add(cases[i]);
            insns.add(new IntInsnNode(Opcodes.BIPUSH, (i + 1) * 10));
            insns.add(new InsnNode(Opcodes.IRETURN));
        }
        insns.add(fallback);
        insns.add(new InsnNode(Opcodes.ICONST_M1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode early() {
        MethodNode method = method("early", "(I)I", 1, 2);
        InsnList insns = method.instructions;
        LabelNode negative = new LabelNode();
        LabelNode zero = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new JumpInsnNode(Opcodes.IFLT, negative));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, zero));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.ICONST_2));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(negative);
        insns.add(new IntInsnNode(Opcodes.BIPUSH, -2));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(zero);
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    /** {@code wide(a, b) = a * 3 + b}: two long parameters occupying slots 0..3. */
    private static MethodNode wide() {
        MethodNode method = method("wide", "(JJ)J", 4, 4);
        InsnList insns = method.instructions;
        insns.add(new VarInsnNode(Opcodes.LLOAD, 0));
        insns.add(new org.objectweb.asm.tree.LdcInsnNode(Long.valueOf(3L)));
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new VarInsnNode(Opcodes.LLOAD, 2));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new InsnNode(Opcodes.LRETURN));
        return method;
    }

    /** {@code chain(i)} = i * 3 for i in 0..39 and -1 otherwise, built from 40 blocks. */
    private static MethodNode chain() {
        MethodNode method = method("chain", "(I)I", 1, 2);
        InsnList insns = method.instructions;
        for (int i = 0; i < 40; i++) {
            LabelNode next = new LabelNode();
            insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
            insns.add(new IntInsnNode(Opcodes.BIPUSH, i));
            insns.add(new JumpInsnNode(Opcodes.IF_ICMPNE, next));
            io.umbra.core.util.AsmUtil.pushInt(insns, i * 3);
            insns.add(new InsnNode(Opcodes.IRETURN));
            insns.add(next);
        }
        insns.add(new InsnNode(Opcodes.ICONST_M1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static final int chainOriginalSize = 40 * 6 + 2;

    /** A legacy subroutine: illegal for ASM's frame computation, legal for a V1_5 class. */
    private static MethodNode jsrMethod() {
        MethodNode method = method("jsrLike", "()I", 1, 1);
        InsnList insns = method.instructions;
        LabelNode subroutine = new LabelNode();
        insns.add(new JumpInsnNode(Opcodes.JSR, subroutine));
        insns.add(new InsnNode(Opcodes.ICONST_5));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(subroutine);
        insns.add(new VarInsnNode(Opcodes.ASTORE, 0));
        insns.add(new VarInsnNode(Opcodes.RET, 0));
        return method;
    }

    // ------------------------------------------------------------------ context

    private static PassContext context(byte[] originalBytes, ClassNode node, long seed,
                                       String renderer, String seedName, Map<String, String> extra) {
        return context(originalBytes, node, seed, renderer, seedName, extra, true);
    }

    private static PassContext context(byte[] originalBytes, ClassNode node, long seed,
                                       String renderer, String seedName, Map<String, String> extra,
                                       boolean enable) {
        try {
            UmbraConfig.Builder builder = new UmbraConfig.Builder()
                    .input(Paths.get("in.jar"))
                    .output(Paths.get("out.jar"))
                    .seed(seed)
                    .option("opaque.enabled", String.valueOf(enable))
                    .option("opaque.renderer", renderer)
                    .option("opaque.seed", seedName)
                    .option("opaque.rate", "100")
                    .option("opaque.maxBlocks", "256")
                    .option("opaque.deadCode", "true")
                    .option("opaque.tablePairs", "128");
            if (extra != null) {
                for (Map.Entry<String, String> entry : extra.entrySet()) {
                    builder.option(entry.getKey(), entry.getValue());
                }
            }
            UmbraConfig config = builder.build();
            ClassPool pool = new ClassPool();
            pool.putClass(node.name + ".class", originalBytes, node);
            Hierarchy hierarchy = new Hierarchy();
            hierarchy.addInput(node);
            DefaultRuleSet rules = new DefaultRuleSet(new ArrayList<String>(),
                    new ArrayList<String>(), false, false);
            Log log = Boolean.getBoolean("umbra.opaquetest.verbose")
                    ? Log.console(true) : new Log(null, false);
            return new PassContext(config, pool, hierarchy, rules, new DefaultRuntimeSupport(),
                    new MappingSet(), new Stats(), log, new Random(seed), ProgressListener.NONE);
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }

    // ------------------------------------------------------------------ helpers

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
        check(errors.isEmpty(), "CheckClassAdapter (" + phase + "): " + tail(errors));
        return load(bytes);
    }

    private static Class<?> load(byte[] bytes) {
        final Map<String, byte[]> classes = new HashMap<String, byte[]>();
        classes.put(TARGET_DOTTED, bytes);
        ClassLoader loader = new ClassLoader(OpaqueTest.class.getClassLoader()) {
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
            return Class.forName(TARGET_DOTTED, true, loader);
        } catch (ClassNotFoundException failure) {
            throw new AssertionError("cannot load the transformed class", failure);
        }
    }

    private static int callInt(Class<?> type, String name, int a) throws Exception {
        Method method = type.getDeclaredMethod(name, int.class);
        method.setAccessible(true);
        return ((Integer) method.invoke(null, Integer.valueOf(a))).intValue();
    }

    private static int callInt2(Class<?> type, String name, int a, int b) throws Exception {
        Method method = type.getDeclaredMethod(name, int.class, int.class);
        method.setAccessible(true);
        return ((Integer) method.invoke(null, Integer.valueOf(a), Integer.valueOf(b))).intValue();
    }

    private static long callLong2(Class<?> type, String name, long a, long b) throws Exception {
        Method method = type.getDeclaredMethod(name, long.class, long.class);
        method.setAccessible(true);
        return ((Long) method.invoke(null, Long.valueOf(a), Long.valueOf(b))).longValue();
    }

    private static long stat(PassContext context, String key) {
        Long value = context.stats().snapshot().get(key);
        return value == null ? 0L : value.longValue();
    }

    /** The generated XOR helper: static, synthetic and {@code (II)I} (the target's own arith is public). */
    private static int helperCount(ClassNode node) {
        int count = 0;
        for (MethodNode method : node.methods) {
            if ("(II)I".equals(method.desc)
                    && (method.access & (Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC))
                    == (Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC)) {
                count++;
            }
        }
        return count;
    }

    private static String describe(ClassNode node) {
        StringBuilder out = new StringBuilder("[");
        for (MethodNode method : node.methods) {
            if (out.length() > 1) {
                out.append(", ");
            }
            out.append(method.name).append(method.desc).append('/')
                    .append(Integer.toHexString(method.access));
        }
        return out.append(']').toString();
    }

    private static int intStaticFields(ClassNode node) {
        int count = 0;
        for (FieldNode field : node.fields) {
            if ("I".equals(field.desc) && (field.access & Opcodes.ACC_STATIC) != 0) {
                count++;
            }
        }
        return count;
    }

    private static int methodCount(ClassNode node) {
        return node.methods.size();
    }

    private static int instructionTotal(ClassNode node) {
        int total = 0;
        for (MethodNode method : node.methods) {
            total += method.instructions.size();
        }
        return total;
    }

    private static int instructionCount(ClassNode node, String name) {
        for (MethodNode method : node.methods) {
            if (name.equals(method.name)) {
                return method.instructions.size();
            }
        }
        return -1;
    }

    private static boolean containsJsr(ClassNode node) {
        return io.umbra.core.util.AsmUtil.containsJsrOrRet(node);
    }

    private static boolean callsHelper(ClassNode node) {
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof org.objectweb.asm.tree.MethodInsnNode) {
                    org.objectweb.asm.tree.MethodInsnNode call =
                            (org.objectweb.asm.tree.MethodInsnNode) insn;
                    if (TARGET.equals(call.owner) && "(II)I".equals(call.desc)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static int handlerCount(ClassNode node) {
        int count = 0;
        for (MethodNode method : node.methods) {
            if (method.tryCatchBlocks != null) {
                for (TryCatchBlockNode block : method.tryCatchBlocks) {
                    if ("java/lang/IllegalStateException".equals(block.type)) {
                        count++;
                    }
                }
            }
        }
        return count;
    }

    private static int tableSwitchCount(ClassNode node) {
        int count = 0;
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof TableSwitchInsnNode) {
                    count++;
                }
            }
        }
        return count;
    }

    /** {@code arith} only uses slots 0 and 1 before the pass; the state must be above them. */
    private static boolean usesExtraLocal(ClassNode node) {
        for (MethodNode method : node.methods) {
            if (!"arith".equals(method.name)) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof VarInsnNode && ((VarInsnNode) insn).var >= 2) {
                    return true;
                }
            }
        }
        return false;
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
