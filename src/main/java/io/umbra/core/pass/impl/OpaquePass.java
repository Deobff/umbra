package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.KeyRootMask;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.pass.impl.opaque.BlockGraph;
import io.umbra.core.pass.impl.opaque.ClassState;
import io.umbra.core.pass.impl.opaque.PredicateRenderer;
import io.umbra.core.pass.impl.opaque.Renderers;
import io.umbra.core.pass.impl.opaque.SeedLoader;
import io.umbra.core.pass.impl.opaque.SeedLoaders;
import io.umbra.core.pass.impl.opaque.SeedSite;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

/**
 * Opaque predicates with a rolling block state (port of the reference implementation's
 * {@code IntegerBlockPredicateRenderer} and its renderer/seed-loader families).
 *
 * <h3>Why it works</h3>
 *
 * <p>Every transformed method gets one extra int local, the <em>rolling state</em>
 * {@code p}. It is written once at the entry with the entry block's seed and
 * rewritten on every control-flow edge to the successor's seed:</p>
 *
 * <pre>
 *   entry:        p = enc(seed(entry), methodPrivate)
 *   edge A -&gt; B:  p = enc(seed(B), seed(A))          == p ^ (seed(A) ^ seed(B))
 *   head of B:    if ((p ^ seed(B)) != 0) &lt;- dead block  (always true on the real path)
 * </pre>
 *
 * <p>{@code enc(outcome, starting)} is the reference's {@code XorNumberTransformer}:
 * {@code (outcome ^ starting) ^ <run time value of the state>}. The build-time
 * half never appears as a literal - it goes through the per-class
 * {@link io.umbra.core.pass.impl.flow.RuntimeTable} {@code int[]}, whose contents
 * are produced by an xorshift chain seeded from {@code System.nanoTime()} in
 * {@code <clinit>} - so no single algebraic rewrite recovers the seed.</p>
 *
 * <p>The guard is always true by construction, and the truth is not a
 * mathematical identity but data flow: only a path that ran the edge setter for
 * the block arrives with {@code p == seed(B)}. Patching a jump, re-entering a
 * block or reusing a block leaves the state one step behind, the comparison
 * flips, and control falls into the dead block. Exception handlers are the one
 * entry that bypasses an edge setter, so a handler block is never guarded and
 * every edge leaving it assigns the successor seed absolutely instead of
 * relative to the state.</p>
 *
 * <h3>Shapes</h3>
 *
 * <p>{@code opaque.renderer} selects the always-true guard
 * ({@code conditional}, {@code switch}, {@code exception}, {@code unconditional},
 * {@code internal} or {@code mix}) and {@code opaque.seed} selects the value
 * shape of the state ({@code static}, {@code enhanced}, {@code exception},
 * {@code switch}, {@code internal} or {@code mix}). Both dimensions keep a
 * separate counter.</p>
 *
 * <h3>Safety</h3>
 *
 * <p>Everything runs through {@link MethodGate}: the method is transformed on a
 * copy, verified, and only then committed; a rejected method keeps its original
 * bytes. Nothing is inserted where the entry frame is not empty (a merged block
 * with a live operand stack, an exception handler), on a constructor before
 * {@code super()} (constructors are not eligible at all), or across a try-range
 * boundary - the guards are stack-neutral, so existing ranges keep covering the
 * same operand stack. The class is rolled back as a whole if the result does not
 * serialize.</p>
 */
public final class OpaquePass implements Pass {

    private static final String LABEL = "umbra.opaque.predicates";

    @Override
    public String name() {
        return "opaque";
    }

    @Override
    public int order() {
        return 88;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool("opaque.enabled", false);
    }

    /**
     * The deterministic stream every seed, name and shape choice of this class
     * comes from. Derived from the seed, a private domain label and the class
     * name, so this layer is reproducible whatever the passes around it draw.
     */
    private static Random classStream(PassContext context, String className) {
        byte[] material = io.umbra.core.util.BuildRoot.derive(context.config().seed(), LABEL);
        long domain = 0L;
        for (int i = 0; i < 8; i++) {
            domain |= (material[i] & 0xFFL) << (8 * i);
        }
        long nameHash = className == null ? 0L : (long) className.hashCode();
        return new Random(domain ^ (nameHash * 0x9E3779B97F4A7C15L) ^ context.config().seed());
    }

    @Override
    public void run(PassContext context) {
        String rendererOption = option(context, "opaque.renderer", "conditional");
        String seedOption = option(context, "opaque.seed", "static");
        int rate = clamp(context.config().optionInt("opaque.rate", 100));
        int maxBlocks = Math.max(1, context.config().optionInt("opaque.maxBlocks", 256));
        boolean deadCode = context.config().optionBool("opaque.deadCode", true);
        int pairBudget = Math.max(2, context.config().optionInt("opaque.tablePairs", 128));

        KeyRootMask mask = KeyRootMask.create(context, true);
        String tableMode = mask == null ? "static" : "native";
        MethodGate gate = new MethodGate(context);

        Tally totals = new Tally();
        int classes = 0;
        int methods = 0;
        int rollbacks = 0;
        int totalClasses = 0;
        int totalMethods = 0;

        Map<String, Integer> seedClasses = new LinkedHashMap<String, Integer>();

        for (ClassNode node : context.classes().classes().values()) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                totals.skippedHelper++;
                continue;
            }
            if (!context.rules().skipBodyTransform(node.name) && context.rules().transformClass(node)) {
                totalClasses++;
                for (MethodNode method : node.methods) {
                    if (countsAsMethod(method)) {
                        totalMethods++;
                    }
                }
            }
            if (context.rules().skipBodyTransform(node.name)) {
                totals.skippedRule++;
                continue;
            }
            if (!context.rules().transformClass(node)) {
                totals.skippedRule++;
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0
                    || "module-info".equals(node.name)) {
                totals.skippedShape++;
                continue;
            }

            Random random = classStream(context, node.name);
            String seedName = SeedLoaders.pickName(seedOption, random);
            ClassState state = new ClassState(context, node, random, pairBudget, mask);
            SeedLoader loader = SeedLoaders.create(seedName, random, state);
            state.setLoader(loader);
            state.prepare();

            List<MethodNode> originals = new ArrayList<MethodNode>(node.methods);
            List<MethodNode> snapshots = new ArrayList<MethodNode>();
            for (MethodNode method : originals) {
                snapshots.add(MethodGate.copy(method));
            }
            List<FieldNode> savedFields = new ArrayList<FieldNode>(node.fields);

            Tally cls = new Tally();
            int classMethods = 0;
            try {
                for (MethodNode method : originals) {
                    if (!eligible(context, method)) {
                        cls.ineligible++;
                        continue;
                    }
                    MethodNode work = MethodGate.copy(method);
                    boolean changed;
                    try {
                        changed = instrument(state, work, node.name, rate, maxBlocks, deadCode,
                                random, rendererOption, cls);
                    } catch (RuntimeException failure) {
                        cls.analysisSkipped++;
                        context.log().debug("opaque: left %s.%s untouched: %s",
                                node.name, method.name, failure.toString());
                        continue;
                    }
                    if (!changed) {
                        continue;
                    }
                    if (!gate.verify(node, work)) {
                        cls.verifySkipped++;
                        context.log().debug("opaque: verification rejected %s.%s",
                                node.name, method.name);
                        continue;
                    }
                    MethodGate.commit(method, work);
                    classMethods++;
                }
                if (classMethods == 0) {
                    totals.skippedNoMethods++;
                    totals.add(cls);
                    continue;
                }
                loader.materialize(state);
                state.materialize();
                if (!gate.writes(node)) {
                    restore(node, originals, snapshots, savedFields);
                    rollbacks++;
                    totals.add(cls);
                    context.log().debug("opaque: rolled back class %s: it does not serialize",
                            node.name);
                    continue;
                }
                classes++;
                methods += classMethods;
                totals.add(cls);
                totals.runtimePairs += state.runtimePairs();
                totals.plainConstants += state.plainConstants();
                totals.seed(seedName, classMethods);
                Integer seen = seedClasses.get(seedName);
                seedClasses.put(seedName, Integer.valueOf(seen == null ? 1 : seen.intValue() + 1));
            } catch (RuntimeException failure) {
                restore(node, originals, snapshots, savedFields);
                rollbacks++;
                totals.add(cls);
                context.log().debug("opaque: rolled back class %s: %s", node.name, failure.toString());
            }
        }

        context.stats().add("opaque.methods", methods);
        context.stats().add("opaque.classes", classes);
        context.stats().add("opaque.blocks", totals.blocks);
        context.stats().add("opaque.setters", totals.setters);
        context.stats().add("opaque.runtimePairs", totals.runtimePairs);
        context.stats().add("opaque.plainConstants", totals.plainConstants);
        context.stats().add("opaque.skipped.stack", totals.skippedStack);
        context.stats().add("opaque.skipped.blocks", totals.skippedBlocks);
        context.stats().add("opaque.skipped.handlers", totals.skippedHandlers);
        context.stats().add("opaque.skipped.rate", totals.skippedRate);
        context.stats().add("opaque.skipped.analysis", totals.analysisSkipped);
        context.stats().add("opaque.skipped.verify", totals.verifySkipped);
        context.stats().add("opaque.skipped.ineligible", totals.ineligible);
        context.stats().add("opaque.skipped.classes", totals.skippedRule + totals.skippedShape
                + totals.skippedHelper + totals.skippedNoMethods);
        context.stats().add("opaque.skip.rollback", rollbacks);
        context.stats().add("opaque.methods.total", totalMethods);
        for (Map.Entry<String, Integer> entry : totals.seedCounts.entrySet()) {
            context.stats().add("opaque.seed." + entry.getKey(), entry.getValue().intValue());
        }
        for (String name : SeedLoaders.names()) {
            context.stats().add("opaque.seed." + name + ".classes",
                    seedClasses.containsKey(name) ? seedClasses.get(name).intValue() : 0);
        }
        for (String name : Renderers.names()) {
            context.stats().add("opaque.renderers." + name,
                    totals.guards.containsKey(name) ? totals.guards.get(name).intValue() : 0);
        }
        context.stats().text("opaque.coverage",
                String.valueOf(classes) + "/" + String.valueOf(totalClasses));
        context.stats().text("opaque.tableMode", tableMode);
        context.log().info("opaque-predicates[renderer=%s seed=%s rate=%d table=%s]: %d methods "
                        + "in %d/%d classes, %d guards, %d seed setters, %d stack/handler blocks "
                        + "skipped, %d rollbacks",
                rendererOption, seedOption, Integer.valueOf(rate), tableMode,
                Integer.valueOf(methods), Integer.valueOf(classes), Integer.valueOf(totalClasses),
                Integer.valueOf(totals.blocks), Integer.valueOf(totals.setters),
                Integer.valueOf(totals.skippedStack + totals.skippedHandlers),
                Integer.valueOf(rollbacks));
    }

    /**
     * Rewrites one method. Returns true only when at least one guard was emitted,
     * so a method that can take no predicate keeps its original bytes.
     */
    private static boolean instrument(ClassState state, MethodNode method, String owner,
                                      int rate, int maxBlocks, boolean deadCode,
                                      Random random, String rendererOption, Tally tally) {
        Frame<BasicValue>[] frames;
        try {
            frames = new Analyzer<BasicValue>(new BasicInterpreter()).analyze(owner, method);
        } catch (Throwable failure) {
            tally.analysisSkipped++;
            return false;
        }
        List<BlockGraph.Block> blocks = BlockGraph.build(method, frames);
        if (blocks == null || blocks.isEmpty()) {
            tally.analysisSkipped++;
            return false;
        }
        Tally mine = new Tally();
        if (blocks.size() > maxBlocks) {
            mine.skippedBlocks += blocks.size();
            tally.add(mine);
            return false;
        }
        BlockGraph.Block entry = blocks.get(0);
        if (!entry.reachable) {
            mine.skippedBlocks += blocks.size();
            tally.add(mine);
            return false;
        }
        int local = nextFreeLocal(method);
        if (local > 60000) {
            mine.skippedBlocks += blocks.size();
            tally.add(mine);
            return false;
        }
        method.maxLocals = Math.max(method.maxLocals, local + 1);

        for (int i = 0; i < blocks.size(); i++) {
            blocks.get(i).value = random.nextInt();
        }
        int privateValue = random.nextInt();

        InsnList prelude = new InsnList();
        state.loader().pushValue(prelude, state, local,
                new SeedSite(entry.value, privateValue, SeedSite.OPERAND_PRIVATE, privateValue));
        prelude.add(new VarInsnNode(Opcodes.ISTORE, local));
        method.instructions.insert(prelude);

        // Edge setters first: a fall-through setter lands before the target block's
        // labels and every forward edge gets a stub at the end of the method, so the
        // guard that is inserted afterwards always runs once the state is correct.
        InsnList stubs = new InsnList();
        InsnList deferred = new InsnList();
        int stubCount = 0;
        int setters = 0;
        for (BlockGraph.Block block : blocks) {
            if (!block.reachable) {
                mine.skippedBlocks++;
                continue;
            }
            for (BlockGraph.Edge edge : block.edges) {
                SeedSite site = block.handler
                        ? new SeedSite(edge.target.value, 0, SeedSite.OPERAND_ZERO, 0)
                        : new SeedSite(edge.target.value, block.value, SeedSite.OPERAND_LOCAL, 0);
                InsnList setter = new InsnList();
                state.loader().pushValue(setter, state, local, site);
                setter.add(new VarInsnNode(Opcodes.ISTORE, local));
                if (edge.kind == BlockGraph.KIND_FALLTHROUGH) {
                    method.instructions.insertBefore(edge.target.start, setter);
                } else {
                    LabelNode stub = new LabelNode();
                    stubs.add(stub);
                    stubs.add(setter);
                    stubs.add(new JumpInsnNode(Opcodes.GOTO, edge.label));
                    BlockGraph.retarget(edge, stub);
                    stubCount++;
                }
                setters++;
            }
        }

        int guards = 0;
        for (BlockGraph.Block block : blocks) {
            if (!block.reachable) {
                continue;
            }
            if (block.handler) {
                mine.skippedHandlers++;
                continue;
            }
            if (!block.guardable) {
                mine.skippedStack++;
                continue;
            }
            if (rate < 100 && random.nextInt(100) >= rate) {
                mine.skippedRate++;
                continue;
            }
            PredicateRenderer renderer = Renderers.pick(rendererOption, random);
            boolean throwDead = deadCode && random.nextInt(4) == 0;
            InsnList guard = new InsnList();
            renderer.emitGuard(guard, deferred, method, state, local, block.value, deadCode,
                    throwDead);
            method.instructions.insertBefore(block.firstReal, guard);
            guards++;
            mine.guard(renderer.name());
        }
        if (stubCount > 0) {
            method.instructions.add(stubs);
        }
        // Exception handlers go last: ASM's frame computation cannot order a handler
        // that sits between its protected range and the code that follows it.
        method.instructions.add(deferred);
        if (guards == 0) {
            // Every block was already accounted for by the counters above (rate,
            // stack, handler), so counting the method again would double count.
            tally.add(mine);
            return false;
        }
        mine.blocks += guards;
        mine.setters += setters;
        tally.add(mine);
        return true;
    }

    private static boolean eligible(PassContext context, MethodNode method) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        if (method.instructions == null || method.instructions.size() < 2) {
            return false;
        }
        if (AsmUtil.containsJsrOrRet(method)) {
            return false;
        }
        return !context.rules().hasKeepAnnotation(method);
    }

    private static boolean countsAsMethod(MethodNode method) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        return !method.name.startsWith("<");
    }

    /**
     * Restores a rolled-back class in place: the original {@link MethodNode}
     * objects keep their annotations and the snapshotted bodies are put back, and
     * the members {@code materialize()} added are dropped with the method and
     * field lists.
     */
    private static void restore(ClassNode node, List<MethodNode> originals,
                                List<MethodNode> snapshots, List<FieldNode> fields) {
        for (int i = 0; i < originals.size() && i < snapshots.size(); i++) {
            MethodNode target = originals.get(i);
            MethodNode snapshot = snapshots.get(i);
            target.instructions = snapshot.instructions;
            target.tryCatchBlocks = snapshot.tryCatchBlocks;
            target.maxStack = snapshot.maxStack;
            target.maxLocals = snapshot.maxLocals;
            target.localVariables = snapshot.localVariables;
        }
        node.methods = new ArrayList<MethodNode>(originals);
        node.fields = new ArrayList<FieldNode>(fields);
    }

    private static int nextFreeLocal(MethodNode method) {
        int used = Math.max(0, method.maxLocals);
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof VarInsnNode) {
                int slot = ((VarInsnNode) insn).var;
                int size = (insn.getOpcode() == Opcodes.LLOAD || insn.getOpcode() == Opcodes.LSTORE
                        || insn.getOpcode() == Opcodes.DLOAD
                        || insn.getOpcode() == Opcodes.DSTORE) ? 2 : 1;
                used = Math.max(used, slot + size);
            } else if (insn instanceof IincInsnNode) {
                used = Math.max(used, ((IincInsnNode) insn).var + 1);
            }
        }
        return used;
    }

    private static String option(PassContext context, String key, String fallback) {
        String value = context.config().option(key, fallback);
        if (value == null) {
            return fallback;
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private static int clamp(int value) {
        return Math.max(0, Math.min(100, value));
    }

    /** Mutable counter bag; merged into the run totals only when a class is kept. */
    private static final class Tally {
        int blocks;
        int setters;
        int skippedStack;
        int skippedBlocks;
        int skippedHandlers;
        int skippedRate;
        int analysisSkipped;
        int verifySkipped;
        int ineligible;
        int runtimePairs;
        int plainConstants;
        int skippedHelper;
        int skippedRule;
        int skippedShape;
        int skippedNoMethods;
        final Map<String, Integer> guards = new LinkedHashMap<String, Integer>();
        final Map<String, Integer> seedCounts = new LinkedHashMap<String, Integer>();

        void guard(String name) {
            Integer old = guards.get(name);
            guards.put(name, Integer.valueOf(old == null ? 1 : old.intValue() + 1));
        }

        void seed(String name, int count) {
            Integer old = seedCounts.get(name);
            seedCounts.put(name, Integer.valueOf(old == null ? count : old.intValue() + count));
        }

        void add(Tally other) {
            blocks += other.blocks;
            setters += other.setters;
            skippedStack += other.skippedStack;
            skippedBlocks += other.skippedBlocks;
            skippedHandlers += other.skippedHandlers;
            skippedRate += other.skippedRate;
            analysisSkipped += other.analysisSkipped;
            verifySkipped += other.verifySkipped;
            ineligible += other.ineligible;
            runtimePairs += other.runtimePairs;
            plainConstants += other.plainConstants;
            skippedHelper += other.skippedHelper;
            skippedRule += other.skippedRule;
            skippedShape += other.skippedShape;
            skippedNoMethods += other.skippedNoMethods;
            for (Map.Entry<String, Integer> entry : other.guards.entrySet()) {
                Integer old = guards.get(entry.getKey());
                guards.put(entry.getKey(), Integer.valueOf(old == null
                        ? entry.getValue().intValue()
                        : old.intValue() + entry.getValue().intValue()));
            }
            for (Map.Entry<String, Integer> entry : other.seedCounts.entrySet()) {
                Integer old = seedCounts.get(entry.getKey());
                seedCounts.put(entry.getKey(), Integer.valueOf(old == null
                        ? entry.getValue().intValue()
                        : old.intValue() + entry.getValue().intValue()));
            }
        }
    }
}
