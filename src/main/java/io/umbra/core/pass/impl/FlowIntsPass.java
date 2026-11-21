package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.flow.MethodFlowAnalyzer;
import io.umbra.core.pass.impl.flow.KeyRootMask;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.pass.impl.flow.RuntimeTable;
import io.umbra.core.pass.impl.flowints.FlowIntEmitter;
import io.umbra.core.pass.impl.flowints.FlowStatePlan;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.BuildRoot;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.LocalVariableAnnotationNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Flow integers (aidsfuscator {@code FlowIntsTransformer}).
 *
 * <p>Every method gets one extra {@code int} local that carries a control-flow
 * sensitive state. Constants are no longer pushed directly: a site materialises
 * the constant from the state ({@code (s | seed) ^ delta}), and the state itself
 * is advanced block by block with an affine step
 * ({@code s = s * A + B}). A reader therefore has to reconstruct the whole state
 * history of every path before a single constant collapses, which is exactly the
 * property {@code ConstantValue} scanning, algebraic simplifiers and
 * dead-constant passes do not have.</p>
 *
 * <p>Build-time state assignment lives in {@link FlowStatePlan}: it visits the
 * blocks in reverse post-order, chains a block from its predecessor when the
 * incoming value is unique and re-anchors it when a join disagrees or an
 * exception edge can arrive with an unknown value. Emission lives in
 * {@link FlowIntEmitter}. This class only decides what is eligible, drives
 * {@link MethodGate} (copy - transform - verify - commit) and keeps the books:
 * no method that fails verification is ever committed, and a class that could
 * not keep a single method is rolled back whole so no orphan table field
 * survives.</p>
 *
 * <p>Opt-in: {@code flowInts.enabled} defaults to {@code false}, so an existing
 * build produces byte-identical output until the pass is asked for.</p>
 */
public final class FlowIntsPass implements Pass {

    private static final String OPTION_ENABLED = "flowInts.enabled";
    private static final String OPTION_RATE = "flowInts.rate";
    private static final String OPTION_INCLUDE_LONG = "flowInts.includeLong";
    private static final String OPTION_INCLUDE_ICONST = "flowInts.includeIconst";
    private static final String OPTION_INCLUDE_CLINIT = "flowInts.includeClinit";
    private static final String OPTION_INHERIT = "flowInts.inherit";
    private static final String OPTION_CONFUSE = "flowInts.confuse";
    private static final String OPTION_CONFUSE_PERCENT = "flowInts.confusePercent";
    private static final String OPTION_SEPARATE = "flowInts.separateBlocks";
    private static final String OPTION_MAX_INSTRUCTIONS = "flowInts.maxInstructions";
    private static final String OPTION_TABLE_PAIRS = "flowInts.tablePairs";
    private static final String OPTION_DEBUG_ASSERT = "flowInts.debugAssert";

    /** Build-time settings, resolved once per run. */
    private static final class Settings {
        final int rate;
        final boolean includeLong;
        final boolean includeIconst;
        final boolean includeClinit;
        final int inherit;
        final boolean confuse;
        final int confusePercent;
        final boolean separate;
        final int maxInstructions;
        final int tablePairs;
        final boolean debugAssert;

        Settings(PassContext context) {
            this.rate = clamp(context.config().optionInt(OPTION_RATE, 100), 0, 100);
            this.includeLong = context.config().optionBool(OPTION_INCLUDE_LONG, false);
            this.includeIconst = context.config().optionBool(OPTION_INCLUDE_ICONST, true);
            this.includeClinit = context.config().optionBool(OPTION_INCLUDE_CLINIT, false);
            this.inherit = clamp(context.config().optionInt(OPTION_INHERIT, 60), 0, 100);
            this.confuse = context.config().optionBool(OPTION_CONFUSE, false);
            this.confusePercent = clamp(context.config().optionInt(OPTION_CONFUSE_PERCENT, 5), 0, 100);
            this.separate = context.config().optionBool(OPTION_SEPARATE, true);
            this.maxInstructions = Math.max(64,
                    context.config().optionInt(OPTION_MAX_INSTRUCTIONS, 20000));
            this.tablePairs = Math.max(2, context.config().optionInt(OPTION_TABLE_PAIRS, 1024));
            this.debugAssert = context.config().optionBool(OPTION_DEBUG_ASSERT, false);
        }
    }

    /** Per-method result of one transform attempt. */
    private static final class Result {
        int sites;
        int longSites;
        int states;
        int seeds;
        int merges;
        int joins;
        int tableConstants;
        int fallback;
        int skipped;
        boolean blocked;
        String summary = "";

        boolean changed() {
            return !blocked && sites + longSites > 0;
        }
    }

    /** A method as it was before the class transform, for whole-class rollback. */
    private static final class Saved {
        final MethodNode method;
        final List<LocalVariableNode> localVariables;
        final List<LocalVariableAnnotationNode> visibleAnnotations;
        final List<LocalVariableAnnotationNode> invisibleAnnotations;

        private Saved(MethodNode method) {
            this.method = method;
            this.localVariables = method.localVariables;
            this.visibleAnnotations = method.visibleLocalVariableAnnotations;
            this.invisibleAnnotations = method.invisibleLocalVariableAnnotations;
        }

        static Saved of(MethodNode method) {
            return new Saved(MethodGate.copy(method));
        }

        void restore(MethodNode target) {
            target.instructions = method.instructions;
            target.tryCatchBlocks = method.tryCatchBlocks;
            target.maxStack = method.maxStack;
            target.maxLocals = method.maxLocals;
            target.localVariables = localVariables;
            target.visibleLocalVariableAnnotations = visibleAnnotations;
            target.invisibleLocalVariableAnnotations = invisibleAnnotations;
        }
    }

    @Override
    public String name() {
        return "flow-ints";
    }

    @Override
    public int order() {
        return 91;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool(OPTION_ENABLED, false);
    }

    @Override
    public void run(PassContext context) {
        Settings settings = new Settings(context);
        MethodGate gate = new MethodGate(context);
        KeyRootMask tableMask = KeyRootMask.create(context, true);
        String tableMode = tableMask == null ? "static" : "native";

        long methods = 0L;
        long classes = 0L;
        long sites = 0L;
        long longSites = 0L;
        long states = 0L;
        long seeds = 0L;
        long merges = 0L;
        long joins = 0L;
        long runtimePairs = 0L;
        long fallback = 0L;
        long tables = 0L;
        long skipped = 0L;
        long ineligible = 0L;
        long rolledBack = 0L;
        long blocked = 0L;

        for (ClassNode node : context.classes().classes().values()) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
            if (context.rules().skipBodyTransform(node.name)) {
                continue;
            }
            if (!context.rules().transformClass(node)) {
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0
                    || "module-info".equals(node.name)) {
                continue;
            }

            Random random = classStream(context, node.name, "flowInts");
            RuntimeTable table = RuntimeTable.create(context, node, settings.tablePairs, tableMask);
            List<Saved> saved = new ArrayList<Saved>(node.methods.size());
            for (int i = 0; i < node.methods.size(); i++) {
                saved.add(Saved.of(node.methods.get(i)));
            }
            List<FieldNode> savedFields = new ArrayList<FieldNode>(node.fields);
            int done = 0;
            Result total = new Result();
            try {
                for (MethodNode method : node.methods) {
                    if (!eligible(method, settings)) {
                        ineligible++;
                        continue;
                    }
                    MethodNode work = MethodGate.copy(method);
                    Result result;
                    try {
                        result = transform(context, node, work, random, table, settings);
                    } catch (RuntimeException failure) {
                        skipped++;
                        context.log().debug("flowInts: skipped %s.%s: %s",
                                node.name, method.name, failure.toString());
                        continue;
                    }
                    if (result.blocked) {
                        blocked++;
                        continue;
                    }
                    if (!result.changed()) {
                        continue;
                    }
                    if (!gate.verify(node, work)) {
                        skipped++;
                        context.log().debug("flowInts: %s.%s did not verify after the rewrite",
                                node.name, method.name);
                        continue;
                    }
                    MethodGate.commit(method, work);
                    context.log().debug("flowInts: %s.%s %s", node.name, method.name,
                            result.summary);
                    done++;
                    total.sites += result.sites;
                    total.longSites += result.longSites;
                    total.states += result.states;
                    total.seeds += result.seeds;
                    total.merges += result.merges;
                    total.joins += result.joins;
                    total.tableConstants += result.tableConstants;
                    total.fallback += result.fallback;
                    total.skipped += result.skipped;
                }
                if (done == 0) {
                    for (int i = 0; i < node.methods.size(); i++) {
                        saved.get(i).restore(node.methods.get(i));
                    }
                    node.fields.clear();
                    node.fields.addAll(savedFields);
                    continue;
                }
                if (!table.isEmpty()) {
                    try {
                        table.materialize(node);
                        tables += table.chunkCount();
                    } catch (RuntimeException failure) {
                        context.log().debug("flowInts: cannot bootstrap the state table of %s: %s",
                                node.name, failure.toString());
                    }
                }
                runtimePairs += table.pairCount();
                methods += done;
                classes++;
                sites += total.sites;
                longSites += total.longSites;
                states += total.states;
                seeds += total.seeds;
                merges += total.merges;
                joins += total.joins;
                fallback += total.fallback;
                skipped += total.skipped;
            } catch (RuntimeException failure) {
                for (int i = 0; i < node.methods.size(); i++) {
                    saved.get(i).restore(node.methods.get(i));
                }
                node.fields.clear();
                node.fields.addAll(savedFields);
                rolledBack++;
                context.log().debug("flowInts: rolled back %s: %s", node.name, failure.toString());
            }
        }

        context.stats().add("flowInts.classes", classes);
        context.stats().add("flowInts.methods", methods);
        context.stats().add("flowInts.sites", sites);
        context.stats().add("flowInts.longSites", longSites);
        context.stats().add("flowInts.states", states);
        context.stats().add("flowInts.seeds", seeds);
        context.stats().add("flowInts.joins", joins);
        context.stats().add("flowInts.skipped", skipped);
        context.stats().add("flowInts.skipped.merge", merges);
        context.stats().add("flowInts.skip.merge", merges);
        context.stats().add("flowInts.skip.rollback", rolledBack);
        context.stats().add("flowInts.runtimePairs", runtimePairs);
        context.stats().add("flowInts.runtimeTables", tables);
        context.stats().add("flowInts.fallbackConstants", fallback);
        context.stats().add("flowInts.ineligible", ineligible);
        context.stats().add("flowInts.blocked", blocked);
        context.stats().text("flowInts.tableMode", tableMode);
        context.log().info("flow-ints[rate=%d inherit=%d long=%s confuse=%s]: %d constants "
                        + "(%d long) materialised from %d state updates across %d methods / "
                        + "%d classes (joins=%d merge-reseeds=%d refused=%d table=%s)",
                settings.rate, settings.inherit, String.valueOf(settings.includeLong),
                String.valueOf(settings.confuse), sites, longSites, states, methods, classes,
                joins, merges, blocked, tableMode);
    }

    private static int clamp(int value, int min, int max) {
        if (value < min) {
            return min;
        }
        if (value > max) {
            return max;
        }
        return value;
    }

    private static boolean eligible(MethodNode method, Settings settings) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.instructions == null || method.instructions.size() == 0) {
            return false;
        }
        if ("<clinit>".equals(method.name)) {
            return settings.includeClinit;
        }
        if ("<init>".equals(method.name)) {
            return true;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        return true;
    }

    /**
     * Rewrites one method copy: state seeds/advances at block heads, then every
     * eligible constant push. Sites are collected before anything is inserted so
     * the newly emitted state arithmetic can never be treated as a site.
     */
    private static Result transform(PassContext context, ClassNode owner, MethodNode method,
                                    Random random, RuntimeTable table, Settings settings) {
        Result result = new Result();
        if (AsmUtil.containsJsrOrRet(method)) {
            return result;
        }
        if (method.instructions.size() > settings.maxInstructions) {
            return result;
        }
        MethodFlowAnalyzer flow = MethodFlowAnalyzer.of(owner.name, method, analyse(owner.name, method));
        if (flow == null || flow.blockCount() == 0) {
            return result;
        }
        FlowStatePlan plan = FlowStatePlan.create(flow, random, settings.inherit);
        result.states = plan.states();
        result.seeds = plan.seeds();
        result.merges = plan.merges();
        result.joins = plan.joins();
        result.summary = plan.summary();

        List<MethodFlowAnalyzer.Block> blocks = flow.blocks();

        List<MethodFlowAnalyzer.Block> siteBlocks = new ArrayList<MethodFlowAnalyzer.Block>();
        List<AbstractInsnNode> siteInsns = new ArrayList<AbstractInsnNode>();
        for (int b = 0; b < blocks.size(); b++) {
            MethodFlowAnalyzer.Block block = blocks.get(b);
            if (plan.mode(block.index()) == FlowStatePlan.MODE_SKIP) {
                continue;
            }
            AbstractInsnNode stop = b + 1 < blocks.size() ? blocks.get(b + 1).startInsn() : null;
            for (AbstractInsnNode cursor = block.startInsn(); cursor != null && cursor != stop;
                 cursor = cursor.getNext()) {
                if (!isCandidate(cursor, settings)) {
                    continue;
                }
                if (forbidden(cursor)) {
                    result.skipped++;
                    continue;
                }
                if (random.nextInt(100) >= settings.rate) {
                    result.skipped++;
                    continue;
                }
                siteBlocks.add(block);
                siteInsns.add(cursor);
            }
        }

        if (siteInsns.isEmpty() && plan.advances() + plan.seeds() == 0) {
            return result;
        }

        int stateLocal = nextFreeLocal(method);
        int methodSeed = random.nextInt();
        FlowIntEmitter emitter = new FlowIntEmitter(table, random, stateLocal, methodSeed,
                settings.confuse, settings.confusePercent);

        for (int b = 0; b < blocks.size(); b++) {
            MethodFlowAnalyzer.Block block = blocks.get(b);
            int mode = plan.mode(block.index());
            if (mode == FlowStatePlan.MODE_SKIP) {
                continue;
            }
            if (mode == FlowStatePlan.MODE_NONE) {
                if (settings.debugAssert) {
                    AbstractInsnNode anchor = firstReal(block, blocks);
                    if (anchor != null) {
                        InsnList only = new InsnList();
                        emitStateMismatch(only, owner, method, stateLocal, block.index(),
                                plan.state(block.index()));
                        method.instructions.insertBefore(anchor, only);
                    }
                }
                continue;
            }
            AbstractInsnNode anchor = firstReal(block, blocks);
            if (anchor == null) {
                // A block that must write the state has no instruction to write
                // it before: the chain would be off by one at run time. Refuse the
                // whole method instead of emitting a site that cannot be reached
                // with the promised value.
                context.log().debug("flowInts: %s.%s has no anchor for block %d; "
                        + "method left untouched", owner.name, method.name, block.index());
                result.blocked = true;
                return result;
            }
            InsnList list = new InsnList();
            if (mode == FlowStatePlan.MODE_ADVANCE) {
                emitter.emitAdvance(list, plan.incoming(block.index()), plan.state(block.index()));
                if (settings.debugAssert) {
                    emitStateMismatch(list, owner, method, stateLocal, block.index(),
                            plan.state(block.index()));
                }
            } else {
                emitter.emitSeed(list, plan.state(block.index()));
                if (settings.debugAssert) {
                    emitStateMismatch(list, owner, method, stateLocal, block.index(),
                            plan.state(block.index()));
                }
            }
            if (settings.separate) {
                list.add(new LabelNode());
            }
            method.instructions.insertBefore(anchor, list);
        }

        for (int i = 0; i < siteInsns.size(); i++) {
            AbstractInsnNode insn = siteInsns.get(i);
            int blockState = plan.state(siteBlocks.get(i).index());
            InsnList sequence = new InsnList();
            if (isIntPush(insn)) {
                int target = FlowIntEmitter.intValue(insn);
                emitter.emitIntSite(sequence, blockState, target);
                if (settings.debugAssert) {
                    emitSiteAssertion(sequence, owner, method, siteBlocks.get(i).index(), target);
                }
                result.sites++;
            } else {
                emitter.emitLongSite(sequence, blockState, FlowIntEmitter.longValue(insn));
                result.longSites++;
            }
            method.instructions.insertBefore(insn, sequence);
            method.instructions.remove(insn);
        }

        result.tableConstants = emitter.tableConstants();
        result.fallback = emitter.fallbackConstants();
        if (result.changed()) {
            int bump = result.longSites > 0 ? 8 : 4;
            method.maxStack = Math.min(65535, Math.max(1, method.maxStack) + bump);
            method.maxLocals = Math.max(method.maxLocals, stateLocal + 1);
        }
        return result;
    }

    /**
     * Diagnostic guard ({@code flowInts.debugAssert}): throws when the state
     * variable does not hold the value the build assigned to the block, which is
     * precisely the condition a chained site relies on. Only blocks whose
     * incoming value is load-bearing (advance / keep) are guarded; seed blocks
     * overwrite the variable and cannot be wrong. A build with the option off
     * emits nothing, so it never changes production output.
     */
    /** Throws unless the state local holds {@code expected}, and reports what it saw. */
    private static void emitStateMismatch(InsnList list, ClassNode owner, MethodNode method,
                                          int stateLocal, int block, int expected) {
        LabelNode ok = new LabelNode();
        list.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        AsmUtil.pushInt(list, expected);
        list.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, ok));
        list.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalStateException"));
        list.add(new InsnNode(Opcodes.DUP));
        list.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        list.add(new InsnNode(Opcodes.DUP));
        list.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder",
                "<init>", "()V", false));
        list.add(new LdcInsnNode("flowInts state mismatch: " + owner.name + "." + method.name
                + method.desc + " block " + block + " expected " + expected + " actual "));
        list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        list.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                "append", "(I)Ljava/lang/StringBuilder;", false));
        list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                "toString", "()Ljava/lang/String;", false));
        list.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException",
                "<init>", "(Ljava/lang/String;)V", false));
        list.add(new InsnNode(Opcodes.ATHROW));
        list.add(ok);
    }

    /**
     * Diagnostic guard for one rewritten site ({@code flowInts.debugAssert}):
     * duplicates the materialised value and throws unless it equals the constant
     * the site replaced. This is what catches a state chain that drifts at run
     * time, which no verifier can see.
     */
    private static void emitSiteAssertion(InsnList list, ClassNode owner, MethodNode method,
                                          int block, int target) {
        LabelNode ok = new LabelNode();
        list.add(new InsnNode(Opcodes.DUP));
        AsmUtil.pushInt(list, target);
        list.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, ok));
        list.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalStateException"));
        list.add(new InsnNode(Opcodes.DUP));
        list.add(new LdcInsnNode("flowInts site mismatch: " + owner.name + "." + method.name
                + method.desc + " block " + block + " constant " + target));
        list.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException",
                "<init>", "(Ljava/lang/String;)V", false));
        list.add(new InsnNode(Opcodes.ATHROW));
        list.add(ok);
    }

    private static boolean isCandidate(AbstractInsnNode insn, Settings settings) {
        if (isIntPush(insn)) {
            if (!settings.includeIconst && isIconst(insn)) {
                return false;
            }
            return true;
        }
        return settings.includeLong && isLongPush(insn);
    }

    private static boolean isIntPush(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return true;
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return true;
        }
        return insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer;
    }

    private static boolean isIconst(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        return opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5;
    }

    private static boolean isLongPush(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.LCONST_0 || opcode == Opcodes.LCONST_1) {
            return true;
        }
        return insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Long;
    }

    /**
     * Constants that must stay literals: array lengths, {@code new} dimensions
     * and multiplanar dimensions. Switch keys never reach here because they live
     * inside the switch node, and {@code iinc} is not a push at all.
     */
    private static boolean forbidden(AbstractInsnNode insn) {
        AbstractInsnNode next = realNext(insn);
        if (next == null) {
            return false;
        }
        int opcode = next.getOpcode();
        if (opcode == Opcodes.NEWARRAY || opcode == Opcodes.ANEWARRAY
                || opcode == Opcodes.MULTIANEWARRAY) {
            return true;
        }
        int pushes = 0;
        AbstractInsnNode cursor = next;
        while (cursor != null && pushes < 8 && isIntPush(cursor)) {
            pushes++;
            cursor = realNext(cursor);
        }
        return cursor != null && cursor.getOpcode() == Opcodes.MULTIANEWARRAY;
    }

    private static AbstractInsnNode realNext(AbstractInsnNode insn) {
        AbstractInsnNode next = insn.getNext();
        while (next != null && next.getOpcode() < 0) {
            next = next.getNext();
        }
        return next;
    }

    private static AbstractInsnNode firstReal(MethodFlowAnalyzer.Block block,
                                              List<MethodFlowAnalyzer.Block> blocks) {
        int next = block.index() + 1;
        AbstractInsnNode stop = next < blocks.size() ? blocks.get(next).startInsn() : null;
        for (AbstractInsnNode cursor = block.startInsn(); cursor != null && cursor != stop;
             cursor = cursor.getNext()) {
            if (cursor.getOpcode() >= 0) {
                return cursor;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Frame<BasicValue>[] analyse(String owner, MethodNode method) {
        try {
            return new Analyzer<BasicValue>(new BasicInterpreter()).analyze(owner, method);
        } catch (AnalyzerException failure) {
            return null;
        } catch (RuntimeException failure) {
            return null;
        }
    }

    private static int nextFreeLocal(MethodNode method) {
        int used = Math.max(0, method.maxLocals);
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof VarInsnNode) {
                int slot = ((VarInsnNode) insn).var;
                int width = (insn.getOpcode() == Opcodes.LLOAD || insn.getOpcode() == Opcodes.LSTORE
                        || insn.getOpcode() == Opcodes.DLOAD || insn.getOpcode() == Opcodes.DSTORE)
                        ? 2 : 1;
                used = Math.max(used, slot + width);
            } else if (insn instanceof IincInsnNode) {
                used = Math.max(used, ((IincInsnNode) insn).var + 1);
            }
        }
        return used;
    }

    /** Per-class random stream so pass order cannot change a class's result. */
    private static Random classStream(PassContext context, String className, String label) {
        byte[] material = BuildRoot.derive(context.config().seed(), label);
        long domain = 0L;
        for (int i = 0; i < 8; i++) {
            domain |= (material[i] & 0xFFL) << (8 * i);
        }
        long nameHash = className == null ? 0L : (long) className.hashCode();
        return new Random(domain ^ (nameHash * 0x9E3779B97F4A7C15L) ^ context.config().seed());
    }
}
