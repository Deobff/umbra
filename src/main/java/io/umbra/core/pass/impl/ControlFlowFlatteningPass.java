package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.rules.Glob;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * State-machine control-flow flattening.
 *
 * <p>Eligible methods are converted into a dispatcher loop over a random-state
 * variable. Every basic block gets a random-looking {@code int}/{@code long}
 * state constant; the state is decoded with {@code (state ^ key) * multiplier}
 * (an odd multiplier, so the mapping is a bijection modulo 2<sup>32</sup> or
 * 2<sup>64</sup>) and consumed by a {@code tableswitch} whose slot table is
 * padded with junk entries. Blocks are emitted in a shuffled order and the
 * original conditional branches become state selections, so the original CFG
 * shape is no longer visible in the bytecode.</p>
 *
 * <p>Correctness rules enforced by the implementation:</p>
 * <ul>
 *   <li>only blocks entering with an empty operand stack are dispatch targets;</li>
 *   <li>non-parameter locals are initialised to category-correct defaults before
 *       the dispatcher, and a method is skipped when two blocks use the same slot
 *       for incompatible categories;</li>
 *   <li>exception handlers are kept out of the dispatcher: exception table
 *       ranges and handler blocks stay in their original positions (blocks are
 *       emitted in original order whenever try/catch is present), so the handler
 *       ranges, handler entry frames ({@code stack = 1}) and precedence are
 *       untouched;</li>
 *   <li>switches become dispatched block transitions, preserving all targets;</li>
 *   <li>jsr/ret, unreachable or non-empty-stack block entries, oversized methods
 *       and incompatible local layouts fall back to the original method and are
 *       reported per skip category.</li>
 * </ul>
 */
public final class ControlFlowFlatteningPass implements Pass {

    private static final String FLOW_ANNOTATION = "Lio/umbra/annotations/FlowObfuscation;";
    private static final int KIND_FALLTHROUGH = 0;
    private static final int KIND_GOTO = 1;
    private static final int KIND_CONDITIONAL = 2;
    private static final int KIND_SWITCH = 3;
    private static final int KIND_RETURN = 4;

    @Override
    public String name() {
        return "control-flow-flattening";
    }

    @Override
    public int order() {
        return 92;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().flow().enabled() && context.config().flow().flattening();
    }

    @Override
    public void run(PassContext context) {
        int flattened = 0;
        int blocks = 0;
        int tryCatchMethods = 0;
        int switchMethods = 0;
        int max = context.config().flow().maxInstructions();
        int maxBlocks = Math.max(8, context.config().optionInt("flow.maxBlocks", 512));
        Set<String> excluded = excludedNames(context);
        Map<String, Integer> skipped = new LinkedHashMap<String, Integer>();
        MethodGate gate = new MethodGate(context);
        for (ClassNode node : context.classes().classes().values()) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
                if (context.rules().skipBodyTransform(node.name)) {
                    continue;
                }
            if (excluded.contains(node.name)) {
                continue;
            }
            if (!context.rules().transformClass(node)) {
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0
                    || "module-info".equals(node.name)) {
                continue;
            }
            Boolean classEnabled = AsmUtil.annotationBoolean(node.invisibleAnnotations, FLOW_ANNOTATION, "enabled");
            if (classEnabled == null) {
                classEnabled = AsmUtil.annotationBoolean(node.visibleAnnotations, FLOW_ANNOTATION, "enabled");
            }
            if (Boolean.FALSE.equals(classEnabled)) {
                continue;
            }
            // Transactional class transform: if the class as a whole no longer
            // serializes with COMPUTE_FRAMES, every flattened method in it is
            // rolled back to its original body.
            List<MethodNode> savedMethods = new ArrayList<MethodNode>();
            for (MethodNode method : node.methods) {
                savedMethods.add(MethodGate.copy(method));
            }
            int classFlattened = 0;
            int classBlocks = 0;
            int classTryCatch = 0;
            int classSwitches = 0;
            try {
                for (MethodNode method : node.methods) {
                    if (!basicEligible(context, node, method, max, skipped)) {
                        continue;
                    }
                    try {
                        // Transform a deep copy so a rejected method can be left
                        // completely untouched.
                        MethodNode work = MethodGate.copy(method);
                        FlattenResult result = flatten(context, node, work, maxBlocks);
                        if (!gate.verify(node, work)) {
                            increment(skipped, "verify");
                            continue;
                        }
                        MethodGate.commit(method, work);
                        classFlattened++;
                        classBlocks += result.blocks;
                        if (result.tryCatch) {
                            classTryCatch++;
                        }
                        if (result.switchBlocks > 0) {
                            classSwitches++;
                        }
                    } catch (Skip skip) {
                        increment(skipped, skip.reason);
                    } catch (AnalyzerException e) {
                        increment(skipped, "analysis");
                        context.log().debug("flattening skipped %s.%s: %s",
                                node.name, method.name, e.getMessage());
                    } catch (RuntimeException e) {
                        increment(skipped, "error");
                        context.log().debug("flattening skipped %s.%s: %s",
                                node.name, method.name, e.toString());
                    }
                }
                if (classFlattened > 0 && !gate.writes(node)) {
                    throw new IllegalStateException("class does not serialize");
                }
            } catch (RuntimeException e) {
                node.methods = new ArrayList<MethodNode>(savedMethods);
                increment(skipped, "class_verify");
                context.log().debug("flattening: rolled back class %s: %s", node.name, e.toString());
                classFlattened = 0;
                classBlocks = 0;
                classTryCatch = 0;
                classSwitches = 0;
            }
            flattened += classFlattened;
            blocks += classBlocks;
            tryCatchMethods += classTryCatch;
            switchMethods += classSwitches;
        }
        context.stats().add("flow.flattened.methods", flattened);
        context.stats().add("flow.flattened.blocks", blocks);
        context.stats().add("flow.flattened.tryCatch", tryCatchMethods);
        context.stats().add("flow.flattened.switchMethods", switchMethods);
        for (Map.Entry<String, Integer> entry : skipped.entrySet()) {
            context.stats().add("flow.flattened.skipped." + entry.getKey(), entry.getValue().intValue());
        }
        context.log().info("control-flow-flattening: flattened %d methods (%d blocks, %d with try/catch, "
                        + "%d with switches); skipped %s",
                flattened, blocks, tryCatchMethods, switchMethods, skipped);
    }

    private static void increment(Map<String, Integer> map, String key) {
        Integer current = map.get(key);
        map.put(key, Integer.valueOf(current == null ? 1 : current.intValue() + 1));
    }

    /** Resolves class-glob exclusions (written with original names) to current names. */
    private static Set<String> excludedNames(PassContext context) {
        Set<String> result = new LinkedHashSet<String>();
        List<Glob> globs = new ArrayList<Glob>();
        for (String pattern : context.config().flow().flatteningExclude()) {
            if (pattern != null && !pattern.trim().isEmpty()) {
                globs.add(new Glob(pattern.trim()));
            }
        }
        if (globs.isEmpty()) {
            return result;
        }
        for (Glob glob : globs) {
            for (Map.Entry<String, String> entry : context.mappings().classes().entrySet()) {
                if (glob.matches(entry.getKey()) || glob.matches(entry.getValue())) {
                    result.add(entry.getValue());
                }
            }
            for (String name : context.classes().classes().keySet()) {
                if (glob.matches(name)) {
                    result.add(name);
                }
            }
        }
        return result;
    }

    private static boolean basicEligible(PassContext context, ClassNode owner, MethodNode method,
                                         int max, Map<String, Integer> skipped) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        if (method.instructions == null || method.instructions.size() < 4) {
            return false;
        }
        if (context.rules().keepMethod(owner.name, method)) {
            return false;
        }
        Boolean methodEnabled = AsmUtil.annotationBoolean(method.invisibleAnnotations, FLOW_ANNOTATION, "enabled");
        if (methodEnabled == null) {
            methodEnabled = AsmUtil.annotationBoolean(method.visibleAnnotations, FLOW_ANNOTATION, "enabled");
        }
        if (Boolean.FALSE.equals(methodEnabled)) {
            return false;
        }
        if (method.instructions.size() > max) {
            increment(skipped, "too_large");
            return false;
        }
        if (AsmUtil.containsJsrOrRet(method)) {
            increment(skipped, "jsr");
            return false;
        }
        return true;
    }

    // ----------------------------------------------------------------- flatten

    private static FlattenResult flatten(PassContext context, ClassNode owner, MethodNode method,
                                         int maxBlocks) throws AnalyzerException {
        int previousMaxStack = method.maxStack;
        int previousMaxLocals = method.maxLocals;
        Frame<BasicValue>[] frames;
        try {
            Analyzer<BasicValue> analyzer = new Analyzer<BasicValue>(new BasicInterpreter());
            frames = analyzer.analyzeAndComputeMaxs(owner.name, method);
        } catch (AnalyzerException e) {
            method.maxStack = Math.max(1, previousMaxStack);
            method.maxLocals = Math.max(0, previousMaxLocals);
            throw e;
        }
        int analyzedMaxStack = Math.max(1, method.maxStack);
        InsnList instructions = method.instructions;

        List<Block> blocks = buildBlocks(method, frames);
        if (blocks.size() < 2) {
            throw new Skip("blocks");
        }
        if (blocks.size() > maxBlocks) {
            throw new Skip("too_many_blocks");
        }
        boolean hasTryCatch = method.tryCatchBlocks != null && !method.tryCatchBlocks.isEmpty();

        Set<LabelNode> handlerLabels = new LinkedHashSet<LabelNode>();
        if (hasTryCatch) {
            for (TryCatchBlockNode table : method.tryCatchBlocks) {
                handlerLabels.add(table.handler);
            }
        }
        for (Block block : blocks) {
            block.handler = block.leader instanceof LabelNode && handlerLabels.contains((LabelNode) block.leader);
        }
        if (!hasTryCatch && handlerLabels.isEmpty()) {
            // fast path: everything may be shuffled
        }

        // Validate block entry frames and collect local categories.
        int parameterSlots = argumentSlots(method);
        int maxFrameLocals = 0;
        for (Block block : blocks) {
            int index = instructions.indexOf(block.leader);
            if (index < 0 || index >= frames.length || frames[index] == null) {
                throw new Skip("unreachable");
            }
            Frame<BasicValue> frame = frames[index];
            int expectedStack = block.handler ? 1 : 0;
            if (frame.getStackSize() != expectedStack) {
                throw new Skip(block.handler ? "handler_stack" : "stack");
            }
            maxFrameLocals = Math.max(maxFrameLocals, frame.getLocals());
        }
        int localSlots = Math.max(Math.max(1, Math.max(method.maxLocals, parameterSlots)), maxFrameLocals);
        if (localSlots > 60000) {
            throw new Skip("locals");
        }
        String[] slotCategories = new String[localSlots];
        for (Block block : blocks) {
            collectCategories(frames[instructions.indexOf(block.leader)], slotCategories);
        }
        // Every edge into the dispatcher merges the loop frame with the block
        // end frame, so end-of-block local categories must not collide either.
        for (Block block : blocks) {
            if (block.handler || block.terminator == null) {
                continue;
            }
            int index = instructions.indexOf(block.terminator);
            if (index < 0 || index >= frames.length || frames[index] == null) {
                throw new Skip("unreachable");
            }
            collectCategories(frames[index], slotCategories);
        }

        // Resolve transitions for normal blocks; handler blocks keep their
        // original control flow (they are not dispatch entries).
        Map<LabelNode, Integer> labelToBlock = new LinkedHashMap<LabelNode, Integer>();
        for (Block block : blocks) {
            if (block.leader instanceof LabelNode) {
                labelToBlock.put((LabelNode) block.leader, Integer.valueOf(block.index));
            }
        }
        int normalCount = 0;
        int switchBlocks = 0;
        for (Block block : blocks) {
            block.terminator = findTerminator(block.insns);
            if (block.handler) {
                validateHandlerBlock(block, blocks.size(), instructions);
                continue;
            }
            normalCount++;
            resolveTransition(block, blocks, labelToBlock, method);
            if (block.kind == KIND_SWITCH) {
                switchBlocks++;
            }
        }
        if (normalCount < 2) {
            throw new Skip("blocks");
        }

        // State encoding: shuffle the slot space, pad it with junk entries and
        // encode each block state through an invertible affine map.
        Random random = context.random();
        // Category-2 locals merge badly with synthetic catch-all handlers that a
        // later pass may add, so try/catch methods always use the int state.
        boolean useLongState = !hasTryCatch && random.nextBoolean();
        int junkEntries = Math.min(64, Math.max(2, normalCount / 3 + 2));
        int slotSpace = normalCount + junkEntries;
        List<Integer> slots = new ArrayList<Integer>(slotSpace);
        for (int i = 0; i < slotSpace; i++) {
            slots.add(Integer.valueOf(i));
        }
        Collections.shuffle(slots, random);
        int[] slotOf = new int[blocks.size()];
        java.util.Arrays.fill(slotOf, -1);
        int slotCursor = 0;
        for (Block block : blocks) {
            if (!block.handler) {
                block.slot = slots.get(slotCursor++).intValue();
            }
        }
        long xorKey = random.nextLong();
        long multiplier = random.nextLong() | 1L;
        long inverse = inverseOdd(multiplier);
        int intXor = (int) xorKey;
        int intMultiplier = (int) multiplier;
        int intInverse = (int) inverse;
        for (Block block : blocks) {
            if (block.handler) {
                continue;
            }
            if (useLongState) {
                long pre = ((long) block.slot) * inverse;
                block.longState = pre ^ xorKey;
            } else {
                block.intState = (block.slot * intInverse) ^ intXor;
            }
        }

        Block entry = blocks.get(0);
        if (entry.handler) {
            throw new Skip("entry");
        }

        // Output order: exception table labels must keep their relative
        // positions, so methods with handlers keep the original block order.
        List<Block> order = new ArrayList<Block>(blocks);
        if (!hasTryCatch) {
            Collections.shuffle(order, random);
        }

        int stateSize = useLongState ? 2 : 1;
        int stateLocal = localSlots;
        method.maxLocals = stateLocal + stateSize;

        InsnList out = new InsnList();
        emitLocalInit(out, slotCategories, parameterSlots, localSlots);
        if (useLongState) {
            out.add(new LdcInsnNode(Long.valueOf(entry.longState)));
            out.add(new VarInsnNode(Opcodes.LSTORE, stateLocal));
        } else {
            AsmUtil.pushInt(out, entry.intState);
            out.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
        }

        LabelNode loop = new LabelNode();
        out.add(loop);
        if (useLongState) {
            out.add(new VarInsnNode(Opcodes.LLOAD, stateLocal));
            out.add(new LdcInsnNode(Long.valueOf(xorKey)));
            out.add(new InsnNode(Opcodes.LXOR));
            out.add(new LdcInsnNode(Long.valueOf(multiplier)));
            out.add(new InsnNode(Opcodes.LMUL));
            out.add(new InsnNode(Opcodes.L2I));
        } else {
            out.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
            AsmUtil.pushInt(out, intXor);
            out.add(new InsnNode(Opcodes.IXOR));
            AsmUtil.pushInt(out, intMultiplier);
            out.add(new InsnNode(Opcodes.IMUL));
        }

        LabelNode defaultLabel = new LabelNode();
        LabelNode junkLabel = new LabelNode();
        LabelNode[] cases = new LabelNode[slotSpace];
        for (int i = 0; i < slotSpace; i++) {
            cases[i] = junkLabel;
        }
        for (Block block : blocks) {
            if (!block.handler) {
                cases[block.slot] = block.label;
            }
        }
        out.add(new TableSwitchInsnNode(0, slotSpace - 1, defaultLabel, cases));
        out.add(defaultLabel);
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalStateException"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new LdcInsnNode("state"));
        out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException",
                "<init>", "(Ljava/lang/String;)V", false));
        out.add(new InsnNode(Opcodes.ATHROW));
        out.add(junkLabel);
        out.add(junk(random));
        out.add(new JumpInsnNode(Opcodes.GOTO, defaultLabel));

        int switchEmits = 0;
        for (Block block : order) {
            out.add(block.label);
            for (AbstractInsnNode insn : block.insns) {
                if (insn == block.label || insn == block.terminator) {
                    continue;
                }
                out.add(insn);
            }
            if (block.handler) {
                // Handlers keep their original terminator, including direct
                // jumps into the dispatch cases: the state is only read at the
                // loop head, so entering a case block directly is well defined.
                if (block.terminator != null) {
                    out.add(block.terminator);
                }
                continue;
            }
            switch (block.kind) {
                case KIND_GOTO:
                case KIND_FALLTHROUGH:
                    emitState(out, blocks, block.target, stateLocal, loop, useLongState);
                    break;
                case KIND_CONDITIONAL: {
                    JumpInsnNode jump = (JumpInsnNode) block.terminator;
                    LabelNode taken = new LabelNode();
                    out.add(new JumpInsnNode(jump.getOpcode(), taken));
                    emitState(out, blocks, block.falseTarget, stateLocal, loop, useLongState);
                    out.add(taken);
                    emitState(out, blocks, block.trueTarget, stateLocal, loop, useLongState);
                    break;
                }
                case KIND_SWITCH:
                    emitSwitchTransition(out, block, blocks, stateLocal, loop, useLongState);
                    switchEmits++;
                    break;
                case KIND_RETURN:
                    out.add(block.terminator);
                    break;
                default:
                    throw new Skip("kind");
            }
        }

        // Nodes moved out of the old instruction list keep their old next/prev
        // links; every link is overwritten as the nodes are appended in order
        // except for the very last one. A fresh trailing label guarantees the
        // final node's next is null (otherwise the list could be cyclic).
        out.add(new LabelNode());
        method.instructions = out;
        method.maxStack = Math.max(Math.max(analyzedMaxStack, 3), 4);
        method.localVariables = null;
        method.visibleLocalVariableAnnotations = null;
        method.invisibleLocalVariableAnnotations = null;
        // Exception tables are preserved verbatim when handlers exist.
        if (!hasTryCatch) {
            method.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
        }
        FlattenResult result = new FlattenResult();
        result.blocks = normalCount;
        result.tryCatch = hasTryCatch;
        result.switchBlocks = switchEmits;
        return result;
    }

    // ------------------------------------------------------------------ blocks

    private static List<Block> buildBlocks(MethodNode method, Frame<BasicValue>[] frames) {
        InsnList instructions = method.instructions;
        Set<AbstractInsnNode> leaderSet = new LinkedHashSet<AbstractInsnNode>();
        AbstractInsnNode first = instructions.getFirst();
        if (first != null) {
            leaderSet.add(first);
        }
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode table : method.tryCatchBlocks) {
                leaderSet.add(table.handler);
            }
        }
        for (AbstractInsnNode insn = first; insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (insn instanceof JumpInsnNode) {
                leaderSet.add(((JumpInsnNode) insn).label);
                if (insn.getNext() != null) {
                    leaderSet.add(insn.getNext());
                }
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode table = (TableSwitchInsnNode) insn;
                leaderSet.add(table.dflt);
                leaderSet.addAll(table.labels);
                if (insn.getNext() != null) {
                    leaderSet.add(insn.getNext());
                }
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode table = (LookupSwitchInsnNode) insn;
                leaderSet.add(table.dflt);
                leaderSet.addAll(table.labels);
                if (insn.getNext() != null) {
                    leaderSet.add(insn.getNext());
                }
            } else if (isReturnOrThrow(opcode) && insn.getNext() != null) {
                leaderSet.add(insn.getNext());
            }
        }
        List<AbstractInsnNode> leaders = new ArrayList<AbstractInsnNode>();
        for (AbstractInsnNode leader : leaderSet) {
            if (leader != null && instructions.indexOf(leader) >= 0) {
                leaders.add(leader);
            }
        }
        leaders.sort((a, b) -> Integer.compare(instructions.indexOf(a), instructions.indexOf(b)));
        List<Block> blocks = new ArrayList<Block>();
        for (int i = 0; i < leaders.size(); i++) {
            AbstractInsnNode leader = leaders.get(i);
            int start = instructions.indexOf(leader);
            int end = i + 1 < leaders.size() ? instructions.indexOf(leaders.get(i + 1)) : instructions.size();
            LabelNode label = leader instanceof LabelNode ? (LabelNode) leader : new LabelNode();
            Block block = new Block(i, label, leader);
            for (int j = start; j < end; j++) {
                block.insns.add(instructions.get(j));
            }
            blocks.add(block);
        }
        return blocks;
    }

    private static void resolveTransition(Block block, List<Block> blocks,
                                          Map<LabelNode, Integer> labelToBlock, MethodNode method) {
        if (block.terminator == null) {
            block.kind = KIND_FALLTHROUGH;
            block.target = block.index + 1;
            requireNormalTarget(block.target, blocks);
            return;
        }
        int opcode = block.terminator.getOpcode();
        if (opcode == Opcodes.GOTO) {
            block.kind = KIND_GOTO;
            block.target = requireLabelTarget(((JumpInsnNode) block.terminator).label,
                    labelToBlock, blocks);
            return;
        }
        if (isConditional(opcode)) {
            block.kind = KIND_CONDITIONAL;
            block.trueTarget = requireLabelTarget(((JumpInsnNode) block.terminator).label,
                    labelToBlock, blocks);
            block.falseTarget = block.index + 1;
            requireNormalTarget(block.falseTarget, blocks);
            return;
        }
        if (opcode == Opcodes.TABLESWITCH || opcode == Opcodes.LOOKUPSWITCH) {
            block.kind = KIND_SWITCH;
            List<Integer> targets = new ArrayList<Integer>();
            if (opcode == Opcodes.TABLESWITCH) {
                TableSwitchInsnNode table = (TableSwitchInsnNode) block.terminator;
                for (LabelNode label : table.labels) {
                    targets.add(Integer.valueOf(requireLabelTarget(label, labelToBlock, blocks)));
                }
                block.switchDefault = requireLabelTarget(table.dflt, labelToBlock, blocks);
            } else {
                LookupSwitchInsnNode table = (LookupSwitchInsnNode) block.terminator;
                for (LabelNode label : table.labels) {
                    targets.add(Integer.valueOf(requireLabelTarget(label, labelToBlock, blocks)));
                }
                block.switchDefault = requireLabelTarget(table.dflt, labelToBlock, blocks);
            }
            block.switchTargets = new int[targets.size()];
            for (int i = 0; i < targets.size(); i++) {
                block.switchTargets[i] = targets.get(i).intValue();
            }
            return;
        }
        if (isReturnOrThrow(opcode)) {
            block.kind = KIND_RETURN;
            return;
        }
        throw new Skip("terminator");
    }

    private static int requireLabelTarget(LabelNode label, Map<LabelNode, Integer> labelToBlock,
                                          List<Block> blocks) {
        Integer target = labelToBlock.get(label);
        if (target == null) {
            throw new Skip("target");
        }
        requireNormalTarget(target.intValue(), blocks);
        return target.intValue();
    }

    private static void requireNormalTarget(int index, List<Block> blocks) {
        if (index < 0 || index >= blocks.size()) {
            throw new Skip("target");
        }
        if (blocks.get(index).handler) {
            // A normal edge into an exception handler entry would merge a
            // stack-0 frame with the handler's stack-1 frame: leave the method
            // alone instead of corrupting it.
            throw new Skip("handler_edge");
        }
    }

    private static void validateHandlerBlock(Block block, int blockCount, InsnList instructions) {
        if (block.terminator == null) {
            if (block.index + 1 >= blockCount) {
                throw new Skip("fallthrough_end");
            }
            return;
        }
        int opcode = block.terminator.getOpcode();
        if (isConditional(opcode) || isReturnOrThrow(opcode)
                || opcode == Opcodes.GOTO || opcode == Opcodes.TABLESWITCH
                || opcode == Opcodes.LOOKUPSWITCH) {
            return;
        }
        throw new Skip("handler_terminator");
    }

    private static AbstractInsnNode findTerminator(List<AbstractInsnNode> insns) {
        for (int i = insns.size() - 1; i >= 0; i--) {
            AbstractInsnNode insn = insns.get(i);
            if (insn.getOpcode() < 0) {
                continue;
            }
            int opcode = insn.getOpcode();
            if (opcode == Opcodes.GOTO || isConditional(opcode)
                    || opcode == Opcodes.TABLESWITCH || opcode == Opcodes.LOOKUPSWITCH
                    || isReturnOrThrow(opcode)) {
                return insn;
            }
            return null;
        }
        return null;
    }

    // ---------------------------------------------------------------- emission

    private static void emitLocalInit(InsnList out, String[] categories, int from, int to) {
        int slot = from;
        while (slot < to && slot < categories.length) {
            String category = categories[slot];
            if (category == null) {
                slot++;
                continue;
            }
            if ("J".equals(category)) {
                out.add(new InsnNode(Opcodes.LCONST_0));
                out.add(new VarInsnNode(Opcodes.LSTORE, slot));
                slot += 2;
            } else if ("D".equals(category)) {
                out.add(new InsnNode(Opcodes.DCONST_0));
                out.add(new VarInsnNode(Opcodes.DSTORE, slot));
                slot += 2;
            } else if ("F".equals(category)) {
                out.add(new InsnNode(Opcodes.FCONST_0));
                out.add(new VarInsnNode(Opcodes.FSTORE, slot));
                slot++;
            } else if ("L".equals(category)) {
                out.add(new InsnNode(Opcodes.ACONST_NULL));
                out.add(new VarInsnNode(Opcodes.ASTORE, slot));
                slot++;
            } else {
                out.add(new InsnNode(Opcodes.ICONST_0));
                out.add(new VarInsnNode(Opcodes.ISTORE, slot));
                slot++;
            }
        }
    }

    private static void emitState(InsnList out, List<Block> blocks, int target, int stateLocal,
                                  LabelNode loop, boolean useLongState) {
        Block targetBlock = blocks.get(target);
        if (useLongState) {
            out.add(new LdcInsnNode(Long.valueOf(targetBlock.longState)));
            out.add(new VarInsnNode(Opcodes.LSTORE, stateLocal));
        } else {
            AsmUtil.pushInt(out, targetBlock.intState);
            out.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
        }
        out.add(new JumpInsnNode(Opcodes.GOTO, loop));
    }

    private static void emitSwitchTransition(InsnList out, Block block, List<Block> blocks,
                                             int stateLocal, LabelNode loop, boolean useLongState) {
        int targetCount = block.switchTargets.length;
        LabelNode[] caseLabels = new LabelNode[targetCount];
        for (int i = 0; i < targetCount; i++) {
            caseLabels[i] = new LabelNode();
        }
        LabelNode defaultCase = new LabelNode();
        if (block.terminator.getOpcode() == Opcodes.TABLESWITCH) {
            TableSwitchInsnNode table = (TableSwitchInsnNode) block.terminator;
            out.add(new TableSwitchInsnNode(table.min, table.max, defaultCase, caseLabels));
        } else {
            LookupSwitchInsnNode table = (LookupSwitchInsnNode) block.terminator;
            int[] keys = new int[table.keys.size()];
            for (int i = 0; i < keys.length; i++) {
                keys[i] = table.keys.get(i).intValue();
            }
            out.add(new LookupSwitchInsnNode(defaultCase, keys, caseLabels));
        }
        for (int i = 0; i < targetCount; i++) {
            out.add(caseLabels[i]);
            emitState(out, blocks, block.switchTargets[i], stateLocal, loop, useLongState);
        }
        out.add(defaultCase);
        emitState(out, blocks, block.switchDefault, stateLocal, loop, useLongState);
    }

    // ---------------------------------------------------------------- helpers

    private static void collectCategories(Frame<BasicValue> frame, String[] categories) {
        if (frame == null) {
            return;
        }
        int limit = Math.min(frame.getLocals(), categories.length);
        for (int slot = 0; slot < limit; slot++) {
            String category = category(frame.getLocal(slot));
            if (category == null) {
                continue;
            }
            String previous = categories[slot];
            if (previous == null) {
                categories[slot] = category;
            } else if (!previous.equals(category)) {
                throw new Skip("locals");
            }
        }
    }

    private static String category(BasicValue value) {
        if (value == null || value == BasicValue.UNINITIALIZED_VALUE) {
            return null;
        }
        Type type = value.getType();
        if (type == null) {
            return null;
        }
        switch (type.getSort()) {
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT:
                return "I";
            case Type.LONG:
                return "J";
            case Type.FLOAT:
                return "F";
            case Type.DOUBLE:
                return "D";
            case Type.ARRAY:
            case Type.OBJECT:
                return "L";
            default:
                return null;
        }
    }

    private static InsnList junk(Random random) {
        InsnList out = new InsnList();
        switch (random.nextInt(3)) {
            case 0:
                AsmUtil.pushInt(out, random.nextInt());
                AsmUtil.pushInt(out, random.nextInt());
                out.add(new InsnNode(Opcodes.IADD));
                out.add(new InsnNode(Opcodes.POP));
                break;
            case 1:
                out.add(new LdcInsnNode(Long.valueOf(random.nextLong())));
                out.add(new LdcInsnNode(Long.valueOf(random.nextLong())));
                out.add(new InsnNode(Opcodes.LXOR));
                out.add(new InsnNode(Opcodes.POP2));
                break;
            default:
                AsmUtil.pushInt(out, random.nextInt());
                AsmUtil.pushInt(out, random.nextInt());
                out.add(new InsnNode(Opcodes.IMUL));
                out.add(new InsnNode(Opcodes.POP));
                break;
        }
        return out;
    }

    private static int inverseOdd(int value) {
        int inverse = value;
        for (int i = 0; i < 6; i++) {
            inverse *= 2 - value * inverse;
        }
        return inverse;
    }

    private static long inverseOdd(long value) {
        long inverse = value;
        for (int i = 0; i < 7; i++) {
            inverse *= 2L - value * inverse;
        }
        return inverse;
    }

    private static boolean isReturnOrThrow(int opcode) {
        return (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) || opcode == Opcodes.ATHROW;
    }

    private static int argumentSlots(MethodNode method) {
        int slots = (method.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type type : Type.getArgumentTypes(method.desc)) {
            slots += type.getSize();
        }
        return slots;
    }

    private static boolean isConditional(int opcode) {
        return opcode >= Opcodes.IFEQ && opcode <= Opcodes.IF_ACMPNE
                || opcode == Opcodes.IFNULL || opcode == Opcodes.IFNONNULL;
    }

    private static final class Block {
        final int index;
        final LabelNode label;
        final AbstractInsnNode leader;
        final List<AbstractInsnNode> insns = new ArrayList<AbstractInsnNode>();
        AbstractInsnNode terminator;
        boolean handler;
        int kind;
        int target = -1;
        int trueTarget = -1;
        int falseTarget = -1;
        int[] switchTargets;
        int switchDefault = -1;
        int slot = -1;
        int intState;
        long longState;

        Block(int index, LabelNode label, AbstractInsnNode leader) {
            this.index = index;
            this.label = label;
            this.leader = leader;
        }
    }

    private static final class FlattenResult {
        int blocks;
        boolean tryCatch;
        int switchBlocks;
    }

    /** Internal control-flow reason to fall back to the original method. */
    private static final class Skip extends RuntimeException {
        final String reason;

        Skip(String reason) {
            super(reason, null, false, false);
            this.reason = reason;
        }
    }
}
