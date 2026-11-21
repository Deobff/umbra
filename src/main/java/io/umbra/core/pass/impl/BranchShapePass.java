package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.BuildRoot;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Branch shape normalisation, ported from the reference implementation's branch family
 * ({@code transform/impl/the negation transformer.java} and
 * {@code transform/impl/SwitchTransformer.java}).
 *
 * <h3>What is ported, and what the references actually did</h3>
 *
 * <p>Neither reference transformer runs in the reference implementation: {@code
 * the negation transformer} is absent from {@code the reference pipeline}
 * and negates <em>integer constants</em> rather than branches
 * ({@code docs/port/SPEC-skid.md} section 14), and {@code SwitchTransformer}
 * only re-hashes the selector and the case keys of an existing switch
 * (section 15), which lowers to exactly the same switch shape. The technique
 * this pass implements is the shape rewrite both of them are reaching for:
 * rewrite the control flow, leave the data flow alone.</p>
 *
 * <h3>Two sub-transforms, one order</h3>
 *
 * <ol>
 *   <li><b>Switch normalisation</b> ({@code branch.switchMode}): a
 *       {@code tableswitch}/{@code lookupswitch} becomes an if-else chain
 *       ({@code toIf}), or a run of {@code IF_ICMPEQ}/{@code IF_ICMPNE}
 *       comparisons against one local becomes a switch ({@code toSwitch}).
 *       {@code mix} decides per site.</li>
 *   <li><b>Branch negation</b> ({@code branch.negateRate}): every surviving
 *       conditional jump {@code IFxx t} becomes {@code IF!xx skip; GOTO t;
 *       skip:}. Both paths are preserved, only the physical layout changes, so
 *       a decompiler loses the {@code if/else} nesting it inferred from
 *       fallthrough order.</li>
 * </ol>
 *
 * <p>Switch shapes are normalised <em>before</em> branches are negated on
 * purpose: the if-chain detector must see the shape javac actually emits
 * ({@code IF_ICMPNE} to the next check with the body in between), and
 * negating first would replace those comparisons with the inverted-goto form.
 * Sites created by the normaliser are excluded from the negation scan only in
 * the sense that the negation scan walks the instruction list once; it never
 * revisits the same jump twice.</p>
 *
 * <h3>Safety</h3>
 *
 * <p>Every rewritten method goes through {@link MethodGate}: copy, transform,
 * verify, commit. A chain is only merged when its structure proves the stack
 * depth cannot change (each intermediate check is entered solely from the
 * previous check's branch, and every case body transfers control
 * unconditionally), and only when no externally referenced label lives inside
 * the rewritten span. Anything doubtful is skipped and counted rather than
 * guessed at.</p>
 *
 * <p>All randomness comes from a per-method stream derived from the build seed
 * ({@link BuildRoot}), so the same seed produces byte-identical output
 * regardless of how many other methods or classes were processed first.</p>
 */
public final class BranchShapePass implements Pass {

    private static final int MODE_NONE = 0;
    private static final int MODE_TO_IF = 1;
    private static final int MODE_TO_SWITCH = 2;
    private static final int MODE_MIX = 3;

    private static final int SKIP_INELIGIBLE = 0;
    private static final int SKIP_RULE = 1;
    private static final int SKIP_CLINIT = 2;
    private static final int SKIP_JSR = 3;
    private static final int SKIP_BRIDGE = 4;
    private static final int SKIP_LIMIT = 5;
    private static final int SKIP_GATE = 6;
    private static final int SKIP_TRANSFORM = 7;

    private static final String[] SKIP_KEYS = {
            "branch.skipped.ineligible", "branch.skipped.rule", "branch.skipped.clinit",
            "branch.skipped.jsr", "branch.skipped.bridge", "branch.skipped.limit",
            "branch.skipped.gate", "branch.skipped.transform"
    };

    /**
     * Inverse conditional-jump opcode table, indexed by opcode; {@code -1} for
     * everything that is not a conditional branch.
     *
     * <p>The JVM has exactly sixteen conditional branch instructions. Floating
     * point and long comparisons are not branches: {@code lcmp}/{@code fcmpl}/
     * {@code fcmpg}/{@code dcmpl}/{@code dcmpg} push an int, and the resulting
     * {@code IF&lt;cond&gt;} is negated like any other. The table is therefore
     * exhaustive over opcodes, and {@code BranchTest} reflects over
     * {@link Opcodes} to pin that claim instead of trusting it.</p>
     */
    private static final int[] INVERSE = new int[256];

    static {
        Arrays.fill(INVERSE, -1);
        link(Opcodes.IFEQ, Opcodes.IFNE);
        link(Opcodes.IFLT, Opcodes.IFGE);
        link(Opcodes.IFGT, Opcodes.IFLE);
        link(Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE);
        link(Opcodes.IF_ICMPLT, Opcodes.IF_ICMPGE);
        link(Opcodes.IF_ICMPGT, Opcodes.IF_ICMPLE);
        link(Opcodes.IF_ACMPEQ, Opcodes.IF_ACMPNE);
        link(Opcodes.IFNULL, Opcodes.IFNONNULL);
    }

    private static void link(int left, int right) {
        INVERSE[left] = right;
        INVERSE[right] = left;
    }

    /** Inverse of a conditional branch opcode, or {@code -1} for anything else. */
    public static int inverseOpcode(int opcode) {
        if (opcode < 0 || opcode >= INVERSE.length) {
            return -1;
        }
        return INVERSE[opcode];
    }

    /** True for the sixteen conditional branch opcodes and nothing else. */
    public static boolean isConditionalJump(int opcode) {
        return inverseOpcode(opcode) >= 0;
    }

    @Override
    public String name() {
        return "branch-shape";
    }

    @Override
    public int order() {
        return 89;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool("branch.enabled", false);
    }

    @Override
    public void run(PassContext context) {
        Params params = Params.read(context);
        long[] skips = new long[SKIP_KEYS.length];
        long negated = 0L;
        long switchToIf = 0L;
        long ifToSwitch = 0L;
        long sitesSkipped = 0L;
        long skipRollback = 0L;
        int methods = 0;
        int classes = 0;
        MethodGate gate = new MethodGate(context);

        List<ClassNode> candidates = new ArrayList<ClassNode>(context.classes().classes().values());
        for (ClassNode node : candidates) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
            if (context.rules().skipBodyTransform(node.name) || !context.rules().transformClass(node)) {
                skips[SKIP_RULE]++;
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0
                    || "module-info".equals(node.name) || node.name.endsWith("/module-info")) {
                skips[SKIP_INELIGIBLE]++;
                continue;
            }

            List<MethodNode> saved = new ArrayList<MethodNode>();
            for (MethodNode method : node.methods) {
                saved.add(MethodGate.copy(method));
            }

            int classMethods = 0;
            long classNegated = 0L;
            long classSwitchToIf = 0L;
            long classIfToSwitch = 0L;
            long classSitesSkipped = 0L;
            try {
                for (MethodNode method : node.methods) {
                    int reason = skipReason(method, params);
                    if (reason >= 0) {
                        skips[reason]++;
                        continue;
                    }
                    MethodNode work = MethodGate.copy(method);
                    Result result;
                    try {
                        result = transform(context, node, work, params);
                    } catch (RuntimeException failure) {
                        skips[SKIP_TRANSFORM]++;
                        context.log().debug("branch-shape: skipped %s.%s: %s",
                                node.name, method.name, failure);
                        continue;
                    }
                    if (result.sites() == 0) {
                        // Nothing was rewritten, but the methods that refused a site
                        // (a degenerate branch, an unmergeable chain) are still
                        // accountable: the count is how a caller notices that a
                        // class came out shape-identical.
                        classSitesSkipped += result.sitesSkipped;
                        continue;
                    }
                    if (!gate.verify(node, work)) {
                        skips[SKIP_GATE]++;
                        context.log().debug("branch-shape: verification rejected %s.%s",
                                node.name, method.name);
                        continue;
                    }
                    // Commit a *second* copy: MethodGate.verify has just serialised
                    // `work` (and its labels) through one ClassWriter, and ASM resolves
                    // a Label in place, so a later ClassWriter reusing those Label
                    // objects writes jumps against the previous writer's offsets - the
                    // result still passes its own verifier but jumps into the middle of
                    // instructions. A fresh copy gives the final writer virgin labels.
                    MethodGate.commit(method, MethodGate.copy(work));
                    classMethods++;
                    classNegated += result.negated;
                    classSwitchToIf += result.switchToIf;
                    classIfToSwitch += result.ifToSwitch;
                    classSitesSkipped += result.sitesSkipped;
                }
            } catch (RuntimeException failure) {
                node.methods = new ArrayList<MethodNode>(saved);
                skipRollback++;
                context.log().debug("branch-shape: rolled back class %s: %s", node.name, failure);
                continue;
            }

            if (classMethods == 0) {
                continue;
            }
            classes++;
            methods += classMethods;
            negated += classNegated;
            switchToIf += classSwitchToIf;
            ifToSwitch += classIfToSwitch;
            sitesSkipped += classSitesSkipped;
        }

        long skipped = 0L;
        for (long value : skips) {
            skipped += value;
        }
        context.stats().add("branch.classes", classes);
        context.stats().add("branch.methods", methods);
        context.stats().add("branch.sites", negated + switchToIf + ifToSwitch);
        context.stats().add("branch.negated", negated);
        context.stats().add("branch.switchToIf", switchToIf);
        context.stats().add("branch.ifToSwitch", ifToSwitch);
        context.stats().add("branch.skipped", skipped);
        context.stats().add("branch.skipped.sites", sitesSkipped);
        context.stats().add("branch.skip.rollback", skipRollback);
        for (int i = 0; i < SKIP_KEYS.length; i++) {
            context.stats().add(SKIP_KEYS[i], skips[i]);
        }
        context.log().info("branch-shape: %d methods in %d classes, %d branches negated (rate %d), "
                        + "%d switches->if, %d if->switch (mode %s, rate %d), "
                        + "%d methods skipped, %d sites skipped, %d rolled back",
                methods, classes, negated, params.negateRate, switchToIf, ifToSwitch,
                params.modeName, params.switchRate, skipped, sitesSkipped, skipRollback);
    }

    private static int skipReason(MethodNode method, Params params) {
        if (method.instructions == null || method.instructions.size() == 0) {
            return SKIP_INELIGIBLE;
        }
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return SKIP_INELIGIBLE;
        }
        if ("<clinit>".equals(method.name) && !params.includeClinit) {
            return SKIP_CLINIT;
        }
        if (method.name.startsWith("<") && !"<init>".equals(method.name)) {
            return SKIP_INELIGIBLE;
        }
        // A bridge (or a synthetic final shim) forwards to another member; it has
        // no branch shape of its own worth rewriting, and rewriting it is how a
        // signature feels abusable to a tool.
        if ((method.access & Opcodes.ACC_BRIDGE) != 0) {
            return SKIP_BRIDGE;
        }
        if ((method.access & Opcodes.ACC_SYNTHETIC) != 0
                && (method.access & Opcodes.ACC_FINAL) != 0) {
            return SKIP_BRIDGE;
        }
        if (AsmUtil.containsJsrOrRet(method)) {
            return SKIP_JSR;
        }
        if (method.instructions.size() > params.maxInstructions) {
            return SKIP_LIMIT;
        }
        return -1;
    }

    private static Result transform(PassContext context, ClassNode owner, MethodNode method,
                                    Params params) {
        Result result = new Result();
        if (params.mode != MODE_NONE) {
            Random random = methodStream(context, owner, method, "umbra.branch.switch.v1");
            normalizeSwitches(method, params, random, result);
        }
        if (params.negateRate > 0) {
            Random random = methodStream(context, owner, method, "umbra.branch.negate.v1");
            result.negated = negate(method, random, params.negateRate, result);
        }
        return result;
    }

    private static Random methodStream(PassContext context, ClassNode owner, MethodNode method,
                                       String label) {
        byte[] material = BuildRoot.derive(context.config().seed(),
                label + ":" + owner.name + "." + method.name + method.desc);
        long value = 0L;
        for (int i = 0; i < 8; i++) {
            value |= (material[i] & 0xFFL) << (8 * i);
        }
        return new Random(value);
    }

    // ---------------------------------------------------------------- negation

    /**
     * {@code IFxx t} becomes {@code IF!xx skip; GOTO t; skip:}.
     *
     * <p>Both successors are unchanged: {@code skip} sits immediately before the
     * original fallthrough instruction, so the not-taken path executes exactly
     * what it executed before, and the taken path is now a {@code GOTO} to the
     * same label. The only thing that changes is which path is the fallthrough,
     * which is what breaks the if/else nesting a decompiler recovers from
     * physical order.</p>
     *
     * <p>A branch whose target <em>is</em> the next instruction is left alone
     * ({@code t == next}): rewriting it would produce {@code IF!xx skip; GOTO
     * skip; skip:}, an unconditional two-hop, and any later block-splitting pass
     * would spin on it.</p>
     */
    private static long negate(MethodNode method, Random random, int rate, Result result) {
        AbstractInsnNode[] snapshot = method.instructions.toArray();
        long count = 0L;
        for (AbstractInsnNode insn : snapshot) {
            if (!(insn instanceof JumpInsnNode)) {
                continue;
            }
            int inverse = inverseOpcode(insn.getOpcode());
            if (inverse < 0) {
                continue;
            }
            if (rate < 100 && random.nextInt(100) >= rate) {
                continue;
            }
            JumpInsnNode jump = (JumpInsnNode) insn;
            AbstractInsnNode next = nextReal(jump);
            if (next == null) {
                result.sitesSkipped++;
                continue;
            }
            if (targetsNext(jump, next)) {
                // The branch already targets its own fallthrough: rewriting it would
                // emit IF!xx skip; GOTO skip, an unconditional hop to the very next
                // label. Counted, not guessed at.
                result.sitesSkipped++;
                continue;
            }
            LabelNode skip = new LabelNode();
            InsnList replacement = new InsnList();
            replacement.add(new JumpInsnNode(inverse, skip));
            replacement.add(new JumpInsnNode(Opcodes.GOTO, jump.label));
            replacement.add(skip);
            method.instructions.insertBefore(jump, replacement);
            method.instructions.remove(jump);
            count++;
        }
        return count;
    }

    private static boolean targetsNext(JumpInsnNode jump, AbstractInsnNode next) {
        for (AbstractInsnNode cursor = jump.getNext(); cursor != null && cursor != next;
             cursor = cursor.getNext()) {
            if (cursor == jump.label) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------- switch normaliser

    private static void normalizeSwitches(MethodNode method, Params params, Random random,
                                          Result result) {
        AbstractInsnNode[] snapshot = method.instructions.toArray();
        Set<AbstractInsnNode> created = identitySet();
        Set<AbstractInsnNode> consumed = identitySet();
        Map<LabelNode, Integer> refs = labelReferences(method);
        for (AbstractInsnNode insn : snapshot) {
            if (created.contains(insn) || consumed.contains(insn)) {
                continue;
            }
            if (insn instanceof TableSwitchInsnNode || insn instanceof LookupSwitchInsnNode) {
                if (params.mode == MODE_TO_SWITCH) {
                    continue;
                }
                if (!roll(params, random)) {
                    continue;
                }
                int cases = switchCaseCount(insn);
                if (cases < 1 || cases > params.maxCases) {
                    result.sitesSkipped++;
                    continue;
                }
                if (switchToIf(method, insn, params, created)) {
                    result.switchToIf++;
                } else {
                    result.sitesSkipped++;
                }
                continue;
            }
            if (params.mode == MODE_TO_IF) {
                continue;
            }
            if (insn.getOpcode() != Opcodes.ILOAD) {
                continue;
            }
            Step step = stepAt(insn);
            if (step == null || !cleanPseudo(step, refs)) {
                continue;
            }
            if (!roll(params, random)) {
                continue;
            }
            boolean merged;
            if (step.jump.getOpcode() == Opcodes.IF_ICMPNE) {
                merged = invertedChainToSwitch(method, step, params, created, consumed, refs);
            } else {
                merged = adjacentChainToSwitch(method, step, params, created, consumed, refs);
            }
            if (merged) {
                result.ifToSwitch++;
            } else {
                result.sitesSkipped++;
            }
        }
    }

    private static boolean roll(Params params, Random random) {
        if (params.mode == MODE_TO_IF || params.mode == MODE_TO_SWITCH) {
            return true;
        }
        return params.switchRate >= 100 || random.nextInt(100) < params.switchRate;
    }

    private static int switchCaseCount(AbstractInsnNode insn) {
        if (insn instanceof TableSwitchInsnNode) {
            TableSwitchInsnNode table = (TableSwitchInsnNode) insn;
            return table.max - table.min + 1;
        }
        LookupSwitchInsnNode lookup = (LookupSwitchInsnNode) insn;
        return lookup.keys.size();
    }

    /**
     * {@code switch (k)} becomes {@code k -> local; local == c1 ? L1 : ... } and
     * a final {@code GOTO default}.
     *
     * <p>The selector is on the operand stack and the switch consumes it, so it
     * is stored into a fresh local and reloaded per comparison. Anything below
     * the selector stays where it was and reaches every branch unchanged, which
     * is why this works even for a switch emitted inside a larger expression
     * frame.</p>
     */
    private static boolean switchToIf(MethodNode method, AbstractInsnNode insn, Params params,
                                      Set<AbstractInsnNode> created) {
        int[] keys;
        LabelNode[] targets;
        LabelNode dflt;
        if (insn instanceof TableSwitchInsnNode) {
            TableSwitchInsnNode table = (TableSwitchInsnNode) insn;
            int span = table.max - table.min + 1;
            if (table.dflt == null || span <= 0 || table.labels.size() != span) {
                return false;
            }
            keys = new int[span];
            targets = new LabelNode[span];
            for (int i = 0; i < span; i++) {
                keys[i] = table.min + i;
                targets[i] = table.labels.get(i);
            }
            dflt = table.dflt;
        } else if (insn instanceof LookupSwitchInsnNode) {
            LookupSwitchInsnNode lookup = (LookupSwitchInsnNode) insn;
            if (lookup.dflt == null || lookup.keys.isEmpty()
                    || lookup.keys.size() != lookup.labels.size()) {
                return false;
            }
            keys = new int[lookup.keys.size()];
            targets = new LabelNode[lookup.keys.size()];
            for (int i = 0; i < keys.length; i++) {
                keys[i] = lookup.keys.get(i).intValue();
                targets[i] = lookup.labels.get(i);
            }
            dflt = lookup.dflt;
        } else {
            return false;
        }
        if (keys.length > params.maxCases) {
            return false;
        }

        int slot = nextFreeLocal(method);
        method.maxLocals = Math.max(method.maxLocals, slot + 1);
        InsnList replacement = new InsnList();
        VarInsnNode store = new VarInsnNode(Opcodes.ISTORE, slot);
        replacement.add(store);
        created.add(store);
        for (int i = 0; i < keys.length; i++) {
            VarInsnNode load = new VarInsnNode(Opcodes.ILOAD, slot);
            replacement.add(load);
            created.add(load);
            InsnList push = new InsnList();
            AsmUtil.pushInt(push, keys[i]);
            copyInto(push, replacement, created);
            JumpInsnNode compare = new JumpInsnNode(Opcodes.IF_ICMPEQ, targets[i]);
            replacement.add(compare);
            created.add(compare);
        }
        JumpInsnNode toDefault = new JumpInsnNode(Opcodes.GOTO, dflt);
        replacement.add(toDefault);
        created.add(toDefault);
        method.instructions.insertBefore(insn, replacement);
        method.instructions.remove(insn);
        return true;
    }

    /**
     * {@code k1 -> L1; k2 -> L2; ... ; fallthrough} becomes a switch.
     *
     * <p>This is the shape {@code IF_ICMPEQ} chains have: every comparison jumps
     * to its case body and the not-taken path checks the next key. The chain end
     * is the default path, wrapped in a fresh label so the switch can jump to it
     * instead of falling into it.</p>
     */
    private static boolean adjacentChainToSwitch(MethodNode method, Step first, Params params,
                                                 Set<AbstractInsnNode> created,
                                                 Set<AbstractInsnNode> consumed,
                                                 Map<LabelNode, Integer> refs) {
        List<Step> steps = new ArrayList<Step>();
        Set<Integer> keys = new HashSet<Integer>();
        int var = first.var;
        Step current = first;
        while (current != null) {
            if (current.var != var) {
                break;
            }
            if (!keys.add(Integer.valueOf(current.key))) {
                break;
            }
            steps.add(current);
            AbstractInsnNode cursor = nextReal(current.jump);
            if (cursor == null) {
                break;
            }
            Step next = stepAt(cursor);
            if (next == null || created.contains(next.load)
                    || next.jump.getOpcode() != Opcodes.IF_ICMPEQ) {
                break;
            }
            if (hasReferencedBetween(current.jump, next.load, refs)) {
                break;
            }
            current = next;
        }
        if (steps.size() < 2 || steps.size() > params.maxCases) {
            return false;
        }
        Step last = steps.get(steps.size() - 1);
        AbstractInsnNode fallthrough = nextReal(last.jump);
        if (fallthrough == null) {
            return false;
        }
        LabelNode dflt = new LabelNode();
        method.instructions.insert(last.jump, dflt);
        created.add(dflt);

        int[] caseKeys = new int[steps.size()];
        LabelNode[] caseLabels = new LabelNode[steps.size()];
        for (int i = 0; i < steps.size(); i++) {
            caseKeys[i] = steps.get(i).key;
            caseLabels[i] = steps.get(i).jump.label;
        }

        InsnList replacement = new InsnList();
        VarInsnNode load = new VarInsnNode(Opcodes.ILOAD, var);
        replacement.add(load);
        created.add(load);
        replacement.add(switchFor(caseKeys, caseLabels, dflt, params, created));
        method.instructions.insertBefore(first.load, replacement);
        for (Step step : steps) {
            consumed.add(step.load);
            consumed.add(step.constant);
            consumed.add(step.jump);
            method.instructions.remove(step.load);
            method.instructions.remove(step.constant);
            method.instructions.remove(step.jump);
        }
        return true;
    }

    /**
     * The shape javac emits for an if / else-if chain: each comparison jumps
     * <em>over</em> its own body to the next comparison
     * ({@code ILOAD v; push k; IF_ICMPNE next}), and the body in between ends in
     * {@code goto}/{@code return}/{@code athrow}.
     *
     * <p>Merging is safe only under three structural facts, each of which is
     * checked here rather than assumed:</p>
     * <ul>
     *   <li>no body falls through into the next check (otherwise the next check
     *       would run after the body, which a switch cannot express);</li>
     *   <li>no externally referenced label sits between a check's target and the
     *       next check's load (removing the check would retarget that label onto
     *       the following case body);</li>
     *   <li>every intermediate check label is referenced exactly once, by the
     *       previous check's branch.</li>
     * </ul>
     * <p>Together those also prove the stack depth is identical at every check,
     * so the single selector load the switch needs cannot disagree with the
     * frames the original checks produced.</p>
     */
    private static boolean invertedChainToSwitch(MethodNode method, Step first, Params params,
                                                 Set<AbstractInsnNode> created,
                                                 Set<AbstractInsnNode> consumed,
                                                 Map<LabelNode, Integer> refs) {
        List<Step> steps = new ArrayList<Step>();
        List<LabelNode> entries = new ArrayList<LabelNode>();
        Set<Integer> keys = new HashSet<Integer>();
        int var = first.var;
        Step current = first;
        LabelNode dflt = null;
        while (true) {
            if (current.var != var) {
                break;
            }
            if (!keys.add(Integer.valueOf(current.key))) {
                break;
            }
            LabelNode target = current.jump.label;
            if (target == null) {
                break;
            }
            AbstractInsnNode bodyStart = nextReal(current.jump);
            AbstractInsnNode afterTarget = firstRealFrom(target);
            if (bodyStart == null || afterTarget == null) {
                break;
            }
            if (!precedes(current.jump, target)) {
                break;
            }
            AbstractInsnNode bodyEnd = previousReal(afterTarget);
            if (bodyEnd == null || !transfersControl(bodyEnd)) {
                break;
            }
            Step next = stepAt(afterTarget);
            if (next != null && (next.var != var || next.jump.getOpcode() != Opcodes.IF_ICMPNE
                    || created.contains(next.load))) {
                next = null;
            }
            if (next != null) {
                if (refCount(refs, target) != 1) {
                    break;
                }
                if (hasReferencedBetween(target, next.load, refs)) {
                    break;
                }
            }
            steps.add(current);
            entries.add(null);
            if (next == null) {
                dflt = target;
                break;
            }
            current = next;
        }
        if (steps.size() < 2 || steps.size() > params.maxCases || dflt == null) {
            return false;
        }

        int[] caseKeys = new int[steps.size()];
        LabelNode[] caseLabels = new LabelNode[steps.size()];
        for (int i = 0; i < steps.size(); i++) {
            Step step = steps.get(i);
            caseKeys[i] = step.key;
            LabelNode entry = new LabelNode();
            method.instructions.insert(step.jump, entry);
            entries.set(i, entry);
            caseLabels[i] = entry;
            created.add(entry);
        }

        InsnList replacement = new InsnList();
        VarInsnNode load = new VarInsnNode(Opcodes.ILOAD, var);
        replacement.add(load);
        created.add(load);
        replacement.add(switchFor(caseKeys, caseLabels, dflt, params, created));
        method.instructions.insertBefore(first.load, replacement);
        for (Step step : steps) {
            consumed.add(step.load);
            consumed.add(step.constant);
            consumed.add(step.jump);
            method.instructions.remove(step.load);
            method.instructions.remove(step.constant);
            method.instructions.remove(step.jump);
        }
        return true;
    }

    /**
     * Builds the cheapest correct switch for a key set: a table when the keys
     * span at most twice the case count (gaps shared the default label), a
     * lookup table otherwise.
     */
    private static AbstractInsnNode switchFor(int[] keys, LabelNode[] labels, LabelNode dflt,
                                              Params params, Set<AbstractInsnNode> created) {
        int count = keys.length;
        int min = Integer.MAX_VALUE;
        int max = Integer.MIN_VALUE;
        int[] sortedKeys = keys.clone();
        LabelNode[] sortedLabels = labels.clone();
        for (int i = 0; i < count; i++) {
            min = Math.min(min, keys[i]);
            max = Math.max(max, keys[i]);
        }
        // Keep the sort stable on duplicate keys (they are already rejected, but
        // an unchanged order keeps the output deterministic either way).
        for (int i = 1; i < count; i++) {
            int key = sortedKeys[i];
            LabelNode label = sortedLabels[i];
            int j = i - 1;
            while (j >= 0 && sortedKeys[j] > key) {
                sortedKeys[j + 1] = sortedKeys[j];
                sortedLabels[j + 1] = sortedLabels[j];
                j--;
            }
            sortedKeys[j + 1] = key;
            sortedLabels[j + 1] = label;
        }
        long span = (long) max - (long) min + 1L;
        AbstractInsnNode result;
        if (span > 0L && span <= Math.max(1L, (long) count * 2L) && span <= params.maxCases * 2L) {
            int width = (int) span;
            LabelNode[] table = new LabelNode[width];
            for (int i = 0; i < width; i++) {
                table[i] = dflt;
            }
            for (int i = 0; i < count; i++) {
                table[sortedKeys[i] - min] = sortedLabels[i];
            }
            result = new TableSwitchInsnNode(min, max, dflt, table);
        } else {
            result = new LookupSwitchInsnNode(dflt, sortedKeys, sortedLabels);
        }
        created.add(result);
        return result;
    }

    // ------------------------------------------------------------- structures

    private static final class Step {
        final VarInsnNode load;
        final AbstractInsnNode constant;
        final JumpInsnNode jump;
        final int var;
        final int key;

        Step(VarInsnNode load, AbstractInsnNode constant, JumpInsnNode jump, int key) {
            this.load = load;
            this.constant = constant;
            this.jump = jump;
            this.var = load.var;
            this.key = key;
        }
    }

    private static Step stepAt(AbstractInsnNode node) {
        if (!(node instanceof VarInsnNode) || node.getOpcode() != Opcodes.ILOAD) {
            return null;
        }
        AbstractInsnNode constant = nextReal(node);
        if (constant == null) {
            return null;
        }
        Integer key = intConstant(constant);
        if (key == null) {
            return null;
        }
        AbstractInsnNode third = nextReal(constant);
        if (!(third instanceof JumpInsnNode)) {
            return null;
        }
        int opcode = third.getOpcode();
        if (opcode != Opcodes.IF_ICMPEQ && opcode != Opcodes.IF_ICMPNE) {
            return null;
        }
        return new Step((VarInsnNode) node, constant, (JumpInsnNode) third, key.intValue());
    }

    private static Integer intConstant(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return Integer.valueOf(opcode - Opcodes.ICONST_0);
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return Integer.valueOf(((IntInsnNode) insn).operand);
        }
        if (insn instanceof LdcInsnNode) {
            Object value = ((LdcInsnNode) insn).cst;
            if (value instanceof Integer) {
                return (Integer) value;
            }
        }
        return null;
    }

    private static boolean cleanPseudo(Step step, Map<LabelNode, Integer> refs) {
        return !hasReferencedBetween(step.load, step.constant, refs)
                && !hasReferencedBetween(step.constant, step.jump, refs);
    }

    private static boolean transfersControl(AbstractInsnNode insn) {
        switch (insn.getOpcode()) {
            case Opcodes.GOTO:
            case Opcodes.TABLESWITCH:
            case Opcodes.LOOKUPSWITCH:
            case Opcodes.ATHROW:
            case Opcodes.IRETURN:
            case Opcodes.LRETURN:
            case Opcodes.FRETURN:
            case Opcodes.DRETURN:
            case Opcodes.ARETURN:
            case Opcodes.RETURN:
            case Opcodes.RET:
                return true;
            default:
                return false;
        }
    }

    private static AbstractInsnNode nextReal(AbstractInsnNode node) {
        AbstractInsnNode cursor = node == null ? null : node.getNext();
        while (cursor != null && cursor.getOpcode() < 0) {
            cursor = cursor.getNext();
        }
        return cursor;
    }

    private static AbstractInsnNode previousReal(AbstractInsnNode node) {
        AbstractInsnNode cursor = node == null ? null : node.getPrevious();
        while (cursor != null && cursor.getOpcode() < 0) {
            cursor = cursor.getPrevious();
        }
        return cursor;
    }

    private static AbstractInsnNode firstRealFrom(AbstractInsnNode node) {
        AbstractInsnNode cursor = node;
        while (cursor != null && cursor.getOpcode() < 0) {
            cursor = cursor.getNext();
        }
        return cursor;
    }

    private static boolean precedes(AbstractInsnNode first, AbstractInsnNode second) {
        for (AbstractInsnNode cursor = first.getNext(); cursor != null; cursor = cursor.getNext()) {
            if (cursor == second) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasReferencedBetween(AbstractInsnNode from, AbstractInsnNode to,
                                                Map<LabelNode, Integer> refs) {
        for (AbstractInsnNode cursor = from.getNext(); cursor != null && cursor != to;
             cursor = cursor.getNext()) {
            if (cursor instanceof LabelNode && refCount(refs, (LabelNode) cursor) > 0) {
                return true;
            }
        }
        return false;
    }

    private static int refCount(Map<LabelNode, Integer> refs, LabelNode label) {
        Integer count = refs.get(label);
        return count == null ? 0 : count.intValue();
    }

    /**
     * Counts every label reference a rewrite could orphan: branch targets,
     * switch targets and exception range boundaries. A label with a reference is
     * a legal entry point and must keep meaning what it meant, which is why a
     * chain that contains one is not merged.
     */
    private static Map<LabelNode, Integer> labelReferences(MethodNode method) {
        Map<LabelNode, Integer> refs = new IdentityHashMap<LabelNode, Integer>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode) {
                count(refs, ((JumpInsnNode) insn).label);
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode table = (TableSwitchInsnNode) insn;
                count(refs, table.dflt);
                for (LabelNode label : table.labels) {
                    count(refs, label);
                }
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode lookup = (LookupSwitchInsnNode) insn;
                count(refs, lookup.dflt);
                for (LabelNode label : lookup.labels) {
                    count(refs, label);
                }
            }
        }
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode block : method.tryCatchBlocks) {
                count(refs, block.start);
                count(refs, block.end);
                count(refs, block.handler);
            }
        }
        return refs;
    }

    private static void count(Map<LabelNode, Integer> refs, LabelNode label) {
        if (label == null) {
            return;
        }
        Integer current = refs.get(label);
        refs.put(label, Integer.valueOf(current == null ? 1 : current.intValue() + 1));
    }

    private static int nextFreeLocal(MethodNode method) {
        int slot = Math.max(0, method.maxLocals);
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof VarInsnNode) {
                VarInsnNode var = (VarInsnNode) insn;
                int width = 1;
                switch (var.getOpcode()) {
                    case Opcodes.LLOAD:
                    case Opcodes.DLOAD:
                    case Opcodes.LSTORE:
                    case Opcodes.DSTORE:
                        width = 2;
                        break;
                    default:
                        break;
                }
                slot = Math.max(slot, var.var + width);
            } else if (insn instanceof IincInsnNode) {
                slot = Math.max(slot, ((IincInsnNode) insn).var + 1);
            }
        }
        return slot;
    }

    private static void copyInto(InsnList source, InsnList target,
                                 Set<AbstractInsnNode> created) {
        AbstractInsnNode node = source.getFirst();
        while (node != null) {
            AbstractInsnNode next = node.getNext();
            target.add(node);
            created.add(node);
            node = next;
        }
    }

    private static <T> Set<T> identitySet() {
        return Collections.newSetFromMap(new IdentityHashMap<T, Boolean>());
    }

    private static final class Result {
        long negated;
        long switchToIf;
        long ifToSwitch;
        long sitesSkipped;

        long sites() {
            return negated + switchToIf + ifToSwitch;
        }
    }

    private static final class Params {
        int mode = MODE_MIX;
        String modeName = "mix";
        int negateRate = 50;
        int switchRate = 50;
        boolean includeClinit;
        int maxCases = 512;
        int maxInstructions = 10000;

        static Params read(PassContext context) {
            Params params = new Params();
            String raw = context.config().option("branch.switchMode", "mix");
            params.modeName = raw == null ? "mix" : raw.trim().toLowerCase(Locale.ROOT);
            if ("toif".equals(params.modeName) || "if".equals(params.modeName)
                    || "to_if".equals(params.modeName)) {
                params.mode = MODE_TO_IF;
            } else if ("toswitch".equals(params.modeName) || "switch".equals(params.modeName)
                    || "to_switch".equals(params.modeName)) {
                params.mode = MODE_TO_SWITCH;
            } else if ("none".equals(params.modeName) || "off".equals(params.modeName)
                    || "false".equals(params.modeName)) {
                params.mode = MODE_NONE;
            } else {
                params.mode = MODE_MIX;
                params.modeName = "mix";
            }
            params.negateRate = clamp(context.config().optionInt("branch.negateRate", 50), 0, 100);
            params.switchRate = clamp(context.config().optionInt("branch.switchRate", 50), 0, 100);
            params.includeClinit = context.config().optionBool("branch.includeClinit", false);
            params.maxCases = Math.max(2, context.config().optionInt("branch.maxSwitchCases", 512));
            params.maxInstructions = Math.max(64,
                    context.config().optionInt("branch.maxInstructions", 10000));
            return params;
        }

        private static int clamp(int value, int min, int max) {
            if (value < min) {
                return min;
            }
            return Math.min(value, max);
        }
    }
}
