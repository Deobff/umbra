package io.umbra.core.pass.impl.flowints;

import io.umbra.core.flow.MethodFlowAnalyzer;

import java.util.List;
import java.util.Random;

/**
 * Build-time assignment of the flow-ints state variable.
 *
 * <p>aidsfuscator's {@code FlowIntsTransformer} walks the control-flow graph,
 * gives every block a build-time state value and inserts an update wherever a
 * block's value differs from the value its first predecessor carries
 * ({@code flowInts/FlowIntsTransformer.java:55-108}, {@code initializeValues}
 * at {@code :162-204}). Because the state variable is read at a constant push
 * site, the JVM evaluation order must reproduce exactly the build-time value or
 * the site materialises the wrong constant; the whole transform therefore hangs
 * off one invariant:</p>
 *
 * <blockquote>At the first instruction of every block the state variable holds
 * the block's assigned value, on every run-time path that reaches it.</blockquote>
 *
 * <p>The donor guarantees the invariant by union-find: all predecessors of a
 * join block are unified, so a join can only ever be entered with one value
 * ({@code initializeValues}). This port keeps that reasoning but makes the
 * disagreement explicit instead of silently forcing it: blocks are visited in
 * reverse post-order (the same linear order the donor relies on), and whenever
 * the incoming value is not uniquely known - a join whose predecessors carry
 * different values, or a back edge whose latch has not been assigned yet - the
 * block is re-anchored with {@code s = value} instead of being chained from an
 * unknown predecessor. Re-anchoring is unconditionally sound (it overwrites the
 * state before any site in the block reads it), so the invariant holds by
 * construction and the disagreement is counted for the report rather than
 * papered over.</p>
 *
 * <p>Blocks that are exception handlers, or that are the target of an exception
 * edge, can be entered from anywhere inside a protected range, so their incoming
 * state is unknown by definition and they are always re-anchored. Unreachable
 * blocks are left completely alone ({@link #MODE_SKIP}): dead code carries no
 * frames, and inserting a local read into it only gives the verifier something
 * to complain about.</p>
 *
 * <p><b>Empty blocks are transparent.</b> A block can consist only of labels -
 * two leaders next to each other produce a block with no real instruction at
 * all. Nothing can be emitted there, so nothing can advance the state either:
 * whatever its predecessor left in the variable arrives unchanged at the
 * successors, and the successors are the ones that must anchor or advance.
 * Predecessor resolution therefore walks <em>through</em> empty blocks, which is
 * what makes a successor's "unique incoming value" claim true at run time. The
 * planner plans no write for an empty block, and the emitter has nothing to
 * place; a non-empty block whose first real instruction cannot be located is a
 * hard error the pass refuses to paper over.</p>
 */
public final class FlowStatePlan {

    /** The block keeps whatever state its predecessors carried. */
    public static final int MODE_NONE = 0;

    /** The block starts a chain: {@code s = value}. */
    public static final int MODE_SEED = 1;

    /** The block advances the chain: {@code s = s * A + B}, {@code from * A + B == value}. */
    public static final int MODE_ADVANCE = 2;

    /** A join whose incoming states disagree: the chain is re-anchored. */
    public static final int MODE_RESEED = 3;

    /** Unreachable block: no state, no sites. */
    public static final int MODE_SKIP = 4;

    private final int[] state;
    private final int[] mode;
    private final int[] incoming;
    private final int states;
    private final int seeds;
    private final int advances;
    private final int merges;
    private final int joins;
    private final boolean[] empty;

    private FlowStatePlan(int[] state, int[] mode, int[] incoming, int states, int seeds,
                          int advances, int merges, int joins, boolean[] empty) {
        this.empty = empty;
        this.state = state;
        this.mode = mode;
        this.incoming = incoming;
        this.states = states;
        this.seeds = seeds;
        this.advances = advances;
        this.merges = merges;
        this.joins = joins;
    }

    public int size() {
        return state.length;
    }

    public int state(int block) {
        return state[block];
    }

    public int mode(int block) {
        return mode[block];
    }

    /** The predecessor value an {@link #MODE_ADVANCE} block transitions from. */
    public int incoming(int block) {
        return incoming[block];
    }

    /** Seed + advance + re-anchor sites, i.e. every place the variable is written. */
    public int states() {
        return states;
    }

    public int seeds() {
        return seeds;
    }

    public int advances() {
        return advances;
    }

    /** Join points whose incoming states disagreed, re-anchored instead of chained. */
    public int merges() {
        return merges;
    }

    /** Blocks with two or more normal (non-exception) predecessors. */
    public int joins() {
        return joins;
    }

    /** True when the block carries no real instruction and only forwards control. */
    public boolean isEmpty(int block) {
        return block >= 0 && block < empty.length && empty[block];
    }

    /**
     * Assigns one state value per block for {@code flow} using {@code random}.
     *
     * @param inheritPercent chance that a block with a unique incoming value keeps
     *                       it (0..100); a lower value means more state updates
     *                       and more instruction growth
     */
    public static FlowStatePlan create(MethodFlowAnalyzer flow, Random random, int inheritPercent) {
        int count = flow.blockCount();
        int[] state = new int[count];
        int[] mode = new int[count];
        int[] incoming = new int[count];
        boolean[] assigned = new boolean[count];
        boolean[] exceptionEntry = new boolean[count];

        List<MethodFlowAnalyzer.Block> blocks = flow.blocks();
        for (int i = 0; i < count; i++) {
            MethodFlowAnalyzer.Block block = blocks.get(i);
            if (block.isHandlerEntry()) {
                exceptionEntry[block.index()] = true;
            }
            List<MethodFlowAnalyzer.Block> handlers = block.handlers();
            for (int h = 0; h < handlers.size(); h++) {
                MethodFlowAnalyzer.Block handler = handlers.get(h);
                if (handler != null) {
                    exceptionEntry[handler.index()] = true;
                }
            }
        }

        boolean[] empty = new boolean[count];
        for (int i = 0; i < count; i++) {
            empty[i] = !hasRealInstruction(blocks, blocks.get(i));
        }

        int[][] rawPreds = new int[count][];
        for (int i = 0; i < count; i++) {
            MethodFlowAnalyzer.Block block = blocks.get(i);
            List<MethodFlowAnalyzer.Block> preds = block.predecessors();
            int[] buffer = new int[preds.size()];
            int used = 0;
            for (int p = 0; p < preds.size(); p++) {
                MethodFlowAnalyzer.Block pred = preds.get(p);
                if (pred == null) {
                    continue;
                }
                if (containsIdentity(pred.handlers(), block)) {
                    continue;
                }
                buffer[used++] = pred.index();
            }
            if (used == buffer.length) {
                rawPreds[i] = buffer;
            } else {
                int[] trimmed = new int[used];
                System.arraycopy(buffer, 0, trimmed, 0, used);
                rawPreds[i] = trimmed;
            }
        }

        int[][] normalPreds = new int[count][];
        for (int i = 0; i < count; i++) {
            normalPreds[i] = resolvePreds(rawPreds, empty, count, i);
        }

        int states = 0;
        int seeds = 0;
        int advances = 0;
        int merges = 0;
        int joins = 0;

        MethodFlowAnalyzer.Block entry = flow.entry();
        List<MethodFlowAnalyzer.Block> order = flow.reversePostOrder();
        for (int i = 0; i < order.size(); i++) {
            MethodFlowAnalyzer.Block block = order.get(i);
            int index = block.index();
            int[] preds = normalPreds[index];
            int first = 0;
            int reachable = 0;
            boolean haveFirst = false;
            boolean differ = false;
            boolean unknown = false;
            for (int p = 0; p < preds.length; p++) {
                MethodFlowAnalyzer.Block pred = blocks.get(preds[p]);
                if (!pred.isReachable()) {
                    continue;
                }
                reachable++;
                if (!assigned[pred.index()]) {
                    unknown = true;
                    continue;
                }
                int value = state[pred.index()];
                if (!haveFirst) {
                    first = value;
                    haveFirst = true;
                } else if (value != first) {
                    differ = true;
                }
            }
            if (reachable >= 2) {
                joins++;
            }
            if (empty[index]) {
                state[index] = haveFirst ? first : 0;
                mode[index] = MODE_NONE;
                assigned[index] = true;
            } else if (block == entry || exceptionEntry[index] || block.isHandlerEntry()
                    || reachable == 0) {
                state[index] = random.nextInt();
                mode[index] = MODE_SEED;
                seeds++;
                states++;
                assigned[index] = true;
            } else if (unknown || differ) {
                state[index] = random.nextInt();
                mode[index] = MODE_RESEED;
                merges++;
                states++;
                assigned[index] = true;
            } else {
                int roll = random.nextInt(100);
                if (roll < inheritPercent) {
                    state[index] = first;
                    mode[index] = MODE_NONE;
                } else {
                    int fresh = random.nextInt();
                    if (fresh == first) {
                        fresh = ~fresh;
                    }
                    state[index] = fresh;
                    mode[index] = MODE_ADVANCE;
                    incoming[index] = first;
                    advances++;
                    states++;
                }
                assigned[index] = true;
            }
        }

        for (int i = 0; i < count; i++) {
            if (assigned[i]) {
                continue;
            }
            mode[i] = MODE_SKIP;
            state[i] = 0;
        }

        return new FlowStatePlan(state, mode, incoming, states, seeds, advances, merges, joins,
                empty);
    }

    /** A block with no real instruction cannot host a state write. */
    private static boolean hasRealInstruction(List<MethodFlowAnalyzer.Block> blocks,
                                              MethodFlowAnalyzer.Block block) {
        int next = block.index() + 1;
        org.objectweb.asm.tree.AbstractInsnNode stop =
                next < blocks.size() ? blocks.get(next).startInsn() : null;
        for (org.objectweb.asm.tree.AbstractInsnNode cursor = block.startInsn();
             cursor != null && cursor != stop; cursor = cursor.getNext()) {
            if (cursor.getOpcode() >= 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Flattens the predecessors of {@code index} through empty blocks, so the
     * value a successor sees is the value the last real block on the path left
     * behind. Recursion terminates: an empty block holds no branch, so a cycle
     * made only of empty blocks cannot exist.
     */
    private static int[] resolvePreds(int[][] rawPreds, boolean[] empty, int count, int index) {
        java.util.LinkedHashSet<Integer> out = new java.util.LinkedHashSet<Integer>();
        boolean[] guard = new boolean[count];
        for (int p = 0; p < rawPreds[index].length; p++) {
            resolve(rawPreds[index][p], rawPreds, empty, out, guard);
        }
        int[] result = new int[out.size()];
        int cursor = 0;
        for (Integer value : out) {
            result[cursor++] = value.intValue();
        }
        return result;
    }

    private static void resolve(int pred, int[][] rawPreds, boolean[] empty,
                                java.util.LinkedHashSet<Integer> out, boolean[] guard) {
        if (pred < 0 || pred >= empty.length || guard[pred]) {
            return;
        }
        if (!empty[pred]) {
            out.add(Integer.valueOf(pred));
            return;
        }
        guard[pred] = true;
        for (int p = 0; p < rawPreds[pred].length; p++) {
            resolve(rawPreds[pred][p], rawPreds, empty, out, guard);
        }
        guard[pred] = false;
    }

    private static boolean containsIdentity(List<MethodFlowAnalyzer.Block> list,
                                            MethodFlowAnalyzer.Block wanted) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i) == wanted) {
                return true;
            }
        }
        return false;
    }

    /** Diagnostic text used by the pass log; never feeds a build decision. */
    public String summary() {
        return "states=" + states + " seeds=" + seeds + " advances=" + advances
                + " joins=" + joins + " reseeds=" + merges;
    }
}
