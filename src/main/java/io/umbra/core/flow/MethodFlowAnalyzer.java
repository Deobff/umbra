package io.umbra.core.flow;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Control-flow model of a single method: basic blocks, dominator tree, natural
 * loops and local-variable liveness.
 *
 * <p>The shape follows the flow analyser used by commercial obfuscators: the
 * instruction list is cut into basic blocks at every branch target, switch
 * label, post-branch instruction, return/throw follower and every exception
 * table boundary, so a handler entry and a protected range start are block
 * leaders of their own. Edges are the fall-through edge, the explicit branch
 * edges, the switch edges and one edge from every block covered by a try range
 * to that range's handler.</p>
 *
 * <p>Dominators use the Cooper-Harvey-Kennedy iterative formulation: blocks are
 * numbered in reverse postorder, the immediate dominator of a block is the
 * meet (over the dominator tree) of its already-numbered predecessors, and the
 * whole pass is repeated until the numbering stops changing. That converges in
 * a handful of sweeps on reducible code and does not need a Lengauer-Tarjan
 * union-find.</p>
 *
 * <p>Natural loops are recovered from the back edges of the dominator tree: an
 * edge {@code latch -> header} whose target dominates its source closes a loop,
 * and the loop body is the header plus every block that reaches a latch
 * without leaving the loop through the header. Liveness is the usual backward
 * data-flow problem over block-level use/def sets, so a caller can pick an
 * insertion point where as few locals as possible are live.</p>
 *
 * <p>Everything is read-only with respect to the {@link MethodNode}: the
 * analyser stores instruction references, never indices, so an anchor picked
 * here stays valid when instructions are inserted elsewhere in the list.</p>
 */
public final class MethodFlowAnalyzer {

    private static final Comparator<Block> BLOCK_RANK = new Comparator<Block>() {
        @Override
        public int compare(Block a, Block b) {
            int rankA = a.rank();
            int rankB = b.rank();
            if (rankA != rankB) {
                return rankA < rankB ? -1 : 1;
            }
            int liveA = a.liveIn().cardinality();
            int liveB = b.liveIn().cardinality();
            if (liveA != liveB) {
                return liveA < liveB ? -1 : 1;
            }
            return a.start() < b.start() ? -1 : (a.start() == b.start() ? 0 : 1);
        }
    };

    public static final class Block {
        private final int index;
        private final int start;
        private final int end;
        private final AbstractInsnNode startInsn;
        private final List<Block> successors = new ArrayList<Block>();
        private final List<Block> predecessors = new ArrayList<Block>();
        private final List<Block> handlers = new ArrayList<Block>();
        private final List<NaturalLoop> loops = new ArrayList<NaturalLoop>();
        private final BitSet use = new BitSet();
        private final BitSet def = new BitSet();
        private final BitSet liveIn = new BitSet();
        private final BitSet liveOut = new BitSet();
        private boolean stackEmpty;
        private boolean inTryRange;
        private boolean handlerEntry;
        private boolean loopHeader;
        private int postOrder = -1;
        private int reverseOrder = -1;
        private Block idom;

        Block(int index, int start, int end, AbstractInsnNode startInsn) {
            this.index = index;
            this.start = start;
            this.end = end;
            this.startInsn = startInsn;
        }

        public int index() { return index; }

        public int start() { return start; }

        public int end() { return end; }

        public AbstractInsnNode startInsn() { return startInsn; }

        public List<Block> successors() { return Collections.unmodifiableList(successors); }

        public List<Block> predecessors() { return Collections.unmodifiableList(predecessors); }

        public List<Block> handlers() { return Collections.unmodifiableList(handlers); }

        public List<NaturalLoop> loops() { return Collections.unmodifiableList(loops); }

        public BitSet use() { return use; }

        public BitSet def() { return def; }

        public BitSet liveIn() { return liveIn; }

        public BitSet liveOut() { return liveOut; }

        public Block idom() { return idom; }

        public boolean isStackEmpty() { return stackEmpty; }

        public boolean isInTryRange() { return inTryRange; }

        public boolean isHandlerEntry() { return handlerEntry; }

        public boolean isLoopHeader() { return loopHeader; }

        public int postOrder() { return postOrder; }

        public int reverseOrder() { return reverseOrder; }

        public boolean isReachable() { return postOrder >= 0; }

        private int rank() {
            int rank = 0;
            if (loopHeader) {
                rank -= 2;
            }
            if (inTryRange) {
                rank += 1;
            }
            if (handlerEntry) {
                rank += 1;
            }
            return rank;
        }

        @Override
        public String toString() {
            return "block[" + index + " " + start + ".." + end + "]";
        }
    }

    public static final class NaturalLoop {
        private final Block header;
        private final List<Block> latches = new ArrayList<Block>();
        private final Set<Block> body = new LinkedHashSet<Block>();
        private int depth;

        public Block header() { return header; }

        public List<Block> latches() { return Collections.unmodifiableList(latches); }

        public Set<Block> body() { return Collections.unmodifiableSet(body); }

        public int depth() { return depth; }

        public boolean contains(Block block) { return body.contains(block); }

        NaturalLoop(Block header) {
            this.header = header;
        }
    }

    private final String owner;
    private final AbstractInsnNode[] insns;
    private final List<Block> blocks = new ArrayList<Block>();
    private final List<Block> reversePostOrder = new ArrayList<Block>();
    private final List<NaturalLoop> naturalLoops = new ArrayList<NaturalLoop>();
    private final Map<AbstractInsnNode, Block> byStart = new IdentityHashMap<AbstractInsnNode, Block>();
    private final Map<AbstractInsnNode, Integer> positions = new IdentityHashMap<AbstractInsnNode, Integer>();

    private MethodFlowAnalyzer(String owner, MethodNode method, Frame<BasicValue>[] frames) {
        this.owner = owner;
        this.insns = method.instructions.toArray();
        buildBlocks(method);
        buildEdges(method, frames);
        computePostOrder();
        computeDominators();
        computeNaturalLoops();
        computeLiveness(method.maxLocals);
        rank();
    }

    public static MethodFlowAnalyzer of(String owner, MethodNode method, Frame<BasicValue>[] frames) {
        if (method == null || method.instructions == null || method.instructions.size() == 0) {
            return null;
        }
        try {
            return new MethodFlowAnalyzer(owner, method, frames);
        } catch (RuntimeException failure) {
            return null;
        }
    }

    public String owner() { return owner; }

    public List<Block> blocks() { return Collections.unmodifiableList(blocks); }

    public List<Block> reversePostOrder() { return Collections.unmodifiableList(reversePostOrder); }

    public Block entry() { return blocks.isEmpty() ? null : blocks.get(0); }

    public int blockCount() { return blocks.size(); }

    public List<NaturalLoop> naturalLoops() { return Collections.unmodifiableList(naturalLoops); }

    public int loopCount() { return naturalLoops.size(); }

    public boolean hasLoops() { return !naturalLoops.isEmpty(); }

    public Block blockOf(AbstractInsnNode insn) {
        return byStart.get(insn);
    }

    public boolean dominates(Block dominator, Block block) {
        if (dominator == null || block == null || !block.isReachable() || !dominator.isReachable()) {
            return false;
        }
        Block cursor = block;
        int guard = blocks.size() + 1;
        while (cursor != null && guard-- > 0) {
            if (cursor == dominator) {
                return true;
            }
            if (cursor.idom == cursor) {
                return false;
            }
            cursor = cursor.idom;
        }
        return false;
    }

    public List<Block> dominatorPath(Block block) {
        List<Block> path = new ArrayList<Block>();
        Block cursor = block;
        int guard = blocks.size() + 1;
        while (cursor != null && guard-- > 0) {
            path.add(cursor);
            if (cursor.idom == cursor || cursor.idom == null) {
                break;
            }
            cursor = cursor.idom;
        }
        return path;
    }

    public int depth(Block block) {
        int depth = 0;
        for (NaturalLoop loop : naturalLoops) {
            if (loop.contains(block)) {
                depth++;
            }
        }
        return depth;
    }

    public List<AbstractInsnNode> safePoints() {
        List<Block> ranked = new ArrayList<Block>();
        for (Block block : blocks) {
            if (block == entry() || !block.isReachable() || block.startInsn == null) {
                continue;
            }
            if (!block.isStackEmpty()) {
                continue;
            }
            ranked.add(block);
        }
        Collections.sort(ranked, BLOCK_RANK);
        List<AbstractInsnNode> points = new ArrayList<AbstractInsnNode>(ranked.size());
        for (Block block : ranked) {
            points.add(block.startInsn);
        }
        return points;
    }

    public List<AbstractInsnNode> rankCandidates(List<AbstractInsnNode> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return Collections.emptyList();
        }
        Set<AbstractInsnNode> wanted = Collections.newSetFromMap(
                new IdentityHashMap<AbstractInsnNode, Boolean>());
        wanted.addAll(candidates);
        List<AbstractInsnNode> ranked = new ArrayList<AbstractInsnNode>();
        for (AbstractInsnNode point : safePoints()) {
            if (wanted.contains(point)) {
                ranked.add(point);
            }
        }
        return ranked;
    }

    public String summary() {
        return "blocks=" + blocks.size() + " loops=" + naturalLoops.size()
                + " reachable=" + reversePostOrder.size();
    }

    private void buildBlocks(MethodNode method) {
        int count = insns.length;
        boolean[] leader = new boolean[count];
        leader[0] = true;
        positions.clear();
        for (int i = 0; i < count; i++) {
            positions.put(insns[i], Integer.valueOf(i));
        }
        for (int i = 0; i < count; i++) {
            AbstractInsnNode insn = insns[i];
            if (insn instanceof JumpInsnNode) {
                markLeader(leader, positions, ((JumpInsnNode) insn).label);
                if (i + 1 < count) {
                    leader[i + 1] = true;
                }
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode table = (TableSwitchInsnNode) insn;
                markLeader(leader, positions, table.dflt);
                for (int l = 0; l < table.labels.size(); l++) {
                    markLeader(leader, positions, table.labels.get(l));
                }
                if (i + 1 < count) {
                    leader[i + 1] = true;
                }
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode lookup = (LookupSwitchInsnNode) insn;
                markLeader(leader, positions, lookup.dflt);
                for (int l = 0; l < lookup.labels.size(); l++) {
                    markLeader(leader, positions, lookup.labels.get(l));
                }
                if (i + 1 < count) {
                    leader[i + 1] = true;
                }
            } else if (isReturnOrThrow(insn.getOpcode()) && i + 1 < count) {
                leader[i + 1] = true;
            }
        }
        if (method.tryCatchBlocks != null) {
            for (int t = 0; t < method.tryCatchBlocks.size(); t++) {
                TryCatchBlockNode table = method.tryCatchBlocks.get(t);
                markLeader(leader, positions, table.start);
                markLeader(leader, positions, table.end);
                markLeader(leader, positions, table.handler);
            }
        }
        int blockStart = 0;
        for (int i = 1; i <= count; i++) {
            if (i < count && !leader[i]) {
                continue;
            }
            Block block = new Block(blocks.size(), blockStart, i - 1, insns[blockStart]);
            blocks.add(block);
            byStart.put(insns[blockStart], block);
            blockStart = i;
        }
    }

    private static void markLeader(boolean[] leader, Map<AbstractInsnNode, Integer> positions,
                                   AbstractInsnNode node) {
        if (node == null) {
            return;
        }
        Integer index = positions.get(node);
        if (index != null && index.intValue() >= 0 && index.intValue() < leader.length) {
            leader[index.intValue()] = true;
        }
    }

    private void buildEdges(MethodNode method, Frame<BasicValue>[] frames) {
        int count = insns.length;
        int[] blockOf = new int[count];
        for (int b = 0; b < blocks.size(); b++) {
            Block block = blocks.get(b);
            for (int i = block.start; i <= block.end && i < count; i++) {
                blockOf[i] = b;
            }
        }
        for (int b = 0; b < blocks.size(); b++) {
            Block block = blocks.get(b);
            AbstractInsnNode last = lastReal(block);
            if (last == null) {
                connect(block, blockOfIndex(blockOf, block.end + 1));
                continue;
            }
            int opcode = last.getOpcode();
            int lastIndex = indexOf(last);
            if (opcode == Opcodes.GOTO || opcode == Opcodes.JSR) {
                if (last instanceof JumpInsnNode) {
                    connect(block, blockAt((JumpInsnNode) last));
                }
            } else if (opcode == Opcodes.TABLESWITCH) {
                TableSwitchInsnNode table = (TableSwitchInsnNode) last;
                connect(block, blockOfIndex(blockOf, indexOf(table.dflt)));
                for (int l = 0; l < table.labels.size(); l++) {
                    connect(block, blockOfIndex(blockOf, indexOf(table.labels.get(l))));
                }
            } else if (opcode == Opcodes.LOOKUPSWITCH) {
                LookupSwitchInsnNode lookup = (LookupSwitchInsnNode) last;
                connect(block, blockOfIndex(blockOf, indexOf(lookup.dflt)));
                for (int l = 0; l < lookup.labels.size(); l++) {
                    connect(block, blockOfIndex(blockOf, indexOf(lookup.labels.get(l))));
                }
            } else if (isConditionalJump(opcode) && last instanceof JumpInsnNode) {
                connect(block, blockAt((JumpInsnNode) last));
                connect(block, blockOfIndex(blockOf, lastIndex + 1));
            } else if (!isReturnOrThrow(opcode)) {
                connect(block, blockOfIndex(blockOf, lastIndex + 1));
            }
        }
        if (method.tryCatchBlocks != null) {
            for (int t = 0; t < method.tryCatchBlocks.size(); t++) {
                TryCatchBlockNode table = method.tryCatchBlocks.get(t);
                int start = indexOf(table.start);
                int end = indexOf(table.end);
                int handler = indexOf(table.handler);
                if (start < 0 || end < 0 || handler < 0) {
                    continue;
                }
                Block handlerBlock = blocks.get(blockOf[handler]);
                handlerBlock.handlerEntry = true;
                for (int b = 0; b < blocks.size(); b++) {
                    Block block = blocks.get(b);
                    if (block.start >= start && block.start < end) {
                        block.inTryRange = true;
                        connect(block, handlerBlock);
                    }
                }
            }
        }
        if (frames != null && frames.length == count) {
            for (int b = 0; b < blocks.size(); b++) {
                Block block = blocks.get(b);
                Frame<BasicValue> frame = frames[block.start];
                block.stackEmpty = frame != null && frame.getStackSize() == 0;
            }
        }
    }

    private AbstractInsnNode lastReal(Block block) {
        for (int i = block.end; i >= block.start; i--) {
            if (insns[i].getOpcode() >= 0) {
                return insns[i];
            }
        }
        return null;
    }

    private Block blockOfIndex(int[] blockOf, int index) {
        if (index < 0 || index >= blockOf.length) {
            return null;
        }
        return blocks.get(blockOf[index]);
    }

    private Block blockAt(JumpInsnNode jump) {
        Block target = byStart.get(jump.label);
        if (target != null) {
            return target;
        }
        int index = indexOf(jump.label);
        if (index < 0) {
            return null;
        }
        for (int b = 0; b < blocks.size(); b++) {
            Block block = blocks.get(b);
            if (index >= block.start && index <= block.end) {
                return block;
            }
        }
        return null;
    }

    private void connect(Block from, Block to) {
        if (from == null || to == null) {
            return;
        }
        if (!from.successors.contains(to)) {
            from.successors.add(to);
        }
        if (!to.predecessors.contains(from)) {
            to.predecessors.add(from);
        }
    }

    private int indexOf(AbstractInsnNode node) {
        if (node == null) {
            return -1;
        }
        Integer index = positions.get(node);
        return index == null ? -1 : index.intValue();
    }

    private void computePostOrder() {
        if (blocks.isEmpty()) {
            return;
        }
        int count = blocks.size();
        boolean[] visited = new boolean[count];
        int[] next = new int[count];
        Deque<Block> stack = new ArrayDeque<Block>();
        stack.push(blocks.get(0));
        visited[0] = true;
        while (!stack.isEmpty()) {
            Block block = stack.peek();
            if (next[block.index] < block.successors.size()) {
                Block successor = block.successors.get(next[block.index]++);
                if (!visited[successor.index]) {
                    visited[successor.index] = true;
                    stack.push(successor);
                }
            } else {
                stack.pop();
                block.postOrder = reversePostOrder.size();
                reversePostOrder.add(block);
            }
        }
        Collections.reverse(reversePostOrder);
        for (int i = 0; i < reversePostOrder.size(); i++) {
            reversePostOrder.get(i).reverseOrder = i;
        }
    }

    private void computeDominators() {
        if (reversePostOrder.isEmpty()) {
            return;
        }
        Block entry = reversePostOrder.get(0);
        entry.idom = entry;
        boolean changed = true;
        int guard = blocks.size() * 4 + 16;
        while (changed && guard-- > 0) {
            changed = false;
            for (int i = 1; i < reversePostOrder.size(); i++) {
                Block block = reversePostOrder.get(i);
                Block newIdom = null;
                for (int p = 0; p < block.predecessors.size(); p++) {
                    Block predecessor = block.predecessors.get(p);
                    if (predecessor.isReachable() && predecessor.idom != null) {
                        newIdom = predecessor;
                        break;
                    }
                }
                if (newIdom == null) {
                    continue;
                }
                for (int p = 0; p < block.predecessors.size(); p++) {
                    Block predecessor = block.predecessors.get(p);
                    if (predecessor == newIdom || !predecessor.isReachable()
                            || predecessor.idom == null) {
                        continue;
                    }
                    newIdom = intersect(predecessor, newIdom);
                }
                if (block.idom != newIdom) {
                    block.idom = newIdom;
                    changed = true;
                }
            }
        }
    }

    private Block intersect(Block first, Block second) {
        Block a = first;
        Block b = second;
        int guard = blocks.size() * 4 + 16;
        while (a != b && guard-- > 0) {
            while (a.postOrder < b.postOrder) {
                a = a.idom;
                if (a == null) {
                    return b;
                }
            }
            while (b.postOrder < a.postOrder) {
                b = b.idom;
                if (b == null) {
                    return a;
                }
            }
        }
        return a;
    }

    private void computeNaturalLoops() {
        Map<Block, NaturalLoop> byHeader = new LinkedHashMap<Block, NaturalLoop>();
        for (int i = 0; i < reversePostOrder.size(); i++) {
            Block latch = reversePostOrder.get(i);
            for (int s = 0; s < latch.successors.size(); s++) {
                Block header = latch.successors.get(s);
                if (!dominates(header, latch)) {
                    continue;
                }
                NaturalLoop loop = byHeader.get(header);
                if (loop == null) {
                    loop = new NaturalLoop(header);
                    byHeader.put(header, loop);
                }
                if (!loop.latches.contains(latch)) {
                    loop.latches.add(latch);
                }
            }
        }
        for (NaturalLoop loop : byHeader.values()) {
            collectLoopBody(loop);
            loop.header.loopHeader = true;
            loop.header.loops.add(loop);
            naturalLoops.add(loop);
        }
        for (NaturalLoop loop : naturalLoops) {
            int depth = 0;
            for (NaturalLoop other : naturalLoops) {
                if (other != loop && other.contains(loop.header)) {
                    depth++;
                }
            }
            loop.depth = depth;
        }
    }

    private void collectLoopBody(NaturalLoop loop) {
        loop.body.add(loop.header);
        Deque<Block> work = new ArrayDeque<Block>();
        for (int i = 0; i < loop.latches.size(); i++) {
            Block latch = loop.latches.get(i);
            if (latch != loop.header) {
                work.push(latch);
            }
        }
        while (!work.isEmpty()) {
            Block block = work.pop();
            if (!loop.body.add(block)) {
                continue;
            }
            for (int p = 0; p < block.predecessors.size(); p++) {
                Block predecessor = block.predecessors.get(p);
                if (predecessor.isReachable() && !loop.body.contains(predecessor)) {
                    work.push(predecessor);
                }
            }
        }
    }

    private void computeLiveness(int maxLocals) {
        for (int b = 0; b < blocks.size(); b++) {
            Block block = blocks.get(b);
            for (int i = block.start; i <= block.end; i++) {
                AbstractInsnNode insn = insns[i];
                if (insn instanceof VarInsnNode) {
                    int opcode = insn.getOpcode();
                    int var = ((VarInsnNode) insn).var;
                    int width = (opcode == Opcodes.LLOAD || opcode == Opcodes.LSTORE
                            || opcode == Opcodes.DLOAD || opcode == Opcodes.DSTORE) ? 2 : 1;
                    if (opcode >= Opcodes.ILOAD && opcode <= Opcodes.ALOAD) {
                        block.use.set(var, var + width);
                    } else if (opcode >= Opcodes.ISTORE && opcode <= Opcodes.ASTORE) {
                        block.def.set(var, var + width);
                    } else if (opcode == Opcodes.RET) {
                        block.use.set(var);
                    }
                } else if (insn instanceof IincInsnNode) {
                    int var = ((IincInsnNode) insn).var;
                    block.use.set(var);
                    block.def.set(var);
                }
            }
        }
        boolean changed = true;
        int guard = blocks.size() * 8 + 32;
        while (changed && guard-- > 0) {
            changed = false;
            for (int i = reversePostOrder.size() - 1; i >= 0; i--) {
                Block block = reversePostOrder.get(i);
                BitSet out = new BitSet(Math.max(1, maxLocals));
                for (int s = 0; s < block.successors.size(); s++) {
                    out.or(block.successors.get(s).liveIn);
                }
                if (!out.equals(block.liveOut)) {
                    block.liveOut.clear();
                    block.liveOut.or(out);
                    changed = true;
                }
                BitSet in = (BitSet) block.liveOut.clone();
                in.andNot(block.def);
                in.or(block.use);
                if (!in.equals(block.liveIn)) {
                    block.liveIn.clear();
                    block.liveIn.or(in);
                    changed = true;
                }
            }
        }
    }

    private void rank() {
        Collections.sort(blocks, new Comparator<Block>() {
            @Override
            public int compare(Block a, Block b) {
                return a.start - b.start;
            }
        });
    }

    private static boolean isConditionalJump(int opcode) {
        return opcode >= Opcodes.IFEQ && opcode <= Opcodes.IF_ACMPNE
                || opcode == Opcodes.IFNULL || opcode == Opcodes.IFNONNULL;
    }

    private static boolean isReturnOrThrow(int opcode) {
        return (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) || opcode == Opcodes.ATHROW;
    }
}
