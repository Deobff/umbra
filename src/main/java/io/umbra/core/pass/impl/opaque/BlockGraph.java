package io.umbra.core.pass.impl.opaque;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/**
 * Basic blocks of one method, recovered from the instruction list and the
 * frames of an {@link org.objectweb.asm.tree.analysis.Analyzer} run.
 *
 * <p>Leaders follow the usual rule: the first instruction, every branch and
 * switch target, every exception handler and every try-range boundary, and the
 * instruction after any terminator. A split point that would create a block with
 * no real instruction is not taken, so a label that shares its position with
 * another label stays inside the block it actually starts - the mapping from
 * label to block is what the edge retargeting uses, and a jump must always be
 * forwarded to the exact label it named, never to the block's first
 * instruction.</p>
 *
 * <p>A block whose entry frame carries operand stack (a handler frame always
 * does) or whose entry is unreachable is reported as such; the pass refuses to
 * put a guard there instead of guessing.</p>
 */
public final class BlockGraph {

    public static final int KIND_GOTO = 0;
    public static final int KIND_CONDITIONAL = 1;
    public static final int KIND_SWITCH = 2;
    public static final int KIND_FALLTHROUGH = 3;
    public static final int KIND_SWITCH_DEFAULT = 4;

    /** One control-flow edge. {@code label} is the exact instruction the source names. */
    public static final class Edge {
        public final int kind;
        public final AbstractInsnNode site;
        public final int labelIndex;
        public final LabelNode label;
        public final Block target;

        Edge(int kind, AbstractInsnNode site, int labelIndex, LabelNode label, Block target) {
            this.kind = kind;
            this.site = site;
            this.labelIndex = labelIndex;
            this.label = label;
            this.target = target;
        }
    }

    /** One basic block. */
    public static final class Block {
        public final int id;
        public final int from;
        public final int to;
        public final AbstractInsnNode start;
        public final List<LabelNode> labels = new ArrayList<LabelNode>();
        public final List<Edge> edges = new ArrayList<Edge>();
        public AbstractInsnNode firstReal;
        public int firstRealIndex = -1;
        public AbstractInsnNode last;
        public int value;
        public boolean handler;
        public boolean reachable;
        public boolean guardable;

        Block(int id, int from, int to, AbstractInsnNode start) {
            this.id = id;
            this.from = from;
            this.to = to;
            this.start = start;
        }
    }

    private BlockGraph() {
    }

    /** Splits {@code method}; returns {@code null} when an edge cannot be resolved. */
    public static List<Block> build(MethodNode method, Frame<BasicValue>[] frames) {
        AbstractInsnNode[] arr = method.instructions.toArray();
        int size = arr.length;
        if (size == 0 || frames == null) {
            return Collections.emptyList();
        }
        Map<AbstractInsnNode, Boolean> referenced = new IdentityHashMap<AbstractInsnNode, Boolean>();
        Map<AbstractInsnNode, Boolean> handlerLabels = new IdentityHashMap<AbstractInsnNode, Boolean>();
        for (int i = 0; i < size; i++) {
            AbstractInsnNode insn = arr[i];
            if (insn instanceof JumpInsnNode) {
                referenced.put(((JumpInsnNode) insn).label, Boolean.TRUE);
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode node = (TableSwitchInsnNode) insn;
                referenced.put(node.dflt, Boolean.TRUE);
                for (LabelNode label : node.labels) {
                    referenced.put(label, Boolean.TRUE);
                }
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode node = (LookupSwitchInsnNode) insn;
                referenced.put(node.dflt, Boolean.TRUE);
                for (LabelNode label : node.labels) {
                    referenced.put(label, Boolean.TRUE);
                }
            }
        }
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode block : method.tryCatchBlocks) {
                referenced.put(block.start, Boolean.TRUE);
                referenced.put(block.end, Boolean.TRUE);
                referenced.put(block.handler, Boolean.TRUE);
                handlerLabels.put(block.handler, Boolean.TRUE);
            }
        }

        boolean[] leaders = new boolean[size];
        leaders[0] = true;
        for (int i = 0; i < size; i++) {
            if (arr[i] instanceof LabelNode && referenced.containsKey(arr[i])) {
                leaders[i] = true;
            }
        }
        for (int i = 0; i < size; i++) {
            AbstractInsnNode insn = arr[i];
            int opcode = insn.getOpcode();
            boolean splits = insn instanceof JumpInsnNode || insn instanceof TableSwitchInsnNode
                    || insn instanceof LookupSwitchInsnNode || isTerminal(opcode)
                    || opcode == Opcodes.RET;
            if (splits && i + 1 < size) {
                leaders[i + 1] = true;
            }
        }

        List<Block> blocks = new ArrayList<Block>();
        int start = 0;
        for (int i = 1; i < size; i++) {
            if (!leaders[i] || !hasReal(arr, start, i)) {
                continue;
            }
            blocks.add(block(blocks.size(), arr, start, i, frames, handlerLabels));
            start = i;
        }
        blocks.add(block(blocks.size(), arr, start, size, frames, handlerLabels));

        Map<AbstractInsnNode, Block> byLabel = new IdentityHashMap<AbstractInsnNode, Block>();
        for (Block block : blocks) {
            for (LabelNode label : block.labels) {
                byLabel.put(label, block);
            }
        }
        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            Block next = i + 1 < blocks.size() ? blocks.get(i + 1) : null;
            if (!connect(block, next, byLabel)) {
                return null;
            }
        }
        return blocks;
    }

    private static Block block(int id, AbstractInsnNode[] arr, int from, int to,
                               Frame<BasicValue>[] frames, Map<AbstractInsnNode, Boolean> handlerLabels) {
        Block block = new Block(id, from, to, arr[from]);
        for (int i = from; i < to; i++) {
            AbstractInsnNode insn = arr[i];
            if (insn instanceof LabelNode) {
                block.labels.add((LabelNode) insn);
                if (handlerLabels.containsKey(insn)) {
                    block.handler = true;
                }
            }
            if (insn.getOpcode() >= 0) {
                if (block.firstReal == null) {
                    block.firstReal = insn;
                    block.firstRealIndex = i;
                }
                block.last = insn;
            }
        }
        if (block.firstReal != null && block.firstRealIndex < frames.length) {
            Frame<BasicValue> entry = frames[block.firstRealIndex];
            block.reachable = entry != null;
            block.guardable = block.reachable && entry.getStackSize() == 0 && !block.handler;
        }
        return block;
    }

    private static boolean connect(Block block, Block next, Map<AbstractInsnNode, Block> byLabel) {
        AbstractInsnNode last = block.last;
        if (last == null) {
            return true;
        }
        if (last instanceof JumpInsnNode) {
            JumpInsnNode jump = (JumpInsnNode) last;
            Block target = byLabel.get(jump.label);
            if (target == null) {
                return false;
            }
            if (jump.getOpcode() == Opcodes.GOTO) {
                block.edges.add(new Edge(KIND_GOTO, jump, -1, jump.label, target));
            } else {
                block.edges.add(new Edge(KIND_CONDITIONAL, jump, -1, jump.label, target));
                if (next != null) {
                    block.edges.add(new Edge(KIND_FALLTHROUGH, null, -1, null, next));
                }
            }
            return true;
        }
        if (last instanceof TableSwitchInsnNode) {
            TableSwitchInsnNode node = (TableSwitchInsnNode) last;
            for (int i = 0; i < node.labels.size(); i++) {
                Block target = byLabel.get(node.labels.get(i));
                if (target == null) {
                    return false;
                }
                block.edges.add(new Edge(KIND_SWITCH, node, i, node.labels.get(i), target));
            }
            Block fallback = byLabel.get(node.dflt);
            if (fallback == null) {
                return false;
            }
            block.edges.add(new Edge(KIND_SWITCH_DEFAULT, node, -1, node.dflt, fallback));
            return true;
        }
        if (last instanceof LookupSwitchInsnNode) {
            LookupSwitchInsnNode node = (LookupSwitchInsnNode) last;
            for (int i = 0; i < node.labels.size(); i++) {
                Block target = byLabel.get(node.labels.get(i));
                if (target == null) {
                    return false;
                }
                block.edges.add(new Edge(KIND_SWITCH, node, i, node.labels.get(i), target));
            }
            Block fallback = byLabel.get(node.dflt);
            if (fallback == null) {
                return false;
            }
            block.edges.add(new Edge(KIND_SWITCH_DEFAULT, node, -1, node.dflt, fallback));
            return true;
        }
        if (isTerminal(last.getOpcode()) || last.getOpcode() == Opcodes.RET) {
            return true;
        }
        if (next != null) {
            block.edges.add(new Edge(KIND_FALLTHROUGH, null, -1, null, next));
        }
        return true;
    }

    /** Points the edge at {@code stub} instead of the instruction it used to name. */
    public static void retarget(Edge edge, LabelNode stub) {
        if (edge.kind == KIND_GOTO || edge.kind == KIND_CONDITIONAL) {
            ((JumpInsnNode) edge.site).label = stub;
            return;
        }
        if (edge.kind == KIND_SWITCH) {
            if (edge.site instanceof TableSwitchInsnNode) {
                ((TableSwitchInsnNode) edge.site).labels.set(edge.labelIndex, stub);
            } else {
                ((LookupSwitchInsnNode) edge.site).labels.set(edge.labelIndex, stub);
            }
            return;
        }
        if (edge.kind == KIND_SWITCH_DEFAULT) {
            if (edge.site instanceof TableSwitchInsnNode) {
                ((TableSwitchInsnNode) edge.site).dflt = stub;
            } else {
                ((LookupSwitchInsnNode) edge.site).dflt = stub;
            }
        }
    }

    private static boolean hasReal(AbstractInsnNode[] arr, int from, int to) {
        for (int i = from; i < to; i++) {
            if (arr[i].getOpcode() >= 0) {
                return true;
            }
        }
        return false;
    }

    private static boolean isTerminal(int opcode) {
        return (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) || opcode == Opcodes.ATHROW;
    }
}
