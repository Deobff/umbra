package io.umbra.core.pass.impl.optimize;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Removes instructions that the data flow analysis proves unreachable.
 *
 * <p>The sweep is done in four steps so the result stays loadable by the JVM:</p>
 *
 * <ol>
 *   <li>run {@link Analyzer} with {@link BasicInterpreter}; a {@code null} frame
 *       means the instruction cannot execute;</li>
 *   <li>every {@link LabelNode} inside an unreachable run is <em>kept</em> and
 *       moved in front of the next reachable instruction, because exception
 *       table entries and remaining jumps may still name it;</li>
 *   <li>the rest of the unreachable run is deleted;</li>
 *   <li>exception table entries whose handler is unreachable are dropped, and an
 *       entry that no longer covers any real instruction is dropped as well
 *       (an empty range is illegal in a class file).</li>
 * </ol>
 *
 * <p>{@code <clinit>} and {@code <init>} bodies are swept like any other method:
 * an unreachable block there is just as dead, and deleting it cannot change when
 * {@code this} becomes initialized.</p>
 */
public final class DeadCodeSweeper implements Opcodes {

    /** Statistics of one sweep. */
    public static final class Result {

        /** No unreachable code was found. */
        public static final Result NONE = new Result(0, 0, false);
        /** The method could not be analyzed and was left untouched. */
        public static final Result SKIPPED = new Result(0, 0, true);

        private final int instructions;
        private final int blocks;
        private final boolean skipped;

        private Result(int instructions, int blocks, boolean skipped) {
            this.instructions = instructions;
            this.blocks = blocks;
            this.skipped = skipped;
        }

        private static Result removed(int instructions, int blocks) {
            return new Result(instructions, blocks, false);
        }

        /** Number of removed real instructions (labels, line numbers and frames are free). */
        public int instructions() {
            return instructions;
        }

        /** Number of contiguous unreachable runs that contained at least one real instruction. */
        public int blocks() {
            return blocks;
        }

        /** True when the analysis failed and the method was not modified. */
        public boolean skipped() {
            return skipped;
        }
    }

    private DeadCodeSweeper() {
    }

    public static Result sweep(ClassNode owner, MethodNode method) {
        if (method.instructions == null || method.instructions.size() == 0) {
            return Result.NONE;
        }
        AbstractInsnNode[] insns = method.instructions.toArray();
        Frame<BasicValue>[] frames;
        try {
            frames = new Analyzer<BasicValue>(new BasicInterpreter())
                    .analyzeAndComputeMaxs(owner.name, method);
        } catch (AnalyzerException failure) {
            return Result.SKIPPED;
        } catch (RuntimeException failure) {
            return Result.SKIPPED;
        }
        if (frames == null || frames.length != insns.length) {
            return Result.SKIPPED;
        }

        boolean[] dead = new boolean[insns.length];
        boolean anyDead = false;
        for (int i = 0; i < insns.length; i++) {
            if (frames[i] == null) {
                dead[i] = true;
                anyDead = true;
            }
        }
        if (!anyDead) {
            return Result.NONE;
        }

        InsnList list = method.instructions;
        int removed = 0;
        int blocks = 0;
        int index = 0;
        while (index < insns.length) {
            if (!dead[index]) {
                index++;
                continue;
            }
            int runStart = index;
            int runEnd = index;
            boolean hasReal = false;
            while (runEnd < insns.length && dead[runEnd]) {
                if (insns[runEnd].getOpcode() >= 0) {
                    hasReal = true;
                    removed++;
                }
                runEnd++;
            }
            if (hasReal) {
                blocks++;
            }
            AbstractInsnNode anchor = null;
            for (int j = runEnd; j < insns.length; j++) {
                if (!dead[j]) {
                    anchor = insns[j];
                    break;
                }
            }
            for (int k = runStart; k < runEnd; k++) {
                if (!(insns[k] instanceof LabelNode)) {
                    continue;
                }
                LabelNode label = (LabelNode) insns[k];
                list.remove(label);
                if (anchor != null) {
                    list.insertBefore(anchor, label);
                } else {
                    list.add(label);
                }
            }
            index = runEnd;
        }

        Set<LabelNode> deadLabels = new HashSet<LabelNode>();
        for (int i = 0; i < insns.length; i++) {
            if (!dead[i]) {
                continue;
            }
            if (insns[i] instanceof LabelNode) {
                deadLabels.add((LabelNode) insns[i]);
                continue;
            }
            list.remove(insns[i]);
        }

        if (method.tryCatchBlocks != null && !method.tryCatchBlocks.isEmpty()) {
            List<TryCatchBlockNode> kept = new ArrayList<TryCatchBlockNode>();
            for (TryCatchBlockNode table : method.tryCatchBlocks) {
                if (deadLabels.contains(table.handler)) {
                    continue;
                }
                if (!coversRealInstruction(list, table.start, table.end)) {
                    continue;
                }
                kept.add(table);
            }
            method.tryCatchBlocks = kept;
        }
        return Result.removed(removed, blocks);
    }

    private static boolean coversRealInstruction(InsnList list, LabelNode start, LabelNode end) {
        int from = list.indexOf(start);
        int to = list.indexOf(end);
        if (from < 0 || to < 0) {
            return false;
        }
        for (int i = from + 1; i < to; i++) {
            if (list.get(i).getOpcode() >= 0) {
                return true;
            }
        }
        return false;
    }
}
