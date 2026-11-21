package io.umbra.core.pass.impl.optimize;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Hoists int constants that repeat inside one method into a fresh local.
 *
 * <p>For every value that is pushed at least {@code threshold} times the pass
 * allocates one new local slot, stores the value once at method entry and
 * rewrites every push site to {@code ILOAD}. Array dimension pushes are left
 * alone, as are methods that contain JSR/RET or whose entry point is also a jump
 * or exception-table target (the prologue could be skipped on such a path).</p>
 */
public final class IntConstantReuser implements Opcodes {

    /** Statistics of one hoist. */
    public static final class Result {

        public static final Result NONE = new Result(0, 0);

        private final int reused;
        private final int sites;

        private Result(int reused, int sites) {
            this.reused = reused;
            this.sites = sites;
        }

        /** Number of constants that were hoisted into a new local. */
        public int reused() {
            return reused;
        }

        /** Number of push sites that were rewritten to a local read. */
        public int sites() {
            return sites;
        }
    }

    private IntConstantReuser() {
    }

    public static Result hoist(MethodNode method, int threshold) {
        if (threshold < 2 || method.instructions == null || method.instructions.size() == 0) {
            return Result.NONE;
        }
        if (InsnSupport.hasJsrRet(method)) {
            return Result.NONE;
        }
        InsnList list = method.instructions;
        AbstractInsnNode firstReal = list.getFirst();
        while (firstReal != null && InsnSupport.isPseudo(firstReal)) {
            firstReal = firstReal.getNext();
        }
        if (firstReal == null) {
            return Result.NONE;
        }
        Set<AbstractInsnNode> targets = entryTargets(method);
        for (AbstractInsnNode node = list.getFirst(); node != null; node = node.getNext()) {
            if (targets.contains(node)) {
                return Result.NONE;
            }
            if (node == firstReal) {
                break;
            }
        }

        Map<Integer, List<AbstractInsnNode>> sites = new LinkedHashMap<Integer, List<AbstractInsnNode>>();
        for (AbstractInsnNode insn = list.getFirst(); insn != null; insn = insn.getNext()) {
            if (!InsnSupport.isIntPush(insn)) {
                continue;
            }
            AbstractInsnNode next = InsnSupport.nextReal(insn);
            if (next != null) {
                int opcode = next.getOpcode();
                if (opcode == NEWARRAY || opcode == ANEWARRAY || opcode == MULTIANEWARRAY) {
                    continue;
                }
            }
            Integer value = Integer.valueOf(InsnSupport.intPushValue(insn));
            List<AbstractInsnNode> group = sites.get(value);
            if (group == null) {
                group = new ArrayList<AbstractInsnNode>();
                sites.put(value, group);
            }
            group.add(insn);
        }
        if (sites.isEmpty()) {
            return Result.NONE;
        }

        // Build one prologue and insert it before touching any site: a site may be
        // the very instruction the prologue is anchored on, and replacing it first
        // would detach the anchor and corrupt the instruction list.
        Map<Integer, Integer> slotOfValue = new LinkedHashMap<Integer, Integer>();
        InsnList prologue = new InsnList();
        for (Map.Entry<Integer, List<AbstractInsnNode>> entry : sites.entrySet()) {
            if (entry.getValue().size() < threshold) {
                continue;
            }
            int slot = method.maxLocals;
            method.maxLocals = slot + 1;
            AsmUtil.pushInt(prologue, entry.getKey().intValue());
            prologue.add(new VarInsnNode(ISTORE, slot));
            slotOfValue.put(entry.getKey(), Integer.valueOf(slot));
        }
        if (slotOfValue.isEmpty()) {
            return Result.NONE;
        }
        list.insertBefore(firstReal, prologue);

        int reused = 0;
        int rewritten = 0;
        for (Map.Entry<Integer, List<AbstractInsnNode>> entry : sites.entrySet()) {
            Integer slot = slotOfValue.get(entry.getKey());
            if (slot == null) {
                continue;
            }
            List<AbstractInsnNode> group = entry.getValue();
            for (int i = 0; i < group.size(); i++) {
                list.set(group.get(i), new VarInsnNode(ILOAD, slot.intValue()));
                rewritten++;
            }
            reused++;
        }
        return new Result(reused, rewritten);
    }

    private static Set<AbstractInsnNode> entryTargets(MethodNode method) {
        Set<AbstractInsnNode> targets = new HashSet<AbstractInsnNode>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode) {
                targets.add(((JumpInsnNode) insn).label);
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode sw = (LookupSwitchInsnNode) insn;
                targets.add(sw.dflt);
                targets.addAll(sw.labels);
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode sw = (TableSwitchInsnNode) insn;
                targets.add(sw.dflt);
                targets.addAll(sw.labels);
            }
        }
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode table : method.tryCatchBlocks) {
                targets.add(table.start);
                targets.add(table.end);
                targets.add(table.handler);
            }
        }
        return targets;
    }
}
