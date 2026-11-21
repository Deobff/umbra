package io.umbra.core.pass.impl.optimize;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Deletes stores into locals that are never read.
 *
 * <p>A store is only removed together with the instruction that produced its
 * value, and only when that producer is side-effect free and cannot be the entry
 * point of a jump or handler. Slots that hold parameters, a catch handler's
 * exception, or {@code this} are never considered. A slot only counts as removed
 * when <em>every</em> store into it was deleted.</p>
 */
public final class UnusedLocalSweeper implements Opcodes {

    private UnusedLocalSweeper() {
    }

    /** Returns the number of local slots whose stores were all removed. */
    public static int sweep(MethodNode method) {
        if (method.instructions == null || method.instructions.size() == 0) {
            return 0;
        }
        if (InsnSupport.hasJsrRet(method)) {
            return 0;
        }
        Map<Integer, Integer> loads = new HashMap<Integer, Integer>();
        Map<Integer, Integer> stores = new HashMap<Integer, Integer>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (InsnSupport.isLoad(opcode)) {
                bump(loads, ((VarInsnNode) insn).var);
            } else if (InsnSupport.isStore(opcode)) {
                bump(stores, ((VarInsnNode) insn).var);
            } else if (insn instanceof IincInsnNode) {
                bump(loads, ((IincInsnNode) insn).var);
                bump(stores, ((IincInsnNode) insn).var);
            }
        }
        if (stores.isEmpty()) {
            return 0;
        }

        Set<Integer> protectedSlots = new HashSet<Integer>();
        int firstFree = InsnSupport.firstFreeParamSlot(method);
        for (int slot = 0; slot < firstFree; slot++) {
            protectedSlots.add(Integer.valueOf(slot));
        }
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode table : method.tryCatchBlocks) {
                AbstractInsnNode node = table.handler;
                while (node != null && InsnSupport.isPseudo(node)) {
                    node = node.getNext();
                }
                if (node instanceof VarInsnNode && InsnSupport.isStore(node.getOpcode())) {
                    protectedSlots.add(Integer.valueOf(((VarInsnNode) node).var));
                }
            }
        }
        Set<AbstractInsnNode> targets = entryTargets(method);

        int cleared = 0;
        for (Map.Entry<Integer, Integer> entry : stores.entrySet()) {
            Integer slot = entry.getKey();
            if (protectedSlots.contains(slot)) {
                continue;
            }
            Integer read = loads.get(slot);
            if (read != null && read.intValue() != 0) {
                continue;
            }
            List<AbstractInsnNode> slotStores = new ArrayList<AbstractInsnNode>();
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (InsnSupport.isStore(insn.getOpcode()) && ((VarInsnNode) insn).var == slot.intValue()) {
                    slotStores.add(insn);
                }
            }
            if (slotStores.isEmpty()) {
                continue;
            }
            boolean allRemoved = true;
            for (int i = 0; i < slotStores.size(); i++) {
                AbstractInsnNode store = slotStores.get(i);
                AbstractInsnNode producer = InsnSupport.previousReal(store);
                if (producer == null || !InsnSupport.isSimpleProducer(producer)) {
                    allRemoved = false;
                    continue;
                }
                if (hasTargetLabelBetween(producer, store, targets)) {
                    allRemoved = false;
                    continue;
                }
                method.instructions.remove(producer);
                method.instructions.remove(store);
            }
            if (allRemoved) {
                cleared++;
            }
        }
        return cleared;
    }

    private static void bump(Map<Integer, Integer> counters, int slot) {
        Integer key = Integer.valueOf(slot);
        Integer current = counters.get(key);
        counters.put(key, Integer.valueOf(current == null ? 1 : current.intValue() + 1));
    }

    private static boolean hasTargetLabelBetween(AbstractInsnNode from, AbstractInsnNode to,
                                                 Set<AbstractInsnNode> targets) {
        for (AbstractInsnNode node = from.getNext(); node != null && node != to; node = node.getNext()) {
            if (node instanceof LabelNode && targets.contains(node)) {
                return true;
            }
        }
        return false;
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
