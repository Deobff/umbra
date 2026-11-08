package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.KeyRootMask;
import io.umbra.core.pass.impl.flow.RuntimeTable;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.IdentityHashMap;
import java.util.Map;

/**
 * Mixed Boolean-Arithmetic (MBA) rewriting.
 *
 * <p>Integer and long arithmetic is replaced by algebraically equivalent
 * expressions built from bitwise and additive operations, and integer/long
 * constants are re-materialised through a per-method runtime key. All
 * identities are exact in two's complement modular arithmetic, so overflow,
 * array indexes, comparison results and branch conditions are unchanged.</p>
 *
 * <p>Genuine rewrite families (verified for every 32/64-bit input by
 * {@code FlowTest}):</p>
 * <pre>
 *   a + b = (a | b) + (a &amp; b)
 *   a - b = (a ^ b) - ((~a &amp; b) &lt;&lt; 1)
 *   a ^ b = (a | b) - (a &amp; b)
 *   a &amp; b = (a | b) - (a ^ b)
 *   a | b = (a &amp; b) + (a ^ b)
 * </pre>
 *
 * <p>The int forms use only stack shuffles; the long forms use two scratch
 * locals because the JVM has no instruction that duplicates two category-2
 * values at once.</p>
 *
 * <p>Constants are not re-materialised through a cancelling runtime key (the old
 * {@code ((c ^ K) ^ k) ^ (K ^ k)} shape collapsed to {@code c} with one
 * algebraic rewrite, W3/W4). They are read as the xor of two entries of the
 * per-class runtime table ({@link RuntimeTable}): both entries come out of an
 * xorshift chain seeded in {@code <clinit>}, so folding the constant requires
 * array scalarisation plus cross-{@code <clinit>} data flow. When the class
 * pair budget is exhausted the literal is left untouched instead of falling back
 * to a foldable shape.</p>
 */
public final class MbaPass implements Pass {

    private static final int[] INT_OPS = {
            Opcodes.IADD, Opcodes.ISUB, Opcodes.IXOR, Opcodes.IAND, Opcodes.IOR
    };
    private static final int[] LONG_OPS = {
            Opcodes.LADD, Opcodes.LSUB, Opcodes.LXOR, Opcodes.LAND, Opcodes.LOR
    };

    @Override
    public String name() {
        return "mba";
    }

    @Override
    public int order() {
        return 85;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool("mba.enabled", false);
    }

    @Override
    public void run(PassContext context) {
        int depth = Math.max(1, Math.min(4, context.config().optionInt("mba.depth", 2)));
        boolean ints = context.config().optionBool("mba.ints", true);
        int maxPerMethod = Math.max(1, context.config().optionInt("mba.maxPerMethod", 400));
        boolean floats = context.config().optionBool("mba.floats", false);
        if (floats) {
            context.log().debug("mba: float/double rewriting is not supported; ignoring mba.floats");
        }
        int methods = 0;
        int expressions = 0;
        int constants = 0;
        int runtimeConstants = 0;
        int runtimeTables = 0;
        int fallbackConstants = 0;
        int skipped = 0;
        int pairBudget = Math.max(2, context.config().optionInt("mba.tablePairs", 256));
        KeyRootMask tableMask = KeyRootMask.create(context, true);
        String tableMode = tableMask == null ? "static" : "native";
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
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) {
                continue;
            }

            RuntimeTable table = RuntimeTable.create(context, node, pairBudget, tableMask);
            int classExpressions = 0;
            int classConstants = 0;
            int classRuntime = 0;
            int classFallback = 0;
            for (MethodNode method : node.methods) {
                if (!eligible(method)) {
                    continue;
                }
                int[] result;
                try {
                    result = rewriteMethod(context, method, depth, ints, maxPerMethod, table);
                } catch (RuntimeException e) {
                    skipped++;
                    context.log().debug("mba: skipped %s.%s: %s", node.name, method.name, e.toString());
                    continue;
                }
                if (result[0] > 0 || result[1] > 0) {
                    methods++;
                    classExpressions += result[0];
                    classConstants += result[1];
                    classRuntime += result[2];
                    classFallback += result[3];
                }
            }
            if (!table.isEmpty()) {
                try {
                    table.materialize(node);
                    runtimeTables += table.chunkCount();
                } catch (RuntimeException e) {
                    context.log().debug("mba: cannot bootstrap the runtime table of %s: %s",
                            node.name, e.toString());
                }
            }
            expressions += classExpressions;
            constants += classConstants;
            runtimeConstants += classRuntime;
            fallbackConstants += classFallback;
        }
        context.stats().add("mba.methods", methods);
        context.stats().add("mba.expressions", expressions);
        context.stats().add("mba.constants", constants);
        context.stats().add("mba.runtimeConstants", runtimeConstants);
        context.stats().add("mba.runtimeTables", runtimeTables);
        context.stats().add("mba.fallbackConstants", fallbackConstants);
        context.stats().add("mba.skipped", skipped);
        context.stats().text("mba.tableMode", tableMode);
        context.log().info("mba[depth=%d]: rewrote %d arithmetic expressions and %d constants "
                        + "(%d via runtime tables, %d table fallbacks, table=%s) in %d methods",
                depth, expressions, constants, runtimeConstants, fallbackConstants, tableMode,
                methods);
    }

    private static boolean eligible(MethodNode method) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.instructions == null || method.instructions.size() == 0) {
            return false;
        }

        if (AsmUtil.containsJsrOrRet(method)) {
            return false;
        }

        return method.instructions.size() <= 60000;
    }

    private static int[] rewriteMethod(PassContext context, MethodNode method, int depth,
                                       boolean ints, int maxPerMethod, RuntimeTable table) {
        MethodPlan plan = plan(method, ints);
        if (plan.intOps == 0 && plan.longOps == 0 && plan.constants == 0) {
            return new int[4];
        }
        int budget = maxPerMethod;

        int constantReserve = Math.min(plan.constants, Math.max(1, maxPerMethod / 2));
        int opBudget = Math.max(0, budget - constantReserve);
        int constBudget = budget;

        int nextLocal = nextFreeLocal(method);
        int longTemp = -1;
        int neededLongTemps = plan.longOps > 0 ? 1 : 0;
        if (neededLongTemps > 0) {
            longTemp = nextLocal;
            nextLocal += 4;
        }
        if (nextLocal > method.maxLocals) {
            method.maxLocals = nextLocal;
        }

        int expressions = 0;
        if (ints && opBudget > 0) {
            expressions = rewriteArithmetic(method, ints, depth, opBudget, longTemp);
        }
        int[] rewritten = new int[3];
        int remaining = Math.max(0, constBudget - expressions);
        if (remaining > 0 && plan.constants > 0) {
            rewritten = rewriteConstants(context, method, ints, remaining, table, plan.constants);
        }
        return new int[] { expressions, rewritten[0], rewritten[1], rewritten[2] };
    }

    private static MethodPlan plan(MethodNode method, boolean ints) {
        MethodPlan plan = new MethodPlan();
        boolean needsTemps = false;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (isIntOp(opcode)) {
                plan.intOps++;
            } else if (isLongOp(opcode)) {
                plan.longOps++;
                needsTemps = true;
            } else if (isRewritableConstant(insn, ints) && !forbiddenConstant(method, insn)) {
                plan.constants++;
            }
        }
        plan.needsLongTemps = needsTemps;
        return plan;
    }

    private static int rewriteArithmetic(MethodNode method, boolean ints, int depth,
                                         int opBudget, int longTemp) {
        Map<AbstractInsnNode, Integer> generation = new IdentityHashMap<AbstractInsnNode, Integer>();
        int count = 0;
        for (int pass = 1; pass <= depth && count < opBudget; pass++) {
            AbstractInsnNode[] snapshot = method.instructions.toArray();
            for (AbstractInsnNode insn : snapshot) {
                if (count >= opBudget) {
                    break;
                }
                if (insn.getOpcode() < 0) {
                    continue;
                }
                if (!isIntOp(insn.getOpcode()) && !isLongOp(insn.getOpcode())) {
                    continue;
                }
                Integer tag = generation.get(insn);
                int createdIn = tag == null ? 0 : tag.intValue();
                if (createdIn >= pass) {
                    continue;
                }
                if (!ints) {
                    continue;
                }
                boolean isLong = isLongOp(insn.getOpcode());

                if (isLong && createdIn != 0) {
                    continue;
                }
                if (isLong && longTemp < 0) {
                    continue;
                }
                InsnList replacement = buildReplacement(insn.getOpcode(), isLong, longTemp);
                if (replacement == null) {
                    continue;
                }

                for (AbstractInsnNode added = replacement.getFirst(); added != null; added = added.getNext()) {
                    if (added.getOpcode() >= 0) {
                        generation.put(added, Integer.valueOf(pass));
                    }
                }
                method.instructions.insertBefore(insn, replacement);
                method.instructions.remove(insn);
                count++;
            }
        }
        if (count > 0) {
            method.maxStack = Math.max(method.maxStack, 8);
        }
        return count;
    }

    private static InsnList buildReplacement(int opcode, boolean isLong, int longTemp) {
        InsnList out = new InsnList();
        if (!isLong) {
            switch (opcode) {
                case Opcodes.IADD:
                    out.add(new InsnNode(Opcodes.DUP2));
                    out.add(new InsnNode(Opcodes.IOR));
                    out.add(new InsnNode(Opcodes.DUP_X2));
                    out.add(new InsnNode(Opcodes.POP));
                    out.add(new InsnNode(Opcodes.IAND));
                    out.add(new InsnNode(Opcodes.IADD));
                    return out;
                case Opcodes.ISUB:
                    out.add(new InsnNode(Opcodes.DUP2));
                    out.add(new InsnNode(Opcodes.ICONST_M1));
                    out.add(new InsnNode(Opcodes.IXOR));
                    out.add(new InsnNode(Opcodes.IAND));
                    out.add(new InsnNode(Opcodes.DUP_X2));
                    out.add(new InsnNode(Opcodes.POP));
                    out.add(new InsnNode(Opcodes.SWAP));
                    out.add(new InsnNode(Opcodes.ICONST_M1));
                    out.add(new InsnNode(Opcodes.IXOR));
                    out.add(new InsnNode(Opcodes.SWAP));
                    out.add(new InsnNode(Opcodes.IAND));
                    out.add(new InsnNode(Opcodes.ISUB));
                    return out;
                case Opcodes.IXOR:
                    out.add(new InsnNode(Opcodes.DUP2));
                    out.add(new InsnNode(Opcodes.IOR));
                    out.add(new InsnNode(Opcodes.DUP_X2));
                    out.add(new InsnNode(Opcodes.POP));
                    out.add(new InsnNode(Opcodes.IAND));
                    out.add(new InsnNode(Opcodes.IXOR));
                    return out;
                case Opcodes.IAND:
                    out.add(new InsnNode(Opcodes.DUP2));
                    out.add(new InsnNode(Opcodes.IOR));
                    out.add(new InsnNode(Opcodes.DUP_X2));
                    out.add(new InsnNode(Opcodes.POP));
                    out.add(new InsnNode(Opcodes.IXOR));
                    out.add(new InsnNode(Opcodes.ISUB));
                    return out;
                case Opcodes.IOR:
                    out.add(new InsnNode(Opcodes.DUP2));
                    out.add(new InsnNode(Opcodes.IAND));
                    out.add(new InsnNode(Opcodes.DUP_X2));
                    out.add(new InsnNode(Opcodes.POP));
                    out.add(new InsnNode(Opcodes.IXOR));
                    out.add(new InsnNode(Opcodes.IADD));
                    return out;
                default:
                    return null;
            }
        }
        int t2 = longTemp + 2;
        out.add(new VarInsnNode(Opcodes.LSTORE, t2));
        out.add(new VarInsnNode(Opcodes.LSTORE, longTemp));
        switch (opcode) {
            case Opcodes.LADD:
                out.add(new VarInsnNode(Opcodes.LLOAD, longTemp));
                out.add(new VarInsnNode(Opcodes.LLOAD, t2));
                out.add(new InsnNode(Opcodes.LOR));
                out.add(new VarInsnNode(Opcodes.LLOAD, longTemp));
                out.add(new VarInsnNode(Opcodes.LLOAD, t2));
                out.add(new InsnNode(Opcodes.LAND));
                out.add(new InsnNode(Opcodes.LADD));
                return out;
            case Opcodes.LSUB:

                out.add(new VarInsnNode(Opcodes.LLOAD, longTemp));
                out.add(new VarInsnNode(Opcodes.LLOAD, t2));
                out.add(new LdcInsnNode(Long.valueOf(-1L)));
                out.add(new InsnNode(Opcodes.LXOR));
                out.add(new InsnNode(Opcodes.LAND));
                out.add(new VarInsnNode(Opcodes.LLOAD, t2));
                out.add(new VarInsnNode(Opcodes.LLOAD, longTemp));
                out.add(new LdcInsnNode(Long.valueOf(-1L)));
                out.add(new InsnNode(Opcodes.LXOR));
                out.add(new InsnNode(Opcodes.LAND));
                out.add(new InsnNode(Opcodes.LSUB));
                return out;
            case Opcodes.LXOR:
                out.add(new VarInsnNode(Opcodes.LLOAD, longTemp));
                out.add(new VarInsnNode(Opcodes.LLOAD, t2));
                out.add(new InsnNode(Opcodes.LOR));
                out.add(new VarInsnNode(Opcodes.LLOAD, longTemp));
                out.add(new VarInsnNode(Opcodes.LLOAD, t2));
                out.add(new InsnNode(Opcodes.LAND));
                out.add(new InsnNode(Opcodes.LSUB));
                return out;
            case Opcodes.LAND:
                out.add(new VarInsnNode(Opcodes.LLOAD, longTemp));
                out.add(new VarInsnNode(Opcodes.LLOAD, t2));
                out.add(new InsnNode(Opcodes.LOR));
                out.add(new VarInsnNode(Opcodes.LLOAD, longTemp));
                out.add(new VarInsnNode(Opcodes.LLOAD, t2));
                out.add(new InsnNode(Opcodes.LXOR));
                out.add(new InsnNode(Opcodes.LSUB));
                return out;
            case Opcodes.LOR:
                out.add(new VarInsnNode(Opcodes.LLOAD, longTemp));
                out.add(new VarInsnNode(Opcodes.LLOAD, t2));
                out.add(new InsnNode(Opcodes.LAND));
                out.add(new VarInsnNode(Opcodes.LLOAD, longTemp));
                out.add(new VarInsnNode(Opcodes.LLOAD, t2));
                out.add(new InsnNode(Opcodes.LXOR));
                out.add(new InsnNode(Opcodes.LADD));
                return out;
            default:
                return null;
        }
    }

    private static int[] rewriteConstants(PassContext context, MethodNode method, boolean ints,
                                          int budget, RuntimeTable table, int candidateCount) {
        int limit = Math.min(budget, candidateCount);
        int count = 0;
        int masked = 0;
        int fallbacks = 0;
        AbstractInsnNode[] snapshot = method.instructions.toArray();
        for (AbstractInsnNode insn : snapshot) {
            if (count >= limit) {
                break;
            }
            if (!isRewritableConstant(insn, ints)) {
                continue;
            }
            if (forbiddenConstant(method, insn)) {
                continue;
            }
            Object constant = constantValue(insn);
            if (constant == null) {
                continue;
            }
            InsnList replacement = new InsnList();
            boolean tableBacked;
            if (constant instanceof Integer) {
                int value = ((Integer) constant).intValue();
                RuntimeTable.Pair pair = table.pair(value);
                tableBacked = pair != null;
                if (tableBacked) {
                    table.emitInt(replacement, pair);
                }
            } else {
                long value = ((Long) constant).longValue();
                tableBacked = table.emitLong(replacement, value);
            }
            if (!tableBacked) {

                fallbacks++;
                continue;
            }
            method.instructions.insertBefore(insn, replacement);
            method.instructions.remove(insn);
            count++;
            masked++;
        }
        if (count > 0) {
            method.maxStack = Math.max(method.maxStack, 6);
        }
        return new int[] { count, masked, fallbacks };
    }

    private static boolean isRewritableConstant(AbstractInsnNode insn, boolean ints) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return true;
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return true;
        }
        if (insn instanceof LdcInsnNode) {
            Object value = ((LdcInsnNode) insn).cst;
            if (value instanceof Integer) {
                return true;
            }
            return ints && value instanceof Long;
        }
        return false;
    }

    private static Object constantValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return Integer.valueOf(opcode - Opcodes.ICONST_0);
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return Integer.valueOf(((IntInsnNode) insn).operand);
        }
        if (insn instanceof LdcInsnNode) {
            Object value = ((LdcInsnNode) insn).cst;
            if (value instanceof Integer || value instanceof Long) {
                return value;
            }
        }
        return null;
    }

    private static boolean forbiddenConstant(MethodNode method, AbstractInsnNode insn) {
        AbstractInsnNode next = realNext(insn);
        if (next == null) {
            return false;
        }
        int opcode = next.getOpcode();
        if (opcode == Opcodes.NEWARRAY || opcode == Opcodes.ANEWARRAY
                || opcode == Opcodes.MULTIANEWARRAY || opcode == Opcodes.TABLESWITCH
                || opcode == Opcodes.LOOKUPSWITCH || opcode == Opcodes.INVOKEDYNAMIC
                || isArrayAccess(opcode)) {
            return true;
        }

        int pushes = 0;
        AbstractInsnNode cursor = next;
        while (cursor != null && pushes < 8) {
            if (isSimplePush(cursor)) {
                pushes++;
                cursor = realNext(cursor);
                continue;
            }
            break;
        }
        if (cursor != null && cursor.getOpcode() == Opcodes.MULTIANEWARRAY) {
            return true;
        }
        if (cursor != null && isArrayStore(cursor.getOpcode())) {
            return true;
        }
        return cursor != null && isArrayLoad(cursor.getOpcode());
    }

    private static boolean isSimplePush(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return true;
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return true;
        }
        return insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer;
    }

    private static boolean isArrayAccess(int opcode) {
        return isArrayLoad(opcode) || isArrayStore(opcode);
    }

    private static boolean isArrayLoad(int opcode) {
        return opcode >= Opcodes.IALOAD && opcode <= Opcodes.SALOAD;
    }

    private static boolean isArrayStore(int opcode) {
        return opcode >= Opcodes.IASTORE && opcode <= Opcodes.SASTORE;
    }

    private static AbstractInsnNode realNext(AbstractInsnNode insn) {
        AbstractInsnNode next = insn.getNext();
        while (next != null && next.getOpcode() < 0) {
            next = next.getNext();
        }
        return next;
    }

    private static boolean isIntOp(int opcode) {
        for (int candidate : INT_OPS) {
            if (candidate == opcode) {
                return true;
            }
        }
        return false;
    }

    private static boolean isLongOp(int opcode) {
        for (int candidate : LONG_OPS) {
            if (candidate == opcode) {
                return true;
            }
        }
        return false;
    }

    private static int nextFreeLocal(MethodNode method) {
        int used = Math.max(0, method.maxLocals);
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof VarInsnNode) {
                int slot = ((VarInsnNode) insn).var;
                int size = (insn.getOpcode() == Opcodes.LLOAD || insn.getOpcode() == Opcodes.LSTORE
                        || insn.getOpcode() == Opcodes.DLOAD || insn.getOpcode() == Opcodes.DSTORE) ? 2 : 1;
                used = Math.max(used, slot + size);
            } else if (insn instanceof IincInsnNode) {
                used = Math.max(used, ((IincInsnNode) insn).var + 1);
            }
        }
        return used;
    }

    private static final class MethodPlan {
        int intOps;
        int longOps;
        int constants;
        boolean needsLongTemps;
    }
}
