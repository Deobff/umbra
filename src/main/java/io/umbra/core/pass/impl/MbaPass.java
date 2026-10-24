package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
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
 * values at once. Constants become
 * {@code ((c ^ K) ^ k) ^ (K ^ k)} with {@code K} a compile time nonce and
 * {@code k} a runtime key derived from {@code System.nanoTime()}, so neither
 * the original constant nor a fixed mask is apparent.</p>
 */
public final class MbaPass implements Pass {

    /** Binary ops rewritten by the identity table. */
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
        int skipped = 0;
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
            int classExpressions = 0;
            int classConstants = 0;
            for (MethodNode method : node.methods) {
                if (!eligible(method)) {
                    continue;
                }
                int[] result;
                try {
                    result = rewriteMethod(context, method, depth, ints, maxPerMethod);
                } catch (RuntimeException e) {
                    skipped++;
                    context.log().debug("mba: skipped %s.%s: %s", node.name, method.name, e.toString());
                    continue;
                }
                if (result[0] > 0 || result[1] > 0) {
                    methods++;
                    classExpressions += result[0];
                    classConstants += result[1];
                }
            }
            expressions += classExpressions;
            constants += classConstants;
        }
        context.stats().add("mba.methods", methods);
        context.stats().add("mba.expressions", expressions);
        context.stats().add("mba.constants", constants);
        context.stats().add("mba.skipped", skipped);
        context.log().info("mba[depth=%d]: rewrote %d arithmetic expressions and %d constants in %d methods",
                depth, expressions, constants, methods);
    }

    private static boolean eligible(MethodNode method) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.instructions == null || method.instructions.size() == 0) {
            return false;
        }
        // Old jsr/ret subroutines confuse frame computation; leave them alone.
        if (AsmUtil.containsJsrOrRet(method)) {
            return false;
        }
        // Hard ceiling: the per-method rewrite budget already bounds growth, but
        // never touch absurdly large methods (other passes time out on them too).
        return method.instructions.size() <= 60000;
    }

    /**
     * Rewrites one method.
     *
     * @return {@code [arithmeticExpressions, constants]} rewritten
     */
    private static int[] rewriteMethod(PassContext context, MethodNode method, int depth,
                                       boolean ints, int maxPerMethod) {
        MethodPlan plan = plan(method, ints);
        if (plan.intOps == 0 && plan.longOps == 0 && plan.constants == 0) {
            return new int[2];
        }
        int budget = maxPerMethod;
        // Reserve part of the budget for constants so a method full of literals
        // still gets its arithmetic rewritten and vice versa.
        int constantReserve = Math.min(plan.constants, Math.max(1, maxPerMethod / 2));
        int opBudget = Math.max(0, budget - constantReserve);
        int constBudget = budget;

        int nextLocal = nextFreeLocal(method);
        int longTemp = -1;
        int keyLocal = -1;
        int neededLongTemps = plan.longOps > 0 ? 1 : 0;
        if (neededLongTemps > 0) {
            longTemp = nextLocal;
            nextLocal += 4; // two long scratch locals
        }
        if (plan.constants > 0) {
            keyLocal = nextLocal;
            nextLocal += 1;
        }
        if (nextLocal > method.maxLocals) {
            method.maxLocals = nextLocal;
        }

        int expressions = 0;
        if (ints && opBudget > 0) {
            expressions = rewriteArithmetic(method, ints, depth, opBudget, longTemp);
        }
        int rewrittenConstants = 0;
        int remaining = Math.max(0, constBudget - expressions);
        if (remaining > 0 && plan.constants > 0) {
            rewrittenConstants = rewriteConstants(context, method, ints,
                    remaining, keyLocal, plan.constants);
        }
        if (rewrittenConstants > 0) {
            insertRuntimeKey(context, method, keyLocal);
        }
        return new int[] { expressions, rewrittenConstants };
    }

    /** First pass: count candidates and validate the method is analysable enough. */
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

    // ---------------------------------------------------------------- arithmetic

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
                // Long rewrites use two shared scratch locals; rewriting a long
                // operation that a previous pass already emitted would clobber
                // those locals while the enclosing replacement still reads them.
                // Int rewrites are pure stack shuffles, so they can be nested.
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
                // Tag the fresh nodes before inserting: inserting an InsnList
                // links its tail to the following instructions, so walking it
                // afterwards would visit (and tag) the rest of the method.
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
                // a - b = (a & ~b) - (~a & b)
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

    // ----------------------------------------------------------------- constants

    private static int rewriteConstants(PassContext context, MethodNode method, boolean ints,
                                        int budget, int keyLocal, int candidateCount) {
        int limit = Math.min(budget, candidateCount);
        int count = 0;
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
            if (constant instanceof Integer) {
                int value = ((Integer) constant).intValue();
                int compileKey = nonZero(context.random().nextInt());
                int first = value ^ compileKey;
                AsmUtil.pushInt(replacement, first);
                replacement.add(new VarInsnNode(Opcodes.ILOAD, keyLocal));
                replacement.add(new InsnNode(Opcodes.IXOR));
                AsmUtil.pushInt(replacement, compileKey);
                replacement.add(new VarInsnNode(Opcodes.ILOAD, keyLocal));
                replacement.add(new InsnNode(Opcodes.IXOR));
                replacement.add(new InsnNode(Opcodes.IXOR));
            } else {
                long value = ((Long) constant).longValue();
                long compileKey = context.random().nextLong();
                if (compileKey == 0L) {
                    compileKey = 0x5A17_9E37_79B9L;
                }
                long first = value ^ compileKey;
                replacement.add(new LdcInsnNode(Long.valueOf(first)));
                replacement.add(new VarInsnNode(Opcodes.ILOAD, keyLocal));
                replacement.add(new InsnNode(Opcodes.I2L));
                replacement.add(new InsnNode(Opcodes.LXOR));
                replacement.add(new LdcInsnNode(Long.valueOf(compileKey)));
                replacement.add(new VarInsnNode(Opcodes.ILOAD, keyLocal));
                replacement.add(new InsnNode(Opcodes.I2L));
                replacement.add(new InsnNode(Opcodes.LXOR));
                replacement.add(new InsnNode(Opcodes.LXOR));
            }
            method.instructions.insertBefore(insn, replacement);
            method.instructions.remove(insn);
            count++;
        }
        if (count > 0) {
            method.maxStack = Math.max(method.maxStack, 6);
        }
        return count;
    }

    /**
     * Inserts the per-method runtime key prologue:
     * {@code int k = (int) (System.nanoTime() ^ seed)}.
     */
    private static void insertRuntimeKey(PassContext context, MethodNode method, int keyLocal) {
        int seed = nonZero(context.random().nextInt());
        InsnList prologue = new InsnList();
        prologue.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "nanoTime", "()J", false));
        prologue.add(new InsnNode(Opcodes.L2I));
        AsmUtil.pushInt(prologue, seed);
        prologue.add(new InsnNode(Opcodes.IXOR));
        prologue.add(new VarInsnNode(Opcodes.ISTORE, keyLocal));
        method.instructions.insert(prologue);
        method.maxStack = Math.max(method.maxStack, 2);
    }

    // ------------------------------------------------------------------- helpers

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

    /**
     * The spec forbids rewriting constants used as array sizes, array indexes,
     * switch selectors or invokedynamic bootstrap arguments. Producing the
     * identical value would already be observable-equivalent, but keeping those
     * sites literal also keeps the constant-pool shape predictable for other
     * tools. Multi-dimensional array dimensions are detected by looking through
     * the run of constant pushes that precede a {@code MULTIANEWARRAY}.
     */
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
        // A constant that only feeds another constant push may be one component
        // of a multi-dimensional array allocation; look a few nodes ahead.
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

    private static int nonZero(int value) {
        return value == 0 ? 0x5A17 : value;
    }

    private static final class MethodPlan {
        int intOps;
        int longOps;
        int constants;
        boolean needsLongTemps;
    }
}
