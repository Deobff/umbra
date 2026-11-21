package io.umbra.core.pass.impl.flowints;

import io.umbra.core.pass.impl.flow.RuntimeTable;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

/**
 * Emits the flow-ints instruction shapes.
 *
 * <p>The site shape is the donor's exact one
 * ({@code flowInts/FlowIntsTransformer.java:218-226}):</p>
 *
 * <pre>
 * ILOAD   s
 *   seed                ; method seed
 *   IOR
 *   (state | seed) ^ target
 *   IXOR                ; == target while s == state
 * </pre>
 *
 * <p>{@code OR} and {@code XOR} commute with the constant, so the two masks
 * cancel and the site yields the original constant exactly when the state
 * variable holds the value the build assigned to that block. A second reader
 * only sees {@code (s | K) ^ D}: neither the constant nor the seed alone
 * recovers the value without the state history.</p>
 *
 * <p>The state advance is {@code s = s * A + B} with an odd {@code A} and
 * {@code B = to - from * A}, i.e. an affine advance whose fixed point is not
 * predictable without {@code from}. {@code IMUL} overflow is the normal Java int
 * wrap-around, so no guard is needed. The donor's flow confuser
 * ({@code createFlowConfuser}, {@code :110-160}) is available as an option: it
 * routes the advance through a {@code lookupswitch} keyed on the current state,
 * with the real case taken because the state is provably the expected value and
 * decoy cases that would corrupt it if they were ever reached.</p>
 *
 * <p>Long constants use the donor's bit-split shape
 * ({@code :230-269}): the build folds {@code s & 0xFFFFFFFF} into both halves of
 * the constant, and the run-time sequence splits it back with
 * {@code LSHL/LUSHR/LAND/LXOR}. {@code LDC2_W} of the donor's {@code 0xFFFFFFFF}
 * masks is kept verbatim.</p>
 *
 * <p>Every constant the emitter needs goes through {@link RuntimeTable} when a
 * pair is still available, so no raw build-time constant lands at a site; when
 * the table is exhausted the emitter falls back to a plain {@code pushInt} and
 * counts it, which keeps the transform correct instead of failing the method.</p>
 */
public final class FlowIntEmitter {

    private final RuntimeTable table;
    private final Random random;
    private final int stateLocal;
    private final int methodSeed;
    private final boolean confuse;
    private final int confusePercent;
    private final RuntimeTable.Pair seedPair;
    private int tableConstants;
    private int fallbackConstants;

    public FlowIntEmitter(RuntimeTable table, Random random, int stateLocal, int methodSeed,
                          boolean confuse, int confusePercent) {
        this.table = table;
        this.random = random;
        this.stateLocal = stateLocal;
        this.methodSeed = methodSeed;
        this.confuse = confuse;
        this.confusePercent = Math.max(0, Math.min(100, confusePercent));
        this.seedPair = table == null ? null : table.pair(methodSeed);
    }

    public int stateLocal() {
        return stateLocal;
    }

    public int methodSeed() {
        return methodSeed;
    }

    public int tableConstants() {
        return tableConstants;
    }

    public int fallbackConstants() {
        return fallbackConstants;
    }

    /** Pushes {@code value}, preferring a runtime-table pair over a literal. */
    public void emitConst(InsnList out, int value) {
        if (table != null) {
            RuntimeTable.Pair pair = table.pair(value);
            if (pair != null) {
                table.emitInt(out, pair);
                tableConstants++;
                return;
            }
        }
        AsmUtil.pushInt(out, value);
        fallbackConstants++;
    }

    /** Pushes the per-method seed; one pair is allocated per method and reused. */
    private void emitSeedConst(InsnList out) {
        if (table != null && seedPair != null) {
            table.emitInt(out, seedPair);
            tableConstants++;
            return;
        }
        AsmUtil.pushInt(out, methodSeed);
        fallbackConstants++;
    }

    /** {@code s = value}. */
    public void emitSeed(InsnList out, int value) {
        emitConst(out, value);
        out.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
    }

    /** {@code s = s * A + B} with {@code from * A + B == to}. */
    public void emitAdvance(InsnList out, int from, int to) {
        if (confuse && random.nextInt(100) < confusePercent) {
            emitConfusedAdvance(out, from, to);
            return;
        }
        emitLinearAdvance(out, from, to);
    }

    private void emitLinearAdvance(InsnList out, int from, int to) {
        int a = oddMultiplier();
        int b = to - from * a;
        out.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        emitConst(out, a);
        out.add(new InsnNode(Opcodes.IMUL));
        emitConst(out, b);
        out.add(new InsnNode(Opcodes.IADD));
        out.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
    }

    private int oddMultiplier() {
        int a = random.nextInt() | 1;
        if (a == 1) {
            a = 3;
        }
        return a;
    }

    /**
     * The donor's decoy switch around the advance. The real case is keyed on
     * {@code from}, which is the provable run-time state, so the decoy cases are
     * never entered; each decoy corrupts the state and then falls through to the
     * exit, which keeps the emitted bytecode verifiable (frames agree at
     * {@code exit}) without ever changing behaviour.
     */
    private void emitConfusedAdvance(InsnList out, int from, int to) {
        LabelNode dispatch = new LabelNode();
        LabelNode real = new LabelNode();
        LabelNode decoyA = new LabelNode();
        LabelNode decoyB = new LabelNode();
        LabelNode exit = new LabelNode();

        int spareA = uniqueKey(from, 0);
        int spareB = uniqueKey(from, spareA);
        TreeMap<Integer, LabelNode> cases = new TreeMap<Integer, LabelNode>();
        cases.put(Integer.valueOf(from), real);
        cases.put(Integer.valueOf(spareA), decoyA);
        cases.put(Integer.valueOf(spareB), decoyB);
        int[] keys = new int[cases.size()];
        LabelNode[] labels = new LabelNode[cases.size()];
        int cursor = 0;
        for (Map.Entry<Integer, LabelNode> entry : cases.entrySet()) {
            keys[cursor] = entry.getKey().intValue();
            labels[cursor] = entry.getValue();
            cursor++;
        }

        out.add(dispatch);
        out.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        out.add(new LookupSwitchInsnNode(decoyA, keys, labels));
        out.add(real);
        emitLinearAdvance(out, from, to);
        out.add(new JumpInsnNode(Opcodes.GOTO, exit));
        out.add(decoyA);
        out.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        emitConst(out, random.nextInt());
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
        out.add(new JumpInsnNode(Opcodes.GOTO, exit));
        out.add(decoyB);
        out.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        emitConst(out, random.nextInt());
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
        out.add(new JumpInsnNode(Opcodes.GOTO, exit));
        out.add(exit);
    }

    private int uniqueKey(int avoid, int avoidToo) {
        int candidate = random.nextInt();
        int guard = 0;
        while ((candidate == avoid || (avoidToo != 0 && candidate == avoidToo)) && guard++ < 64) {
            candidate = ~candidate ^ 0x5BF03635;
        }
        if (candidate == avoid || candidate == avoidToo) {
            candidate = avoid ^ 0x9E3779B9;
        }
        return candidate;
    }

    /** Replaces one int constant push with the state-derived shape. */
    public void emitIntSite(InsnList out, int blockState, int target) {
        out.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        emitSeedConst(out);
        out.add(new InsnNode(Opcodes.IOR));
        emitConst(out, (blockState | methodSeed) ^ target);
        out.add(new InsnNode(Opcodes.IXOR));
    }

    /** Replaces one long constant push with the donor's split-mask shape. */
    public void emitLongSite(InsnList out, int blockState, long target) {
        long mask = blockState & 0xFFFFFFFFL;
        long low = (target & 0xFFFFFFFFL) ^ mask;
        long high = (target >>> 32) ^ mask;
        long obfuscated = low | (high << 32);
        emitLongConst(out, obfuscated);
        out.add(new InsnNode(Opcodes.DUP2));
        AsmUtil.pushInt(out, 32);
        out.add(new InsnNode(Opcodes.LSHL));
        AsmUtil.pushInt(out, 32);
        out.add(new InsnNode(Opcodes.LUSHR));
        out.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        out.add(new InsnNode(Opcodes.I2L));
        out.add(new LdcInsnNode(Long.valueOf(0xFFFFFFFFL)));
        out.add(new InsnNode(Opcodes.LAND));
        out.add(new InsnNode(Opcodes.LXOR));
        out.add(new InsnNode(Opcodes.DUP2_X2));
        out.add(new InsnNode(Opcodes.POP2));
        AsmUtil.pushInt(out, 32);
        out.add(new InsnNode(Opcodes.LUSHR));
        out.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        out.add(new InsnNode(Opcodes.I2L));
        out.add(new LdcInsnNode(Long.valueOf(0xFFFFFFFFL)));
        out.add(new InsnNode(Opcodes.LAND));
        out.add(new InsnNode(Opcodes.LXOR));
        AsmUtil.pushInt(out, 32);
        out.add(new InsnNode(Opcodes.LSHL));
        out.add(new InsnNode(Opcodes.LOR));
    }

    private void emitLongConst(InsnList out, long value) {
        if (table != null && table.emitLong(out, value)) {
            tableConstants += 2;
            return;
        }
        out.add(new LdcInsnNode(Long.valueOf(value)));
        fallbackConstants++;
    }

    /** Reads the constant behind an int push instruction. */
    public static int intValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return opcode - Opcodes.ICONST_0;
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return ((IntInsnNode) insn).operand;
        }
        if (insn instanceof LdcInsnNode) {
            Object constant = ((LdcInsnNode) insn).cst;
            if (constant instanceof Integer) {
                return ((Integer) constant).intValue();
            }
        }
        throw new IllegalArgumentException("not an int push");
    }

    /** Reads the constant behind a long push instruction. */
    public static long longValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.LCONST_0) {
            return 0L;
        }
        if (opcode == Opcodes.LCONST_1) {
            return 1L;
        }
        if (insn instanceof LdcInsnNode) {
            Object constant = ((LdcInsnNode) insn).cst;
            if (constant instanceof Long) {
                return ((Long) constant).longValue();
            }
        }
        throw new IllegalArgumentException("not a long push");
    }
}
