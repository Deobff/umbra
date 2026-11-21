package io.umbra.core.pass.impl.numberhash;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;

/**
 * One reversible step of a number-hash program.
 *
 * <p>A program is a fixed sequence of steps. The emitted bytecode applies the
 * steps in order (that sequence <em>is</em> the decoder), and the build-time
 * encoder applies the inverses in reverse order. Because every step is a
 * bijection on {@code int}, so is the whole program, which is what lets the
 * encoder map a literal to a different constant without losing information.</p>
 *
 * <p>Every step consumes exactly one {@code int} from the operand stack and
 * leaves exactly one, never touches a local and never emits a branch. A
 * sequence of steps can therefore be spliced into any int expression without
 * disturbing the surrounding evaluation order, and {@link #stackNeed()} bounds
 * the extra stack it adds.</p>
 *
 * <p>The invertibility rules matter more than the shapes:</p>
 * <ul>
 *   <li>{@code XOR}/{@code ADD}/{@code SUB} are involutions or negations of
 *       each other, valid for every operand.</li>
 *   <li>{@code MUL} is only invertible for an <b>odd</b> multiplier; an even one
 *       loses the low bit and is rejected at construction time.</li>
 *   <li>{@code ROTL}/{@code ROTR} use {@code IUSHR}, i.e. a real 32-bit
 *       rotation. The reference's {@code >>} version is an arithmetic shift, which
 *       collapses every negative input onto a handful of values (see
 *       {@link Hashes#bitwiseStrict(int)}); it is deliberately not ported.</li>
 *   <li>{@code XORSHIFT16} is {@code x ^ (x >>> 16)}, which is its own inverse:
 *       {@code (x ^ (x>>>16)) ^ ((x ^ (x>>>16)) >>> 16) == x}. Shifts other than
 *       16 need a multi-term inverse and are not offered.</li>
 *   <li>{@code TABLE} permutes the low byte through a 256-entry table and
 *       leaves the upper 24 bits alone; it is inverted by the inverse
 *       permutation, so it is a bijection exactly when the table is.</li>
 * </ul>
 */
public final class Step {

    public static final int KIND_XOR = 1;
    public static final int KIND_ADD = 2;
    public static final int KIND_SUB = 3;
    public static final int KIND_MUL = 4;
    public static final int KIND_ROTL = 5;
    public static final int KIND_ROTR = 6;
    public static final int KIND_XORSHIFT16 = 7;
    public static final int KIND_NEG = 8;
    public static final int KIND_TABLE = 9;

    private final int kind;
    private final int operand;
    private final String table;
    private final String inverseTable;

    private Step(int kind, int operand, String table, String inverseTable) {
        this.kind = kind;
        this.operand = operand;
        this.table = table;
        this.inverseTable = inverseTable;
    }

    public static Step xor(int constant) {
        return new Step(KIND_XOR, constant, null, null);
    }

    public static Step add(int constant) {
        return new Step(KIND_ADD, constant, null, null);
    }

    public static Step sub(int constant) {
        return new Step(KIND_SUB, constant, null, null);
    }

    /**
     * Multiplication by an odd constant. The multiplier must be odd: an even one
     * is not invertible modulo 2^32 and would silently lose the low bit.
     */
    public static Step mul(int oddMultiplier) {
        if ((oddMultiplier & 1) == 0) {
            throw new IllegalArgumentException("multiplier must be odd: " + oddMultiplier);
        }
        return new Step(KIND_MUL, oddMultiplier, null, null);
    }

    public static Step rotl(int bits) {
        if (bits < 1 || bits > 31) {
            throw new IllegalArgumentException("rotl bits out of range: " + bits);
        }
        return new Step(KIND_ROTL, bits, null, null);
    }

    public static Step rotr(int bits) {
        if (bits < 1 || bits > 31) {
            throw new IllegalArgumentException("rotr bits out of range: " + bits);
        }
        return new Step(KIND_ROTR, bits, null, null);
    }

    public static Step xorshift16() {
        return new Step(KIND_XORSHIFT16, 16, null, null);
    }

    public static Step neg() {
        return new Step(KIND_NEG, 0, null, null);
    }

    /**
     * Low-byte permutation step. {@code forward} is the table the emitted
     * decoder reads, {@code inverse} is the table the encoder applies.
     */
    public static Step table(String forward, String inverse) {
        if (forward == null || inverse == null) {
            throw new IllegalArgumentException("table");
        }
        if (forward.length() != 256 || inverse.length() != 256) {
            throw new IllegalArgumentException("table must hold 256 entries");
        }
        return new Step(KIND_TABLE, 0, forward, inverse);
    }

    public int kind() {
        return kind;
    }

    public int operand() {
        return operand;
    }

    /** Extra operand-stack slots this step needs on top of the incoming value. */
    public int stackNeed() {
        switch (kind) {
            case KIND_XOR:
            case KIND_ADD:
            case KIND_SUB:
            case KIND_MUL:
            case KIND_XORSHIFT16:
                return 2;
            case KIND_ROTL:
            case KIND_ROTR:
            case KIND_TABLE:
                return 3;
            case KIND_NEG:
                return 0;
            default:
                return 2;
        }
    }

    /** Forward evaluation: the build-time mirror of {@link #emit(InsnList)}. */
    public int apply(int value) {
        switch (kind) {
            case KIND_XOR:
                return value ^ operand;
            case KIND_ADD:
                return value + operand;
            case KIND_SUB:
                return value - operand;
            case KIND_MUL:
                return value * operand;
            case KIND_ROTL:
                return Integer.rotateLeft(value, operand);
            case KIND_ROTR:
                return Integer.rotateRight(value, operand);
            case KIND_XORSHIFT16:
                return value ^ (value >>> 16);
            case KIND_NEG:
                return -value;
            case KIND_TABLE:
                return lookup(table, value);
            default:
                throw new IllegalStateException("unknown step kind " + kind);
        }
    }

    /** Inverse evaluation, used by the encoder. */
    public int invert(int value) {
        switch (kind) {
            case KIND_XOR:
                return value ^ operand;
            case KIND_ADD:
                return value - operand;
            case KIND_SUB:
                return value + operand;
            case KIND_MUL:
                return value * modularInverse(operand);
            case KIND_ROTL:
                return Integer.rotateRight(value, operand);
            case KIND_ROTR:
                return Integer.rotateLeft(value, operand);
            case KIND_XORSHIFT16:
                return value ^ (value >>> 16);
            case KIND_NEG:
                return -value;
            case KIND_TABLE:
                return lookup(inverseTable, value);
            default:
                throw new IllegalStateException("unknown step kind " + kind);
        }
    }

    /**
     * Emits the forward transformation: one int in, one int out.
     *
     * <p>{@code ROTL} is the interesting shape. It needs two copies of the
     * value, so it uses {@code DUP ... SWAP ... IOR}; the reference's expression
     * form used {@code ISHR} there and therefore lost the sign bit.</p>
     */
    public void emit(InsnList out) {
        switch (kind) {
            case KIND_XOR:
                AsmUtil.pushInt(out, operand);
                out.add(new InsnNode(Opcodes.IXOR));
                return;
            case KIND_ADD:
                AsmUtil.pushInt(out, operand);
                out.add(new InsnNode(Opcodes.IADD));
                return;
            case KIND_SUB:
                AsmUtil.pushInt(out, operand);
                out.add(new InsnNode(Opcodes.ISUB));
                return;
            case KIND_MUL:
                AsmUtil.pushInt(out, operand);
                out.add(new InsnNode(Opcodes.IMUL));
                return;
            case KIND_ROTL:
                out.add(new InsnNode(Opcodes.DUP));
                AsmUtil.pushInt(out, operand);
                out.add(new InsnNode(Opcodes.ISHL));
                out.add(new InsnNode(Opcodes.SWAP));
                AsmUtil.pushInt(out, 32 - operand);
                out.add(new InsnNode(Opcodes.IUSHR));
                out.add(new InsnNode(Opcodes.IOR));
                return;
            case KIND_ROTR:
                out.add(new InsnNode(Opcodes.DUP));
                AsmUtil.pushInt(out, operand);
                out.add(new InsnNode(Opcodes.IUSHR));
                out.add(new InsnNode(Opcodes.SWAP));
                AsmUtil.pushInt(out, 32 - operand);
                out.add(new InsnNode(Opcodes.ISHL));
                out.add(new InsnNode(Opcodes.IOR));
                return;
            case KIND_XORSHIFT16:
                out.add(new InsnNode(Opcodes.DUP));
                AsmUtil.pushInt(out, 16);
                out.add(new InsnNode(Opcodes.IUSHR));
                out.add(new InsnNode(Opcodes.IXOR));
                return;
            case KIND_NEG:
                out.add(new InsnNode(Opcodes.INEG));
                return;
            case KIND_TABLE:
                emitTable(out, table);
                return;
            default:
                throw new IllegalStateException("unknown step kind " + kind);
        }
    }

    /**
     * Emits {@code t[value & 0xFF] | (value & 0xFFFFFF00)} using
     * {@code String.charAt} as the table load, so the step needs no field, no
     * helper method and no local.
     */
    private static void emitTable(InsnList out, String lookupTable) {
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new LdcInsnNode(lookupTable));
        out.add(new InsnNode(Opcodes.SWAP));
        AsmUtil.pushInt(out, 0xFF);
        out.add(new InsnNode(Opcodes.IAND));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C", false));
        out.add(new InsnNode(Opcodes.SWAP));
        AsmUtil.pushInt(out, 0xFFFFFF00);
        out.add(new InsnNode(Opcodes.IAND));
        out.add(new InsnNode(Opcodes.IOR));
    }

    /** Build-time mirror of {@link #emitTable(InsnList, String)}. */
    public static int lookup(String lookupTable, int value) {
        int index = value & 0xFF;
        int mapped = lookupTable.charAt(index);
        return mapped | (value & 0xFFFFFF00);
    }

    /**
     * Modular inverse of an odd {@code int} modulo 2^32 (Newton iteration,
     * five rounds are enough because each doubles the correct low-bit count).
     */
    static int modularInverse(int odd) {
        int inverse = odd;
        for (int i = 0; i < 5; i++) {
            inverse *= 2 - odd * inverse;
        }
        return inverse;
    }

    public String describe() {
        switch (kind) {
            case KIND_XOR:
                return "xor(0x" + Integer.toHexString(operand) + ")";
            case KIND_ADD:
                return "add(" + operand + ")";
            case KIND_SUB:
                return "sub(" + operand + ")";
            case KIND_MUL:
                return "mul(" + operand + ")";
            case KIND_ROTL:
                return "rotl(" + operand + ")";
            case KIND_ROTR:
                return "rotr(" + operand + ")";
            case KIND_XORSHIFT16:
                return "xorshift16()";
            case KIND_NEG:
                return "neg()";
            case KIND_TABLE:
                return "table(256)";
            default:
                return "step(" + kind + ")";
        }
    }
}
