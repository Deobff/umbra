package io.umbra.core.pass.impl.integer;

import io.umbra.core.pass.impl.integer.masks.AddMask;
import io.umbra.core.pass.impl.integer.masks.AndMask;
import io.umbra.core.pass.impl.integer.masks.DivMask;
import io.umbra.core.pass.impl.integer.masks.LeftShiftMask;
import io.umbra.core.pass.impl.integer.masks.MulMask;
import io.umbra.core.pass.impl.integer.masks.NegMask;
import io.umbra.core.pass.impl.integer.masks.OrMask;
import io.umbra.core.pass.impl.integer.masks.RightShiftMask;
import io.umbra.core.pass.impl.integer.masks.SubMask;
import io.umbra.core.pass.impl.integer.masks.UShiftRightMask;
import io.umbra.core.pass.impl.integer.masks.XorMask;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * An ordered chain of {@link IntMask} stages.
 *
 * <p>Port of {@code dev.lvstrng.aidsfuscator.polymorph.semi.IntPolymorphStack}:
 * the value walks the chain in insertion order on the way in
 * ({@link #apply(int)}), and in reverse on the way out
 * ({@link #applyInverse(int)}). The three dump methods map one-to-one onto the
 * donor:</p>
 *
 * <ul>
 *   <li>{@link #dump()} - every mask's {@code insns()} concatenated, no
 *       separator (donor {@code dump()}). This is the shape a call site uses:
 *       it consumes and produces exactly one {@code int}, so the stack stays
 *       balanced and no local is touched.</li>
 *   <li>{@link #dumpWithLocal(int)} - the donor's
 *       {@code dumpWithList(() -> ISTORE slot; ILOAD slot)}: after every mask the
 *       value is spilled to a local and reloaded. The spill is what defeats a
 *       peephole pass: two adjacent arithmetic nodes that would fold or cancel
 *       can no longer see each other. Only a standalone decryptor method may
 *       use it, because it needs a private local slot.</li>
 *   <li>{@link #dumpWithIndex(int)} - the {@code LoopBasedXorIntMask} shape: the
 *       xor key is selected from a {@code keys} table by the loop index,
 *       {@code ILOAD slot; push(keys.length); IREM; TABLESWITCH -> push(keys[i])},
 *       then {@code IXOR}. A loop that decrypts an array picks a different key
 *       per element without an extra table load or a bounds check.</li>
 * </ul>
 *
 * <p>Randomness is always supplied by the caller (CONTRACT §0.6). {@link #random}
 * draws from {@code {xor, add, sub}} with operands in
 * {@code [0, Character.MAX_VALUE)}, which is exactly what the donor's
 * {@code DefaultIntegerDecryptor} picks; {@code allowNonInvertible} widens the
 * pool to all eleven families for decode-only chains.</p>
 */
public final class IntMaskStack {

    /** Operand bound used by the donor decryptor ({@code Character.MAX_VALUE}). */
    public static final int OPERAND_BOUND = Character.MAX_VALUE;

    /** Inclusive bounds of the loop key table length. */
    public static final int LOOP_MIN_KEYS = 4;
    public static final int LOOP_MAX_KEYS = 32;

    /** Loop key values live in {@code [0, 255]} so the switch payload stays tiny. */
    private static final int LOOP_KEY_BOUND = 256;

    private final List<IntMask<?>> masks;
    private final int[] loopKeys;

    private IntMaskStack(List<IntMask<?>> masks, int[] loopKeys) {
        this.masks = masks;
        this.loopKeys = loopKeys;
    }

    /** Builds a chain from explicit masks, in apply order. */
    public static IntMaskStack of(IntMask<?>... masks) {
        List<IntMask<?>> list = new ArrayList<IntMask<?>>(masks.length);
        for (int i = 0; i < masks.length; i++) {
            if (masks[i] == null) {
                throw new IllegalArgumentException("null mask at index " + i);
            }
            list.add(masks[i]);
        }
        return new IntMaskStack(list, null);
    }

    /**
     * Builds a chain of {@code count} masks drawn from the supplied stream.
     *
     * @param count             number of stages, {@code <= 0} yields the identity chain
     * @param allowNonInvertible {@code false} draws from {@code {xor, add, sub}}
     *                           only (encodable), {@code true} draws from all
     *                           eleven families (decode-only chains)
     */
    public static IntMaskStack random(Random random, int count, boolean allowNonInvertible) {
        if (random == null) {
            throw new IllegalArgumentException("random");
        }
        List<IntMask<?>> list = new ArrayList<IntMask<?>>(Math.max(0, count));
        for (int i = 0; i < count; i++) {
            list.add(nextMask(random, allowNonInvertible));
        }
        return new IntMaskStack(list, null);
    }

    /** {@link #random} plus a loop key table, as used by a loop decryptor. */
    public static IntMaskStack randomLoop(Random random, int count, boolean allowNonInvertible) {
        return random(random, count, allowNonInvertible).withLoopKeys(random);
    }

    /**
     * Draws the key table used by {@link #dumpWithIndex(int)}. Length is
     * {@code 4..32}, every key is {@code 0..255}; both come from the supplied
     * stream so the chain stays reproducible for a seed.
     */
    public IntMaskStack withLoopKeys(Random random) {
        if (random == null) {
            throw new IllegalArgumentException("random");
        }
        int length = LOOP_MIN_KEYS + random.nextInt(LOOP_MAX_KEYS - LOOP_MIN_KEYS + 1);
        int[] keys = new int[length];
        for (int i = 0; i < length; i++) {
            keys[i] = random.nextInt(LOOP_KEY_BOUND);
        }
        return new IntMaskStack(masks, keys);
    }

    /** Attaches a caller-built key table (defensive copy). */
    public IntMaskStack withLoopKeys(int[] keys) {
        if (keys == null || keys.length == 0) {
            throw new IllegalArgumentException("empty loop key table");
        }
        return new IntMaskStack(masks, keys.clone());
    }

    /**
     * The donor's mask pool. Without {@code allowNonInvertible} this is the
     * decryptor's {@code {XorMask, SubMask, AddMask}} tuple; with it the order
     * follows {@code IntPolymorphStack.allMasks}.
     */
    private static IntMask<?> nextMask(Random random, boolean allowNonInvertible) {
        if (!allowNonInvertible) {
            switch (random.nextInt(3)) {
                case 0:
                    return new XorMask().ofRandomValue(random, OPERAND_BOUND);
                case 1:
                    return new AddMask().ofRandomValue(random, OPERAND_BOUND);
                default:
                    return new SubMask().ofRandomValue(random, OPERAND_BOUND);
            }
        }
        switch (random.nextInt(11)) {
            case 0:
                return new AddMask().ofRandomValue(random, OPERAND_BOUND);
            case 1:
                return new SubMask().ofRandomValue(random, OPERAND_BOUND);
            case 2:
                return new MulMask().ofRandomValue(random);
            case 3:
                // A zero divisor throws at runtime; keep the operand non-zero.
                return new DivMask().ofValue(1 + random.nextInt(OPERAND_BOUND));
            case 4:
                return new UShiftRightMask().ofValue(random.nextInt(32));
            case 5:
                return new RightShiftMask().ofValue(random.nextInt(32));
            case 6:
                return new LeftShiftMask().ofValue(random.nextInt(32));
            case 7:
                return new XorMask().ofRandomValue(random, OPERAND_BOUND);
            case 8:
                return new OrMask().ofRandomValue(random);
            case 9:
                return new AndMask().ofRandomValue(random);
            default:
                return new NegMask();
        }
    }

    public int size() {
        return masks.size();
    }

    public boolean isEmpty() {
        return masks.isEmpty();
    }

    /** The stages, in apply order. Unmodifiable. */
    public List<IntMask<?>> masks() {
        return Collections.unmodifiableList(masks);
    }

    /** Applies every stage in insertion order. */
    public int apply(int n) {
        int value = n;
        for (int i = 0; i < masks.size(); i++) {
            value = masks.get(i).apply(value);
        }
        return value;
    }

    /**
     * Undoes every stage in reverse order. Throws
     * {@link UnsupportedOperationException} as soon as a non-invertible stage is
     * reached, which is how {@link #invertible()} classifies the chain.
     */
    public int applyInverse(int n) {
        int value = n;
        for (int i = masks.size() - 1; i >= 0; i--) {
            value = masks.get(i).applyInverse(value);
        }
        return value;
    }

    /** {@link #apply} plus the loop key selected by {@code index}. */
    public int applyLooped(int n, int index) {
        return apply(n) ^ keyAt(index);
    }

    /** Inverse of {@link #applyLooped}. */
    public int applyLoopedInverse(int n, int index) {
        return applyInverse(n ^ keyAt(index));
    }

    /**
     * The key {@code dumpWithIndex} selects for {@code index}. A negative
     * remainder sends the {@code TABLESWITCH} to its default label, which is
     * route {@code 0}, so negative indices resolve to {@code keys[0]} here too.
     */
    public int keyAt(int index) {
        if (loopKeys == null) {
            throw new IllegalStateException("chain has no loop key table");
        }
        int slot = index % loopKeys.length;
        if (slot < 0) {
            slot = 0;
        }
        return loopKeys[slot];
    }

    public int[] loopKeys() {
        return loopKeys == null ? null : loopKeys.clone();
    }

    public boolean hasLoop() {
        return loopKeys != null;
    }

    /** Whether every stage implements an inverse, i.e. the chain can encode. */
    public boolean invertible() {
        for (int i = 0; i < masks.size(); i++) {
            if (!masks.get(i).invertible()) {
                return false;
            }
        }
        return true;
    }

    /** {@code "xor+add+sub"}: the family sequence, for logs and stats. */
    public String families() {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < masks.size(); i++) {
            if (i > 0) {
                out.append('+');
            }
            out.append(masks.get(i).family());
        }
        return out.toString();
    }

    /**
     * The call-site shape: every stage's instructions back to back.
     *
     * <p>Consumes one {@code int} from the operand stack and leaves one
     * {@code int}; the peak depth is two slots and no local is touched, so it can
     * be appended to any int expression.</p>
     */
    public InsnList dump() {
        InsnList out = new InsnList();
        for (int i = 0; i < masks.size(); i++) {
            out.add(masks.get(i).insns());
        }
        return out;
    }

    /**
     * The donor's anti-peephole shape: after every stage
     * {@code ISTORE slot; ILOAD slot}.
     *
     * @param slot a local slot the caller owns; it must be free for the whole
     *             method and of type {@code int}
     */
    public InsnList dumpWithLocal(int slot) {
        if (slot < 0) {
            throw new IllegalArgumentException("negative local slot " + slot);
        }
        InsnList out = new InsnList();
        for (int i = 0; i < masks.size(); i++) {
            out.add(masks.get(i).insns());
            out.add(new VarInsnNode(Opcodes.ISTORE, slot));
            out.add(new VarInsnNode(Opcodes.ILOAD, slot));
        }
        return out;
    }

    /**
     * The {@code LoopBasedXorIntMask} shape: picks the xor key from the key table
     * with the loop index held in {@code slot}.
     *
     * <p>Emits {@code ILOAD slot; push(keys.length); IREM; TABLESWITCH} with one
     * route per key, each route {@code push(keys[i]); GOTO end}, then
     * {@code end: IXOR}. The operand stack must already hold the value to decode;
     * one {@code int} is consumed and one produced.</p>
     *
     * @param slot a local slot holding the loop index
     */
    public InsnList dumpWithIndex(int slot) {
        if (loopKeys == null) {
            throw new IllegalStateException("chain has no loop key table: call withLoopKeys first");
        }
        if (slot < 0) {
            throw new IllegalArgumentException("negative local slot " + slot);
        }
        InsnList out = new InsnList();
        LabelNode end = new LabelNode();
        LabelNode[] routes = new LabelNode[loopKeys.length];
        for (int i = 0; i < routes.length; i++) {
            routes[i] = new LabelNode();
        }
        out.add(new VarInsnNode(Opcodes.ILOAD, slot));
        AsmUtil.pushInt(out, loopKeys.length);
        out.add(new InsnNode(Opcodes.IREM));
        out.add(new TableSwitchInsnNode(0, loopKeys.length - 1, routes[0], routes));
        for (int i = 0; i < routes.length; i++) {
            out.add(routes[i]);
            AsmUtil.pushInt(out, loopKeys[i]);
            out.add(new JumpInsnNode(Opcodes.GOTO, end));
        }
        out.add(end);
        out.add(new InsnNode(Opcodes.IXOR));
        return out;
    }

    /** {@link #dump()} followed by {@link #dumpWithIndex(int)}: a full loop decode. */
    public InsnList dumpLooped(int slot) {
        InsnList out = new InsnList();
        out.add(dump());
        out.add(dumpWithIndex(slot));
        return out;
    }

    /** One log line: size, family sequence, invertibility, loop table. */
    public String describe() {
        StringBuilder out = new StringBuilder("masks=").append(masks.size());
        out.append(" [").append(families()).append(']');
        out.append(" invertible=").append(invertible());
        if (loopKeys != null) {
            out.append(" loopKeys=").append(loopKeys.length).append(Arrays.toString(loopKeys));
        }
        return out.toString();
    }

    @Override
    public String toString() {
        return describe();
    }
}
