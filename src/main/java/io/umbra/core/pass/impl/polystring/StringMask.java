package io.umbra.core.pass.impl.polystring;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.Random;

/**
 * One reversible per-character transform of the polymorphic string loop.
 *
 * <p>Ported from aidsfuscator's {@code polymorph.full.integer} mask family
 * ({@code XorIntMask}, {@code LoopXorIntMask}, {@code LoopBasedXorIntMask},
 * {@code VarXorIntMask}) and its loop carriers
 * ({@code polymorph.full.strings.ForLoopStringMask} /
 * {@code DoWhileLoopStringMask}).</p>
 *
 * <p>Every mask is applied to the {@code char} value loaded from the payload
 * array while the loop index is live, so the transform is position dependent.
 * {@link #applyInverse} is the exact inverse of {@link #apply}: the build encrypts
 * with the inverse in reverse mask order and the runtime replays the masks in
 * forward order, which is the same contract the source uses.</p>
 */
public abstract class StringMask {

    public abstract String label();

    /** Build-time forward transform. */
    public abstract int apply(int value, int index, int key);

    /** Build-time inverse of {@link #apply}. */
    public abstract int applyInverse(int value, int index, int key);

    /**
     * Emits the runtime transform for an {@code int} already on the operand stack.
     *
     * @param indexSlot local slot holding the loop index ({@code >= 0})
     * @param keySlot   local slot holding the site key
     */
    public abstract void emit(InsnList out, int indexSlot, int keySlot);

    /** A constant XOR, the {@code XorIntMask} equivalent. */
    public static StringMask constXor(int value) {
        return new ConstXor(value);
    }

    /** XOR with the loop index, the {@code LoopXorIntMask} equivalent. */
    public static StringMask indexXor() {
        return new IndexXor();
    }

    /** XOR with a key carried in a local, the {@code VarXorIntMask} equivalent. */
    public static StringMask keyXor() {
        return new KeyXor();
    }

    /** XOR with {@code keys[index % keys.length]}, the {@code LoopBasedXorIntMask} equivalent. */
    public static StringMask positionXor(int[] keys) {
        return new PositionXor(keys);
    }

    /**
     * Draws one mask the way the source's {@code ForLoopStringMask} does: a
     * constant XOR in the {@code char} range, a position table XOR with 4..32
     * entries in {@code 0..255}, or the loop index itself.
     */
    public static StringMask random(Random random, boolean allowTables) {
        int pick = random.nextInt(allowTables ? 3 : 2);
        if (pick == 0) {
            return new ConstXor(random.nextInt(0x10000));
        }
        if (pick == 1) {
            return new IndexXor();
        }
        int length = 4 + random.nextInt(29);
        int[] keys = new int[length];
        for (int i = 0; i < length; i++) {
            keys[i] = random.nextInt(256);
        }
        return new PositionXor(keys);
    }

    /** {@code value ^ constant}. */
    private static final class ConstXor extends StringMask {
        private final int value;

        ConstXor(int value) {
            this.value = value & 0xFFFF;
        }

        @Override
        public String label() {
            return "xor";
        }

        @Override
        public int apply(int value, int index, int key) {
            return (value ^ this.value) & 0xFFFF;
        }

        @Override
        public int applyInverse(int value, int index, int key) {
            return (value ^ this.value) & 0xFFFF;
        }

        @Override
        public void emit(InsnList out, int indexSlot, int keySlot) {
            AsmUtil.pushInt(out, value);
            out.add(new InsnNode(Opcodes.IXOR));
        }
    }

    /** {@code value ^ index}. */
    private static final class IndexXor extends StringMask {
        @Override
        public String label() {
            return "index";
        }

        @Override
        public int apply(int value, int index, int key) {
            return (value ^ index) & 0xFFFF;
        }

        @Override
        public int applyInverse(int value, int index, int key) {
            return (value ^ index) & 0xFFFF;
        }

        @Override
        public void emit(InsnList out, int indexSlot, int keySlot) {
            out.add(new VarInsnNode(Opcodes.ILOAD, indexSlot));
            out.add(new InsnNode(Opcodes.IXOR));
        }
    }

    /** {@code value ^ keySlot}. */
    private static final class KeyXor extends StringMask {
        @Override
        public String label() {
            return "key";
        }

        @Override
        public int apply(int value, int index, int key) {
            return (value ^ key) & 0xFFFF;
        }

        @Override
        public int applyInverse(int value, int index, int key) {
            return (value ^ key) & 0xFFFF;
        }

        @Override
        public void emit(InsnList out, int indexSlot, int keySlot) {
            out.add(new VarInsnNode(Opcodes.ILOAD, keySlot));
            out.add(new InsnNode(Opcodes.IXOR));
        }
    }

    /**
     * {@code value ^ keys[index % keys.length]} rendered as a {@code tableswitch},
     * exactly the shape {@code LoopBasedXorIntMask} emits: the position is reduced,
     * switched on, and the selected key is XORed.
     */
    private static final class PositionXor extends StringMask {
        private final int[] keys;

        PositionXor(int[] keys) {
            this.keys = keys;
        }

        @Override
        public String label() {
            return "table";
        }

        @Override
        public int apply(int value, int index, int key) {
            return (value ^ keys[index % keys.length]) & 0xFFFF;
        }

        @Override
        public int applyInverse(int value, int index, int key) {
            return (value ^ keys[index % keys.length]) & 0xFFFF;
        }

        @Override
        public void emit(InsnList out, int indexSlot, int keySlot) {
            LabelNode end = new LabelNode();
            LabelNode dflt = new LabelNode();
            LabelNode[] labels = new LabelNode[keys.length];
            for (int i = 0; i < labels.length; i++) {
                labels[i] = new LabelNode();
            }
            out.add(new VarInsnNode(Opcodes.ILOAD, indexSlot));
            AsmUtil.pushInt(out, keys.length);
            out.add(new InsnNode(Opcodes.IREM));
            out.add(new TableSwitchInsnNode(0, labels.length - 1, dflt, labels));
            for (int i = 0; i < labels.length; i++) {
                out.add(labels[i]);
                AsmUtil.pushInt(out, keys[i]);
                out.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.GOTO, end));
            }
            out.add(dflt);
            AsmUtil.pushInt(out, 0);
            out.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.GOTO, end));
            out.add(end);
            out.add(new InsnNode(Opcodes.IXOR));
        }
    }
}
