package io.umbra.core.pass.impl.polystring;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.Locale;

/**
 * The per-character transform layered under the {@link MaskChain}.
 *
 * <ul>
 *   <li>{@link #MASK} - identity; the mask chain does all the work (the default,
 *       and the the reference implementation shape);</li>
 *   <li>{@link #CAESAR} - ported from the reference implementation's
 *       {@code the Caesar generator}: {@code c = (c + k) & 0xFFFF};</li>
 *   <li>{@link #IV} - ported from the reference implementation's {@code the IV generator}:
 *       the key is an index-derived initialisation vector,
 *       {@code c ^= (k * (i + 1)) >>> 8};</li>
 *   <li>{@link #POOL} - the {@code StringPoolerEncryptionGenerator} shape: the
 *       class decodes its whole pool once into a cache and every call site only
 *       reads the cache, so one decryption serves many sites.</li>
 * </ul>
 */
public enum StringCodec {

    MASK, CAESAR, IV, POOL;

    public static StringCodec parse(String value, StringCodec fallback) {
        if (value == null) {
            return fallback;
        }
        String normalised = value.trim().toLowerCase(Locale.ROOT);
        for (StringCodec codec : values()) {
            if (codec.name().toLowerCase(Locale.ROOT).equals(normalised)) {
                return codec;
            }
        }
        return fallback;
    }

    /** Build-side transform: maps the plaintext character to what goes into the payload. */
    public int encode(int value, int index, int key) {
        switch (this) {
            case CAESAR:
                return (value - key) & 0xFFFF;
            case IV:
                return (value ^ ivKey(index, key)) & 0xFFFF;
            case POOL:
                return (value - key) & 0xFFFF;
            default:
                return value & 0xFFFF;
        }
    }

    /** Build-side model of the runtime decode, used by the self test. */
    public int decode(int value, int index, int key) {
        switch (this) {
            case CAESAR:
            case POOL:
                return (value + key) & 0xFFFF;
            case IV:
                return (value ^ ivKey(index, key)) & 0xFFFF;
            default:
                return value & 0xFFFF;
        }
    }

    private static void pushKey(InsnList out, int keySlot, boolean keyIsLong) {
        if (keyIsLong) {
            out.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
            out.add(new InsnNode(Opcodes.L2I));
        } else {
            out.add(new VarInsnNode(Opcodes.ILOAD, keySlot));
        }
    }

    private static int ivKey(int index, int key) {
        return (key * (index + 1)) >>> 8;
    }

    /**
     * Emits the runtime transform for an {@code int} already on the operand stack.
     *
     * @param keyIsLong whether the key slot holds a {@code long}; the value is then
     *                  loaded with {@code LLOAD} and narrowed, because the decoder's
     *                  argument layout is random per class
     */
    public void emit(InsnList out, int indexSlot, int keySlot, boolean keyIsLong) {
        switch (this) {
            case CAESAR:
            case POOL:
                pushKey(out, keySlot, keyIsLong);
                out.add(new InsnNode(Opcodes.IADD));
                AsmUtil.pushInt(out, 0xFFFF);
                out.add(new InsnNode(Opcodes.IAND));
                return;
            case IV:
                out.add(new VarInsnNode(Opcodes.ILOAD, indexSlot));
                out.add(new InsnNode(Opcodes.ICONST_1));
                out.add(new InsnNode(Opcodes.IADD));
                pushKey(out, keySlot, keyIsLong);
                out.add(new InsnNode(Opcodes.IMUL));
                AsmUtil.pushInt(out, 8);
                out.add(new InsnNode(Opcodes.IUSHR));
                out.add(new InsnNode(Opcodes.IXOR));
                return;
            default:
                return;
        }
    }
}
