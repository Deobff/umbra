package io.umbra.core.pass.impl.polystring;

import org.objectweb.asm.tree.InsnList;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * An ordered stack of {@link StringMask} transforms, the
 * {@code IntPolymorphStack} equivalent for characters.
 *
 * <p>{@link #encode} walks the masks in reverse applying their inverse, which is
 * the exact contract of aidsfuscator's
 * {@code ForLoopStringMask.applyInverse}: the runtime replays the masks in
 * forward order over the stored payload, so the build has to undo them in the
 * opposite order.</p>
 */
public final class MaskChain {

    private final List<StringMask> masks = new ArrayList<StringMask>();

    private MaskChain() {
    }

    public static MaskChain random(Random random, int count, boolean allowTables) {
        MaskChain chain = new MaskChain();
        int draw = Math.max(1, count);
        for (int i = 0; i < draw; i++) {
            chain.masks.add(StringMask.random(random, allowTables));
        }
        return chain;
    }

    public static MaskChain of(StringMask... entries) {
        MaskChain chain = new MaskChain();
        for (StringMask entry : entries) {
            chain.masks.add(entry);
        }
        return chain;
    }

    public int size() {
        return masks.size();
    }

    public int encode(int value, int index, int key) {
        int current = value & 0xFFFF;
        for (int i = masks.size() - 1; i >= 0; i--) {
            current = masks.get(i).applyInverse(current, index, key);
        }
        return current & 0xFFFF;
    }

    public int decode(int value, int index, int key) {
        int current = value & 0xFFFF;
        for (int i = 0; i < masks.size(); i++) {
            current = masks.get(i).apply(current, index, key);
        }
        return current & 0xFFFF;
    }

    public void emit(InsnList out, int indexSlot, int keySlot) {
        for (int i = 0; i < masks.size(); i++) {
            masks.get(i).emit(out, indexSlot, keySlot);
        }
    }

    public String describe() {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < masks.size(); i++) {
            if (i > 0) {
                out.append('+');
            }
            out.append(masks.get(i).label());
        }
        return out.toString();
    }
}
