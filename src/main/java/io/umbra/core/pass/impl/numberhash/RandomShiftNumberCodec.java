package io.umbra.core.pass.impl.numberhash;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Port of {@code RandomShiftNumberTransformer} as a valid codec.
 *
 * <p>The reference builds a mask by walking {@code starting} through a random chain
 * of {@code >>}, {@code <<} and {@code &} operations (0..3 rounds; the operand is
 * either a fresh byte-range constant or {@code starting} itself), then emits
 * {@code (outcome ^ firstSeed) ^ <the same chain applied to starting>}. The chain
 * cancels, leaving {@code outcome}; the {@code ^ firstSeed} is what the site
 * carries.</p>
 *
 * <p>That is exactly the shape implemented here: the <em>decoder</em> recomputes
 * {@code firstSeed} from a constant with the recorded chain and XORs it with the
 * encoded constant, and the encoder XORs the literal with the build-time
 * {@code firstSeed}. The chain itself is not required to be invertible - only
 * the final XOR is - so this codec is a bijection on the full domain and can
 * reproduce the reference's non-invertible mixer verbatim.</p>
 *
 * <p>Constants are the reference's: {@code nextInt(127) + 1} for the shift rounds,
 * {@code nextInt(254) + 1} for the AND rounds, and {@code nextInt(4)} rounds.</p>
 */
public final class RandomShiftNumberCodec implements NumberHashCodec {

    private static final int KIND_SHR = 0;
    private static final int KIND_SHL = 1;
    private static final int KIND_AND = 2;

    private final int starting;
    private final int[] kinds;
    private final int[] amounts;
    private final boolean[] fromStarting;
    private final int firstSeed;

    public RandomShiftNumberCodec(Random random) {
        this.starting = random.nextInt();
        int rounds = random.nextInt(4);
        this.kinds = new int[rounds];
        this.amounts = new int[rounds];
        this.fromStarting = new boolean[rounds];
        boolean switcher = false;
        for (int i = 0; i < rounds; i++) {
            int kind = random.nextInt(3);
            kinds[i] = kind;
            fromStarting[i] = switcher;
            if (switcher) {
                amounts[i] = starting;
            } else if (kind == KIND_AND) {
                amounts[i] = random.nextInt(254) + 1;
            } else {
                amounts[i] = random.nextInt(127) + 1;
            }
            switcher = !switcher;
        }
        this.firstSeed = fold(starting);
    }

    private int fold(int value) {
        int current = value;
        for (int i = 0; i < kinds.length; i++) {
            current = apply(current, i);
        }
        return current;
    }

    private int apply(int value, int index) {
        int amount = amounts[index];
        switch (kinds[index]) {
            case KIND_SHR:
                return value >> amount;
            case KIND_SHL:
                return value << amount;
            case KIND_AND:
            default:
                return value & amount;
        }
    }

    @Override
    public String name() {
        return "randomshift";
    }

    @Override
    public int encode(int value) {
        return value ^ firstSeed;
    }

    @Override
    public int decode(int value) {
        return value ^ firstSeed;
    }

    @Override
    public InsnList emitDecode(InsnList out, int slotBudget) {
        AsmUtil.pushInt(out, starting);
        for (int i = 0; i < kinds.length; i++) {
            AsmUtil.pushInt(out, amounts[i]);
            switch (kinds[i]) {
                case KIND_SHR:
                    out.add(new InsnNode(Opcodes.ISHR));
                    break;
                case KIND_SHL:
                    out.add(new InsnNode(Opcodes.ISHL));
                    break;
                case KIND_AND:
                default:
                    out.add(new InsnNode(Opcodes.IAND));
                    break;
            }
        }
        out.add(new InsnNode(Opcodes.IXOR));
        return out;
    }

    @Override
    public int stackNeed() {
        return 2;
    }

    @Override
    public boolean prefersSpill() {
        return false;
    }

    @Override
    public void useSpillSlot(int slot) {
        // The chain is a constant fold over two stack slots; a local would only
        // make it longer, so this codec ignores the offer.
    }

    @Override
    public boolean bijective() {
        return true;
    }

    @Override
    public String domain() {
        return Hashes.DOMAIN_FULL;
    }

    /** The recorded chain, for logging and determinism checks. */
    public String program() {
        List<String> parts = new ArrayList<String>();
        for (int i = 0; i < kinds.length; i++) {
            String op = kinds[i] == KIND_SHR ? ">>" : (kinds[i] == KIND_SHL ? "<<" : "&");
            parts.add(op + amounts[i]);
        }
        return "start=0x" + Integer.toHexString(starting)
                + " seed=0x" + Integer.toHexString(firstSeed)
                + " chain=[" + join(parts) + "]";
    }

    private static String join(List<String> parts) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append(parts.get(i));
        }
        return out.toString();
    }
}
