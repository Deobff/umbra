package io.umbra.core.pass.impl.numberhash;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * A codec assembled from a fixed program of {@link Step}s.
 *
 * <p>The program is the whole hash: the decoder emits the steps in order, the
 * encoder applies their inverses in reverse order, and the build-time mirror
 * {@link #decode(int)} walks the same steps so the two cannot drift.</p>
 *
 * <p>Two emission modes:</p>
 * <ul>
 *   <li><b>stack</b> - steps are spliced one after another on the operand stack.
 *       Compact, needs at most {@link #stackNeed()} extra slots, touches no
 *       local.</li>
 *   <li><b>spill</b> - the value is stored into a caller-provided local between
 *       steps. This is the "sequent operations over a local" shape the reference's
 *       interpreter-style hash used, and it is what keeps a long program from
 *       raising {@code maxStack} by a step-sized amount at every site while the
 *       surrounding expression already holds operands.</li>
 * </ul>
 *
 * <p>Spill is only used when the pass actually allocated a slot and the program
 * is long enough to justify it ({@link #SPILL_MIN_STEPS}); otherwise the stack
 * form is emitted, so a caller that never allocates a slot still gets correct
 * bytecode.</p>
 */
public final class ProgramCodec implements NumberHashCodec {

    /** Programs at least this long prefer a spill local over a deep stack. */
    public static final int SPILL_MIN_STEPS = 4;

    private final String name;
    private final Step[] steps;
    private final boolean bijective;
    private final String domain;
    private int spillSlot = -1;

    public ProgramCodec(String name, Step[] steps, boolean bijective, String domain) {
        if (name == null) {
            throw new IllegalArgumentException("name");
        }
        if (steps == null || steps.length == 0) {
            throw new IllegalArgumentException("steps");
        }
        this.name = name;
        this.steps = steps.clone();
        this.bijective = bijective;
        this.domain = domain;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public int encode(int value) {
        int current = value;
        for (int i = steps.length - 1; i >= 0; i--) {
            current = steps[i].invert(current);
        }
        return current;
    }

    @Override
    public int decode(int value) {
        int current = value;
        for (int i = 0; i < steps.length; i++) {
            current = steps[i].apply(current);
        }
        return current;
    }

    @Override
    public InsnList emitDecode(InsnList out, int slotBudget) {
        if (spillSlot >= 0 && (steps.length >= SPILL_MIN_STEPS || stackNeed() > slotBudget)) {
            emitSpilled(out);
        } else {
            for (int i = 0; i < steps.length; i++) {
                steps[i].emit(out);
            }
        }
        return out;
    }

    private void emitSpilled(InsnList out) {
        out.add(new VarInsnNode(Opcodes.ISTORE, spillSlot));
        for (int i = 0; i < steps.length; i++) {
            out.add(new VarInsnNode(Opcodes.ILOAD, spillSlot));
            steps[i].emit(out);
            out.add(new VarInsnNode(Opcodes.ISTORE, spillSlot));
        }
        out.add(new VarInsnNode(Opcodes.ILOAD, spillSlot));
    }

    @Override
    public int stackNeed() {
        int need = 0;
        for (int i = 0; i < steps.length; i++) {
            need = Math.max(need, steps[i].stackNeed());
        }
        return need;
    }

    @Override
    public boolean prefersSpill() {
        return steps.length >= SPILL_MIN_STEPS;
    }

    @Override
    public void useSpillSlot(int slot) {
        this.spillSlot = slot;
    }

    @Override
    public boolean bijective() {
        return bijective;
    }

    @Override
    public String domain() {
        return domain;
    }

    public int stepCount() {
        return steps.length;
    }

    /** The program, for logging and for the determinism test. */
    public String program() {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < steps.length; i++) {
            if (i > 0) {
                out.append(" ; ");
            }
            out.append(steps[i].describe());
        }
        return out.toString();
    }
}
