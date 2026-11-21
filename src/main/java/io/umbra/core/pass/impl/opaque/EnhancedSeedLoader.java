package io.umbra.core.pass.impl.opaque;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;

import java.util.Random;

/**
 * Donor {@code EnhancedStaticSeedLoaderRenderer}: the static XOR helper plus the
 * parity carrier the donor's own {@code createInternal} describes but never wires.
 *
 * <p>Two {@code private static int} fields are added to the class, one seeded
 * even and one seeded odd. Every helper call advances the odd field by
 * {@code (even + <odd step>) % 256}, which cannot change its low bit, and the
 * value expression is shaped as {@code x ^ (odd & 1) ^ (odd & 1)} so the result
 * is unchanged while the emitted code depends on a run-time field whose parity
 * is an invariant instead of a literal: the donor's parity predicate.</p>
 *
 * <p>Correctness does not depend on the invariant holding: the two field reads
 * are the same expression, so the pair cancels even on a VM that ignores the
 * constant-value attribute of the fields.</p>
 */
public final class EnhancedSeedLoader implements SeedLoader {

    private final String evenField;
    private final String oddField;
    private final int evenValue;
    private final int oddValue;
    private final int oddStep;

    public EnhancedSeedLoader(Random random, ClassState state) {
        this.evenField = state.uniqueFieldName(random, 9);
        String odd = state.uniqueFieldName(random, 9);
        while (odd.equals(evenField)) {
            odd = state.uniqueFieldName(random, 9);
        }
        this.oddField = odd;
        this.evenValue = 2 * random.nextInt(127);
        this.oddValue = 1 + 2 * random.nextInt(127);
        this.oddStep = 1 + 2 * random.nextInt(63);
    }

    @Override
    public String name() {
        return "enhanced";
    }

    @Override
    public boolean needsHelper() {
        return true;
    }

    @Override
    public void materialize(ClassState state) {
        state.addField(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                evenField, "I", null, Integer.valueOf(evenValue)));
        state.addField(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                oddField, "I", null, Integer.valueOf(oddValue)));
    }

    @Override
    public void install(ClassState state) {
        InsnList body = new InsnList();
        // odd = (even + step) % 256 ; even + odd is odd and 256 is even => the field stays odd
        body.add(new FieldInsnNode(Opcodes.GETSTATIC, state.node().name, evenField, "I"));
        AsmUtil.pushInt(body, oddStep);
        body.add(new InsnNode(Opcodes.IADD));
        AsmUtil.pushInt(body, 256);
        body.add(new InsnNode(Opcodes.IREM));
        body.add(new FieldInsnNode(Opcodes.PUTSTATIC, state.node().name, oddField, "I"));
        body.add(XorHelper.plain(state.swapped()));
        XorHelper.install(state, body, 2, 3);
    }

    @Override
    public void pushValue(InsnList out, ClassState state, int local, SeedSite site) {
        Operands.push(out, state, local, site);
        for (int i = 0; i < 2; i++) {
            out.add(new FieldInsnNode(Opcodes.GETSTATIC, state.node().name, oddField, "I"));
            out.add(new InsnNode(Opcodes.ICONST_1));
            out.add(new InsnNode(Opcodes.IAND));
            out.add(new InsnNode(Opcodes.IXOR));
        }
        state.pushConstant(out, site.mask());
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, state.node().name,
                state.helperName(), "(II)I", false));
    }
}
