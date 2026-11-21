package io.umbra.core.pass.impl.opaque;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Donor {@code ExceptionSeedLoaderRenderer}, which in 2.0.11 is byte-identical to
 * the internal loader; the shape it is named after is implemented here: the
 * helper takes the seed through a try block whose {@code ArithmeticException}
 * handler can never be entered.
 *
 * <p>{@code a / (b | 1)} cannot divide by zero for any {@code b}, and the only
 * other int division trap ({@code Integer.MIN_VALUE / -1}) does not raise
 * either, so the handler is dead code the verifier still has to model -
 * including its frame and its exception-table entry.</p>
 */
public final class ExceptionSeedLoader implements SeedLoader {

    @Override
    public String name() {
        return "exception";
    }

    @Override
    public boolean needsHelper() {
        return true;
    }

    @Override
    public void install(ClassState state) {
        InsnList body = new InsnList();
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        body.add(start);
        body.add(new VarInsnNode(Opcodes.ILOAD, 0));
        body.add(new VarInsnNode(Opcodes.ILOAD, 1));
        body.add(new InsnNode(Opcodes.ICONST_1));
        body.add(new InsnNode(Opcodes.IOR));
        body.add(new InsnNode(Opcodes.IDIV));
        body.add(new InsnNode(Opcodes.POP));
        body.add(new VarInsnNode(Opcodes.ILOAD, 0));
        body.add(new VarInsnNode(Opcodes.ILOAD, 1));
        body.add(new InsnNode(Opcodes.IXOR));
        body.add(new InsnNode(Opcodes.IRETURN));
        body.add(end);
        body.add(handler);
        body.add(new VarInsnNode(Opcodes.ASTORE, 2));
        body.add(new VarInsnNode(Opcodes.ILOAD, 0));
        body.add(new VarInsnNode(Opcodes.ILOAD, 1));
        body.add(new InsnNode(Opcodes.IXOR));
        body.add(new InsnNode(Opcodes.IRETURN));
        XorHelper.install(state, body, 3, 3,
                new TryCatchBlockNode(start, end, handler, "java/lang/ArithmeticException"));
    }

    @Override
    public void pushValue(InsnList out, ClassState state, int local, SeedSite site) {
        Operands.push(out, state, local, site);
        state.pushConstant(out, site.mask());
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, state.node().name,
                state.helperName(), "(II)I", false));
    }

    @Override
    public void materialize(ClassState state) {
    }
}
