package io.umbra.core.pass.impl.opaque;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodInsnNode;

/**
 * Donor {@code StaticSeedLoaderRenderer}: one {@code private static int <rnd>(int a, int b)}
 * per class whose body is {@code return a ^ b}, and every edge writes
 * {@code local = <rnd>(local, successor ^ block)}.
 *
 * <p>The class-level helper is also the only place a static analyser can find
 * the XOR at all: the call sites carry two opaque operands and no operator.</p>
 */
public final class StaticSeedLoader implements SeedLoader {

    @Override
    public String name() {
        return "static";
    }

    @Override
    public boolean needsHelper() {
        return true;
    }

    @Override
    public void install(ClassState state) {
        XorHelper.install(state, XorHelper.plain(state.swapped()), 2, 2);
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
