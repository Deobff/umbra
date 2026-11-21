package io.umbra.core.pass.impl.opaque;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;

/**
 * Donor {@code InternalSeedLoaderRenderer}: the same XOR, inlined.
 *
 * <p>No helper is generated, so the constant half of the mask is the only
 * build-time value at the site; it is still routed through the per-class
 * runtime table so it does not show up as a literal.</p>
 */
public final class InternalSeedLoader implements SeedLoader {

    @Override
    public String name() {
        return "internal";
    }

    @Override
    public boolean needsHelper() {
        return false;
    }

    @Override
    public void install(ClassState state) {
    }

    @Override
    public void pushValue(InsnList out, ClassState state, int local, SeedSite site) {
        Operands.push(out, state, local, site);
        state.pushConstant(out, site.mask());
        out.add(new InsnNode(Opcodes.IXOR));
    }

    @Override
    public void materialize(ClassState state) {
    }
}
