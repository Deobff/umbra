package io.umbra.core.model;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

/**
 * {@link ClassWriter} that resolves common superclasses through Umbra's
 * lightweight {@link Hierarchy} instead of the tool's own class loader.
 */
public final class UmbraClassWriter extends ClassWriter {

    private final Hierarchy hierarchy;

    public UmbraClassWriter(int flags, Hierarchy hierarchy) {
        super(flags);
        this.hierarchy = hierarchy;
    }

    @Override
    protected String getCommonSuperClass(String type1, String type2) {
        return hierarchy.getCommonSuperClass(type1, type2);
    }

    /**
     * Writes the class without recomputing stack map frames: the frames already in
     * the node (for example the ones read back from the original archive) are
     * emitted as they are and only the max stack/local sizes are computed.
     *
     * <p>This is the last resort for a class whose methods are so large that ASM's
     * frame computation runs out of budget. It is valid only for a node that still
     * carries the frames of the bytecode it holds, which is exactly the
     * pre-obfuscation class.</p>
     */
    /**
     * Writes the class without computing anything: the max stack/local sizes and the
     * stack map frames already in the node are emitted verbatim.
     *
     * <p>This is the copy mode ASM itself uses for a {@code ClassReader} round trip.
     * It is valid only for a node whose bodies, maxs and frames all come from the
     * original archive - the pre-obfuscation class - and it is the only way to write
     * a method so large that ASM's frame budget gives up on it.</p>
     */
    public static byte[] toBytesWithoutComputation(ClassNode node, Hierarchy hierarchy) {
        UmbraClassWriter writer = new UmbraClassWriter(0, hierarchy);
        node.accept(writer);
        return writer.toByteArray();
    }

    public static byte[] toBytesPreservingFrames(ClassNode node, Hierarchy hierarchy) {
        UmbraClassWriter writer = new UmbraClassWriter(ClassWriter.COMPUTE_MAXS, hierarchy);
        node.accept(writer);
        return writer.toByteArray();
    }

    public static byte[] toBytes(ClassNode node, Hierarchy hierarchy) {
        try {
            UmbraClassWriter writer = new UmbraClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS, hierarchy);
            node.accept(writer);
            return writer.toByteArray();
        } catch (RuntimeException first) {
            if ((node.version & 0xFFFF) >= Opcodes.V1_6) {
                throw first;
            }
            UmbraClassWriter writer = new UmbraClassWriter(ClassWriter.COMPUTE_MAXS, hierarchy);
            node.accept(writer);
            return writer.toByteArray();
        }
    }
}
