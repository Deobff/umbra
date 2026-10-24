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
     * Serializes a class, preferring computed frames. For class file versions
     * before 1.6 (major 50) frames are optional, so an incomplete hierarchy may
     * fall back to computing max stack/locals only. For version 1.6 and newer a
     * StackMapTable is mandatory: silently dropping frames would produce an
     * unverifiable class, so the failure is propagated and {@code Jars.write}
     * reports the class name.
     *
     * @param node      class to serialize
     * @param hierarchy hierarchy resolver
     * @return class file bytes
     */
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
