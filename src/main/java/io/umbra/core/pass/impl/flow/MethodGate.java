package io.umbra.core.pass.impl.flow;

import io.umbra.core.api.PassContext;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;

/**
 * Transform-then-verify gate shared by control-flow passes.
 *
 * <p>A method is transformed on a deep copy ({@link #copy(MethodNode)}), the
 * resulting method is serialized as a one-method class with computed frames and
 * checked by ASM's {@link CheckClassAdapter} using the program's own class pool
 * for hierarchy resolution, and only a successful method is committed back
 * ({@link #commit(MethodNode, MethodNode)}). Any verifier or frame-computation
 * failure therefore leaves the original method byte-for-byte intact, which is
 * what guarantees that a pass can never produce an unverifiable class.</p>
 */
public final class MethodGate {

    private final PassContext context;
    private final Map<String, byte[]> serialized = new HashMap<String, byte[]>();
    private volatile String currentName = "";
    private volatile byte[] currentBytes;
    private final ClassLoader loader;

    public MethodGate(PassContext context) {
        this.context = context;
        this.loader = new ClassLoader(MethodGate.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                String internal = name.replace('.', '/');
                byte[] data;
                if (internal.equals(MethodGate.this.currentName)) {
                    data = MethodGate.this.currentBytes;
                } else {
                    data = MethodGate.this.poolBytes(internal);
                }
                if (data == null) {
                    return super.findClass(name);
                }
                return defineClass(name, data, 0, data.length);
            }
        };
    }

    /** Deep-copies a method including labels, try/catch blocks and debug nodes. */
    public static MethodNode copy(MethodNode original) {
        MethodNode copy = new MethodNode(original.access, original.name, original.desc,
                original.signature, original.exceptions == null
                        ? null : original.exceptions.toArray(new String[0]));
        Map<LabelNode, LabelNode> labels = new IdentityHashMap<LabelNode, LabelNode>();
        for (AbstractInsnNode insn = original.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode) {
                labels.put((LabelNode) insn, new LabelNode());
            }
        }
        for (AbstractInsnNode insn = original.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            AbstractInsnNode cloned = insn.clone(labels);
            if (cloned != null) {
                copy.instructions.add(cloned);
            }
        }
        if (original.tryCatchBlocks != null) {
            copy.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
            for (TryCatchBlockNode table : original.tryCatchBlocks) {
                copy.tryCatchBlocks.add(new TryCatchBlockNode(
                        labels.get(table.start), labels.get(table.end),
                        labels.get(table.handler), table.type));
            }
        }
        copy.maxStack = original.maxStack;
        copy.maxLocals = original.maxLocals;
        return copy;
    }

    /** Installs a verified transformed method into the real method node. */
    public static void commit(MethodNode target, MethodNode work) {
        target.instructions = work.instructions;
        target.tryCatchBlocks = work.tryCatchBlocks;
        target.maxStack = work.maxStack;
        target.maxLocals = work.maxLocals;
        target.localVariables = null;
        target.visibleLocalVariableAnnotations = null;
        target.invisibleLocalVariableAnnotations = null;
    }

    /**
     * Serializes a complete class the same way the engine will at write time
     * ({@code COMPUTE_FRAMES} with the program hierarchy). A pass can therefore
     * detect class-level frame-computation failures before committing and roll
     * the whole class back.
     *
     * @return true when the class serializes successfully
     */
    public boolean writes(ClassNode owner) {
        try {
            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
                @Override
                protected String getCommonSuperClass(String a, String b) {
                    return context.hierarchy().getCommonSuperClass(a, b);
                }
            };
            owner.accept(writer);
            writer.toByteArray();
            return true;
        } catch (Throwable failure) {
            context.log().debug("method-gate: class %s does not serialize after transform: %s",
                    owner.name, failure);
            return false;
        }
    }

    /**
     * @return true when the transformed method passes frame computation and
     *         ASM's type checker
     */
    public boolean verify(ClassNode owner, MethodNode method) {
        byte[] bytes;
        try {
            ClassNode mini = new ClassNode();
            mini.version = owner.version;
            mini.access = owner.access;
            mini.name = owner.name;
            mini.superName = owner.superName;
            mini.interfaces = owner.interfaces == null
                    ? null : new ArrayList<String>(owner.interfaces);
            mini.methods.add(method);
            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
                @Override
                protected String getCommonSuperClass(String a, String b) {
                    return context.hierarchy().getCommonSuperClass(a, b);
                }
            };
            mini.accept(writer);
            bytes = writer.toByteArray();
        } catch (Throwable failure) {
            context.log().debug("method-gate: frame computation failed for %s.%s: %s",
                    owner.name, method.name, failure);
            return false;
        }
        currentName = owner.name;
        currentBytes = bytes;
        StringWriter errors = new StringWriter();
        PrintWriter print = new PrintWriter(errors);
        try {
            CheckClassAdapter.verify(new ClassReader(bytes), loader, false, print);
        } catch (Throwable failure) {
            context.log().debug("method-gate: verification failed for %s.%s: %s",
                    owner.name, method.name, failure);
            return false;
        }
        String output = errors.toString();
        if (!output.isEmpty()) {
            context.log().debug("method-gate: verification rejected %s.%s: %s",
                    owner.name, method.name, output.trim());
            return false;
        }
        return true;
    }

    private byte[] poolBytes(String internal) {
        synchronized (serialized) {
            if (serialized.containsKey(internal)) {
                return serialized.get(internal);
            }
            ClassNode node = context.classes().getClass(internal);
            byte[] bytes = null;
            if (node != null) {
                try {
                    ClassWriter writer = new ClassWriter(
                            ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
                        @Override
                        protected String getCommonSuperClass(String a, String b) {
                            return context.hierarchy().getCommonSuperClass(a, b);
                        }
                    };
                    node.accept(writer);
                    bytes = writer.toByteArray();
                } catch (Throwable failure) {
                    context.log().debug("method-gate: cannot serialize %s for verification: %s",
                            internal, failure);
                    bytes = null;
                }
            }
            serialized.put(internal, bytes);
            return bytes;
        }
    }
}
