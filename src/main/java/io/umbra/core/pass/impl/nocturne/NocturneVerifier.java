package io.umbra.core.pass.impl.nocturne;

import io.umbra.core.api.PassContext;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * Verification gate for Nocturne.
 *
 * <p>Nocturne rewrites whole method bodies and injects shadow methods, so a bug
 * in one dispatch/shadow pair could emit an unverifiable class. Before a class
 * is accepted, its transformed form is serialized with {@code COMPUTE_FRAMES}
 * and checked by ASM's {@link CheckClassAdapter}. The checker resolves the
 * program's own reference types through a class loader backed by the current
 * {@code ClassPool}, so frame merges against input classes behave like they do
 * at engine write time. A rejected class is restored by the pass and reported
 * as a skip.</p>
 */
public final class NocturneVerifier {

    private final PassContext context;
    private final Map<String, byte[]> serialized = new HashMap<String, byte[]>();
    private volatile String currentName = "";
    private volatile byte[] currentBytes;
    private final ClassLoader loader;

    public NocturneVerifier(PassContext context) {
        this.context = context;
        this.loader = new ClassLoader(NocturneVerifier.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                String internal = name.replace('.', '/');
                byte[] data;
                if (internal.equals(NocturneVerifier.this.currentName)) {
                    data = NocturneVerifier.this.currentBytes;
                } else {
                    data = NocturneVerifier.this.poolBytes(internal);
                }
                if (data == null) {
                    return super.findClass(name);
                }
                return defineClass(name, data, 0, data.length);
            }
        };
    }

    /**
     * @return true when the transformed class serializes with computed frames
     *         and passes ASM's type checker
     */
    public boolean verifyClass(ClassNode owner) {
        byte[] bytes;
        try {
            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
                @Override
                protected String getCommonSuperClass(String a, String b) {
                    return context.hierarchy().getCommonSuperClass(a, b);
                }
            };
            owner.accept(writer);
            bytes = writer.toByteArray();
        } catch (Throwable failure) {
            if (System.getProperty("umbra.nocturne.stack") != null) {
                failure.printStackTrace();
                diagnose(owner, failure);
            }
            context.log().debug("nocturne: frame computation failed for %s: %s", owner.name, failure);
            return false;
        }
        currentName = owner.name;
        currentBytes = bytes;
        StringWriter errors = new StringWriter();
        PrintWriter print = new PrintWriter(errors);
        try {
            CheckClassAdapter.verify(new ClassReader(bytes), loader, false, print);
        } catch (Throwable failure) {
            context.log().debug("nocturne: verification failed for %s: %s", owner.name, failure);
            return false;
        }
        String output = errors.toString();
        if (!output.isEmpty()) {
            context.log().debug("nocturne: verification rejected %s: %s", owner.name, output.trim());
            return false;
        }
        return true;
    }

    /** Debug helper: finds the method whose frames cannot be computed. */
    private void diagnose(ClassNode owner, Throwable failure) {
        System.err.println("NOCTURNE CLASS FAIL " + owner.name + " -> " + failure);
        for (org.objectweb.asm.tree.MethodNode method : owner.methods) {
            ClassNode mini = new ClassNode();
            mini.version = owner.version;
            mini.access = owner.access;
            mini.name = owner.name;
            mini.superName = owner.superName;
            mini.interfaces = owner.interfaces;
            mini.methods.add(method);
            try {
                ClassWriter writer = new ClassWriter(
                        ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
                    @Override
                    protected String getCommonSuperClass(String a, String b) {
                        return context.hierarchy().getCommonSuperClass(a, b);
                    }
                };
                mini.accept(writer);
            } catch (Throwable methodFailure) {
                System.err.println("NOCTURNE METHOD FAIL " + method.name + method.desc
                        + " insns=" + method.instructions.size()
                        + " maxLocals=" + method.maxLocals
                        + " maxStack=" + method.maxStack
                        + " -> " + methodFailure);
                if (System.getProperty("umbra.nocturne.dump") != null) {
                    int index = 0;
                    for (org.objectweb.asm.tree.AbstractInsnNode insn =
                            method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                        System.err.println("  " + (index++) + ": " + describe(insn));
                    }
                }
            }
        }
    }

    private static String describe(org.objectweb.asm.tree.AbstractInsnNode insn) {
        StringBuilder text = new StringBuilder(insn.getClass().getSimpleName());
        text.append(" op=").append(insn.getOpcode());
        if (insn instanceof org.objectweb.asm.tree.VarInsnNode) {
            text.append(" var=").append(((org.objectweb.asm.tree.VarInsnNode) insn).var);
        } else if (insn instanceof org.objectweb.asm.tree.MethodInsnNode) {
            org.objectweb.asm.tree.MethodInsnNode call =
                    (org.objectweb.asm.tree.MethodInsnNode) insn;
            text.append(' ').append(call.owner).append('.').append(call.name).append(call.desc);
        } else if (insn instanceof org.objectweb.asm.tree.LdcInsnNode) {
            text.append(" cst=").append(((org.objectweb.asm.tree.LdcInsnNode) insn).cst);
        } else if (insn instanceof org.objectweb.asm.tree.TypeInsnNode) {
            text.append(" type=").append(((org.objectweb.asm.tree.TypeInsnNode) insn).desc);
        } else if (insn instanceof org.objectweb.asm.tree.JumpInsnNode) {
            text.append(" ->").append(((org.objectweb.asm.tree.JumpInsnNode) insn).label);
        } else if (insn.getClass().getSimpleName().contains("Switch")) {
            text.append(' ').append(insn);
        }
        return text.toString();
    }

    private byte[] poolBytes(String internal) {        synchronized (serialized) {
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
                    context.log().debug("nocturne: cannot serialize %s for verification: %s",
                            internal, failure);
                    bytes = null;
                }
            }
            serialized.put(internal, bytes);
            return bytes;
        }
    }
}
