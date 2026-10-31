package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.Iterator;

/**
 * Moves {@code ConstantValue} initializers of static fields into
 * {@code <clinit>}. This prevents decompilers from displaying the original
 * constant directly on the field declaration.
 */
public final class FieldInitializationPass implements Pass {

    @Override
    public String name() {
        return "field-initialization";
    }

    @Override
    public int order() {
        return 20;
    }

    @Override
    public boolean enabled(PassContext context) {
        return true;
    }

    @Override
    public void run(PassContext context) {
        int moved = 0;
        for (ClassNode node : context.classes().classes().values()) {
            if (!context.rules().transformClass(node) || context.classes().isFrozen(node.name)) {
                continue;
            }
                if (context.rules().skipBodyTransform(node.name)) {
                    continue;
                }
            if ((node.access & Opcodes.ACC_INTERFACE) != 0) {
                continue;
            }
            InsnList pending = new InsnList();
            for (Iterator<FieldNode> it = node.fields.iterator(); it.hasNext(); ) {
                FieldNode field = it.next();
                if ((field.access & Opcodes.ACC_STATIC) == 0 || field.value == null) {
                    continue;
                }
                if (context.rules().keepField(node.name, field)) {
                    continue;
                }
                AsmUtil.push(pending, field.value);
                pending.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, field.name, field.desc));
                field.value = null;
                moved++;
            }
            if (pending.size() > 0) {
                install(node, pending);
            }
        }
        context.stats().add("constants.moved", moved);
        context.log().info("field-initialization: moved %d static constants into <clinit>", moved);
    }

    /**
     * Inserts the moved assignments before the terminal {@code RETURN} of the
     * class initializer.
     *
     * <p>Appending them to the instruction list (the previous behaviour) put every
     * assignment behind that return, i.e. into dead code: the JVM never executed
     * them, so the field kept its default value instead of the original constant
     * while the {@code ConstantValue} attribute had already been removed. Classes
     * that had no initializer at all were hit hardest, because the pass creates one
     * that is nothing but a {@code RETURN}.</p>
     */
    private static void install(ClassNode node, InsnList pending) {
        MethodNode clinit = findClinit(node);
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.maxLocals = 0;
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            node.methods.add(clinit);
        }
        AbstractInsnNode last = clinit.instructions.getLast();
        if (last != null && last.getOpcode() == Opcodes.RETURN) {
            clinit.instructions.insertBefore(last, pending);
        } else {
            clinit.instructions.add(pending);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        }
        // Moved constants can be long/double values (2 stack slots).
        clinit.maxStack = Math.max(clinit.maxStack, 2);
    }

    private static MethodNode findClinit(ClassNode node) {
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method;
            }
        }
        return null;
    }
}
