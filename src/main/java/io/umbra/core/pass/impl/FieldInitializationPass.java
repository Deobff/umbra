package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
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
            InsnList init = null;
            for (Iterator<FieldNode> it = node.fields.iterator(); it.hasNext(); ) {
                FieldNode field = it.next();
                if ((field.access & Opcodes.ACC_STATIC) == 0 || field.value == null) {
                    continue;
                }
                if (context.rules().keepField(node.name, field)) {
                    continue;
                }
                if (init == null) {
                    init = clinitInstructions(node);
                }
                AsmUtil.push(init, field.value);
                init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, field.name, field.desc));
                field.value = null;
                moved++;
            }
        }
        context.stats().add("constants.moved", moved);
        context.log().info("field-initialization: moved %d static constants into <clinit>", moved);
    }

    private static InsnList clinitInstructions(ClassNode node) {
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method.instructions;
            }
        }
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 0;
        // Moved constants can be long/double values (2 stack slots).
        clinit.maxStack = 2;
        node.methods.add(clinit);
        return clinit.instructions;
    }
}
