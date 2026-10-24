package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;

/** Adds harmless synthetic fields and methods to increase decompiler noise. */
public final class JunkMemberPass implements Pass {

    private static final String[] FIELD_DESCRIPTORS = {
            "I", "J", "F", "D", "Ljava/lang/Object;", "[B"
    };

    @Override
    public String name() {
        return "junk-members";
    }

    @Override
    public int order() {
        return 100;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().junk().enabled();
    }

    @Override
    public void run(PassContext context) {
        int methods = 0;
        int fields = 0;
        Random random = context.random();
        for (ClassNode node : context.classes().classes().values()) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
                if (context.rules().skipBodyTransform(node.name)) {
                    continue;
                }
            if (!context.rules().transformClass(node)) {
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0
                    || "module-info".equals(node.name)) {
                continue;
            }
            Set<String> names = new HashSet<String>();
            for (MethodNode method : node.methods) {
                names.add(method.name);
            }
            for (FieldNode field : node.fields) {
                names.add(field.name);
            }
            int methodCount = context.config().junk().methods();
            for (int i = 0; i < methodCount; i++) {
                String name = unique(names, "z$m");
                node.methods.add(junkMethod(name, random));
                methods++;
            }
            int fieldCount = context.config().junk().fields();
            for (int i = 0; i < fieldCount; i++) {
                String name = unique(names, "z$p");
                String desc = FIELD_DESCRIPTORS[random.nextInt(FIELD_DESCRIPTORS.length)];
                node.fields.add(new FieldNode(
                        Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                        name, desc, null, null));
                fields++;
            }
        }
        context.stats().add("junk.methods", methods);
        context.stats().add("junk.fields", fields);
        context.log().info("junk-members: added %d methods and %d fields", methods, fields);
    }

    private static MethodNode junkMethod(String name, Random random) {
        int kind = random.nextInt(5);
        int maxStack;
        int maxLocals;
        MethodNode method;
        switch (kind) {
            case 0:
                method = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                        name, "()V", null, null);
                method.instructions.add(new InsnNode(Opcodes.RETURN));
                // No operands; keep a positive bound so no generated method ever
                // reports maxStack == 0 to a downstream Analyzer.
                maxStack = 1;
                maxLocals = 0;
                break;
            case 1:
                method = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                        name, "()I", null, null);
                AsmUtil.pushInt(method.instructions, random.nextInt());
                method.instructions.add(new InsnNode(Opcodes.IRETURN));
                maxStack = 1;
                maxLocals = 0;
                break;
            case 2:
                method = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                        name, "(I)I", null, null);
                method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
                AsmUtil.pushInt(method.instructions, random.nextInt(1024) + 1);
                method.instructions.add(new InsnNode(Opcodes.IXOR));
                method.instructions.add(new InsnNode(Opcodes.IRETURN));
                maxStack = 2;
                maxLocals = 1;
                break;
            case 3:
                method = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                        name, "(J)J", null, null);
                method.instructions.add(new VarInsnNode(Opcodes.LLOAD, 0));
                method.instructions.add(new org.objectweb.asm.tree.LdcInsnNode(Long.valueOf(random.nextLong() | 1L)));
                method.instructions.add(new InsnNode(Opcodes.LXOR));
                method.instructions.add(new InsnNode(Opcodes.LRETURN));
                maxStack = 4;
                maxLocals = 2;
                break;
            default:
                method = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                        name, "(Ljava/lang/String;)Ljava/lang/String;", null, null);
                method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
                method.instructions.add(new InsnNode(Opcodes.ARETURN));
                maxStack = 1;
                maxLocals = 1;
                break;
        }
        method.maxLocals = maxLocals;
        method.maxStack = maxStack;
        return method;
    }

    private static String unique(Set<String> names, String prefix) {
        int counter = 0;
        String candidate;
        do {
            candidate = prefix + Integer.toHexString(counter++);
        } while (names.contains(candidate));
        names.add(candidate);
        return candidate;
    }
}
