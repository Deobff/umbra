package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Replaces integer and long constants with {@code value ^ key} expressions.
 * The transformation is purely local and keeps stack types unchanged.
 */
public final class IntegerEncryptionPass implements Pass {

    @Override
    public String name() {
        return "integer-encryption";
    }

    @Override
    public int order() {
        return 80;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().integerEncryption().enabled();
    }

    @Override
    public void run(PassContext context) {
        boolean includeLong = context.config().integerEncryption().includeLong();
        int encrypted = 0;
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
            for (MethodNode method : node.methods) {
                encrypted += encryptMethod(context, method, includeLong);
            }
        }
        context.stats().add("constants.obfuscated", encrypted);
        context.log().info("integer-encryption: obfuscated %d constants", encrypted);
    }

    private int encryptMethod(PassContext context, MethodNode method, boolean includeLong) {
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof LdcInsnNode) {
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof Integer) {
                    int value = (Integer) constant;
                    int key = context.random().nextInt();
                    if (key == 0) {
                        key = 0x5A17;
                    }
                    InsnList replacement = new InsnList();
                    replacement.add(new LdcInsnNode(Integer.valueOf(value ^ key)));
                    replacement.add(new LdcInsnNode(Integer.valueOf(key)));
                    replacement.add(new InsnNode(Opcodes.IXOR));
                    method.instructions.insertBefore(insn, replacement);
                    method.instructions.remove(insn);
                    count++;
                } else if (includeLong && constant instanceof Long) {
                    long value = (Long) constant;
                    long key = context.random().nextLong();
                    if (key == 0L) {
                        key = 0x5A17L;
                    }
                    InsnList replacement = new InsnList();
                    replacement.add(new LdcInsnNode(Long.valueOf(value ^ key)));
                    replacement.add(new LdcInsnNode(Long.valueOf(key)));
                    replacement.add(new InsnNode(Opcodes.LXOR));
                    method.instructions.insertBefore(insn, replacement);
                    method.instructions.remove(insn);
                    count++;
                }
            }
            insn = next;
        }
        return count;
    }
}
