package io.umbra.core.pass.impl.opaque;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.util.Random;

/**
 * The dead block behind every guard (donor {@code Blocks.exception}).
 *
 * <p>The payload is stack-neutral: each gadget pushes what it pops, so the
 * block can be dropped anywhere the surrounding stack is legal and the verifier
 * still sees the same stack at the guard's join point. The block either falls
 * back to the real body or throws, in which case the throw is unreachable
 * because the guard that branches into it is always taken.</p>
 */
final class DeadCode {

    private static final int MIN_INSTRUCTIONS = 3;
    private static final int MAX_INSTRUCTIONS = 8;

    private DeadCode() {
    }

    static void emitBody(InsnList out, ClassState state, LabelNode body, boolean junk, boolean throwDead) {
        if (junk) {
            junk(out, state);
        }
        if (throwDead) {
            throwIllegalState(out, state);
        } else {
            out.add(new JumpInsnNode(Opcodes.GOTO, body));
        }
    }

    static void junk(InsnList out, ClassState state) {
        Random random = state.random();
        int target = MIN_INSTRUCTIONS + random.nextInt(MAX_INSTRUCTIONS - MIN_INSTRUCTIONS + 1);
        int emitted = 0;
        int gadgets = 0;
        while (emitted < target && gadgets < 4) {
            switch (random.nextInt(6)) {
                case 0:
                    AsmUtil.pushInt(out, random.nextInt());
                    out.add(new InsnNode(Opcodes.POP));
                    emitted += 2;
                    break;
                case 1:
                    AsmUtil.pushInt(out, random.nextInt());
                    AsmUtil.pushInt(out, random.nextInt());
                    out.add(new InsnNode(Opcodes.IXOR));
                    out.add(new InsnNode(Opcodes.POP));
                    emitted += 4;
                    break;
                case 2:
                    AsmUtil.pushInt(out, random.nextInt(1000));
                    AsmUtil.pushInt(out, random.nextInt(1000));
                    out.add(new InsnNode(Opcodes.IMUL));
                    out.add(new InsnNode(Opcodes.POP));
                    emitted += 4;
                    break;
                case 3:
                    AsmUtil.pushInt(out, random.nextInt(1000));
                    AsmUtil.pushInt(out, random.nextInt(1000));
                    out.add(new InsnNode(Opcodes.ISUB));
                    out.add(new InsnNode(Opcodes.POP));
                    emitted += 4;
                    break;
                case 4:
                    out.add(new InsnNode(Opcodes.ACONST_NULL));
                    out.add(new InsnNode(Opcodes.POP));
                    emitted += 2;
                    break;
                default:
                    AsmUtil.pushInt(out, random.nextInt(1000));
                    out.add(new InsnNode(Opcodes.ICONST_1));
                    out.add(new InsnNode(Opcodes.IADD));
                    out.add(new InsnNode(Opcodes.POP));
                    emitted += 4;
                    break;
            }
            gadgets++;
        }
    }

    static void throwIllegalState(InsnList out, ClassState state) {
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalStateException"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException",
                "<init>", "()V", false));
        out.add(new InsnNode(Opcodes.ATHROW));
    }
}
