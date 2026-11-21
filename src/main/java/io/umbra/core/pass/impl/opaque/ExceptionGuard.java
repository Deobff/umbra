package io.umbra.core.pass.impl.opaque;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;

/**
 * Donor {@code ExceptionRenderer}, reduced to the block that needs it: the guard
 * lives inside its own try range and the handler (which only the tampered path
 * can enter) is the dead block.
 *
 * <p>Both endings of the range route to the real body - the compare falls through
 * to the range end, and the throw is caught by the handler we just registered -
 * so no path can escape into a caller even if the state were wrong. The handler
 * frame the verifier computes is exactly the one the dead block's {@code POP}
 * expects.</p>
 *
 * <p>The handler itself is written at the end of the method ({@code deferred})
 * because ASM's frame computation cannot order a handler that sits between its
 * own protected range and the code that follows it; the same layout is what
 * {@code ExceptionObfuscationPass} uses. The dead block behind the handler always
 * jumps back to the body instead of throwing: an exception raised there would be
 * outside this range and would reach the caller.</p>
 */
public final class ExceptionGuard implements PredicateRenderer {

    @Override
    public String name() {
        return "exception";
    }

    @Override
    public void emitGuard(InsnList out, InsnList deferred, MethodNode method, ClassState state,
                          int local, int value, boolean junk, boolean throwDead) {
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        LabelNode body = new LabelNode();
        out.add(start);
        out.add(new VarInsnNode(Opcodes.ILOAD, local));
        AsmUtil.pushInt(out, value);
        out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, end));
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalStateException"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException",
                "<init>", "()V", false));
        out.add(new InsnNode(Opcodes.ATHROW));
        out.add(end);
        out.add(body);
        deferred.add(handler);
        deferred.add(new InsnNode(Opcodes.POP));
        DeadCode.emitBody(deferred, state, body, junk, false);
        if (method.tryCatchBlocks == null) {
            method.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
        }
        method.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler,
                "java/lang/IllegalStateException"));
    }
}
