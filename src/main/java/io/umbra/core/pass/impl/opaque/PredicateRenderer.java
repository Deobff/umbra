package io.umbra.core.pass.impl.opaque;

import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodNode;

/**
 * One guard shape (donor {@code InstructionRenderer}).
 *
 * <p>A guard is emitted at the head of a basic block and must be stack-neutral:
 * it is always entered with the same operand stack it leaves, and its always-true
 * comparison selects the real body while the fall-through path is a dead block.
 * Because the comparison is built from the rolling state local and the block's
 * own seed, a tampered entry (a patched jump, a reused block) makes it fail and
 * sends execution into the dead block instead.</p>
 */
public interface PredicateRenderer {

    /** Option value this shape answers to. */
    String name();

    /**
     * Appends the guard and its dead block to {@code out}, ending with the label
     * the real body starts at.
     *
     * <p>{@code deferred} collects code that has to live at the end of the method:
     * ASM's frame computation cannot order an exception handler that sits between
     * a protected range and the code after it, so the shape that needs a handler
     * appends it there and jumps back to the body label.</p>
     *
     * @param method    owning method, needed by the shape that registers a handler
     * @param value     the seed this block must be running with
     * @param junk      fill the dead block with stack-neutral garbage
     * @param throwDead end the dead block with a throw instead of a jump back
     */
    void emitGuard(InsnList out, InsnList deferred, MethodNode method, ClassState state, int local,
                   int value, boolean junk, boolean throwDead);
}
