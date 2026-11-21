package io.umbra.core.pass.impl.numberhash;

import org.objectweb.asm.tree.InsnList;

/**
 * One reversible int codec: a build-time encoder and a bytecode decoder.
 *
 * <p>The contract is two calls per constant site:</p>
 *
 * <pre>
 * // build time: the emitted constant
 * int encoded = codec.encode(original);
 *
 * // call site: the encoded constant has just been pushed
 * codec.emitDecode(instructions, slotBudget);
 * </pre>
 *
 * <p>{@link #decode(int)} is the build-time mirror of {@link #emitDecode}. It
 * exists so the encoder can be self-checked ({@code decode(encode(x)) == x}) and
 * so the fast pure-Java test can cover the whole domain; the emitted bytecode is
 * pinned to it separately by executing the transformed class on a real JVM.</p>
 *
 * <p>A codec is stateful only in two ways: it may own a spill local slot
 * ({@link #useSpillSlot(int)}) so long programs can keep their intermediate
 * value in a local instead of on the stack, and it may own table constants. It
 * is not bound to a site: the pass picks one codec instance per site from a
 * per-class pool, which is how {@code numberHash.codec=mix} randomises sites
 * without making the encoder depend on the site index.</p>
 */
public interface NumberHashCodec {

    /** Stable identifier used for the {@code numberHash.codec.<name>} statistic. */
    String name();

    /** Build-time encoding of the literal. */
    int encode(int value);

    /** Build-time mirror of {@link #emitDecode(InsnList, int)}. */
    int decode(int value);

    /**
     * Appends the decoder for one int that is already on the operand stack.
     *
     * @param out        instruction list to append to
     * @param slotBudget extra operand-stack slots the caller allows on top of the
     *                   incoming value; a codec whose {@link #stackNeed()} exceeds
     *                   it prefers the spill path when a slot is available
     * @return {@code out}, for chaining
     */
    InsnList emitDecode(InsnList out, int slotBudget);

    /** Extra operand-stack slots the emitted decoder needs (on top of the value). */
    int stackNeed();

    /** Whether the codec asks for a spill local when one can be allocated. */
    boolean prefersSpill();

    /**
     * Makes the codec keep its intermediate value in this local slot, or
     * {@code -1} to go back to a pure stack sequence. The pass owns the slot and
     * is responsible for raising {@code maxLocals}.
     */
    void useSpillSlot(int slot);

    /** True when {@code decode(encode(x)) == x} for every {@code int}. */
    boolean bijective();

    /** Human-readable note about the domain the codec is valid on. */
    String domain();
}
