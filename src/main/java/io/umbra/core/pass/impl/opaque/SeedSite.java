package io.umbra.core.pass.impl.opaque;

/**
 * One seed transition of the rolling state local, in the exact shape the donor
 * calls {@code NumberManager.encrypt}: {@code (outcome ^ starting) ^ <operand>},
 * where the operand is the value the rolling local holds right now, a constant
 * zero (an absolute assignment, used after an exception handler) or the
 * method-private predicate expression.
 *
 * <p>The build-time half of the pair is {@code outcome ^ starting}; the run-time
 * half is the operand. When the operand really is {@code starting} the
 * expression folds to {@code outcome}, which is what keeps the rolling state in
 * step with the block the interpreter is about to enter.</p>
 */
public final class SeedSite {

    /** The operand is {@code ILOAD local}: the rolling value of this method. */
    public static final int OPERAND_LOCAL = 0;

    /** The operand is the literal zero: an absolute {@code local = outcome}. */
    public static final int OPERAND_ZERO = 1;

    /** The operand is the method-private predicate expression of this method. */
    public static final int OPERAND_PRIVATE = 2;

    public final int outcome;
    public final int starting;
    public final int operand;
    public final int privateValue;

    public SeedSite(int outcome, int starting, int operand, int privateValue) {
        this.outcome = outcome;
        this.starting = starting;
        this.operand = operand;
        this.privateValue = privateValue;
    }

    /** The constant half of the donor's {@code (outcome ^ starting)}. */
    public int mask() {
        return outcome ^ starting;
    }
}
