package io.umbra.core.pass.impl.integer;

import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.integer.masks.AddMask;
import io.umbra.core.pass.impl.integer.masks.SubMask;
import io.umbra.core.pass.impl.integer.masks.XorMask;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Facade the integer-constant pass integrates against.
 *
 * <p>One codec is created per class and owns one mask chain per constant site.
 * The contract is two calls per site, mirroring the donor's
 * {@code DefaultIntegerDecryptor}:</p>
 *
 * <pre>
 * // build time: store the masked value in the payload table
 * payload[i] = codec.encode(original, site);
 *
 * // call site: the payload load and the table key have already produced
 * // encode(original) on the operand stack
 * instructions.add(codec.emitDecode(site));
 * </pre>
 *
 * <p>{@link #emitDecode(int)} therefore consumes exactly one {@code int} and
 * leaves exactly one {@code int}, never touches a local and never introduces a
 * jump, so it can be appended to any int expression without changing
 * {@code maxStack} by more than two slots. This is why the call site uses
 * {@link IntMaskStack#dump()} and not the local-spilling
 * {@link IntMaskStack#dumpWithLocal(int)} (which is reserved for a standalone
 * decryptor method) nor {@link IntMaskStack#dumpWithIndex(int)} (which needs a
 * loop index in a local).</p>
 *
 * <p>Chains are drawn lazily-but-deterministically: {@link #create} eagerly
 * builds the first {@code siteCount} chains in index order from the supplied
 * stream, so the bytes do not depend on the order the pass happens to walk the
 * constant sites in. Sites beyond {@code siteCount} derive an independent stream
 * from the class seed and the site index. Two codecs made from the same
 * {@link Random} state therefore produce identical values and identical
 * instruction shapes (CONTRACT §0.6).</p>
 *
 * <p>Long constants are handled in the long domain: the same chain is lifted by
 * sign-extending each int operand, so {@code push(operand); I2L; LXOR|LADD|LSUB}
 * is the exact runtime counterpart of {@link #encodeLong(long, int)}. Only the
 * three invertible families can be lifted; a codec chain is always invertible
 * (see {@code integer.masks.noninvertible}).</p>
 */
public final class IntMaskCodec {

    /** Master switch. Default {@code false}: the layer stays opt-in. */
    public static final String OPTION_ENABLED = "integer.masks";
    /** {@code > 0} arms the layer; {@code 0} keeps it off. Default {@code 0}. */
    public static final String OPTION_COUNT = "integer.masks.count";
    /** Per-site chain length: {@code true} draws 3..7, {@code false} uses the count. */
    public static final String OPTION_RANDOM_SIZE = "integer.masks.random";
    /** Allow decode-only families in a chain (they are swapped out for encoding). */
    public static final String OPTION_NONINVERTIBLE = "integer.masks.noninvertible";

    /** Default per-site chain length range when {@link #OPTION_RANDOM_SIZE} is on. */
    public static final int DEFAULT_MIN_MASKS = 3;
    public static final int DEFAULT_MAX_MASKS = 7;

    private static final long SITE_SALT = 0x9E3779B97F4A7C15L;

    private final PassContext context;
    private final String ownerName;
    private final boolean enabled;
    private final int nominalCount;
    private final boolean randomSize;
    private final boolean allowNonInvertible;
    private final long overflowSeed;
    private final List<IntMaskStack> stacks;
    private final Map<Integer, IntMaskStack> overflow = new HashMap<Integer, IntMaskStack>();
    private final IntegerMaskStats stats = new IntegerMaskStats();

    private IntMaskCodec(PassContext context, String ownerName, boolean enabled, int nominalCount,
                         boolean randomSize, boolean allowNonInvertible, Random classRandom,
                         int siteCount) {
        this.context = context;
        this.ownerName = ownerName;
        this.enabled = enabled;
        this.nominalCount = nominalCount;
        this.randomSize = randomSize;
        this.allowNonInvertible = allowNonInvertible;
        this.stacks = new ArrayList<IntMaskStack>(enabled ? siteCount : 0);
        if (!enabled) {
            // An off codec must not touch the class stream either: otherwise
            // merely constructing it would shift every later draw and change the
            // output of a build that did not opt in (CONTRACT §0.6, opt-in).
            this.overflowSeed = 0L;
            return;
        }
        // Drawn once, before any chain, so the eager build below stays aligned
        // no matter how the caller orders its encode/emitDecode calls.
        this.overflowSeed = classRandom.nextLong();
        for (int site = 0; site < siteCount; site++) {
            this.stacks.add(build(classRandom));
        }
    }

    /**
     * Creates the codec for one class.
     *
     * @param context     run context, read for the option doubles and for logging
     * @param owner       the class being rewritten (only its name is used)
     * @param classRandom deterministic per-class stream (CONTRACT §4)
     * @param siteCount   how many constant sites the caller intends to encode
     */
    public static IntMaskCodec create(PassContext context, ClassNode owner, Random classRandom,
                                      int siteCount) {
        if (context == null) {
            throw new IllegalArgumentException("context");
        }
        if (classRandom == null) {
            throw new IllegalArgumentException("classRandom");
        }
        boolean on = context.config().optionBool(OPTION_ENABLED, false);
        int count = context.config().optionInt(OPTION_COUNT, 0);
        boolean randomSize = context.config().optionBool(OPTION_RANDOM_SIZE, true);
        boolean nonInvertible = context.config().optionBool(OPTION_NONINVERTIBLE, false);
        IntMaskCodec codec = new IntMaskCodec(context, owner == null ? null : owner.name,
                on && count > 0, Math.max(1, count), randomSize, nonInvertible, classRandom,
                Math.max(0, siteCount));
        if (codec.enabled && context.log() != null) {
            context.log().debug("int-mask: %s sites=%d chain=%s nonInvertible=%s",
                    codec.ownerName, Integer.valueOf(siteCount),
                    codec.randomSize ? (DEFAULT_MIN_MASKS + ".." + DEFAULT_MAX_MASKS)
                            : String.valueOf(codec.nominalCount),
                    Boolean.valueOf(codec.allowNonInvertible));
        }
        return codec;
    }

    private IntMaskStack build(Random random) {
        int size = randomSize
                ? DEFAULT_MIN_MASKS + random.nextInt(DEFAULT_MAX_MASKS - DEFAULT_MIN_MASKS + 1)
                : nominalCount;
        IntMaskStack chain = IntMaskStack.random(random, size, allowNonInvertible);
        if (!chain.invertible()) {
            // The encode side needs an inverse, so a decode-only draw is replaced
            // by a reversible chain of the same length instead of failing the site.
            chain = IntMaskStack.random(random, size, false);
            stats.swapped();
            if (context != null && context.log() != null) {
                context.log().debug("int-mask: %s drew a non-invertible chain, swapped it", ownerName);
            }
        }
        stats.record(chain);
        return chain;
    }

    private IntMaskStack stackFor(int site) {
        int key = Math.max(0, site);
        if (key < stacks.size()) {
            return stacks.get(key);
        }
        Integer boxed = Integer.valueOf(key);
        IntMaskStack chain = overflow.get(boxed);
        if (chain == null) {
            // Independent stream so a site beyond siteCount does not depend on
            // the order in which the caller reaches it.
            Random derived = new Random(overflowSeed * SITE_SALT + key);
            chain = build(derived);
            overflow.put(boxed, chain);
        }
        return chain;
    }

    /** Whether the layer is active: {@code integer.masks} and a positive count. */
    public boolean enabled() {
        return enabled;
    }

    /** Chain length the codec aims at, or the random range when size is drawn. */
    public int nominalCount() {
        return nominalCount;
    }

    /** Number of eagerly built chains (the {@code siteCount} passed to create). */
    public int siteCount() {
        return stacks.size();
    }

    /** The chain of one site, for logging or a standalone decryptor. */
    public IntMaskStack stack(int site) {
        return stackFor(site);
    }

    /**
     * Build-time encoding for one int site.
     *
     * @param original the constant the program must end up with
     * @param site     the site index; must be stable for this class
     * @return the value to store in the payload table
     */
    public int encode(int original, int site) {
        if (!enabled) {
            return original;
        }
        return stackFor(site).applyInverse(original);
    }

    /**
     * Build-time encoding for one long site, in the long domain.
     *
     * @param original the constant the program must end up with
     * @param site     the site index; must be stable for this class
     * @return the value to store in the payload table
     */
    public long encodeLong(long original, int site) {
        if (!enabled) {
            return original;
        }
        return inverseLong(stackFor(site), original);
    }

    /** Low 32 bits of {@link #encodeLong(long, int)}. */
    public int encodeLongLow(long original, int site) {
        return (int) encodeLong(original, site);
    }

    /** High 32 bits of {@link #encodeLong(long, int)}. */
    public int encodeLongHigh(long original, int site) {
        return (int) (encodeLong(original, site) >>> 32);
    }

    /**
     * Runtime decode for one int site: the chain's instructions in apply order.
     *
     * <p>Consumes the masked {@code int} and leaves the original; no local, no
     * jump, peak depth two slots.</p>
     */
    public InsnList emitDecode(int site) {
        if (!enabled) {
            return new InsnList();
        }
        return stackFor(site).dump();
    }

    /**
     * Runtime decode for one long site: {@code push(operand); I2L; LXOR|LADD|LSUB}
     * per stage. Consumes the masked {@code long} and leaves the original.
     */
    public InsnList emitDecodeLong(int site) {
        InsnList out = new InsnList();
        if (!enabled) {
            return out;
        }
        List<IntMask<?>> masks = stackFor(site).masks();
        for (int i = 0; i < masks.size(); i++) {
            IntMask<?> mask = masks.get(i);
            AsmUtil.pushInt(out, mask.value());
            out.add(new InsnNode(Opcodes.I2L));
            out.add(new InsnNode(longOpcode(mask)));
        }
        return out;
    }

    /**
     * Tag for the per-shape statistics line: {@code "mask"}, or
     * {@code "mask+loop"} when a chain carries an index-selected key table.
     */
    public String statsKey() {
        for (int i = 0; i < stacks.size(); i++) {
            if (stacks.get(i).hasLoop()) {
                return "mask+loop";
            }
        }
        for (IntMaskStack chain : overflow.values()) {
            if (chain.hasLoop()) {
                return "mask+loop";
            }
        }
        return "mask";
    }

    /** The accumulator for this class; the pass folds or reports it. */
    public IntegerMaskStats stats() {
        return stats;
    }

    /** One log line describing a site, useful when a site misbehaves. */
    public String describeSite(int site) {
        return "site=" + site + " " + stackFor(site).describe();
    }

    private static long inverseLong(IntMaskStack chain, long value) {
        List<IntMask<?>> masks = chain.masks();
        long result = value;
        for (int i = masks.size() - 1; i >= 0; i--) {
            IntMask<?> mask = masks.get(i);
            long operand = mask.value();
            if (mask instanceof XorMask) {
                result ^= operand;
            } else if (mask instanceof AddMask) {
                result -= operand;
            } else if (mask instanceof SubMask) {
                result += operand;
            } else {
                throw new UnsupportedOperationException(
                        "long domain has no implementation for mask family (" + mask.family() + ")");
            }
        }
        return result;
    }

    private static int longOpcode(IntMask<?> mask) {
        if (mask instanceof XorMask) {
            return Opcodes.LXOR;
        }
        if (mask instanceof AddMask) {
            return Opcodes.LADD;
        }
        if (mask instanceof SubMask) {
            return Opcodes.LSUB;
        }
        throw new UnsupportedOperationException(
                "long domain has no implementation for mask family (" + mask.family() + ")");
    }
}
