package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.pass.impl.numberhash.Codecs;
import io.umbra.core.pass.impl.numberhash.NumberHashCodec;
import io.umbra.core.pass.impl.numberhash.SiteScanner;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.BuildRoot;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

/**
 * Rewrites {@code int}/{@code long} constant pushes through reversible codecs.
 *
 * <p>This is the port of the reference implementation's number layer: the reference binds every
 * literal to a per-block opaque predicate and restores it with an XOR, and this
 * pass keeps the "the literal in the pool is not the value" property while using
 * a codec pool that is a bijection on the whole {@code int} domain (see
 * {@link Codecs} and {@code Hashes}). A site becomes
 * {@code push encode(value)} + decoder; the decoder is a short straight-line
 * sequence that consumes and produces exactly one int.</p>
 *
 * <p><b>Order 79 - before integer encryption (80).</b> The two layers compose:
 * this pass takes a site's literal and replaces it with a different literal plus
 * a decoder, and the integer pass then encrypts whichever literals are left -
 * including the encoded ones this pass emitted, and the constants inside the
 * decoders. Encrypting a decoder constant is harmless because the integer pass
 * substitutes an exactly-equal value. Running in the other order would let the
 * integer pass consume the literals first, leaving nothing to hash, so 79 is a
 * hard requirement rather than a preference.</p>
 *
 * <p>Everything is a method-body edit behind {@link MethodGate}: copy, transform,
 * verify, commit. A method whose transformed form fails verification keeps its
 * original bytes, and a class whose transformation throws is restored from the
 * snapshot taken before the class was touched.</p>
 */
public final class NumberHashPass implements Pass {

    public static final String OPTION_ENABLED = "numberHash.enabled";
    public static final String OPTION_RATE = "numberHash.rate";
    public static final String OPTION_MAX_PER_METHOD = "numberHash.maxPerMethod";
    public static final String OPTION_CODEC = "numberHash.codec";
    public static final String OPTION_INCLUDE_LONG = "numberHash.includeLong";
    public static final String OPTION_SPILL = "numberHash.spill";
    public static final String OPTION_SLOT_BUDGET = "numberHash.slotBudget";

    /** Domain label for the per-class deterministic stream (CONTRACT §4). */
    private static final String STREAM_LABEL = "umbra.numberhash.v1";

    private static final int DEFAULT_RATE = 100;
    private static final int DEFAULT_MAX_PER_METHOD = 200;
    private static final int DEFAULT_SLOT_BUDGET = 4;
    private static final int POOL_SIZE = 4;

    @Override
    public String name() {
        return "number-hash";
    }

    @Override
    public int order() {
        return 79;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool(OPTION_ENABLED, false);
    }

    @Override
    public void run(PassContext context) {
        int rate = clamp(context.config().optionInt(OPTION_RATE, DEFAULT_RATE), 0, 100);
        int maxPerMethod = Math.max(0,
                context.config().optionInt(OPTION_MAX_PER_METHOD, DEFAULT_MAX_PER_METHOD));
        boolean includeLong = context.config().optionBool(OPTION_INCLUDE_LONG, false);
        boolean spill = context.config().optionBool(OPTION_SPILL, true);
        int slotBudget = Math.max(0,
                context.config().optionInt(OPTION_SLOT_BUDGET, DEFAULT_SLOT_BUDGET));
        String requested = context.config().option(OPTION_CODEC, Codecs.MIX);
        String codec = Codecs.canonical(requested);
        if (!codec.equalsIgnoreCase(requested.trim())) {
            context.log().warn("number-hash: unknown codec '%s', falling back to '%s'", requested, codec);
        }

        MethodGate gate = new MethodGate(context);
        Map<String, Integer> perCodec = new LinkedHashMap<String, Integer>();
        int methods = 0;
        int sites = 0;
        int longs = 0;
        int skipped = 0;
        int maxPerMethodSkipped = 0;
        int rollbacks = 0;

        for (ClassNode node : context.classes().classes().values()) {
            if (!transformable(context, node)) {
                continue;
            }
            List<MethodNode> targets = new ArrayList<MethodNode>();
            int classSites = 0;
            for (MethodNode method : node.methods) {
                if (!eligible(method)) {
                    if (method != null && method.instructions != null && method.instructions.size() > 0
                            && !method.name.startsWith("<")
                            && (method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0) {
                        // Only JSR/RET lands here: it has to stay untouched.
                        skipped++;
                    }
                    continue;
                }
                int found = SiteScanner.count(method, includeLong);
                if (found > 0) {
                    targets.add(method);
                    classSites += found;
                }
            }
            if (targets.isEmpty()) {
                continue;
            }

            Random classRandom = classStream(context, node.name);
            List<NumberHashCodec> pool = Codecs.pool(codec, classRandom, POOL_SIZE);

            List<MethodNode> snapshot = new ArrayList<MethodNode>();
            for (MethodNode method : node.methods) {
                snapshot.add(MethodGate.copy(method));
            }

            int classMethods = 0;
            int classSitesDone = 0;
            int classLongs = 0;
            int classMaxSkipped = 0;
            try {
                for (MethodNode original : targets) {
                    MethodNode work = MethodGate.copy(original);
                    MethodOutcome outcome = transformMethod(context, work, pool, classRandom, rate,
                            maxPerMethod, includeLong, spill, slotBudget);
                    if (outcome.sites == 0) {
                        skipped++;
                        continue;
                    }
                    if (!gate.verify(node, work)) {
                        skipped++;
                        context.log().debug("number-hash: verification rejected %s.%s",
                                node.name, original.name);
                        continue;
                    }
                    MethodGate.commit(original, work);
                    classMethods++;
                    classSitesDone += outcome.sites;
                    classLongs += outcome.longs;
                    classMaxSkipped += outcome.maxPerMethodSkipped;
                    for (Map.Entry<String, Integer> entry : outcome.perCodec.entrySet()) {
                        bump(perCodec, entry.getKey(), entry.getValue().intValue());
                    }
                }
            } catch (RuntimeException failure) {
                restore(node, snapshot);
                rollbacks++;
                context.stats().add("numberHash.skip.rollback", 1);
                context.log().debug("number-hash: rolled back class %s: %s", node.name, failure);
                continue;
            }

            if (classMethods == 0) {
                restore(node, snapshot);
                continue;
            }
            methods += classMethods;
            sites += classSitesDone;
            longs += classLongs;
            maxPerMethodSkipped += classMaxSkipped;
            context.log().debug("number-hash: %s -> %d methods, %d sites (%d candidate sites)",
                    node.name, Integer.valueOf(classMethods), Integer.valueOf(classSitesDone),
                    Integer.valueOf(classSites));
        }

        context.stats().add("numberHash.methods", methods);
        context.stats().add("numberHash.sites", sites);
        context.stats().add("numberHash.longs", longs);
        context.stats().add("numberHash.skipped", skipped);
        context.stats().add("numberHash.maxPerMethodSkipped", maxPerMethodSkipped);
        context.stats().text("numberHash.codec", codec);
        for (Map.Entry<String, Integer> entry : perCodec.entrySet()) {
            context.stats().add("numberHash.codec." + entry.getKey(), entry.getValue().intValue());
        }
        context.log().info("number-hash[%s]: rewrote %d sites in %d methods "
                        + "(rate=%d%%, maxPerMethod=%d, longs=%d, spill=%s, skipped=%d, rollback=%d)",
                codec, Integer.valueOf(sites), Integer.valueOf(methods), Integer.valueOf(rate),
                Integer.valueOf(maxPerMethod), Integer.valueOf(longs), Boolean.valueOf(spill),
                Integer.valueOf(skipped), Integer.valueOf(rollbacks));
    }

    private static final class MethodOutcome {
        private int sites;
        private int longs;
        private int maxPerMethodSkipped;
        private final Map<String, Integer> perCodec = new LinkedHashMap<String, Integer>();
    }

    private MethodOutcome transformMethod(PassContext context, MethodNode method,
                                          List<NumberHashCodec> pool, Random random, int rate,
                                          int maxPerMethod, boolean includeLong, boolean spill,
                                          int slotBudget) {
        MethodOutcome outcome = new MethodOutcome();
        List<SiteScanner.Site> sites = SiteScanner.collect(method, includeLong);
        int spillSlot = -1;
        int done = 0;
        for (int i = 0; i < sites.size(); i++) {
            SiteScanner.Site site = sites.get(i);
            if (maxPerMethod > 0 && done >= maxPerMethod) {
                outcome.maxPerMethodSkipped++;
                continue;
            }
            if (rate < 100 && random.nextInt(100) >= rate) {
                continue;
            }
            NumberHashCodec codec = pool.get(random.nextInt(pool.size()));
            if (spill && codec.prefersSpill()) {
                if (spillSlot < 0) {
                    spillSlot = method.maxLocals;
                    method.maxLocals = spillSlot + 1;
                }
                codec.useSpillSlot(spillSlot);
            }
            SiteScanner.splice(method, site, codec, slotBudget);
            done++;
            if (site.isLong()) {
                outcome.longs++;
            }
            Integer previous = outcome.perCodec.get(codec.name());
            outcome.perCodec.put(codec.name(),
                    Integer.valueOf(previous == null ? 1 : previous.intValue() + 1));
        }
        outcome.sites = done;
        return outcome;
    }

    private static void restore(ClassNode node, List<MethodNode> snapshot) {
        int count = Math.min(node.methods.size(), snapshot.size());
        for (int i = 0; i < count; i++) {
            MethodGate.commit(node.methods.get(i), snapshot.get(i));
        }
    }

    private static boolean transformable(PassContext context, ClassNode node) {
        if (node == null) {
            return false;
        }
        if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
            return false;
        }
        if (context.rules().skipBodyTransform(node.name)) {
            return false;
        }
        if (!context.rules().transformClass(node)) {
            return false;
        }
        if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) {
            return false;
        }
        return !"module-info".equals(node.name);
    }

    /**
     * A method is eligible when it has a body, is not a constructor or static
     * initializer (CONTRACT §2), and carries no {@code JSR}/{@code RET}.
     *
     * <p>{@code JSR}/{@code RET} is a hard exclusion: ASM cannot recompute stack
     * map frames for a subroutine, so {@link MethodGate#verify} could not prove
     * the result, and the class would be written with
     * {@code toBytesPreservingFrames} or not at all. Such a method keeps its
     * bytes; the rest of the class is still transformed.</p>
     */
    private static boolean eligible(MethodNode method) {
        if (method == null || method.instructions == null || method.instructions.size() == 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        return !AsmUtil.containsJsrOrRet(method);
    }

    private static int clamp(int value, int low, int high) {
        if (value < low) {
            return low;
        }
        return Math.min(value, high);
    }

    private static void bump(Map<String, Integer> counts, String key, int delta) {
        if (delta <= 0) {
            return;
        }
        Integer previous = counts.get(key);
        counts.put(key, Integer.valueOf(previous == null ? delta : previous.intValue() + delta));
    }

    /**
     * The deterministic per-class stream. Derived from the seed, a private domain
     * label and the class name, so this pass reproduces itself whatever the passes
     * before it happened to draw from {@code ctx.random()} (CONTRACT §4).
     */
    private static Random classStream(PassContext context, String className) {
        byte[] material = BuildRoot.derive(context.config().seed(), STREAM_LABEL);
        long domain = 0L;
        for (int i = 0; i < 8; i++) {
            domain |= (material[i] & 0xFFL) << (8 * i);
        }
        long nameHash = className == null ? 0L : className.hashCode();
        return new Random(domain ^ (nameHash * 0x9E3779B97F4A7C15L) ^ context.config().seed());
    }

    /** Lower-case view used by the CLI/GUI when printing the active codec. */
    public static String normalise(String spec) {
        return Codecs.canonical(spec == null ? null : spec.toLowerCase(Locale.ROOT));
    }
}
