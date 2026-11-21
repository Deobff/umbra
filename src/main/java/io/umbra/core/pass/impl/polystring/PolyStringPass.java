package io.umbra.core.pass.impl.polystring;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.BuildRoot;
import io.umbra.core.util.NameGenerator;
import io.umbra.core.util.RuntimeNames;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

/**
 * Per-class polymorphic string decryption.
 *
 * <p>Ported from aidsfuscator's decryptor family
 * ({@code Poly1StringDecryptor} / {@code Poly2StringDecryptor}) and its loop
 * carriers ({@code ForLoopStringMask} / {@code DoWhileLoopStringMask}), plus
 * the reference implementation's {@code the Caesar generator}, {@code the IV generator}
 * and the pooled {@code StringPoolerEncryptionGenerator}.</p>
 *
 * <h3>Why a separate pass</h3>
 *
 * <p>{@link io.umbra.core.pass.impl.StringEncryptionPass} injects one shared
 * decryptor per archive with a fixed shape, which is the cheapest thing for a
 * signature scanner to find. The reference engines do the opposite: every class gets
 * its own decryptor with a random argument layout, a random chain of reversible
 * per-character masks, and a key that includes a hash of the <em>call site</em>
 * taken from the runtime stack trace, so the same ciphertext can only be replayed
 * from the frame it was built for.</p>
 *
 * <p>This pass therefore runs at order 69, one step before the classic string
 * pass at 70: it consumes the {@code LDC} string sites it selects and leaves the
 * rest untouched, so both layers coexist without either being modified.</p>
 */
public final class PolyStringPass implements Pass {

    private static final String LABEL = "umbra.polyStrings.v1";

    /**
     * Longest plaintext a single site may carry.
     *
     * <p>Each payload entry is emitted as one {@code LDC String}. A class-file
     * {@code CONSTANT_Utf8} entry is limited to 65535 modified-UTF-8 bytes and the
     * masked characters are mostly encoded in three bytes, so a longer literal would
     * make the whole helper unserialisable and roll the class back.</p>
     */
    private static final int MAX_PAYLOAD_CHARS = 20000;

    private static final int ROLE_INDEX = 0;
    private static final int ROLE_KEY_A = 1;
    private static final int ROLE_KEY_B = 2;
    private static final int ROLE_KEY_C = 3;

    @Override
    public String name() {
        return "poly-strings";
    }

    @Override
    public int order() {
        return 69;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool("polyStrings.enabled", false);
    }

    @Override
    public void run(PassContext context) {
        int ratio = clamp(context.config().optionInt("polyStrings.ratio", 100), 0, 100);
        int minLength = Math.max(0, context.config().optionInt("polyStrings.minLength", 0));
        int maskCount = Math.max(1, context.config().optionInt("polyStrings.masks", 0));
        boolean traceKey = context.config().optionBool("polyStrings.traceKey", true);
        String loopMode = context.config().option("polyStrings.loop", "mix").toLowerCase(Locale.ROOT);
        StringCodec codec = StringCodec.parse(context.config().option("polyStrings.codec", "mask"),
                StringCodec.MASK);
        if (codec == StringCodec.POOL) {
            traceKey = false;
        }

        int classes = 0;
        int methods = 0;
        int sites = 0;
        int forLoops = 0;
        int doWhileLoops = 0;
        int skippedEmpty = 0;
        int skippedRatio = 0;
        int skippedRule = 0;
        int skippedShort = 0;
        int skippedLong = 0;
        int rollback = 0;
        Map<String, Integer> maskLabels = new LinkedHashMap<String, Integer>();
        MethodGate gate = new MethodGate(context);

        List<ClassNode> candidates = new ArrayList<ClassNode>(context.classes().classes().values());
        for (ClassNode node : candidates) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
            if (context.rules().skipBodyTransform(node.name)
                    || !context.rules().transformClass(node)) {
                skippedRule++;
                continue;
            }
            if ("module-info".equals(node.name)
                    || (node.access & (Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) {
                continue;
            }
            Random classRandom = classStream(context, node.name);
            List<Site> classSites = new ArrayList<Site>();
            Map<String, List<Site>> byMethod = new LinkedHashMap<String, List<Site>>();
            for (MethodNode method : node.methods) {
                if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0
                        || method.instructions == null || method.instructions.size() == 0) {
                    continue;
                }
                List<Site> methodSites = new ArrayList<Site>();
                for (AbstractInsnNode insn = method.instructions.getFirst();
                     insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof LdcInsnNode)) {
                        continue;
                    }
                    Object constant = ((LdcInsnNode) insn).cst;
                    if (!(constant instanceof String)) {
                        continue;
                    }
                    String value = (String) constant;
                    if (value.length() < minLength) {
                        skippedShort++;
                        continue;
                    }
                    // A payload entry becomes one LDC String constant; a CONSTANT_Utf8
                    // entry is capped at 65535 modified-UTF-8 bytes, and the masked
                    // characters are mostly three bytes wide.
                    if (value.length() > MAX_PAYLOAD_CHARS) {
                        skippedLong++;
                        continue;
                    }
                    if (ratio < 100 && classRandom.nextInt(100) >= ratio) {
                        skippedRatio++;
                        continue;
                    }
                    Site site = new Site(method, (LdcInsnNode) insn, value);
                    classSites.add(site);
                    methodSites.add(site);
                }
                if (!methodSites.isEmpty()) {
                    byMethod.put(methodKey(method), methodSites);
                }
            }
            if (classSites.isEmpty()) {
                continue;
            }

            Plan plan = new Plan(node.name, classSites, classRandom, maskCount, codec, traceKey,
                    loopMode);
            ClassNode helper = buildHelper(context, plan, classRandom);
            if (!usable(helper)) {
                rollback++;
                context.log().debug("poly-strings: generated decoder for %s failed verification; "
                        + "the class keeps its plain constants", node.name);
                continue;
            }
            context.classes().addGenerated(helper);

            int committed = 0;
            List<MethodNode> saved = new ArrayList<MethodNode>();
            for (MethodNode method : node.methods) {
                saved.add(MethodGate.copy(method));
            }
            int classSitesDone = 0;
            for (MethodNode method : node.methods) {
                List<Site> methodSites = byMethod.get(methodKey(method));
                if (methodSites == null) {
                    continue;
                }
                MethodNode work = MethodGate.copy(method);
                int[] replaced = new int[1];
                if (!rewrite(context, plan, work, methodSites, replaced)) {
                    continue;
                }
                if (!gate.verify(node, work)) {
                    context.log().debug("poly-strings: verification rejected %s.%s",
                            node.name, method.name);
                    continue;
                }
                MethodGate.commit(method, work);
                committed++;
                classSitesDone += replaced[0];
            }
            if (committed == 0) {
                for (int i = 0; i < node.methods.size(); i++) {
                    MethodGate.commit(node.methods.get(i), saved.get(i));
                }
                context.classes().removeClass(helper.name);
                rollback++;
                continue;
            }
            classes++;
            methods += committed;
            sites += classSitesDone;
            if (plan.doWhile) {
                doWhileLoops++;
            } else {
                forLoops++;
            }
            Integer current = maskLabels.get(plan.chain.describe());
            maskLabels.put(plan.chain.describe(),
                    Integer.valueOf(current == null ? 1 : current.intValue() + 1));
            if (plan.sawEmpty) {
                skippedEmpty += plan.emptyCount;
            }
        }

        context.stats().add("polyStrings.classes", classes);
        context.stats().add("polyStrings.methods", methods);
        context.stats().add("polyStrings.sites", sites);
        context.stats().add("polyStrings.loop.for", forLoops);
        context.stats().add("polyStrings.loop.dowhile", doWhileLoops);
        context.stats().add("polyStrings.skip.empty", skippedEmpty);
        context.stats().add("polyStrings.skip.ratio", skippedRatio);
        context.stats().add("polyStrings.skip.short", skippedShort);
        context.stats().add("polyStrings.skip.long", skippedLong);
        context.stats().add("polyStrings.skip.rule", skippedRule);
        context.stats().add("polyStrings.skip.rollback", rollback);
        context.stats().text("polyStrings.codec", codec.name().toLowerCase(Locale.ROOT));
        context.stats().text("polyStrings.loopMode", loopMode);
        context.stats().text("polyStrings.masks", maskLabels.isEmpty()
                ? "none" : maskLabels.keySet().iterator().next());
        context.stats().add("polyStrings.maskKinds", maskLabels.size());
        if (classes == 0) {
            context.log().warn("poly-strings: no class kept its polymorphic decryptor "
                    + "(sites skipped: ratio=%d short=%d rule=%d)", skippedRatio, skippedShort,
                    skippedRule);
            return;
        }
        context.log().info("poly-strings[%s/%s]: %d sites across %d classes and %d methods "
                        + "(%d for-loops, %d do-while loops, %d mask kinds, %d rollbacks)",
                codec.name().toLowerCase(Locale.ROOT), traceKey ? "trace-key" : "no-trace",
                sites, classes, methods, forLoops, doWhileLoops, maskLabels.size(), rollback);
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private static Random classStream(PassContext context, String className) {
        byte[] material = BuildRoot.derive(context.config().seed(), LABEL);
        long domain = 0L;
        for (int i = 0; i < 8; i++) {
            domain |= (material[i] & 0xFFL) << (8 * i);
        }
        long nameHash = className == null ? 0L : className.hashCode();
        return new Random(domain ^ (nameHash * 0x9E3779B97F4A7C15L) ^ context.config().seed());
    }

    /** One string constant of the target class and how it is encoded. */
    private static final class Site {
        final MethodNode method;
        final LdcInsnNode insn;
        final String plaintext;
        int index = -1;
        int keyA;
        int keyB;
        int keyC;
        int trace;
        char[] payload;

        Site(MethodNode method, LdcInsnNode insn, String plaintext) {
            this.method = method;
            this.insn = insn;
            this.plaintext = plaintext;
        }
    }

    /** Everything the helper class needs for one target class. */
    private static final class Plan {
        final String owner;
        final List<Site> sites;
        final MaskChain chain;
        final StringCodec codec;
        final boolean trace;
        final boolean doWhile;
        final boolean[] longArg = new boolean[4];
        final int[] order = new int[4];
        int[] traceXor;
        int idxXor;
        String poolField;
        String traceField;
        String cacheField;
        String helperName;
        String methodName;
        String methodDesc;
        boolean sawEmpty;
        int emptyCount;
        private final Map<String, Integer> perMethod = new LinkedHashMap<String, Integer>();

        Plan(String owner, List<Site> sites, Random random, int maskCount, StringCodec codec,
             boolean trace, String loopMode) {
            this.owner = owner;
            this.sites = sites;
            this.codec = codec;
            boolean anyEmpty = false;
            for (int i = 0; i < sites.size(); i++) {
                if (sites.get(i).plaintext.isEmpty()) {
                    anyEmpty = true;
                    emptyCount++;
                }
            }
            this.sawEmpty = anyEmpty;
            boolean doWhileRequested = "dowhile".equals(loopMode)
                    || ("mix".equals(loopMode) && random.nextInt(2) == 0);
            // A do-while carrier runs the body before the length test; an empty
            // string would never terminate, so it falls back to the for carrier.
            this.doWhile = doWhileRequested && !anyEmpty;
            int draw = maskCount > 0 ? maskCount : 1 + random.nextInt(4);
            this.chain = MaskChain.random(random, draw, true);
            this.trace = trace;
            for (int i = 0; i < order.length; i++) {
                order[i] = i;
            }
            // Every role takes part in the shuffle, including the index: the reference
            // reshuffles all of Poly1's arguments and lets the index be a narrow type
            // as well, so a fixed first position would be a fingerprint.
            for (int i = order.length - 1; i > 0; i--) {
                int j = random.nextInt(i + 1);
                int swap = order[i];
                order[i] = order[j];
                order[j] = swap;
            }
            for (int role = 0; role < 4; role++) {
                longArg[role] = random.nextInt(4) == 0;
            }
            traceXor = new int[] {random.nextInt()};
            idxXor = random.nextInt();
        }

        int argCount() {
            return 4;
        }

        void done(String method, int count) {
            Integer current = perMethod.get(method);
            perMethod.put(method, Integer.valueOf(current == null ? count
                    : current.intValue() + count));
        }

        int committedPerMethod(String method) {
            Integer value = perMethod.remove(method);
            return value == null ? 0 : value.intValue();
        }
    }

    private static int localSlots(Plan plan) {
        int slots = 0;
        for (int i = 0; i < plan.order.length; i++) {
            slots += plan.longArg[plan.order[i]] ? 2 : 1;
        }
        return slots;
    }

    private static ClassNode buildHelper(PassContext context, Plan plan, Random random) {
        NameGenerator names = new NameGenerator(random, "");
        String simple = "S" + names.random(10);
        ClassNode helper = new ClassNode();
        helper.version = Opcodes.V1_8;
        helper.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC;
        helper.name = RuntimeNames.path(simple);
        helper.superName = "java/lang/Object";
        helper.interfaces = new ArrayList<String>();
        plan.helperName = helper.name;

        encodeSites(plan, random);

        plan.poolField = "p" + names.random(9);
        plan.traceField = plan.trace ? "t" + names.random(9) : null;
        plan.cacheField = plan.codec == StringCodec.POOL ? "c" + names.random(9) : null;
        helper.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                plan.poolField, "[Ljava/lang/String;", null, null));
        if (plan.traceField != null) {
            helper.fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    plan.traceField, "[Ljava/lang/Object;", null, null));
        }
        if (plan.cacheField != null) {
            // The call sites live in the target class, so the cache has to be
            // reachable from there.
            helper.fields.add(new FieldNode(
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    plan.cacheField, "[Ljava/lang/String;", null, null));
        }

        helper.methods.add(clinit(plan));

        StringBuilder desc = new StringBuilder("(");
        for (int i = 0; i < plan.order.length; i++) {
            desc.append(plan.longArg[plan.order[i]] ? 'J' : 'I');
        }
        desc.append(")Ljava/lang/String;");
        plan.methodDesc = desc.toString();
        plan.methodName = "d" + names.random(11);
        helper.methods.add(decryptor(context, plan, random));

        if (plan.cacheField != null) {
            helper.methods.add(pooledWrapper(context, plan));
        }
        return helper;
    }

    private static void encodeSites(Plan plan, Random random) {
        for (int i = 0; i < plan.sites.size(); i++) {
            Site site = plan.sites.get(i);
            site.index = i;
            site.keyA = random.nextInt();
            site.keyB = random.nextInt();
            site.keyC = random.nextInt();
            site.trace = plan.trace
                    ? traceHash(plan.owner, site.method.name) ^ plan.traceXor[0]
                    : 0;
        }
    }

    private static int traceHash(String internalName, String methodName) {
        int classHash = internalName.replace('/', '.').hashCode();
        int methodHash = methodName.hashCode();
        return ((classHash ^ methodHash) >>> 16);
    }

    private static MethodNode clinit(Plan plan) {
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                "<clinit>", "()V", null, null);
        InsnList body = clinit.instructions;
        AsmUtil.pushInt(body, plan.sites.size());
        body.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"));
        body.add(new FieldInsnNode(Opcodes.PUTSTATIC, plan.helperName, plan.poolField,
                "[Ljava/lang/String;"));
        for (int i = 0; i < plan.sites.size(); i++) {
            body.add(new FieldInsnNode(Opcodes.GETSTATIC, plan.helperName, plan.poolField,
                    "[Ljava/lang/String;"));
            AsmUtil.pushInt(body, i);
            body.add(new LdcInsnNode(payload(plan, i)));
            body.add(new InsnNode(Opcodes.AASTORE));
        }
        if (plan.traceField != null) {
            AsmUtil.pushInt(body, plan.sites.size());
            body.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
            body.add(new FieldInsnNode(Opcodes.PUTSTATIC, plan.helperName, plan.traceField,
                    "[Ljava/lang/Object;"));
        }
        if (plan.cacheField != null) {
            AsmUtil.pushInt(body, plan.sites.size());
            body.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"));
            body.add(new FieldInsnNode(Opcodes.PUTSTATIC, plan.helperName, plan.cacheField,
                    "[Ljava/lang/String;"));
        }
        body.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 0;
        clinit.maxStack = 4;
        return clinit;
    }

    private static String payload(Plan plan, int index) {
        Site site = plan.sites.get(index);
        if (site.payload == null) {
            char[] chars = encodePayload(plan, site);
            // Class encryption scans its plaintext helpers for "@@" and treats a hit as
            // an unreplaced template placeholder. An encoded payload is arbitrary
            // 16-bit text, so two '@' characters can land next to each other by chance
            // and would abort the whole build. Re-key the site until the payload is
            // free of that pair; the runtime cancels keyA out, so any key works.
            int attempts = 0;
            while (containsAtPair(chars) && attempts < 64) {
                site.keyA ^= 0x5A17 + attempts;
                chars = encodePayload(plan, site);
                attempts++;
            }
            site.payload = chars;
        }
        return new String(site.payload);
    }

    private static boolean containsAtPair(char[] chars) {
        for (int i = 0; i + 1 < chars.length; i++) {
            if (chars[i] == '@' && chars[i + 1] == '@') {
                return true;
            }
        }
        return false;
    }

    private static char[] encodePayload(Plan plan, Site site) {
        char[] chars = site.plaintext.toCharArray();
        {
            for (int i = 0; i < chars.length; i++) {
                int value = chars[i];
                // The runtime applies the masks, then the codec, then the call-site
                // key pair; the payload therefore has to undo those in the reverse
                // order (the trace hash is folded in here, per site).
                value ^= site.trace ^ site.keyA;
                value = plan.codec.encode(value, i, site.keyB);
                value = plan.chain.encode(value, i, site.keyC);
                chars[i] = (char) (value & 0xFFFF);
            }
        }
        return chars;
    }

    private static MethodNode decryptor(PassContext context, Plan plan, Random random) {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                plan.methodName, plan.methodDesc, null, null);
        InsnList body = method.instructions;
        int slots = localSlots(plan);
        int[] argSlots = new int[4];
        int cursor = 0;
        for (int i = 0; i < plan.order.length; i++) {
            int role = plan.order[i];
            argSlots[role] = cursor;
            cursor += plan.longArg[role] ? 2 : 1;
        }
        int idxSlot = cursor++;
        int arrSlot = cursor++;
        int iSlot = cursor++;
        int hSlot = plan.trace ? cursor++ : -1;
        int cachedSlot = plan.trace ? cursor++ : -1;
        int elementSlot = plan.trace ? cursor++ : -1;
        int keySlot = argSlots[ROLE_KEY_C];
        method.maxLocals = cursor;

        // idx = arg(index) ^ idxXor
        loadArg(body, plan, ROLE_INDEX, argSlots[ROLE_INDEX]);
        AsmUtil.pushInt(body, plan.idxXor);
        body.add(new InsnNode(Opcodes.IXOR));
        body.add(new VarInsnNode(Opcodes.ISTORE, idxSlot));

        // arr = POOL[idx].toCharArray()
        body.add(new FieldInsnNode(Opcodes.GETSTATIC, plan.helperName, plan.poolField,
                "[Ljava/lang/String;"));
        body.add(new VarInsnNode(Opcodes.ILOAD, idxSlot));
        body.add(new InsnNode(Opcodes.AALOAD));
        body.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "toCharArray",
                "()[C", false));
        body.add(new VarInsnNode(Opcodes.ASTORE, arrSlot));

        if (plan.trace) {
            LabelNode have = new LabelNode();
            body.add(new FieldInsnNode(Opcodes.GETSTATIC, plan.helperName, plan.traceField,
                    "[Ljava/lang/Object;"));
            body.add(new VarInsnNode(Opcodes.ILOAD, idxSlot));
            body.add(new InsnNode(Opcodes.AALOAD));
            body.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/StackTraceElement;"));
            body.add(new VarInsnNode(Opcodes.ASTORE, cachedSlot));
            body.add(new VarInsnNode(Opcodes.ALOAD, cachedSlot));
            body.add(new JumpInsnNode(Opcodes.IFNONNULL, have));
            body.add(new TypeInsnNode(Opcodes.NEW, "java/lang/Throwable"));
            body.add(new InsnNode(Opcodes.DUP));
            body.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Throwable",
                    "<init>", "()V", false));
            body.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Throwable",
                    "getStackTrace", "()[Ljava/lang/StackTraceElement;", false));
            body.add(new VarInsnNode(Opcodes.ASTORE, cachedSlot));
            body.add(new FieldInsnNode(Opcodes.GETSTATIC, plan.helperName, plan.traceField,
                    "[Ljava/lang/Object;"));
            body.add(new VarInsnNode(Opcodes.ILOAD, idxSlot));
            body.add(new VarInsnNode(Opcodes.ALOAD, cachedSlot));
            body.add(new InsnNode(Opcodes.AASTORE));
            body.add(have);
            body.add(new VarInsnNode(Opcodes.ALOAD, cachedSlot));
            // getStackTrace() starts at the method that created the throwable, i.e.
            // this decryptor: [0] is the decryptor, [1] is the call site. (The
            // Throwable constructor frame is not part of the array.)
            body.add(new InsnNode(Opcodes.ICONST_1));
            body.add(new InsnNode(Opcodes.AALOAD));
            body.add(new VarInsnNode(Opcodes.ASTORE, elementSlot));
            body.add(new VarInsnNode(Opcodes.ALOAD, elementSlot));
            body.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StackTraceElement",
                    "getClassName", "()Ljava/lang/String;", false));
            body.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                    "hashCode", "()I", false));
            body.add(new VarInsnNode(Opcodes.ALOAD, elementSlot));
            body.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StackTraceElement",
                    "getMethodName", "()Ljava/lang/String;", false));
            body.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                    "hashCode", "()I", false));
            body.add(new InsnNode(Opcodes.IXOR));
            AsmUtil.pushInt(body, 16);
            body.add(new InsnNode(Opcodes.IUSHR));
            AsmUtil.pushInt(body, plan.traceXor[0]);
            body.add(new InsnNode(Opcodes.IXOR));
            body.add(new VarInsnNode(Opcodes.ISTORE, hSlot));
        }

        AsmUtil.pushInt(body, 0);
        body.add(new VarInsnNode(Opcodes.ISTORE, iSlot));

        LabelNode loop = new LabelNode();
        LabelNode exit = new LabelNode();
        if (!plan.doWhile) {
            body.add(loop);
            body.add(new VarInsnNode(Opcodes.ILOAD, iSlot));
            body.add(new VarInsnNode(Opcodes.ALOAD, arrSlot));
            body.add(new InsnNode(Opcodes.ARRAYLENGTH));
            body.add(new JumpInsnNode(Opcodes.IF_ICMPGE, exit));
        } else {
            body.add(loop);
        }

        body.add(new VarInsnNode(Opcodes.ALOAD, arrSlot));
        body.add(new VarInsnNode(Opcodes.ILOAD, iSlot));
        body.add(new VarInsnNode(Opcodes.ALOAD, arrSlot));
        body.add(new VarInsnNode(Opcodes.ILOAD, iSlot));
        body.add(new InsnNode(Opcodes.CALOAD));
        plan.chain.emit(body, iSlot, keySlot);
        plan.codec.emit(body, iSlot, argSlots[ROLE_KEY_B], plan.longArg[ROLE_KEY_B]);
        if (plan.trace) {
            body.add(new VarInsnNode(Opcodes.ILOAD, hSlot));
            body.add(new InsnNode(Opcodes.IXOR));
        }
        loadArg(body, plan, ROLE_KEY_A, argSlots[ROLE_KEY_A]);
        body.add(new InsnNode(Opcodes.IXOR));
        body.add(new InsnNode(Opcodes.I2C));
        body.add(new InsnNode(Opcodes.CASTORE));
        body.add(new org.objectweb.asm.tree.IincInsnNode(iSlot, 1));

        if (plan.doWhile) {
            body.add(new VarInsnNode(Opcodes.ILOAD, iSlot));
            body.add(new VarInsnNode(Opcodes.ALOAD, arrSlot));
            body.add(new InsnNode(Opcodes.ARRAYLENGTH));
            body.add(new JumpInsnNode(Opcodes.IF_ICMPLT, loop));
        } else {
            body.add(new JumpInsnNode(Opcodes.GOTO, loop));
        }
        body.add(exit);
        body.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        body.add(new InsnNode(Opcodes.DUP));
        body.add(new VarInsnNode(Opcodes.ALOAD, arrSlot));
        body.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>",
                "([C)V", false));
        body.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "intern",
                "()Ljava/lang/String;", false));
        body.add(new InsnNode(Opcodes.ARETURN));
        method.maxStack = 8;
        return method;
    }

    /**
     * Pooled entry point: the first call at a site runs the decoder and stores the
     * result in the class cache, later calls return the cached value, so repeated
     * evaluation of the same constant never re-runs the loop (the reference implementation's
     * {@code StringPoolerEncryptionGenerator} shape). The cache lives in the helper,
     * so no call site needs a guard of its own.
     */
    private static MethodNode pooledWrapper(PassContext context, Plan plan) {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                plan.methodName + "p", plan.methodDesc, null, null);
        InsnList body = method.instructions;
        int[] argSlots = new int[4];
        int cursor = 0;
        for (int i = 0; i < plan.order.length; i++) {
            int role = plan.order[i];
            argSlots[role] = cursor;
            cursor += plan.longArg[role] ? 2 : 1;
        }
        int idxSlot = cursor++;
        int valueSlot = cursor++;
        method.maxLocals = cursor;

        loadArg(body, plan, ROLE_INDEX, argSlots[ROLE_INDEX]);
        AsmUtil.pushInt(body, plan.idxXor);
        body.add(new InsnNode(Opcodes.IXOR));
        body.add(new VarInsnNode(Opcodes.ISTORE, idxSlot));

        LabelNode have = new LabelNode();
        body.add(new FieldInsnNode(Opcodes.GETSTATIC, plan.helperName, plan.cacheField,
                "[Ljava/lang/String;"));
        body.add(new VarInsnNode(Opcodes.ILOAD, idxSlot));
        body.add(new InsnNode(Opcodes.AALOAD));
        body.add(new VarInsnNode(Opcodes.ASTORE, valueSlot));
        body.add(new VarInsnNode(Opcodes.ALOAD, valueSlot));
        body.add(new JumpInsnNode(Opcodes.IFNONNULL, have));

        for (int i = 0; i < plan.order.length; i++) {
            int role = plan.order[i];
            pushArg(body, plan, role, argSlots[role]);
        }
        body.add(new MethodInsnNode(Opcodes.INVOKESTATIC, plan.helperName, plan.methodName,
                plan.methodDesc, false));
        body.add(new VarInsnNode(Opcodes.ASTORE, valueSlot));
        body.add(new FieldInsnNode(Opcodes.GETSTATIC, plan.helperName, plan.cacheField,
                "[Ljava/lang/String;"));
        body.add(new VarInsnNode(Opcodes.ILOAD, idxSlot));
        body.add(new VarInsnNode(Opcodes.ALOAD, valueSlot));
        body.add(new InsnNode(Opcodes.AASTORE));
        body.add(have);
        body.add(new VarInsnNode(Opcodes.ALOAD, valueSlot));
        body.add(new InsnNode(Opcodes.ARETURN));
        method.maxStack = 8;
        return method;
    }

    /** Re-pushes one declared argument unchanged (a {@code long} stays a long). */
    private static void pushArg(InsnList body, Plan plan, int role, int slot) {
        body.add(new VarInsnNode(plan.longArg[role] ? Opcodes.LLOAD : Opcodes.ILOAD, slot));
    }

    private static void loadArg(InsnList body, Plan plan, int role, int slot) {
        if (plan.longArg[role]) {
            body.add(new VarInsnNode(Opcodes.LLOAD, slot));
            body.add(new InsnNode(Opcodes.L2I));
        } else {
            body.add(new VarInsnNode(Opcodes.ILOAD, slot));
        }
    }

    private static String methodKey(MethodNode method) {
        return method.name + method.desc;
    }

    /**
     * Replaces this method's string sites in encounter order.
     *
     * <p>The work method is a deep copy, so the site instructions collected from
     * the original are different objects; the copy preserves the {@code LDC}
     * sequence, so the sites are matched positionally instead of by identity.</p>
     */
    /**
     * Defines the generated helper in a throwaway loader so the real JVM verifier
     * checks the decoder body (the transform gate only covers methods of the input
     * class, not methods this pass generates).
     */
    private static boolean usable(ClassNode helper) {
        try {
            final byte[] bytes = UmbraClassWriter.toBytes(helper, new Hierarchy());
            final String dotted = helper.name.replace('/', '.');
            final ClassLoader loader = new ClassLoader(PolyStringPass.class.getClassLoader()) {
                @Override
                protected Class<?> findClass(String name) throws ClassNotFoundException {
                    if (name.equals(dotted)) {
                        return defineClass(name, bytes, 0, bytes.length);
                    }
                    return super.findClass(name);
                }
            };
            // defineClass only loads; Class.forName(..., initialize=true) links and
            // therefore runs the real bytecode verifier over the decoder body.
            Class.forName(dotted, true, loader);
            return true;
        } catch (Throwable failure) {
            return false;
        }
    }

    private static boolean rewrite(PassContext context, Plan plan, MethodNode method,
                                   List<Site> sites, int[] replaced) {
        boolean touched = false;
        int count = 0;
        int cursor = 0;
        List<AbstractInsnNode> toRemove = new ArrayList<AbstractInsnNode>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof LdcInsnNode)
                    || !(((LdcInsnNode) insn).cst instanceof String)) {
                continue;
            }
            if (cursor >= sites.size()) {
                break;
            }
            Site site = sites.get(cursor);
            String constant = (String) ((LdcInsnNode) insn).cst;
            if (!site.plaintext.equals(constant)) {
                // A site was altered earlier in the pipeline; leave this one alone
                // rather than corrupting an unrelated constant.
                continue;
            }
            cursor++;
            InsnList replacement = new InsnList();
            for (int i = 0; i < plan.order.length; i++) {
                int role = plan.order[i];
                if (role == ROLE_INDEX) {
                    AsmUtil.pushInt(replacement, site.index ^ plan.idxXor);
                } else if (role == ROLE_KEY_A) {
                    AsmUtil.pushInt(replacement, site.keyA);
                } else if (role == ROLE_KEY_B) {
                    AsmUtil.pushInt(replacement, site.keyB);
                } else {
                    AsmUtil.pushInt(replacement, site.keyC);
                }
                if (plan.longArg[role]) {
                    replacement.add(new InsnNode(Opcodes.I2L));
                }
            }
            replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, plan.helperName,
                    plan.cacheField != null ? plan.methodName + "p" : plan.methodName,
                    plan.methodDesc, false));
            method.instructions.insertBefore(insn, replacement);
            toRemove.add(insn);
            touched = true;
            count++;
        }
        for (int i = 0; i < toRemove.size(); i++) {
            method.instructions.remove(toRemove.get(i));
        }
        replaced[0] = count;
        return touched;
    }
}