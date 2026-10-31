package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * Countermeasures aimed at automated / LLM-assisted static analysis.
 *
 * <p>The pass is a JVM approximation of the ideas behind Matryoshka Wall,
 * Double Fond, Dispatch Maze and SemAder-style semantic decoys:</p>
 * <ul>
 *   <li><b>Semantic decoys</b> (Double Fond / SemAder): plausible string
 *       parsers, checksum helpers and normalizers are added to real classes.
 *       Each decoy uses one of four different shapes, has a different return
 *       type and reuses a literal that already exists in the same class, so the
 *       decoys do not cluster by structure, signature or vocabulary.</li>
 *   <li><b>Guarded call sites</b> (Dispatch Maze): real methods call a decoy
 *       behind a predicate whose seed comes from {@code System.nanoTime()}. The
 *       branch is therefore not statically foldable, and the decoys are
 *       referenced from live code instead of looking like unused leftovers.</li>
 *   <li><b>Chained decoys</b>: each decoy also calls the next one behind the
 *       same predicate, so a reference-graph walk finds a chain rather than a
 *       set of leaves.</li>
 *   <li><b>Nested forwarding walls</b> (Matryoshka): a method body is moved
 *       behind one or more private forwarding layers, so a decompiler/LLM sees
 *       a chain of methods instead of the original body.</li>
 * </ul>
 *
 * <p>Every generated member is named through the same {@link NameGenerator} and
 * dictionary the renamer uses, so decoys and wrappers are indistinguishable from
 * renamed program members. Earlier versions used semantic identifiers
 * ({@code expandRoundKey}) and fixed prefixes ({@code s$0}); in a renamed
 * artifact those stood out as the only readable names, which made the decoys
 * trivial to filter out.</p>
 *
 * <p>This raises the token/compute cost of static analysis. It is not a
 * security proof, and dynamic execution plus a human analyst can still recover
 * the logic. The pass runs after renaming and before string encryption and
 * virtualization, so generated code is still encrypted and can be virtualized.</p>
 */
public final class AntiLlmPass implements Pass {

    /** Decoy body shapes; different signatures keep the decoys from clustering. */
    private enum Shape {
        /** {@code int hash(String)}: rolling hash with a mixing table. */
        INT_HASH,
        /** {@code boolean looksLike(String)}: characteristic-bit predicate. */
        BOOL_PREDICATE,
        /** {@code long checksum(String)}: weighted character sum. */
        LONG_CHECKSUM,
        /** {@code String normalize(String)}: trim plus length cap. */
        STRING_NORMALIZE
    }

    private static final int NAME_LENGTH = 5;

    @Override
    public String name() {
        return "anti-llm";
    }

    @Override
    public int order() {
        return 55;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().antiLlm().enabled();
    }

    @Override
    public void run(PassContext context) {
        int decoys = 0;
        int callSites = 0;
        int wrapperLayers = 0;
        int seeds = 0;
        int classes = 0;
        Random random = context.random();
        UmbraConfig.RenamerOptions renamer = context.config().renamer();
        NameGenerator names = new NameGenerator(random, "", renamer.dictionary(),
                renamer.minimumNameLength());

        java.util.Map<ClassNode, String> registrySeed = new java.util.LinkedHashMap<ClassNode, String>();
        java.util.Map<ClassNode, List<String[]>> registryDecoys =
                new java.util.LinkedHashMap<ClassNode, List<String[]>>();

        for (ClassNode node : new ArrayList<ClassNode>(context.classes().classes().values())) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
            if (context.rules().skipBodyTransform(node.name)) {
                continue;
            }
            if ("module-info".equals(node.name)) {
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) {
                continue;
            }
            if (!context.rules().transformClass(node)) {
                continue;
            }

            List<MethodNode> originals = new ArrayList<MethodNode>(node.methods);
            Set<String> added = new HashSet<String>();
            boolean touched = false;

            int decoyCount = context.config().antiLlm().decoyMethodsPerClass();
            if (decoyCount > 0) {
                touched = true;
                List<String> literals = collectLiterals(node);
                List<String> decoyNames = new ArrayList<String>();
                List<String> decoyDescs = new ArrayList<String>();
                for (int i = 0; i < decoyCount; i++) {
                    Shape shape = Shape.values()[random.nextInt(Shape.values().length)];
                    String name = uniqueMethodName(node, names);
                    String desc = descriptorOf(shape);
                    String literal = literals.get(random.nextInt(literals.size()));
                    node.methods.add(createDecoy(name, shape, literal, random));
                    added.add(name);
                    decoyNames.add(name);
                    decoyDescs.add(desc);
                    decoys++;
                }

                String seedField = uniqueFieldName(node, names);
                String seedMethod = uniqueMethodName(node, names);
                node.methods.add(createSeed(seedMethod, random));
                added.add(seedMethod);
                // Anchor one visible reference in the static initializer: virtualization
                // moves the guarded call sites of ordinary methods into VM payloads, so
                // without this anchor a decoy looks unreferenced in the class file.
                MethodNode clinit = ensureClinit(node);
                insertDecoyCall(node, clinit, seedField, decoyNames.get(0), decoyDescs.get(0),
                        literals.get(random.nextInt(literals.size())), random);
                addSeedInit(node, seedField, seedMethod);
                seeds++;

                // Chain the decoys so a reference-graph walk finds live-looking code
                // instead of a set of never-called leaves.
                for (int i = 0; i + 1 < decoyNames.size(); i++) {
                    MethodNode decoy = findMethod(node, decoyNames.get(i));
                    if (decoy != null) {
                        insertDecoyCall(node, decoy, seedField, decoyNames.get(i + 1),
                                decoyDescs.get(i + 1), literals.get(random.nextInt(literals.size())),
                                random);
                    }
                }

                if (!decoyNames.isEmpty()) {
                    List<String[]> recorded = new ArrayList<String[]>();
                    for (int i = 0; i < decoyNames.size(); i++) {
                        recorded.add(new String[] {decoyNames.get(i), decoyDescs.get(i)});
                    }
                    registryDecoys.put(node, recorded);
                    registrySeed.put(node, seedField);
                }
                List<MethodNode> eligible = new ArrayList<MethodNode>();
                for (MethodNode method : originals) {
                    if (callSiteEligible(method) && !added.contains(method.name)) {
                        eligible.add(method);
                    }
                }
                int sites = Math.min(context.config().antiLlm().decoyCallSitesPerClass(),
                        Math.min(decoyNames.size(), eligible.size()));
                for (int i = 0; i < sites; i++) {
                    insertDecoyCall(node, eligible.get(i), seedField, decoyNames.get(i),
                            decoyDescs.get(i), literals.get(random.nextInt(literals.size())),
                            random);
                    callSites++;
                }
            }

            int layers = context.config().antiLlm().wrapperLayers();
            int maxWrapped = context.config().antiLlm().maxWrappedMethodsPerClass();
            if (layers > 0 && maxWrapped > 0) {
                int wrapped = 0;
                for (MethodNode method : originals) {
                    if (wrapped >= maxWrapped) {
                        break;
                    }
                    if (!wrapEligible(method) || added.contains(method.name)) {
                        continue;
                    }
                    wrap(node, method, layers, names);
                    wrapperLayers += layers;
                    wrapped++;
                    touched = true;
                }
            }
            if (touched) {
                classes++;
            }
        }

        if (registryDecoys.size() >= 2) {
            List<ClassNode> known = new ArrayList<ClassNode>(registryDecoys.keySet());
            int cross = 0;
            for (ClassNode caller : known) {
                String seed = registrySeed.get(caller);
                if (seed == null) {
                    continue;
                }
                List<MethodNode> hosts = new ArrayList<MethodNode>();
                for (MethodNode method : caller.methods) {
                    if (callSiteEligible(method)) {
                        hosts.add(method);
                    }
                }
                if (hosts.isEmpty()) {
                    continue;
                }
                Collections.shuffle(hosts, random);
                int limit = Math.min(2, hosts.size());
                for (int i = 0; i < limit; i++) {
                    ClassNode target = known.get(random.nextInt(known.size()));
                    if (target == caller || !samePackage(target.name, caller.name)) {
                        continue;
                    }
                    List<String[]> pool = registryDecoys.get(target);
                    if (pool == null || pool.isEmpty()) {
                        continue;
                    }
                    String[] decoy = pool.get(random.nextInt(pool.size()));
                    // The decoy is created private because only its own class calls
                    // it; a cross-class call site needs at least package access, and
                    // the target must be in the same package (the flattener puts
                    // every renamed class there). Skipping the promotion is what
                    // produced an intermittent IllegalAccessError at runtime: the
                    // call site is guarded by a nanoTime-seeded predicate, so the
                    // illegal instruction only linked when the guard happened to
                    // fire.
                    promoteDecoy(target, decoy[0], decoy[1]);
                    insertDecoyCall(caller, hosts.get(i), seed, target.name, decoy[0], decoy[1],
                            "", random);
                    cross++;
                }
            }
            callSites += cross;
        }

        context.stats().add("antiLlm.decoys", decoys);
        context.stats().add("antiLlm.callsites", callSites);
        context.stats().add("antiLlm.wrapperLayers", wrapperLayers);
        context.stats().add("antiLlm.seeds", seeds);
        context.stats().add("antiLlm.classes", classes);
        context.log().info("anti-llm: %d decoy methods, %d guarded call sites, %d wrapper layers across %d classes",
                decoys, callSites, wrapperLayers, classes);
    }

    private static boolean callSiteEligible(MethodNode method) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        return method.instructions != null && method.instructions.size() > 1;
    }

    private static boolean wrapEligible(MethodNode method) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE
                | Opcodes.ACC_BRIDGE | Opcodes.ACC_SYNTHETIC)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        if (method.instructions == null || method.instructions.size() < 2) {
            return false;
        }
        if (method.visibleAnnotations != null && !method.visibleAnnotations.isEmpty()) {
            return false;
        }
        if (method.invisibleAnnotations != null && !method.invisibleAnnotations.isEmpty()) {
            return false;
        }
        return method.attrs == null || method.attrs.isEmpty();
    }

    /**
     * Literals a decoy can feed its own body with.
     *
     * <p>Reusing constants that already occur in the same class keeps the decoy
     * plausible and avoids shipping a fixed decoy vocabulary: earlier versions
     * embedded strings such as {@code "AES/CBC/PKCS5Padding"}, which turned the
     * decoys themselves into a fingerprint.</p>
     */
    private static List<String> collectLiterals(ClassNode node) {
        List<String> literals = new ArrayList<String>();
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof LdcInsnNode) {
                    Object value = ((LdcInsnNode) insn).cst;
                    if (value instanceof String && !((String) value).isEmpty()
                            && ((String) value).length() <= 64) {
                        literals.add((String) value);
                    }
                }
            }
        }
        if (literals.isEmpty()) {
            literals.add("");
        }
        return literals;
    }

    private static String descriptorOf(Shape shape) {
        switch (shape) {
            case BOOL_PREDICATE:
                return "(Ljava/lang/String;)Z";
            case LONG_CHECKSUM:
                return "(Ljava/lang/String;)J";
            case STRING_NORMALIZE:
                return "(Ljava/lang/String;)Ljava/lang/String;";
            default:
                return "(Ljava/lang/String;)I";
        }
    }

    /**
     * Makes a decoy callable from another class: decoys are created private
     * because only their owner calls them, while a cross-class call site needs at
     * least package access.
     */
    private static void promoteDecoy(ClassNode target, String name, String desc) {
        for (MethodNode method : target.methods) {
            if (method.name.equals(name) && method.desc.equals(desc)) {
                method.access &= ~(Opcodes.ACC_PRIVATE | Opcodes.ACC_PROTECTED);
                return;
            }
        }
    }

    /** True when both internal names live in the same package ("" = default). */
    private static boolean samePackage(String a, String b) {
        int slashA = a.lastIndexOf('/');
        int slashB = b.lastIndexOf('/');
        String packageA = slashA < 0 ? "" : a.substring(0, slashA);
        String packageB = slashB < 0 ? "" : b.substring(0, slashB);
        return packageA.equals(packageB);
    }

    /** Adds a private decoy with one of four plausible shapes. */
    private static MethodNode createDecoy(String name, Shape shape, String literal, Random random) {
        MethodNode method = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                name, descriptorOf(shape), null, null);
        switch (shape) {
            case BOOL_PREDICATE:
                buildPredicate(method, literal, random);
                break;
            case LONG_CHECKSUM:
                buildChecksum(method, literal, random);
                break;
            case STRING_NORMALIZE:
                buildNormalize(method, literal, random);
                break;
            default:
                buildHash(method, literal, random);
                break;
        }
        return method;
    }

    /** {@code int hash(String)}: rolling hash plus a small mixing table. */
    private static void buildHash(MethodNode method, String literal, Random random) {
        InsnList code = method.instructions;
        int multiplier = oddMultiplier(random);
        AsmUtil.pushInt(code, random.nextInt());
        code.add(new VarInsnNode(Opcodes.ISTORE, 1));
        AsmUtil.pushInt(code, 0);
        code.add(new VarInsnNode(Opcodes.ISTORE, 2));

        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        code.add(loop);
        code.add(new VarInsnNode(Opcodes.ILOAD, 2));
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "length", "()I", false));
        code.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        AsmUtil.pushInt(code, multiplier);
        code.add(new InsnNode(Opcodes.IMUL));
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 2));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "charAt", "(I)C", false));
        code.add(new InsnNode(Opcodes.IADD));
        code.add(new VarInsnNode(Opcodes.ISTORE, 1));
        code.add(new IincInsnNode(2, 1));
        code.add(new JumpInsnNode(Opcodes.GOTO, loop));
        code.add(end);

        AsmUtil.pushInt(code, 8);
        code.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        code.add(new VarInsnNode(Opcodes.ASTORE, 3));
        for (int i = 0; i < 8; i++) {
            code.add(new VarInsnNode(Opcodes.ALOAD, 3));
            AsmUtil.pushInt(code, i);
            AsmUtil.pushInt(code, random.nextInt());
            code.add(new InsnNode(Opcodes.IASTORE));
        }
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        code.add(new VarInsnNode(Opcodes.ALOAD, 3));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        AsmUtil.pushInt(code, 4);
        code.add(new InsnNode(Opcodes.IUSHR));
        AsmUtil.pushInt(code, 7);
        code.add(new InsnNode(Opcodes.IAND));
        code.add(new InsnNode(Opcodes.IALOAD));
        code.add(new InsnNode(Opcodes.IXOR));
        code.add(new VarInsnNode(Opcodes.ISTORE, 1));

        semanticCue(code, literal, random);
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        code.add(new InsnNode(Opcodes.IRETURN));
        method.maxLocals = 4;
        method.maxStack = 4;
    }

    /** {@code boolean looksLike(String)}: characteristic-bit test. */
    private static void buildPredicate(MethodNode method, String literal, Random random) {
        InsnList code = method.instructions;
        int multiplier = oddMultiplier(random);
        int mask = 1 + random.nextInt(0xFFFF);
        int target = random.nextInt() & mask;
        AsmUtil.pushInt(code, 0);
        code.add(new VarInsnNode(Opcodes.ISTORE, 1));
        AsmUtil.pushInt(code, 0);
        code.add(new VarInsnNode(Opcodes.ISTORE, 2));

        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        code.add(loop);
        code.add(new VarInsnNode(Opcodes.ILOAD, 2));
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "length", "()I", false));
        code.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        AsmUtil.pushInt(code, multiplier);
        code.add(new InsnNode(Opcodes.IMUL));
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 2));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "charAt", "(I)C", false));
        code.add(new InsnNode(Opcodes.IXOR));
        code.add(new VarInsnNode(Opcodes.ISTORE, 1));
        code.add(new IincInsnNode(2, 1));
        code.add(new JumpInsnNode(Opcodes.GOTO, loop));
        code.add(end);

        semanticCue(code, literal, random);
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        AsmUtil.pushInt(code, mask);
        code.add(new InsnNode(Opcodes.IAND));
        AsmUtil.pushInt(code, target);
        LabelNode differs = new LabelNode();
        code.add(new JumpInsnNode(Opcodes.IF_ICMPNE, differs));
        code.add(new InsnNode(Opcodes.ICONST_1));
        code.add(new InsnNode(Opcodes.IRETURN));
        code.add(differs);
        code.add(new InsnNode(Opcodes.ICONST_0));
        code.add(new InsnNode(Opcodes.IRETURN));
        method.maxLocals = 3;
        method.maxStack = 4;
    }

    /** {@code long checksum(String)}: weighted character sum. */
    private static void buildChecksum(MethodNode method, String literal, Random random) {
        InsnList code = method.instructions;
        int weight = oddMultiplier(random);
        code.add(new LdcInsnNode(Long.valueOf(random.nextLong())));
        code.add(new VarInsnNode(Opcodes.LSTORE, 1));
        AsmUtil.pushInt(code, 0);
        code.add(new VarInsnNode(Opcodes.ISTORE, 3));

        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        code.add(loop);
        code.add(new VarInsnNode(Opcodes.ILOAD, 3));
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "length", "()I", false));
        code.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        code.add(new VarInsnNode(Opcodes.LLOAD, 1));
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 3));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "charAt", "(I)C", false));
        AsmUtil.pushInt(code, weight);
        code.add(new InsnNode(Opcodes.IMUL));
        code.add(new InsnNode(Opcodes.I2L));
        code.add(new InsnNode(Opcodes.LADD));
        code.add(new VarInsnNode(Opcodes.LSTORE, 1));
        code.add(new IincInsnNode(3, 1));
        code.add(new JumpInsnNode(Opcodes.GOTO, loop));
        code.add(end);

        semanticCue(code, literal, random);
        code.add(new VarInsnNode(Opcodes.LLOAD, 1));
        code.add(new InsnNode(Opcodes.LRETURN));
        method.maxLocals = 4;
        method.maxStack = 5;
    }

    /** {@code String normalize(String)}: trim plus length cap. */
    private static void buildNormalize(MethodNode method, String literal, Random random) {
        InsnList code = method.instructions;
        int cap = 4 + random.nextInt(28);
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "trim", "()Ljava/lang/String;", false));
        code.add(new VarInsnNode(Opcodes.ASTORE, 1));
        semanticCue(code, literal, random);
        LabelNode shortEnough = new LabelNode();
        code.add(new VarInsnNode(Opcodes.ALOAD, 1));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "length", "()I", false));
        AsmUtil.pushInt(code, cap);
        code.add(new JumpInsnNode(Opcodes.IF_ICMPLE, shortEnough));
        code.add(new VarInsnNode(Opcodes.ALOAD, 1));
        AsmUtil.pushInt(code, 0);
        AsmUtil.pushInt(code, cap);
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "substring", "(II)Ljava/lang/String;", false));
        code.add(new InsnNode(Opcodes.ARETURN));
        code.add(shortEnough);
        code.add(new VarInsnNode(Opcodes.ALOAD, 1));
        code.add(new InsnNode(Opcodes.ARETURN));
        method.maxLocals = 2;
        method.maxStack = 3;
    }

    /**
     * A cheap, plausible use of a literal already present in the class. Which
     * {@code String} operation is used varies so the decoys do not share one shape.
     */
    private static void semanticCue(InsnList code, String literal, Random random) {
        code.add(new LdcInsnNode(literal));
        switch (random.nextInt(3)) {
            case 0:
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                        "hashCode", "()I", false));
                code.add(new InsnNode(Opcodes.POP));
                break;
            case 1:
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                        "length", "()I", false));
                code.add(new InsnNode(Opcodes.POP));
                break;
            default:
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                        "intern", "()Ljava/lang/String;", false));
                code.add(new InsnNode(Opcodes.POP));
                break;
        }
    }

    private static int oddMultiplier(Random random) {
        int value = (random.nextInt() | 1);
        return value == 0 ? 31 : value;
    }

    /**
     * The call-site seed.
     *
     * <p>It mixes {@code System.nanoTime()}, so no static analysis can fold the
     * guarded call away: the decoy path looks reachable and must be followed. The
     * value is read once per class during initialization, so the cost is one call
     * per class and the decoy body only ever runs if the value happens to match.</p>
     */
    private static MethodNode createSeed(String name, Random random) {
        MethodNode method = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                name, "()I", null, null);
        InsnList code = method.instructions;
        int multiplier = oddMultiplier(random);
        int salt = random.nextInt();
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "nanoTime", "()J", false));
        code.add(new InsnNode(Opcodes.DUP2));
        AsmUtil.pushInt(code, 32);
        code.add(new InsnNode(Opcodes.LUSHR));
        code.add(new InsnNode(Opcodes.LXOR));
        code.add(new InsnNode(Opcodes.L2I));
        AsmUtil.pushInt(code, multiplier);
        code.add(new InsnNode(Opcodes.IMUL));
        AsmUtil.pushInt(code, salt);
        code.add(new InsnNode(Opcodes.IXOR));
        code.add(new InsnNode(Opcodes.IRETURN));
        method.maxLocals = 0;
        method.maxStack = 4;
        return method;
    }

    private static MethodNode ensureClinit(ClassNode node) {
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method;
            }
        }
        MethodNode created = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        created.instructions.add(new InsnNode(Opcodes.RETURN));
        created.maxLocals = 0;
        created.maxStack = 1;
        node.methods.add(created);
        return created;
    }

    private static void addSeedInit(ClassNode node, String fieldName, String seedMethod) {
        node.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL
                        | Opcodes.ACC_SYNTHETIC,
                fieldName, "I", null, null));

        MethodNode clinit = ensureClinit(node);
        InsnList init = new InsnList();
        init.add(new MethodInsnNode(Opcodes.INVOKESTATIC, node.name, seedMethod, "()I", false));
        init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, fieldName, "I"));
        clinit.instructions.insert(init);
        clinit.maxStack = Math.max(clinit.maxStack, 1);
    }

    /**
     * Inserts {@code if ((seed & mask) == target) decoy(literal);} at the start of
     * {@code method}. The predicate compares a runtime-derived seed against a
     * random constant, so the branch is not statically decidable.
     */
    private static void insertDecoyCall(ClassNode caller, MethodNode method, String seedField,
                                        String targetOwner, String decoyName, String decoyDesc,
                                        String literal, Random random) {
        int mask = 1 + random.nextInt(0x7FFFFF);
        int target = random.nextInt() & mask;
        LabelNode real = new LabelNode();
        InsnList prelude = new InsnList();
        prelude.add(new FieldInsnNode(Opcodes.GETSTATIC, caller.name, seedField, "I"));
        AsmUtil.pushInt(prelude, mask);
        prelude.add(new InsnNode(Opcodes.IAND));
        AsmUtil.pushInt(prelude, target);
        prelude.add(new JumpInsnNode(Opcodes.IF_ICMPNE, real));
        prelude.add(new LdcInsnNode(literal));
        prelude.add(new MethodInsnNode(Opcodes.INVOKESTATIC, targetOwner, decoyName,
                decoyDesc, false));
        prelude.add(popFor(decoyDesc));
        prelude.add(real);
        method.instructions.insert(prelude);
        method.maxStack = Math.max(method.maxStack, 3);
    }
    private static void insertDecoyCall(ClassNode owner, MethodNode method, String seedField,
                                        String decoyName, String decoyDesc, String literal,
                                        Random random) {
        int mask = 1 + random.nextInt(0x7FFFFF);
        int target = random.nextInt() & mask;
        LabelNode real = new LabelNode();
        InsnList prelude = new InsnList();
        prelude.add(new FieldInsnNode(Opcodes.GETSTATIC, owner.name, seedField, "I"));
        AsmUtil.pushInt(prelude, mask);
        prelude.add(new InsnNode(Opcodes.IAND));
        AsmUtil.pushInt(prelude, target);
        prelude.add(new JumpInsnNode(Opcodes.IF_ICMPNE, real));
        prelude.add(new LdcInsnNode(literal));
        prelude.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, decoyName,
                decoyDesc, false));
        prelude.add(popFor(decoyDesc));
        prelude.add(real);
        method.instructions.insert(prelude);
        method.maxStack = Math.max(method.maxStack, 3);
    }

    private static AbstractInsnNode popFor(String desc) {
        Type type = Type.getReturnType(desc);
        return new InsnNode(type.getSize() == 2 ? Opcodes.POP2 : Opcodes.POP);
    }

    private static MethodNode findMethod(ClassNode node, String name) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name)) {
                return method;
            }
        }
        return null;
    }

    /** Moves the body behind {@code layers} private forwarding methods. */
    private static void wrap(ClassNode node, MethodNode method, int layers, NameGenerator names) {
        MethodNode current = method;
        for (int i = 0; i < layers; i++) {
            String bodyName = uniqueMethodName(node, names);
            MethodNode body = new MethodNode(movedAccess(current.access), bodyName,
                    current.desc, current.signature,
                    current.exceptions == null ? null : current.exceptions.toArray(new String[0]));
            body.instructions = current.instructions;
            body.tryCatchBlocks = current.tryCatchBlocks;
            body.localVariables = current.localVariables;
            body.visibleLocalVariableAnnotations = current.visibleLocalVariableAnnotations;
            body.invisibleLocalVariableAnnotations = current.invisibleLocalVariableAnnotations;
            body.maxLocals = Math.max(current.maxLocals, argumentSlots(current));
            body.maxStack = current.maxStack;
            node.methods.add(body);

            current.instructions = forwarder(node, current, bodyName);
            current.tryCatchBlocks = new ArrayList<org.objectweb.asm.tree.TryCatchBlockNode>();
            current.localVariables = null;
            current.visibleLocalVariableAnnotations = null;
            current.invisibleLocalVariableAnnotations = null;
            int forwarderSlots = argumentSlots(current);
            current.maxLocals = Math.max(current.maxLocals, forwarderSlots);
            // A forwarder pushes receiver + arguments before the call and may keep
            // a 2-slot return value afterwards; never leave maxStack at 0.
            current.maxStack = forwarderSlots + 2;
            current = body;
        }
    }

    private static int movedAccess(int access) {
        int keep = access & (Opcodes.ACC_STATIC | Opcodes.ACC_STRICT | Opcodes.ACC_FINAL);
        return keep | Opcodes.ACC_PRIVATE | Opcodes.ACC_SYNTHETIC;
    }

    private static InsnList forwarder(ClassNode owner, MethodNode method, String bodyName) {
        InsnList out = new InsnList();
        boolean isStatic = (method.access & Opcodes.ACC_STATIC) != 0;
        if (!isStatic) {
            out.add(new VarInsnNode(Opcodes.ALOAD, 0));
        }
        int slot = isStatic ? 0 : 1;
        for (Type argument : Type.getArgumentTypes(method.desc)) {
            out.add(new VarInsnNode(AsmUtil.loadOpcode(argument), slot));
            slot += argument.getSize();
        }
        out.add(new MethodInsnNode(isStatic ? Opcodes.INVOKESTATIC : Opcodes.INVOKESPECIAL,
                owner.name, bodyName, method.desc, false));
        out.add(new InsnNode(AsmUtil.returnOpcode(Type.getReturnType(method.desc))));
        return out;
    }

    private static int argumentSlots(MethodNode method) {
        int slots = (method.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type argument : Type.getArgumentTypes(method.desc)) {
            slots += argument.getSize();
        }
        return slots;
    }

    /**
     * A member name from the renamer's own generator and dictionary, so generated
     * members cannot be told apart from renamed program members.
     */
    private static String uniqueMethodName(ClassNode node, NameGenerator names) {
        Set<String> existing = new HashSet<String>();
        for (MethodNode method : node.methods) {
            existing.add(method.name);
        }
        for (int attempt = 0; attempt < 10000; attempt++) {
            String candidate = names.random(NAME_LENGTH);
            if (!existing.contains(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to allocate a unique member name");
    }

    private static String uniqueFieldName(ClassNode node, NameGenerator names) {
        Set<String> existing = new HashSet<String>();
        for (FieldNode field : node.fields) {
            existing.add(field.name);
        }
        for (int attempt = 0; attempt < 10000; attempt++) {
            String candidate = names.random(NAME_LENGTH);
            if (!existing.contains(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to allocate a unique field name");
    }
}
