package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.integer.IntMaskCodec;
import io.umbra.core.pass.impl.shape.ShapeSelector;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Encrypts {@code int}/{@code long} constants.
 *
 * <p>Two shapes are available:</p>
 *
 * <ul>
 *   <li>{@code string} (default) - the values of one class are packed into a
 *       synthetic {@code String} constant (two chars per int, four per long),
 *       XORed with a per-chunk key, and the call site is reduced to
 *       {@code invokestatic z$d<k>(index)}. The decoder reads the packed chars
 *       back and unmasks them, so no constant folding, algebraic simplification
 *       or {@code ldc}-scanning pass can recover the value: the site carries
 *       only an index and the packed data is not a number in the pool.</li>
 *   <li>{@code xor} - the legacy {@code value ^ key} form, kept for
 *       interfaces (where a mutable static field is illegal) and as an
 *       explicit downgrade.</li>
 * </ul>
 */
public final class IntegerEncryptionPass implements Pass {

    private static final int CHUNK_VALUES = 4096;

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

    /**
     * The deterministic stream every name and key of this pass is drawn from.
     *
     * <p>Keys used to come from the shared {@code ctx.random()} chain. That chain is
     * consumed by every other pass in pipeline order, so the keys silently depended
     * on how many values the passes before this one happened to draw: two runs with
     * the same seed agreed on names and structure and drifted on the integer
     * literals (measured: 23 of 557 entries, every class's chunk key). Deriving the
     * stream from the seed, a private domain label and the class name makes this
     * layer reproducible on its own, whatever the passes before it do.</p>
     */
    private static Random classStream(PassContext context, String className) {
        byte[] material = io.umbra.core.util.BuildRoot.derive(context.config().seed(),
                "umbra.integer.keys");
        long domain = 0L;
        for (int i = 0; i < 8; i++) {
            domain |= (material[i] & 0xFFL) << (8 * i);
        }
        long nameHash = className == null ? 0L : className.hashCode();
        return new Random(domain ^ (nameHash * 0x9E3779B97F4A7C15L) ^ context.config().seed());
    }

    @Override
    public void run(PassContext context) {
        boolean includeLong = context.config().integerEncryption().includeLong();
        String shape = context.config().option("integer.shape", "string").toLowerCase(java.util.Locale.ROOT);
        ShapeSelector selector = ShapeSelector.create(context);
        int encrypted = 0;
        int packedSites = 0;
        Map<String, Integer> perShape = new LinkedHashMap<String, Integer>();
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
            boolean canHostFields = (node.access
                    & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) == 0;
            Random classRandom = classStream(context, node.name);

            // Polymorphic mask chains (aidsfuscator's IntPolymorphStack). The codecs
            // are built before any payload is written so the per-site chains exist
            // in site order; a disabled codec consumes no random draws, so a build
            // that does not opt in stays byte-identical.
            Map<AbstractInsnNode, Integer> maskIds = new IdentityHashMap<AbstractInsnNode, Integer>();
            int intSites = 0;
            int longSites = 0;
            for (MethodNode method : node.methods) {
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                     insn = insn.getNext()) {
                    if (!(insn instanceof LdcInsnNode)) {
                        continue;
                    }
                    Object constant = ((LdcInsnNode) insn).cst;
                    if (constant instanceof Integer) {
                        maskIds.put(insn, Integer.valueOf(intSites++));
                    } else if (includeLong && constant instanceof Long) {
                        maskIds.put(insn, Integer.valueOf(longSites++));
                    }
                }
            }
            IntMaskCodec maskInt = IntMaskCodec.create(context, node, classRandom, intSites);
            IntMaskCodec maskLong = IntMaskCodec.create(context, node, classRandom, longSites);
            if (maskInt.enabled()) {
                context.stats().add("integer.masks.classes", 1);
            }

            if (selector != null) {
                int[] counts = encryptClassShaped(context, node, includeLong, canHostFields, selector,
                        classRandom, maskInt, maskLong, maskIds);
                encrypted += counts[0];
                packedSites += counts[1];
                maskStats(context, maskInt, maskLong);
                continue;
            }
            String chosen = shape;
            if ("random".equals(chosen)) {
                String[] pool = canHostFields
                        ? new String[] { "string", "array" }
                        : new String[] { "string" };
                chosen = pool[classRandom.nextInt(pool.length)];
            }
            if ("xor".equals(chosen) || !canHostFields) {
                int xorCount = 0;
                for (MethodNode method : node.methods) {
                    xorCount += encryptMethodXor(context, method, includeLong, classRandom,
                            maskInt, maskLong, maskIds);
                }
                encrypted += xorCount;
                bump(perShape, "xor", xorCount);
                maskStats(context, maskInt, maskLong);
                continue;
            }
            int[] counts;
            if ("array".equals(chosen)) {
                counts = encryptClassArray(context, node, includeLong, false, classRandom,
                        maskInt, maskLong, maskIds);
            } else if ("indy".equals(chosen)) {
                counts = encryptClassArray(context, node, includeLong, true, classRandom,
                        maskInt, maskLong, maskIds);
            } else if ("lookup2".equals(chosen)) {
                counts = encryptClassPacked(context, node, includeLong, classRandom,
                        maskInt, maskLong, maskIds);
                chosen = "string";
            } else {
                counts = encryptClassPacked(context, node, includeLong, classRandom,
                        maskInt, maskLong, maskIds);
                chosen = "string";
            }
            encrypted += counts[0];
            packedSites += counts[1];
            bump(perShape, chosen, counts[1]);
            maskStats(context, maskInt, maskLong);
        }
        context.stats().add("constants.obfuscated", encrypted);
        context.stats().add("integer.shape.string", packedSites);
        for (Map.Entry<String, Integer> entry : perShape.entrySet()) {
            context.stats().add("integer.shape." + entry.getKey(), entry.getValue().intValue());
        }
        if (selector != null) {
            selector.report(context.stats());
            context.log().info("integer-encryption[shaped %s]: obfuscated %d constants "
                            + "(%d per-site shapes, %d fallbacks)",
                    selector.describe(), encrypted, selector.sites(), selector.fallbacks());
            return;
        }
        context.log().info("integer-encryption[%s]: obfuscated %d constants (%d shaped)",
                shape, encrypted, packedSites);
    }

    private static void bump(Map<String, Integer> counts, String key, int delta) {
        if (delta <= 0) {
            return;
        }
        Integer old = counts.get(key);
        counts.put(key, Integer.valueOf(old == null ? delta : old.intValue() + delta));
    }

    private int[] encryptClassPacked(PassContext context, ClassNode node, boolean includeLong,
                                     Random classRandom, IntMaskCodec maskInt, IntMaskCodec maskLong,
                                     Map<AbstractInsnNode, Integer> maskIds) {
        List<Site> intSites = new ArrayList<Site>();
        List<Site> longSites = new ArrayList<Site>();
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (!(insn instanceof LdcInsnNode)) {
                    continue;
                }
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof Integer) {
                    intSites.add(new Site(insn, ((Integer) constant).intValue(), false));
                } else if (includeLong && constant instanceof Long) {
                    longSites.add(new Site(insn, ((Long) constant).longValue(), true));
                }
            }
        }
        if (intSites.isEmpty() && longSites.isEmpty()) {
            return new int[] { 0, 0 };
        }
        String base = "z$" + Integer.toHexString(classRandom.nextInt() | 1);
        List<FieldNode> fields = new ArrayList<FieldNode>();
        List<MethodNode> accessors = new ArrayList<MethodNode>();
        int packed = 0;
        packed += pack(context, node, base + "i", intSites, false, fields, accessors, classRandom,
                maskInt, maskIds);
        packed += pack(context, node, base + "j", longSites, true, fields, accessors, classRandom,
                maskLong, maskIds);
        for (FieldNode field : fields) {
            node.fields.add(0, field);
        }
        for (MethodNode accessor : accessors) {
            node.methods.add(accessor);
        }
        int total = intSites.size() + longSites.size();
        return new int[] { total, packed };
    }

    private int pack(PassContext context, ClassNode node, String base, List<Site> sites, boolean longs,
                     List<FieldNode> fields, List<MethodNode> accessors, Random classRandom,
                     IntMaskCodec codec, Map<AbstractInsnNode, Integer> maskIds) {
        if (sites.isEmpty()) {
            return 0;
        }
        Map<Long, Integer> index = new LinkedHashMap<Long, Integer>();
        List<Long> values = new ArrayList<Long>();
        for (Site site : sites) {
            Long boxed = Long.valueOf(site.value);
            if (!index.containsKey(boxed)) {
                index.put(boxed, Integer.valueOf(values.size()));
                values.add(boxed);
            }
        }
        int chunks = (values.size() + CHUNK_VALUES - 1) / CHUNK_VALUES;
        String[] fieldNames = new String[chunks];
        String[] keys = new String[chunks];
        String[] accessorNames = new String[chunks];
        int[] chunkStart = new int[chunks];
        for (int chunk = 0; chunk < chunks; chunk++) {
            int from = chunk * CHUNK_VALUES;
            int to = Math.min(values.size(), from + CHUNK_VALUES);
            chunkStart[chunk] = from;
            long key = classRandom.nextLong();
            fieldNames[chunk] = base + "s" + chunk;
            keys[chunk] = base + "k" + chunk;
            accessorNames[chunk] = base + "d" + chunk;
            StringBuilder text = new StringBuilder((to - from) * (longs ? 4 : 2));
            for (int i = from; i < to; i++) {
                if (longs) {
                    long plain = values.get(i).longValue();
                    long masked = (maskOn(codec) ? codec.encodeLong(plain, i) : plain) ^ key;
                    for (int shift = 48; shift >= 0; shift -= 16) {
                        text.append((char) ((masked >>> shift) & 0xFFFF));
                    }
                } else {
                    int plain = (int) values.get(i).longValue();
                    int masked = (maskOn(codec) ? codec.encode(plain, i) : plain) ^ (int) key;
                    text.append((char) ((masked >>> 16) & 0xFFFF));
                    text.append((char) (masked & 0xFFFF));
                }
            }
            // Neither the masked value table nor the key may live in a
            // ConstantValue attribute: both are seeded in <clinit> instead so a
            // constant-pool dump does not hand over the cipher and the key
            // side by side.
            fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                    fieldNames[chunk], "Ljava/lang/String;", null, null));
            fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                    keys[chunk], "J", null, null));
            MethodNode chunkInit = staticInit(node);
            InsnList chunkSeed = new InsnList();
            chunkSeed.add(new LdcInsnNode(text.toString()));
            chunkSeed.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, fieldNames[chunk],
                    "Ljava/lang/String;"));
            chunkSeed.add(new LdcInsnNode(Long.valueOf(key)));
            chunkSeed.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, keys[chunk], "J"));
            chunkInit.instructions.insert(chunkSeed);
            accessors.add(accessor(node, accessorNames[chunk], fieldNames[chunk], keys[chunk], longs));
        }
        int packed = 0;
        for (Site site : sites) {
            int global = index.get(Long.valueOf(site.value)).intValue();
            int chunk = global / CHUNK_VALUES;
            int local = global - chunkStart[chunk];
            int indexInsn = local;
            InsnList replacement = new InsnList();
            io.umbra.core.util.AsmUtil.pushInt(replacement, indexInsn);
            replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, node.name, accessorNames[chunk],
                    longs ? "(I)J" : "(I)I", false));
            site.maskSite = global;
            appendDecode(replacement, codec, site, longs);
            site.insn.getClass();
            MethodNode owner = ownerOf(node, site.insn);
            owner.instructions.insertBefore(site.insn, replacement);
            owner.instructions.remove(site.insn);
            packed++;
        }
        return packed;
    }

    private static MethodNode ownerOf(ClassNode node, AbstractInsnNode insn) {
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode cursor = method.instructions.getFirst(); cursor != null; cursor = cursor.getNext()) {
                if (cursor == insn) {
                    return method;
                }
            }
        }
        throw new IllegalStateException("constant site not found");
    }

    private static MethodNode accessor(ClassNode node, String name, String field, String keyField,
                                       boolean longs) {
        MethodNode method = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, longs ? "(I)J" : "(I)I", null, null);
        InsnList code = method.instructions;
        int perValue = longs ? 4 : 2;

        code.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 0));
        io.umbra.core.util.AsmUtil.pushInt(code, perValue);
        code.add(new InsnNode(Opcodes.IMUL));
        code.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ISTORE, 1));
        if (longs) {
            code.add(new org.objectweb.asm.tree.InsnNode(Opcodes.LCONST_0));
            code.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.LSTORE, 2));
            for (int i = 0; i < 4; i++) {
                code.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.LLOAD, 2));
                io.umbra.core.util.AsmUtil.pushInt(code, 16);
                code.add(new InsnNode(Opcodes.LSHL));
                code.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC, node.name, field,
                        "Ljava/lang/String;"));
                code.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 1));
                io.umbra.core.util.AsmUtil.pushInt(code, i);
                code.add(new InsnNode(Opcodes.IADD));
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C", false));
                code.add(new InsnNode(Opcodes.I2L));
                code.add(new InsnNode(Opcodes.LOR));
                code.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.LSTORE, 2));
            }
            code.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.LLOAD, 2));
            code.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC, node.name, keyField, "J"));
            code.add(new InsnNode(Opcodes.LXOR));
            code.add(new InsnNode(Opcodes.LRETURN));
            method.maxLocals = 4;
            method.maxStack = 4;
        } else {
            code.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC, node.name, field,
                    "Ljava/lang/String;"));
            code.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 1));
            code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C", false));
            io.umbra.core.util.AsmUtil.pushInt(code, 16);
            code.add(new InsnNode(Opcodes.ISHL));
            code.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC, node.name, field,
                    "Ljava/lang/String;"));
            code.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 1));
            code.add(new InsnNode(Opcodes.ICONST_1));
            code.add(new InsnNode(Opcodes.IADD));
            code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C", false));
            code.add(new InsnNode(Opcodes.IOR));
            code.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC, node.name, keyField, "J"));
            code.add(new InsnNode(Opcodes.L2I));
            code.add(new InsnNode(Opcodes.IXOR));
            code.add(new InsnNode(Opcodes.IRETURN));
            method.maxLocals = 2;
            method.maxStack = 4;
        }
        return method;
    }

    private int[] encryptClassArray(PassContext context, ClassNode node, boolean includeLong,
                                    boolean indy, Random classRandom, IntMaskCodec maskInt,
                                    IntMaskCodec maskLong, Map<AbstractInsnNode, Integer> maskIds) {
        List<Site> intSites = new ArrayList<Site>();
        List<Site> longSites = new ArrayList<Site>();
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (!(insn instanceof LdcInsnNode)) {
                    continue;
                }
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof Integer) {
                    intSites.add(new Site(insn, ((Integer) constant).intValue(), false));
                } else if (includeLong && constant instanceof Long) {
                    longSites.add(new Site(insn, ((Long) constant).longValue(), true));
                }
            }
        }
        int shaped = 0;
        shaped += emitArray(context, node, intSites, false, indy, classRandom, maskInt, maskIds);
        shaped += emitArray(context, node, longSites, true, indy, classRandom, maskLong, maskIds);
        return new int[] { intSites.size() + longSites.size(), shaped };
    }

    private int emitArray(PassContext context, ClassNode node, List<Site> sites, boolean longs,
                          boolean indy, Random classRandom, IntMaskCodec codec,
                          Map<AbstractInsnNode, Integer> maskIds) {
        if (sites.isEmpty()) {
            return 0;
        }
        String base = "z$a" + Integer.toHexString(classRandom.nextInt() | 1);
        String arrName = base + "v";
        String keyName = base + "k";
        String arrDesc = longs ? "[J" : "[I";
        String keyDesc = longs ? "J" : "I";
        int intKey = classRandom.nextInt();
        if (intKey == 0) {
            intKey = 0x5A17;
        }
        long longKey = ((long) intKey << 32) | (intKey & 0xFFFFFFFFL);
        node.fields.add(0, new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                arrName, arrDesc, null, null));
        node.fields.add(0, new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                keyName, keyDesc, null, null));
        InsnList init = new InsnList();
        if (longs) {
            init.add(new LdcInsnNode(Long.valueOf(longKey)));
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, keyName, keyDesc));
        } else {
            io.umbra.core.util.AsmUtil.pushInt(init, intKey);
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, keyName, keyDesc));
        }
        io.umbra.core.util.AsmUtil.pushInt(init, sites.size());
        init.add(new IntInsnNode(Opcodes.NEWARRAY, longs ? Opcodes.T_LONG : Opcodes.T_INT));
        init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, arrName, arrDesc));
        int index = 0;
        for (Site site : sites) {
            init.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, arrName, arrDesc));
            io.umbra.core.util.AsmUtil.pushInt(init, index);
            if (longs) {
                long plain = maskLong(codec, site, maskIds);
                init.add(new LdcInsnNode(Long.valueOf(plain ^ longKey)));
                init.add(new InsnNode(Opcodes.LASTORE));
            } else {
                int plain = maskInt(codec, site, maskIds);
                io.umbra.core.util.AsmUtil.pushInt(init, plain ^ intKey);
                init.add(new InsnNode(Opcodes.IASTORE));
            }
            index++;
        }
        staticInit(node).instructions.insert(init);
        int done = 0;
        index = 0;
        for (Site site : sites) {
            InsnList replacement = new InsnList();
            {
                replacement.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, arrName, arrDesc));
                io.umbra.core.util.AsmUtil.pushInt(replacement, index);
                replacement.add(new InsnNode(longs ? Opcodes.LALOAD : Opcodes.IALOAD));
                replacement.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, keyName, keyDesc));
                replacement.add(new InsnNode(longs ? Opcodes.LXOR : Opcodes.IXOR));
                appendDecode(replacement, codec, site, longs);
            }
            MethodNode owner = ownerOf(node, site.insn);
            owner.instructions.insertBefore(site.insn, replacement);
            owner.instructions.remove(site.insn);
            index++;
            done++;
        }
        return done;
    }

    private static MethodNode staticInit(ClassNode node) {
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name)) {
                return method;
            }
        }
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        node.methods.add(clinit);
        return clinit;
    }

    private int encryptMethodXor(PassContext context, MethodNode method, boolean includeLong,
                                 Random classRandom, IntMaskCodec maskInt, IntMaskCodec maskLong,
                                 Map<AbstractInsnNode, Integer> maskIds) {
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof LdcInsnNode) {
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof Integer) {
                    int value = (Integer) constant;
                    int key = classRandom.nextInt();
                    if (key == 0) {
                        key = 0x5A17;
                    }
                    InsnList replacement = new InsnList();
                    int plain = maskOn(maskInt)
                            ? maskInt.encode(value, siteId(maskIds, insn)) : value;
                    replacement.add(new LdcInsnNode(Integer.valueOf(plain ^ key)));
                    replacement.add(new LdcInsnNode(Integer.valueOf(key)));
                    replacement.add(new InsnNode(Opcodes.IXOR));
                    if (maskOn(maskInt)) {
                        replacement.add(maskInt.emitDecode(siteId(maskIds, insn)));
                    }
                    method.instructions.insertBefore(insn, replacement);
                    method.instructions.remove(insn);
                    count++;
                } else if (includeLong && constant instanceof Long) {
                    long value = (Long) constant;
                    long key = classRandom.nextLong();
                    if (key == 0L) {
                        key = 0x5A17L;
                    }
                    InsnList replacement = new InsnList();
                    long plain = maskOn(maskLong)
                            ? maskLong.encodeLong(value, siteId(maskIds, insn)) : value;
                    replacement.add(new LdcInsnNode(Long.valueOf(plain ^ key)));
                    replacement.add(new LdcInsnNode(Long.valueOf(key)));
                    replacement.add(new InsnNode(Opcodes.LXOR));
                    if (maskOn(maskLong)) {
                        replacement.add(maskLong.emitDecodeLong(siteId(maskIds, insn)));
                    }
                    method.instructions.insertBefore(insn, replacement);
                    method.instructions.remove(insn);
                    count++;
                }
            }
            insn = next;
        }
        return count;
    }

    private static final String INDY_BOOTSTRAP_DESC =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;I)Ljava/lang/invoke/CallSite;";

    private int[] encryptClassShaped(PassContext context, ClassNode node, boolean includeLong,
                                     boolean canHostFields, ShapeSelector selector,
                                     Random classRandom, IntMaskCodec maskInt, IntMaskCodec maskLong,
                                     Map<AbstractInsnNode, Integer> maskIds) {
        List<Site> all = collectSites(node, includeLong);
        if (all.isEmpty()) {
            return new int[] { 0, 0 };
        }
        ShapeSelector.Shape[] supported = supportedShapes(node, canHostFields);
        Map<ShapeSelector.Shape, List<Site>> buckets =
                new LinkedHashMap<ShapeSelector.Shape, List<Site>>();
        for (int i = 0; i < all.size(); i++) {
            Site site = all.get(i);
            ShapeSelector.Shape shape = selector.pick(node, supported);
            site.shape = shape;
            List<Site> bucket = buckets.get(shape);
            if (bucket == null) {
                bucket = new ArrayList<Site>();
                buckets.put(shape, bucket);
            }
            bucket.add(site);
        }
        int shaped = 0;
        for (Map.Entry<ShapeSelector.Shape, List<Site>> entry : buckets.entrySet()) {
            ShapeSelector.Shape shape = entry.getKey();
            List<Site> ints = new ArrayList<Site>();
            List<Site> longs = new ArrayList<Site>();
            for (int i = 0; i < entry.getValue().size(); i++) {
                Site site = entry.getValue().get(i);
                if (site.longs) {
                    longs.add(site);
                } else {
                    ints.add(site);
                }
            }
            int done;
            switch (shape) {
                case FIELD_ARRAY_AND_INDEX:
                    done = emitArray(context, node, ints, false, false, classRandom, maskInt, maskIds)
                            + emitArray(context, node, longs, true, false, classRandom, maskLong, maskIds);
                    break;
                case LOOKUP_METHOD_AND_INDEX:
                    done = emitLookupPacked(context, node, ints, longs, classRandom, maskInt, maskLong,
                            maskIds);
                    break;
                case LOOKUP_METHOD_AND_INDEX_DES:
                    done = emitLookupDes(context, node, ints, false, classRandom, maskInt, maskIds)
                            + emitLookupDes(context, node, longs, true, classRandom, maskLong, maskIds);
                    break;
                case LOCAL_ARRAY_AND_INDEX:
                    done = emitLocalArray(context, node, ints, classRandom, maskInt, maskIds)
                            + emitLocalArray(context, node, longs, classRandom, maskLong, maskIds);
                    break;
                case INDY_ENTRY_AND_INDEX:
                    done = emitIndy(context, node, ints, classRandom, maskInt, maskIds)
                            + emitIndy(context, node, longs, classRandom, maskLong, maskIds);
                    break;
                default:
                    done = 0;
                    break;
            }
            selector.count(shape, done);
            shaped += done;
        }
        return new int[] { all.size(), shaped };
    }

    private static ShapeSelector.Shape[] supportedShapes(ClassNode node, boolean canHostFields) {
        List<ShapeSelector.Shape> supported = new ArrayList<ShapeSelector.Shape>();
        supported.add(ShapeSelector.Shape.LOCAL_ARRAY_AND_INDEX);
        if (canHostFields) {
            supported.add(ShapeSelector.Shape.FIELD_ARRAY_AND_INDEX);
            supported.add(ShapeSelector.Shape.LOOKUP_METHOD_AND_INDEX);
            supported.add(ShapeSelector.Shape.LOOKUP_METHOD_AND_INDEX_DES);
            boolean indy = (node.version & 0xFFFF) >= Opcodes.V1_7
                    && !io.umbra.core.util.AsmUtil.containsJsrOrRet(node);
            if (indy) {
                supported.add(ShapeSelector.Shape.INDY_ENTRY_AND_INDEX);
            }
        }
        return supported.toArray(new ShapeSelector.Shape[0]);
    }

    private static List<Site> collectSites(ClassNode node, boolean includeLong) {
        List<Site> sites = new ArrayList<Site>();
        for (int m = 0; m < node.methods.size(); m++) {
            MethodNode method = node.methods.get(m);
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof LdcInsnNode)) {
                    continue;
                }
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof Integer) {
                    sites.add(new Site(insn, ((Integer) constant).intValue(), false));
                } else if (includeLong && constant instanceof Long) {
                    sites.add(new Site(insn, ((Long) constant).longValue(), true));
                }
            }
        }
        return sites;
    }

    private int emitLookupPacked(PassContext context, ClassNode node, List<Site> ints,
                                 List<Site> longs, Random classRandom, IntMaskCodec maskInt,
                                 IntMaskCodec maskLong, Map<AbstractInsnNode, Integer> maskIds) {
        if (ints.isEmpty() && longs.isEmpty()) {
            return 0;
        }
        String base = "z$" + Integer.toHexString(classRandom.nextInt() | 1);
        List<FieldNode> fields = new ArrayList<FieldNode>();
        List<MethodNode> accessors = new ArrayList<MethodNode>();
        int packed = 0;
        packed += pack(context, node, base + "i", ints, false, fields, accessors, classRandom,
                maskInt, maskIds);
        packed += pack(context, node, base + "j", longs, true, fields, accessors, classRandom,
                maskLong, maskIds);
        for (int i = 0; i < fields.size(); i++) {
            node.fields.add(0, fields.get(i));
        }
        for (int i = 0; i < accessors.size(); i++) {
            node.methods.add(accessors.get(i));
        }
        return packed;
    }

    private int emitLookupDes(PassContext context, ClassNode node, List<Site> sites, boolean longs,
                              Random classRandom, IntMaskCodec codec,
                              Map<AbstractInsnNode, Integer> maskIds) {
        if (sites.isEmpty()) {
            return 0;
        }
        String base = "z$e" + Integer.toHexString(classRandom.nextInt() | 1);
        String fieldName = base + "p";
        String accessorName = base + "a";
        long key = classRandom.nextLong();
        StringBuilder text = new StringBuilder(sites.size() * (longs ? 4 : 2));
        for (int i = 0; i < sites.size(); i++) {
            Site site = sites.get(i);
            if (longs) {
                long plain = maskLong(codec, site, maskIds);
                long masked = plain ^ key;
                for (int shift = 48; shift >= 0; shift -= 16) {
                    text.append((char) ((masked >>> shift) & 0xFFFF));
                }
            } else {
                int plain = maskInt(codec, site, maskIds);
                int masked = plain ^ (int) key;
                text.append((char) ((masked >>> 16) & 0xFFFF));
                text.append((char) (masked & 0xFFFF));
            }
        }
        node.fields.add(0, new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                fieldName, "Ljava/lang/String;", null, null));
        MethodNode desInit = staticInit(node);
        InsnList desSeed = new InsnList();
        desSeed.add(new LdcInsnNode(text.toString()));
        desSeed.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, fieldName, "Ljava/lang/String;"));
        desInit.instructions.insert(desSeed);
        node.methods.add(desAccessor(node, accessorName, fieldName, longs));
        int done = 0;
        for (int i = 0; i < sites.size(); i++) {
            Site site = sites.get(i);
            InsnList replacement = new InsnList();
            io.umbra.core.util.AsmUtil.pushInt(replacement, i);
            replacement.add(new LdcInsnNode(Long.valueOf(key)));
            replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, node.name, accessorName,
                    longs ? "(IJ)J" : "(IJ)I", false));
            appendDecode(replacement, codec, site, longs);
            MethodNode owner = ownerOf(node, site.insn);
            owner.instructions.insertBefore(site.insn, replacement);
            owner.instructions.remove(site.insn);
            done++;
        }
        return done;
    }

    private static MethodNode desAccessor(ClassNode node, String name, String field, boolean longs) {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, longs ? "(IJ)J" : "(IJ)I", null, null);
        InsnList code = method.instructions;
        int perValue = longs ? 4 : 2;
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        io.umbra.core.util.AsmUtil.pushInt(code, perValue);
        code.add(new InsnNode(Opcodes.IMUL));
        code.add(new VarInsnNode(Opcodes.ISTORE, 3));
        if (longs) {
            code.add(new InsnNode(Opcodes.LCONST_0));
            code.add(new VarInsnNode(Opcodes.LSTORE, 4));
            for (int i = 0; i < 4; i++) {
                code.add(new VarInsnNode(Opcodes.LLOAD, 4));
                io.umbra.core.util.AsmUtil.pushInt(code, 16);
                code.add(new InsnNode(Opcodes.LSHL));
                code.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, field,
                        "Ljava/lang/String;"));
                code.add(new VarInsnNode(Opcodes.ILOAD, 3));
                io.umbra.core.util.AsmUtil.pushInt(code, i);
                code.add(new InsnNode(Opcodes.IADD));
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "charAt",
                        "(I)C", false));
                code.add(new InsnNode(Opcodes.I2L));
                code.add(new InsnNode(Opcodes.LOR));
                code.add(new VarInsnNode(Opcodes.LSTORE, 4));
            }
            code.add(new VarInsnNode(Opcodes.LLOAD, 4));
            code.add(new VarInsnNode(Opcodes.LLOAD, 1));
            code.add(new InsnNode(Opcodes.LXOR));
            code.add(new InsnNode(Opcodes.LRETURN));
            method.maxLocals = 6;
            method.maxStack = 4;
            return method;
        }
        code.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, field, "Ljava/lang/String;"));
        code.add(new VarInsnNode(Opcodes.ILOAD, 3));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C",
                false));
        io.umbra.core.util.AsmUtil.pushInt(code, 16);
        code.add(new InsnNode(Opcodes.ISHL));
        code.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, field, "Ljava/lang/String;"));
        code.add(new VarInsnNode(Opcodes.ILOAD, 3));
        code.add(new InsnNode(Opcodes.ICONST_1));
        code.add(new InsnNode(Opcodes.IADD));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C",
                false));
        code.add(new InsnNode(Opcodes.IOR));
        code.add(new VarInsnNode(Opcodes.LLOAD, 1));
        code.add(new InsnNode(Opcodes.L2I));
        code.add(new InsnNode(Opcodes.IXOR));
        code.add(new InsnNode(Opcodes.IRETURN));
        method.maxLocals = 4;
        method.maxStack = 4;
        return method;
    }

    private int emitLocalArray(PassContext context, ClassNode node, List<Site> sites,
                               Random classRandom, IntMaskCodec codec,
                               Map<AbstractInsnNode, Integer> maskIds) {
        if (sites.isEmpty()) {
            return 0;
        }
        Map<MethodNode, List<Site>> byMethod = new LinkedHashMap<MethodNode, List<Site>>();
        for (int i = 0; i < sites.size(); i++) {
            Site site = sites.get(i);
            MethodNode owner = ownerOf(node, site.insn);
            List<Site> bucket = byMethod.get(owner);
            if (bucket == null) {
                bucket = new ArrayList<Site>();
                byMethod.put(owner, bucket);
            }
            bucket.add(site);
        }
        int done = 0;
        for (Map.Entry<MethodNode, List<Site>> entry : byMethod.entrySet()) {
            MethodNode method = entry.getKey();
            List<Site> bucket = entry.getValue();
            boolean longs = bucket.get(0).longs;
            int slot = nextFreeLocal(method);
            int key = classRandom.nextInt();
            if (key == 0) {
                key = 0x5A17;
            }
            InsnList prologue = new InsnList();
            io.umbra.core.util.AsmUtil.pushInt(prologue, bucket.size());
            prologue.add(new IntInsnNode(Opcodes.NEWARRAY, longs ? Opcodes.T_LONG : Opcodes.T_INT));
            prologue.add(new VarInsnNode(Opcodes.ASTORE, slot));
            for (int i = 0; i < bucket.size(); i++) {
                Site site = bucket.get(i);
                prologue.add(new VarInsnNode(Opcodes.ALOAD, slot));
                io.umbra.core.util.AsmUtil.pushInt(prologue, i);
                if (longs) {
                    prologue.add(new LdcInsnNode(Long.valueOf(
                            maskLong(codec, site, maskIds) ^ (long) key)));
                    prologue.add(new InsnNode(Opcodes.LASTORE));
                } else {
                    io.umbra.core.util.AsmUtil.pushInt(prologue, maskInt(codec, site, maskIds) ^ key);
                    prologue.add(new InsnNode(Opcodes.IASTORE));
                }
            }
            method.instructions.insert(prologue);
            method.maxLocals = Math.max(method.maxLocals, slot + 1);
            method.maxStack = Math.max(method.maxStack, 4);
            for (int i = 0; i < bucket.size(); i++) {
                Site site = bucket.get(i);
                InsnList replacement = new InsnList();
                replacement.add(new VarInsnNode(Opcodes.ALOAD, slot));
                io.umbra.core.util.AsmUtil.pushInt(replacement, i);
                replacement.add(new InsnNode(longs ? Opcodes.LALOAD : Opcodes.IALOAD));
                if (longs) {
                    replacement.add(new LdcInsnNode(Long.valueOf(key)));
                    replacement.add(new InsnNode(Opcodes.LXOR));
                } else {
                    io.umbra.core.util.AsmUtil.pushInt(replacement, key);
                    replacement.add(new InsnNode(Opcodes.IXOR));
                }
                appendDecode(replacement, codec, site, longs);
                method.instructions.insertBefore(site.insn, replacement);
                method.instructions.remove(site.insn);
                done++;
            }
        }
        return done;
    }

    private int emitIndy(PassContext context, ClassNode node, List<Site> sites, Random classRandom,
                         IntMaskCodec codec, Map<AbstractInsnNode, Integer> maskIds) {
        if (sites.isEmpty()) {
            return 0;
        }
        boolean longs = sites.get(0).longs;
        String base = "z$n" + Integer.toHexString(classRandom.nextInt() | 1);
        String arrName = base + "v";
        String keyName = base + "k";
        String bootName = base + "b";
        String arrDesc = longs ? "[J" : "[I";
        String keyDesc = longs ? "J" : "I";
        int intKey = classRandom.nextInt();
        if (intKey == 0) {
            intKey = 0x5A17;
        }
        long longKey = ((long) intKey << 32) | (intKey & 0xFFFFFFFFL);
        node.fields.add(0, new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                arrName, arrDesc, null, null));
        node.fields.add(0, new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                keyName, keyDesc, null, null));
        InsnList init = new InsnList();
        if (longs) {
            init.add(new LdcInsnNode(Long.valueOf(longKey)));
        } else {
            io.umbra.core.util.AsmUtil.pushInt(init, intKey);
        }
        init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, keyName, keyDesc));
        io.umbra.core.util.AsmUtil.pushInt(init, sites.size());
        init.add(new IntInsnNode(Opcodes.NEWARRAY, longs ? Opcodes.T_LONG : Opcodes.T_INT));
        init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, arrName, arrDesc));
        for (int i = 0; i < sites.size(); i++) {
            Site site = sites.get(i);
            init.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, arrName, arrDesc));
            io.umbra.core.util.AsmUtil.pushInt(init, i);
            if (longs) {
                init.add(new LdcInsnNode(Long.valueOf(
                        maskLong(codec, site, maskIds) ^ longKey)));
                init.add(new InsnNode(Opcodes.LASTORE));
            } else {
                io.umbra.core.util.AsmUtil.pushInt(init, maskInt(codec, site, maskIds) ^ intKey);
                init.add(new InsnNode(Opcodes.IASTORE));
            }
        }
        staticInit(node).instructions.insert(init);
        node.methods.add(indyBootstrap(node, bootName, arrName, arrDesc, keyName, keyDesc, longs));
        Handle handle = new Handle(Opcodes.H_INVOKESTATIC, node.name, bootName,
                INDY_BOOTSTRAP_DESC, false);
        int done = 0;
        for (int i = 0; i < sites.size(); i++) {
            Site site = sites.get(i);
            InvokeDynamicInsnNode call = new InvokeDynamicInsnNode("z" + i,
                    longs ? "()J" : "()I", handle, Integer.valueOf(i));
            MethodNode owner = ownerOf(node, site.insn);
            InsnList replacement = new InsnList();
            replacement.add(call);
            appendDecode(replacement, codec, site, longs);
            owner.instructions.insertBefore(site.insn, replacement);
            owner.instructions.remove(site.insn);
            done++;
        }
        return done;
    }

    private static MethodNode indyBootstrap(ClassNode node, String name, String arrName,
                                            String arrDesc, String keyName, String keyDesc,
                                            boolean longs) {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, INDY_BOOTSTRAP_DESC, null, null);
        InsnList code = method.instructions;
        code.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, arrName, arrDesc));
        code.add(new VarInsnNode(Opcodes.ILOAD, 3));
        code.add(new InsnNode(longs ? Opcodes.LALOAD : Opcodes.IALOAD));
        code.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, keyName, keyDesc));
        code.add(new InsnNode(longs ? Opcodes.LXOR : Opcodes.IXOR));
        if (longs) {
            code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf",
                    "(J)Ljava/lang/Long;", false));
        } else {
            code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf",
                    "(I)Ljava/lang/Integer;", false));
        }
        code.add(new VarInsnNode(Opcodes.ASTORE, 4));
        code.add(new FieldInsnNode(Opcodes.GETSTATIC,
                longs ? "java/lang/Long" : "java/lang/Integer", "TYPE", "Ljava/lang/Class;"));
        code.add(new VarInsnNode(Opcodes.ALOAD, 4));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/invoke/MethodHandles",
                "constant",
                "(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/invoke/MethodHandle;", false));
        code.add(new VarInsnNode(Opcodes.ASTORE, 5));
        code.add(new TypeInsnNode(Opcodes.NEW, "java/lang/invoke/ConstantCallSite"));
        code.add(new InsnNode(Opcodes.DUP));
        code.add(new VarInsnNode(Opcodes.ALOAD, 5));
        code.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/invoke/ConstantCallSite",
                "<init>", "(Ljava/lang/invoke/MethodHandle;)V", false));
        code.add(new InsnNode(Opcodes.ARETURN));
        method.maxLocals = 6;
        method.maxStack = 4;
        return method;
    }

    private static int nextFreeLocal(MethodNode method) {
        int used = Math.max(0, method.maxLocals);
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof VarInsnNode) {
                int slot = ((VarInsnNode) insn).var;
                int size = (insn.getOpcode() == Opcodes.LLOAD || insn.getOpcode() == Opcodes.LSTORE
                        || insn.getOpcode() == Opcodes.DLOAD
                        || insn.getOpcode() == Opcodes.DSTORE) ? 2 : 1;
                used = Math.max(used, slot + size);
            } else if (insn instanceof IincInsnNode) {
                used = Math.max(used, ((IincInsnNode) insn).var + 1);
            }
        }
        return used;
    }

    /**
     * Assigns the mask-chain site id of one constant and creates the chain's
     * encoded payload value. A {@code null} codec means the layer is off, in which
     * case the original value is returned untouched.
     */
    private static int maskInt(IntMaskCodec codec, Site site,
                               Map<AbstractInsnNode, Integer> ids) {
        if (codec == null || !codec.enabled()) {
            return (int) site.value;
        }
        site.maskSite = siteId(ids, site.insn);
        return codec.encode((int) site.value, site.maskSite);
    }

    private static long maskLong(IntMaskCodec codec, Site site,
                                 Map<AbstractInsnNode, Integer> ids) {
        if (codec == null || !codec.enabled()) {
            return site.value;
        }
        site.maskSite = siteId(ids, site.insn);
        return codec.encodeLong(site.value, site.maskSite);
    }

    private static int siteId(Map<AbstractInsnNode, Integer> ids, AbstractInsnNode insn) {
        Integer id = ids.get(insn);
        if (id == null) {
            throw new IllegalStateException("constant site has no mask id");
        }
        return id.intValue();
    }

    /** Appends the runtime decode chain for one site, if the layer is on. */
    private static void appendDecode(InsnList list, IntMaskCodec codec, Site site, boolean longs) {
        if (codec == null || !codec.enabled()) {
            return;
        }
        list.add(longs ? codec.emitDecodeLong(site.maskSite) : codec.emitDecode(site.maskSite));
    }

    private static boolean maskOn(IntMaskCodec codec) {
        return codec != null && codec.enabled();
    }

    private static void maskStats(PassContext context, IntMaskCodec maskInt, IntMaskCodec maskLong) {
        if (maskOn(maskInt)) {
            maskInt.stats().report(context);
            context.stats().text("integer.masks.shape",
                    maskInt.statsKey() + (maskOn(maskLong) ? "," + maskLong.statsKey() : ""));
        } else if (maskOn(maskLong)) {
            maskLong.stats().report(context);
            context.stats().text("integer.masks.shape", maskLong.statsKey());
        }
    }

    private static final class Site {
        private final AbstractInsnNode insn;
        private final long value;
        private final boolean longs;
        private int maskSite;
        private ShapeSelector.Shape shape = ShapeSelector.Shape.LEGACY;

        private Site(AbstractInsnNode insn, long value, boolean longs) {
            this.insn = insn;
            this.value = value;
            this.longs = longs;
        }
    }
}
