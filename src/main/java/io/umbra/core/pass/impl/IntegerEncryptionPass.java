package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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

            if (selector != null) {
                int[] counts = encryptClassShaped(context, node, includeLong, canHostFields, selector);
                encrypted += counts[0];
                packedSites += counts[1];
                continue;
            }
            String chosen = shape;
            if ("random".equals(chosen)) {
                String[] pool = canHostFields
                        ? new String[] { "string", "array" }
                        : new String[] { "string" };
                chosen = pool[context.random().nextInt(pool.length)];
            }
            if ("xor".equals(chosen) || !canHostFields) {
                int xorCount = 0;
                for (MethodNode method : node.methods) {
                    xorCount += encryptMethodXor(context, method, includeLong);
                }
                encrypted += xorCount;
                bump(perShape, "xor", xorCount);
                continue;
            }
            int[] counts;
            if ("array".equals(chosen)) {
                counts = encryptClassArray(context, node, includeLong, false);
            } else if ("indy".equals(chosen)) {
                counts = encryptClassArray(context, node, includeLong, true);
            } else if ("lookup2".equals(chosen)) {
                counts = encryptClassPacked(context, node, includeLong);
                chosen = "string";
            } else {
                counts = encryptClassPacked(context, node, includeLong);
                chosen = "string";
            }
            encrypted += counts[0];
            packedSites += counts[1];
            bump(perShape, chosen, counts[1]);
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

    private int[] encryptClassPacked(PassContext context, ClassNode node, boolean includeLong) {
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
        String base = "z$" + Integer.toHexString(context.random().nextInt() | 1);
        List<FieldNode> fields = new ArrayList<FieldNode>();
        List<MethodNode> accessors = new ArrayList<MethodNode>();
        int packed = 0;
        packed += pack(context, node, base + "i", intSites, false, fields, accessors);
        packed += pack(context, node, base + "j", longSites, true, fields, accessors);
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
                     List<FieldNode> fields, List<MethodNode> accessors) {
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
            long key = context.random().nextLong();
            fieldNames[chunk] = base + "s" + chunk;
            keys[chunk] = base + "k" + chunk;
            accessorNames[chunk] = base + "d" + chunk;
            StringBuilder text = new StringBuilder((to - from) * (longs ? 4 : 2));
            for (int i = from; i < to; i++) {
                if (longs) {
                    long masked = values.get(i).longValue() ^ key;
                    for (int shift = 48; shift >= 0; shift -= 16) {
                        text.append((char) ((masked >>> shift) & 0xFFFF));
                    }
                } else {
                    int masked = (int) values.get(i).longValue() ^ (int) key;
                    text.append((char) ((masked >>> 16) & 0xFFFF));
                    text.append((char) (masked & 0xFFFF));
                }
            }
            fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                    fieldNames[chunk], "Ljava/lang/String;", null, text.toString()));
            fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                    keys[chunk], "J", null, Long.valueOf(key)));
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
                                    boolean indy) {
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
        shaped += emitArray(context, node, intSites, false, indy);
        shaped += emitArray(context, node, longSites, true, indy);
        return new int[] { intSites.size() + longSites.size(), shaped };
    }

    private int emitArray(PassContext context, ClassNode node, List<Site> sites, boolean longs,
                          boolean indy) {
        if (sites.isEmpty()) {
            return 0;
        }
        String base = "z$a" + Integer.toHexString(context.random().nextInt() | 1);
        String arrName = base + "v";
        String keyName = base + "k";
        String arrDesc = longs ? "[J" : "[I";
        String keyDesc = longs ? "J" : "I";
        int intKey = context.random().nextInt();
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
                init.add(new LdcInsnNode(Long.valueOf(site.value ^ longKey)));
                init.add(new InsnNode(Opcodes.LASTORE));
            } else {
                io.umbra.core.util.AsmUtil.pushInt(init, (int) site.value ^ intKey);
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

    private int encryptMethodXor(PassContext context, MethodNode method, boolean includeLong) {
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof LdcInsnNode) {
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof Integer) {
                    int value = (Integer) constant;
                    int key = context.random().nextInt();
                    if (key == 0) {
                        key = 0x5A17;
                    }
                    InsnList replacement = new InsnList();
                    replacement.add(new LdcInsnNode(Integer.valueOf(value ^ key)));
                    replacement.add(new LdcInsnNode(Integer.valueOf(key)));
                    replacement.add(new InsnNode(Opcodes.IXOR));
                    method.instructions.insertBefore(insn, replacement);
                    method.instructions.remove(insn);
                    count++;
                } else if (includeLong && constant instanceof Long) {
                    long value = (Long) constant;
                    long key = context.random().nextLong();
                    if (key == 0L) {
                        key = 0x5A17L;
                    }
                    InsnList replacement = new InsnList();
                    replacement.add(new LdcInsnNode(Long.valueOf(value ^ key)));
                    replacement.add(new LdcInsnNode(Long.valueOf(key)));
                    replacement.add(new InsnNode(Opcodes.LXOR));
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
                                     boolean canHostFields, ShapeSelector selector) {
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
                    done = emitArray(context, node, ints, false, false)
                            + emitArray(context, node, longs, true, false);
                    break;
                case LOOKUP_METHOD_AND_INDEX:
                    done = emitLookupPacked(context, node, ints, longs);
                    break;
                case LOOKUP_METHOD_AND_INDEX_DES:
                    done = emitLookupDes(context, node, ints, false)
                            + emitLookupDes(context, node, longs, true);
                    break;
                case LOCAL_ARRAY_AND_INDEX:
                    done = emitLocalArray(context, node, ints)
                            + emitLocalArray(context, node, longs);
                    break;
                case INDY_ENTRY_AND_INDEX:
                    done = emitIndy(context, node, ints)
                            + emitIndy(context, node, longs);
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
                                 List<Site> longs) {
        if (ints.isEmpty() && longs.isEmpty()) {
            return 0;
        }
        String base = "z$" + Integer.toHexString(context.random().nextInt() | 1);
        List<FieldNode> fields = new ArrayList<FieldNode>();
        List<MethodNode> accessors = new ArrayList<MethodNode>();
        int packed = 0;
        packed += pack(context, node, base + "i", ints, false, fields, accessors);
        packed += pack(context, node, base + "j", longs, true, fields, accessors);
        for (int i = 0; i < fields.size(); i++) {
            node.fields.add(0, fields.get(i));
        }
        for (int i = 0; i < accessors.size(); i++) {
            node.methods.add(accessors.get(i));
        }
        return packed;
    }

    private int emitLookupDes(PassContext context, ClassNode node, List<Site> sites, boolean longs) {
        if (sites.isEmpty()) {
            return 0;
        }
        String base = "z$e" + Integer.toHexString(context.random().nextInt() | 1);
        String fieldName = base + "p";
        String accessorName = base + "a";
        long key = context.random().nextLong();
        StringBuilder text = new StringBuilder(sites.size() * (longs ? 4 : 2));
        for (int i = 0; i < sites.size(); i++) {
            Site site = sites.get(i);
            if (longs) {
                long masked = site.value ^ key;
                for (int shift = 48; shift >= 0; shift -= 16) {
                    text.append((char) ((masked >>> shift) & 0xFFFF));
                }
            } else {
                int masked = (int) site.value ^ (int) key;
                text.append((char) ((masked >>> 16) & 0xFFFF));
                text.append((char) (masked & 0xFFFF));
            }
        }
        node.fields.add(0, new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                fieldName, "Ljava/lang/String;", null, text.toString()));
        node.methods.add(desAccessor(node, accessorName, fieldName, longs));
        int done = 0;
        for (int i = 0; i < sites.size(); i++) {
            Site site = sites.get(i);
            InsnList replacement = new InsnList();
            io.umbra.core.util.AsmUtil.pushInt(replacement, i);
            replacement.add(new LdcInsnNode(Long.valueOf(key)));
            replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, node.name, accessorName,
                    longs ? "(IJ)J" : "(IJ)I", false));
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

    private int emitLocalArray(PassContext context, ClassNode node, List<Site> sites) {
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
            int key = context.random().nextInt();
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
                    prologue.add(new LdcInsnNode(Long.valueOf(site.value ^ (long) key)));
                    prologue.add(new InsnNode(Opcodes.LASTORE));
                } else {
                    io.umbra.core.util.AsmUtil.pushInt(prologue, (int) site.value ^ key);
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
                method.instructions.insertBefore(site.insn, replacement);
                method.instructions.remove(site.insn);
                done++;
            }
        }
        return done;
    }

    private int emitIndy(PassContext context, ClassNode node, List<Site> sites) {
        if (sites.isEmpty()) {
            return 0;
        }
        boolean longs = sites.get(0).longs;
        String base = "z$n" + Integer.toHexString(context.random().nextInt() | 1);
        String arrName = base + "v";
        String keyName = base + "k";
        String bootName = base + "b";
        String arrDesc = longs ? "[J" : "[I";
        String keyDesc = longs ? "J" : "I";
        int intKey = context.random().nextInt();
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
                init.add(new LdcInsnNode(Long.valueOf(site.value ^ longKey)));
                init.add(new InsnNode(Opcodes.LASTORE));
            } else {
                io.umbra.core.util.AsmUtil.pushInt(init, (int) site.value ^ intKey);
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
            owner.instructions.set(site.insn, call);
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

    private static final class Site {
        private final AbstractInsnNode insn;
        private final long value;
        private final boolean longs;
        private ShapeSelector.Shape shape = ShapeSelector.Shape.LEGACY;

        private Site(AbstractInsnNode insn, long value, boolean longs) {
            this.insn = insn;
            this.value = value;
            this.longs = longs;
        }
    }
}
