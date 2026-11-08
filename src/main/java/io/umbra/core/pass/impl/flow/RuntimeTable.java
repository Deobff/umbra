package io.umbra.core.pass.impl.flow;

import io.umbra.core.api.PassContext;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
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
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * Per-class runtime constant table.
 *
 * <p>A protected class gets one or more {@code private static int[]} fields whose
 * entries are filled in {@code <clinit>} by an xorshift chain seeded from
 * {@code System.nanoTime()}. Constants are then materialised as
 * <code>x = TAB[a]; y = TAB[b]; x ^ y</code>, with the table patch
 * <code>TAB[b] = TAB[a] ^ C</code> emitted in the same {@code <clinit>}.</p>
 *
 * <p>Neither array entry is a compile-time constant: both are the output of a
 * runtime PRNG chain that depends on the class-initialisation instant, and the
 * constant {@code C} only appears inside the class initializer, not at any use
 * site. A constant propagation pass therefore has to scalarise the table
 * initialization loop, model the PRNG and carry data flow from {@code <clinit>}
 * into every method before it can fold the value - the algebraic identities
 * this replaces were foldable with a single rewrite pass.</p>
 *
 * <p>The object is two-phase on purpose: {@link #pair(int)} only records an
 * allocation (so a class that is rolled back leaves no orphan field behind) and
 * {@link #materialize(ClassNode)} writes the field and the {@code <clinit>}
 * bootstrap once the class transform is known to be kept.</p>
 *
 * <p>Everything is deterministic for a seed: allocation order, chunk layout,
 * seeds and pair orientation all come from {@link PassContext#random()}.</p>
 */
public final class RuntimeTable {

    public static final String OPTION_ENABLED = "flow.runtimeTables";

    private static final int CHUNK_INTS = 512;

    private static final int MAX_CHUNKS = 8;

    private static final int SHIFT_A = 13;
    private static final int SHIFT_B = 17;
    private static final int SHIFT_C = 5;

    public static final class Pair {
        private final int chunk;
        private final int a;
        private final int b;
        private final int value;

        Pair(int chunk, int a, int b, int value) {
            this.chunk = chunk;
            this.a = a;
            this.b = b;
            this.value = value;
        }

        public int first() {
            return a;
        }

        public int second() {
            return b;
        }

        public int value() {
            return value;
        }
    }

    private static final class Chunk {
        final String field;
        final int seed;
        final List<Pair> pairs = new ArrayList<Pair>();
        int used;
        int length;

        Chunk(String field, int seed) {
            this.field = field;
            this.seed = seed;
        }
    }

    private final ClassNode owner;
    private final Random random;
    private final boolean enabled;
    private final int maxPairs;
    private final KeyRootMask mask;
    private final List<Chunk> chunks = new ArrayList<Chunk>();
    private int pairs;
    private boolean materialized;

    private RuntimeTable(ClassNode owner, Random random, boolean enabled, int maxPairs,
                         KeyRootMask mask) {
        this.owner = owner;
        this.random = random;
        this.enabled = enabled;
        this.maxPairs = Math.max(2, maxPairs);
        this.mask = mask;
    }

    public static RuntimeTable create(PassContext context, ClassNode owner, int maxPairs,
                                      KeyRootMask mask) {
        boolean enabled = context.config().optionBool(OPTION_ENABLED, true);
        return new RuntimeTable(owner, context.random(), enabled, maxPairs, mask);
    }

    public String mode() {
        return mask == null ? "static" : "native";
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int pairCount() {
        return pairs;
    }

    public int chunkCount() {
        return chunks.size();
    }

    public boolean isEmpty() {
        return pairs == 0;
    }

    public Pair pair(int value) {
        if (!enabled || pairs >= maxPairs) {
            return null;
        }
        Chunk chunk = chunks.isEmpty() ? null : chunks.get(chunks.size() - 1);
        if (chunk == null || chunk.used + 2 > CHUNK_INTS) {
            if (chunks.size() >= MAX_CHUNKS) {
                return null;
            }
            chunk = new Chunk(freshFieldName(chunks.size()), random.nextInt() | 1);
            chunks.add(chunk);
        }
        int a = chunk.used;
        int b = chunk.used + 1;
        chunk.used += 2;
        chunk.length = Math.max(chunk.length, Math.max(a, b) + 1);
        boolean swap = random.nextBoolean();
        Pair pair = new Pair(chunks.size() - 1, swap ? b : a, swap ? a : b, value);
        chunk.pairs.add(pair);
        pairs++;
        return pair;
    }

    public void emitInt(InsnList out, Pair pair) {
        if (pair == null) {
            throw new IllegalArgumentException("pair");
        }
        Chunk chunk = chunks.get(pair.chunk);
        out.add(new FieldInsnNode(Opcodes.GETSTATIC, owner.name, chunk.field, "[I"));
        AsmUtil.pushInt(out, pair.a);
        out.add(new InsnNode(Opcodes.IALOAD));
        out.add(new FieldInsnNode(Opcodes.GETSTATIC, owner.name, chunk.field, "[I"));
        AsmUtil.pushInt(out, pair.b);
        out.add(new InsnNode(Opcodes.IALOAD));
        out.add(new InsnNode(Opcodes.IXOR));
    }

    public boolean emitLong(InsnList out, long value) {
        Pair high = pair((int) (value >>> 32));
        Pair low = pair((int) value);
        if (high == null || low == null) {
            return false;
        }
        emitInt(out, high);
        out.add(new InsnNode(Opcodes.I2L));
        AsmUtil.pushInt(out, 32);
        out.add(new InsnNode(Opcodes.LSHL));
        emitInt(out, low);
        out.add(new InsnNode(Opcodes.I2L));
        out.add(new LdcInsnNode(Long.valueOf(0xFFFFFFFFL)));
        out.add(new InsnNode(Opcodes.LAND));
        out.add(new InsnNode(Opcodes.LXOR));
        return true;
    }

    public boolean materialize(ClassNode node) {
        if (materialized || chunks.isEmpty()) {
            return false;
        }
        materialized = true;
        MethodNode clinit = ensureClinit(node);
        int state = freeLocal(clinit);
        int counter = state + 1;
        clinit.maxLocals = Math.max(clinit.maxLocals, counter + 1);
        InsnList init = new InsnList();
        for (Chunk chunk : chunks) {
            node.fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    chunk.field, "[I", null, null));
            int length = Math.max(2, chunk.length);
            AsmUtil.pushInt(init, length);
            init.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, chunk.field, "[I"));
            init.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                    "nanoTime", "()J", false));
            init.add(new InsnNode(Opcodes.L2I));
            AsmUtil.pushInt(init, chunk.seed);
            init.add(new InsnNode(Opcodes.IXOR));
            init.add(new InsnNode(Opcodes.ICONST_1));
            init.add(new InsnNode(Opcodes.IOR));
            init.add(new VarInsnNode(Opcodes.ISTORE, state));
            init.add(new InsnNode(Opcodes.ICONST_0));
            init.add(new VarInsnNode(Opcodes.ISTORE, counter));
            LabelNode loop = new LabelNode();
            LabelNode end = new LabelNode();
            init.add(loop);
            init.add(new VarInsnNode(Opcodes.ILOAD, counter));
            AsmUtil.pushInt(init, length);
            init.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
            xorshift(init, state, SHIFT_A, false);
            xorshift(init, state, SHIFT_B, true);
            xorshift(init, state, SHIFT_C, false);
            init.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, chunk.field, "[I"));
            init.add(new VarInsnNode(Opcodes.ILOAD, counter));
            init.add(new VarInsnNode(Opcodes.ILOAD, state));
            init.add(new InsnNode(Opcodes.IASTORE));
            init.add(new IincInsnNode(counter, 1));
            init.add(new JumpInsnNode(Opcodes.GOTO, loop));
            init.add(end);
            for (Pair pair : chunk.pairs) {

                init.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, chunk.field, "[I"));
                AsmUtil.pushInt(init, pair.b);
                init.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, chunk.field, "[I"));
                AsmUtil.pushInt(init, pair.a);
                init.add(new InsnNode(Opcodes.IALOAD));
                if (mask == null) {
                    AsmUtil.pushInt(init, pair.value);
                } else {

                    AsmUtil.pushInt(init, pair.value ^ mask.value(pair.b));
                    mask.emit(init, pair.b);
                    init.add(new InsnNode(Opcodes.IXOR));
                }
                init.add(new InsnNode(Opcodes.IXOR));
                init.add(new InsnNode(Opcodes.IASTORE));
            }
        }
        insertAtStart(clinit, init);
        clinit.maxStack = Math.max(clinit.maxStack, mask == null ? 4 : 6);
        return true;
    }

    private String freshFieldName(int index) {
        Set<String> names = new HashSet<String>();
        for (FieldNode field : owner.fields) {
            names.add(field.name);
        }
        for (Chunk existing : chunks) {
            names.add(existing.field);
        }
        String candidate = "z$t" + Integer.toHexString(index);
        int suffix = 0;
        while (names.contains(candidate)) {
            candidate = "z$t" + Integer.toHexString(index) + "$" + Integer.toHexString(suffix++);
        }
        return candidate;
    }

    private static void xorshift(InsnList out, int slot, int shift, boolean unsigned) {
        out.add(new VarInsnNode(Opcodes.ILOAD, slot));
        out.add(new VarInsnNode(Opcodes.ILOAD, slot));
        AsmUtil.pushInt(out, shift);
        out.add(new InsnNode(unsigned ? Opcodes.IUSHR : Opcodes.ISHL));
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, slot));
    }

    private static MethodNode ensureClinit(ClassNode node) {
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method;
            }
        }
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 0;
        clinit.maxStack = 1;
        node.methods.add(clinit);
        return clinit;
    }

    private static void insertAtStart(MethodNode method, InsnList init) {
        AbstractInsnNode first = method.instructions.getFirst();
        if (first == null) {
            method.instructions.add(init);
        } else {
            method.instructions.insertBefore(first, init);
        }
    }

    private static int freeLocal(MethodNode method) {
        int used = Math.max(0, method.maxLocals);
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof VarInsnNode) {
                int slot = ((VarInsnNode) insn).var;
                int size = (insn.getOpcode() == Opcodes.LLOAD || insn.getOpcode() == Opcodes.LSTORE
                        || insn.getOpcode() == Opcodes.DLOAD || insn.getOpcode() == Opcodes.DSTORE) ? 2 : 1;
                used = Math.max(used, slot + size);
            } else if (insn instanceof IincInsnNode) {
                used = Math.max(used, ((IincInsnNode) insn).var + 1);
            }
        }
        return used;
    }
}
