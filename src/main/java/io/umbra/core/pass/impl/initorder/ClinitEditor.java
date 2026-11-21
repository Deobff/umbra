package io.umbra.core.pass.impl.initorder;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Statement-level edits of a {@code <clinit>} body.
 *
 * <p>Two edits are supported, both deliberately paranoid because a class
 * initialiser runs exactly once and a wrong reorder is invisible until some
 * unrelated class reads a static field:</p>
 *
 * <ul>
 *   <li><b>reorder</b> permutes maximal runs of consecutive <em>independent</em>
 *       statements. A statement is independent only when the operand stack is
 *       empty before its first instruction (so it cannot consume or produce a
 *       value across the boundary), it writes no field and no local, it branches
 *       nowhere, it stays outside every exception range, and the only calls it
 *       makes are pure constant constructors ({@code String.<init>},
 *       {@code Integer.valueOf}, ...). Under those rules any permutation of a run
 *       is unobservable: the statements are side-effect free and their operands
 *       all come from the bytecode itself.</li>
 *   <li><b>hoist</b> turns {@code push constant; PUTSTATIC C.f} into a
 *       {@code ConstantValue} attribute on {@code f}, which the VM applies during
 *       preparation, so the pair leaves the initialiser entirely. It only fires
 *       when the field is declared in the same class, is static, has no
 *       {@code ConstantValue} yet, is written exactly once in the whole
 *       initialiser and is never read before that write by the same initialiser.
 *       Anything else keeps its {@code PUTSTATIC}.</li>
 * </ul>
 *
 * <p>Both edits work on a {@link MethodNode} that the caller obtained through
 * {@code MethodGate.copy}, with a frame array computed on the original method
 * body: the copy is node-for-node identical in order, so positions line up.</p>
 */
public final class ClinitEditor {

    /** Marker placed between a field name and its descriptor in the pending map. */
    private static final String KEY_SEPARATOR = Character.toString((char) 0);

    private static final Set<String> PURE_OWNERS = Collections.newSetFromMap(
            new LinkedHashMap<String, Boolean>());

    static {
        PURE_OWNERS.add("java/lang/Object");
        PURE_OWNERS.add("java/lang/String");
        PURE_OWNERS.add("java/lang/Integer");
        PURE_OWNERS.add("java/lang/Long");
        PURE_OWNERS.add("java/lang/Short");
        PURE_OWNERS.add("java/lang/Byte");
        PURE_OWNERS.add("java/lang/Boolean");
        PURE_OWNERS.add("java/lang/Character");
        PURE_OWNERS.add("java/lang/Float");
        PURE_OWNERS.add("java/lang/Double");
        PURE_OWNERS.add("java/math/BigInteger");
        PURE_OWNERS.add("java/math/BigDecimal");
    }

    /** One statement of the initialiser: a node range plus its verdict. */
    public static final class Statement {
        public final int start;
        public final int end;
        public final Set<String> reads = new LinkedHashSet<String>();
        public final Set<String> writes = new LinkedHashSet<String>();
        public boolean independent;
        public int rank;
        public int tiebreak;

        Statement(int start, int end) {
            this.start = start;
            this.end = end;
            this.rank = Integer.MAX_VALUE;
        }
    }

    private ClinitEditor() {
    }

    @SuppressWarnings("unchecked")
    public static Frame<BasicValue>[] analyse(String owner, MethodNode method) {
        try {
            return new Analyzer<BasicValue>(new BasicInterpreter()).analyze(owner, method);
        } catch (AnalyzerException failure) {
            return null;
        } catch (RuntimeException failure) {
            return null;
        }
    }

    /**
     * Cuts the body into statements. A new statement starts at the first
     * instruction, at every instruction whose incoming frame has an empty
     * operand stack, and at every exception-table boundary label.
     */
    public static List<Statement> statements(MethodNode method, Frame<BasicValue>[] frames) {
        AbstractInsnNode[] insns = method.instructions.toArray();
        List<Statement> out = new ArrayList<Statement>();
        if (insns.length == 0) {
            return out;
        }
        Set<AbstractInsnNode> boundary = Collections.newSetFromMap(
                new IdentityHashMap<AbstractInsnNode, Boolean>());
        if (method.tryCatchBlocks != null) {
            for (int t = 0; t < method.tryCatchBlocks.size(); t++) {
                TryCatchBlockNode table = method.tryCatchBlocks.get(t);
                if (table.start != null) {
                    boundary.add(table.start);
                }
                if (table.end != null) {
                    boundary.add(table.end);
                }
                if (table.handler != null) {
                    boundary.add(table.handler);
                }
            }
        }
        boolean[] cut = new boolean[insns.length];
        cut[0] = true;
        for (int i = 0; i < insns.length; i++) {
            if (boundary.contains(insns[i])) {
                cut[i] = true;
            }
            if (insns[i].getOpcode() < 0) {
                continue;
            }
            if (frames != null && i < frames.length && frames[i] != null
                    && frames[i].getStackSize() == 0 && i > 0) {
                cut[i] = true;
            }
        }
        int begin = 0;
        for (int i = 1; i < insns.length; i++) {
            if (cut[i]) {
                out.add(new Statement(begin, i - 1));
                begin = i;
            }
        }
        out.add(new Statement(begin, insns.length - 1));
        return out;
    }

    /**
     * Decides, per statement, whether it may be moved, and its ordering rank.
     *
     * @param strictIndependence {@code true} rejects every statement that writes a
     *                           field; {@code false} allows field writes and defers
     *                           the proof to {@link #runSafe}, which requires the
     *                           write sets of a run to be disjoint and no statement
     *                           to read a field another one writes
     */
    public static void classify(MethodNode method, List<Statement> statements,
                                Frame<BasicValue>[] frames, Map<String, Integer> ranks,
                                long seed, boolean strictIndependence) {
        AbstractInsnNode[] insns = method.instructions.toArray();
        int[] trapStart = new int[0];
        int[] trapEnd = new int[0];
        int[] trapHandler = new int[0];
        if (method.tryCatchBlocks != null && method.tryCatchBlocks.size() > 0) {
            Map<AbstractInsnNode, Integer> positions = new IdentityHashMap<AbstractInsnNode, Integer>();
            for (int i = 0; i < insns.length; i++) {
                positions.put(insns[i], Integer.valueOf(i));
            }
            trapStart = new int[method.tryCatchBlocks.size()];
            trapEnd = new int[method.tryCatchBlocks.size()];
            trapHandler = new int[method.tryCatchBlocks.size()];
            for (int t = 0; t < method.tryCatchBlocks.size(); t++) {
                TryCatchBlockNode table = method.tryCatchBlocks.get(t);
                trapStart[t] = position(positions, table.start);
                trapEnd[t] = position(positions, table.end);
                trapHandler[t] = position(positions, table.handler);
            }
        }
        Random random = new Random(seed);
        for (int s = 0; s < statements.size(); s++) {
            Statement statement = statements.get(s);
            statement.tiebreak = random.nextInt();
            int firstReal = -1;
            for (int i = statement.start; i <= statement.end; i++) {
                if (insns[i].getOpcode() >= 0) {
                    firstReal = i;
                    break;
                }
            }
            if (firstReal < 0) {
                continue;
            }
            if (frames == null || firstReal >= frames.length || frames[firstReal] == null
                    || frames[firstReal].getStackSize() != 0) {
                continue;
            }
            int afterReal = nextReal(insns, statement.end);
            if (afterReal >= 0) {
                if (afterReal >= frames.length || frames[afterReal] == null
                        || frames[afterReal].getStackSize() != 0) {
                    continue;
                }
            }
            if (insideTrap(firstReal, trapStart, trapEnd)) {
                continue;
            }
            if (crossesTrapBoundary(statement.start, statement.end, trapStart, trapEnd, trapHandler)) {
                continue;
            }
            boolean independent = true;
            int rank = Integer.MAX_VALUE;
            for (int i = statement.start; i <= statement.end && independent; i++) {
                AbstractInsnNode insn = insns[i];
                int opcode = insn.getOpcode();
                if (opcode < 0) {
                    continue;
                }
                if (frames[i] == null) {
                    independent = false;
                    break;
                }
                if (!isMovableOpcode(opcode)) {
                    independent = false;
                    break;
                }
                if (insn instanceof VarInsnNode || insn instanceof IincInsnNode) {
                    independent = false;
                    break;
                }
                if (insn instanceof FieldInsnNode) {
                    FieldInsnNode field = (FieldInsnNode) insn;
                    String key = field.owner + '.' + field.name + field.desc;
                    if (field.getOpcode() == Opcodes.PUTSTATIC
                            || field.getOpcode() == Opcodes.PUTFIELD) {
                        if (strictIndependence) {
                            independent = false;
                            break;
                        }
                        statement.writes.add(key);
                        continue;
                    }
                    statement.reads.add(key);
                    Integer own = ranks.get(field.owner);
                    if (own != null && own.intValue() < rank) {
                        rank = own.intValue();
                    }
                    continue;
                }
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode call = (MethodInsnNode) insn;
                    if (!isPureConstantCall(call)) {
                        independent = false;
                        break;
                    }
                    Integer own = ranks.get(call.owner);
                    if (own != null && own.intValue() < rank) {
                        rank = own.intValue();
                    }
                    continue;
                }
                if (insn instanceof InvokeDynamicInsnNode) {
                    independent = false;
                    break;
                }
            }
            statement.independent = independent;
            statement.rank = independent ? rank : Integer.MAX_VALUE;
        }
    }

    /**
     * The proof that a permutation of {@code run} is unobservable: no two
     * statements write the same field, and no statement reads a field that
     * another statement in the run writes. Combined with empty operand stacks at
     * every boundary and the absence of calls with side effects, every statement
     * in the run becomes a pure function of state that none of the others touch.
     */
    private static boolean runSafe(List<Statement> run) {
        for (int i = 0; i < run.size(); i++) {
            Statement left = run.get(i);
            for (int j = 0; j < run.size(); j++) {
                if (i == j) {
                    continue;
                }
                Statement right = run.get(j);
                for (String key : right.writes) {
                    if (left.writes.contains(key)) {
                        return false;
                    }
                    if (left.reads.contains(key)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private static int nextReal(AbstractInsnNode[] insns, int index) {
        for (int i = index + 1; i < insns.length; i++) {
            if (insns[i].getOpcode() >= 0) {
                return i;
            }
        }
        return -1;
    }

    private static int position(Map<AbstractInsnNode, Integer> positions, AbstractInsnNode node) {
        if (node == null) {
            return -1;
        }
        Integer value = positions.get(node);
        return value == null ? -1 : value.intValue();
    }

    private static boolean insideTrap(int index, int[] starts, int[] ends) {
        for (int t = 0; t < starts.length; t++) {
            if (starts[t] >= 0 && ends[t] >= 0 && index >= starts[t] && index < ends[t]) {
                return true;
            }
        }
        return false;
    }

    private static boolean crossesTrapBoundary(int start, int end, int[] starts, int[] ends,
                                               int[] handlers) {
        for (int t = 0; t < starts.length; t++) {
            int[] marks = { starts[t], ends[t], handlers[t] };
            for (int m = 0; m < marks.length; m++) {
                if (marks[m] >= start && marks[m] <= end) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isMovableOpcode(int opcode) {
        if (opcode >= Opcodes.IFEQ && opcode <= Opcodes.IF_ACMPNE) {
            return false;
        }
        if (opcode == Opcodes.IFNULL || opcode == Opcodes.IFNONNULL) {
            return false;
        }
        if (opcode == Opcodes.GOTO || opcode == Opcodes.JSR || opcode == Opcodes.RET) {
            return false;
        }
        if (opcode == Opcodes.TABLESWITCH || opcode == Opcodes.LOOKUPSWITCH) {
            return false;
        }
        if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) {
            return false;
        }
        if (opcode == Opcodes.ATHROW) {
            return false;
        }
        if (opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT) {
            return false;
        }
        return true;
    }

    private static boolean isPureConstantCall(MethodInsnNode call) {
        if (!("<init>".equals(call.name) || "valueOf".equals(call.name)
                || "toString".equals(call.name))) {
            return false;
        }
        return PURE_OWNERS.contains(call.owner);
    }

    /**
     * Reorders every maximal run of independent statements by initialisation
     * rank (dependencies first) and returns how many statements were moved.
     */
    public static int reorder(MethodNode method, List<Statement> statements) {
        AbstractInsnNode[] insns = method.instructions.toArray();
        int moved = 0;
        int i = 0;
        while (i < statements.size()) {
            if (!statements.get(i).independent) {
                i++;
                continue;
            }
            int j = i;
            while (j + 1 < statements.size() && statements.get(j + 1).independent) {
                j++;
            }
            if (j > i && runSafe(statements.subList(i, j + 1))) {
                final List<Statement> run = statements.subList(i, j + 1);
                Integer[] permutation = new Integer[run.size()];
                for (int k = 0; k < permutation.length; k++) {
                    permutation[k] = Integer.valueOf(k);
                }
                Arrays.sort(permutation, new Comparator<Integer>() {
                    @Override
                    public int compare(Integer a, Integer b) {
                        Statement first = run.get(a.intValue());
                        Statement second = run.get(b.intValue());
                        if (first.rank != second.rank) {
                            return first.rank < second.rank ? -1 : 1;
                        }
                        if (first.tiebreak != second.tiebreak) {
                            return first.tiebreak < second.tiebreak ? -1 : 1;
                        }
                        return a.intValue() < b.intValue() ? -1 : (a.equals(b) ? 0 : 1);
                    }
                });
                boolean identity = true;
                for (int k = 0; k < permutation.length; k++) {
                    if (permutation[k].intValue() != k) {
                        identity = false;
                        break;
                    }
                }
                if (!identity) {
                    List<List<AbstractInsnNode>> groups = new ArrayList<List<AbstractInsnNode>>();
                    for (int k = 0; k < run.size(); k++) {
                        Statement statement = run.get(k);
                        List<AbstractInsnNode> nodes = new ArrayList<AbstractInsnNode>();
                        for (int n = statement.start; n <= statement.end; n++) {
                            nodes.add(insns[n]);
                        }
                        groups.add(nodes);
                    }
                    int lastEnd = run.get(run.size() - 1).end;
                    AbstractInsnNode anchor = lastEnd + 1 < insns.length ? insns[lastEnd + 1] : null;
                    for (int g = 0; g < groups.size(); g++) {
                        List<AbstractInsnNode> nodes = groups.get(g);
                        for (int n = 0; n < nodes.size(); n++) {
                            method.instructions.remove(nodes.get(n));
                        }
                    }
                    for (int g = 0; g < permutation.length; g++) {
                        List<AbstractInsnNode> nodes = groups.get(permutation[g].intValue());
                        for (int n = 0; n < nodes.size(); n++) {
                            if (anchor != null) {
                                method.instructions.insertBefore(anchor, nodes.get(n));
                            } else {
                                method.instructions.add(nodes.get(n));
                            }
                        }
                    }
                    moved += run.size();
                }
            }
            i = j + 1;
        }
        return moved;
    }

    /**
     * Hoists constant static initialisers into {@code ConstantValue} attributes.
     *
     * @param pending receives {@code name + KEY_SEPARATOR + desc -> constant value};
     *                the caller applies it to the fields only after the edited
     *                initialiser verified, so a rejected body leaves the class
     *                untouched
     * @return the number of hoisted fields
     */
    public static int hoist(ClassNode node, MethodNode method, Frame<BasicValue>[] frames,
                            Map<String, Object> pending) {
        AbstractInsnNode[] insns = method.instructions.toArray();
        Map<String, FieldNode> own = new LinkedHashMap<String, FieldNode>();
        for (int i = 0; i < node.fields.size(); i++) {
            FieldNode field = node.fields.get(i);
            if ((field.access & Opcodes.ACC_STATIC) == 0) {
                continue;
            }
            own.put(field.name + KEY_SEPARATOR + field.desc, field);
        }
        Map<String, Integer> puts = new LinkedHashMap<String, Integer>();
        Map<String, Integer> gets = new LinkedHashMap<String, Integer>();
        List<Integer> putPositions = new ArrayList<Integer>();
        for (int i = 0; i < insns.length; i++) {
            if (!(insns[i] instanceof FieldInsnNode)) {
                continue;
            }
            FieldInsnNode field = (FieldInsnNode) insns[i];
            if (!field.owner.equals(node.name)) {
                continue;
            }
            String key = field.name + KEY_SEPARATOR + field.desc;
            if (!own.containsKey(key)) {
                continue;
            }
            if (field.getOpcode() == Opcodes.PUTSTATIC) {
                Integer count = puts.get(key);
                puts.put(key, Integer.valueOf(count == null ? 1 : count.intValue() + 1));
                putPositions.add(Integer.valueOf(i));
            } else if (field.getOpcode() == Opcodes.GETSTATIC) {
                Integer count = gets.get(key);
                gets.put(key, Integer.valueOf(count == null ? 1 : count.intValue() + 1));
            }
        }
        if (putPositions.isEmpty()) {
            return 0;
        }
        int[] trapStart = new int[0];
        int[] trapEnd = new int[0];
        int[] trapHandler = new int[0];
        if (method.tryCatchBlocks != null && method.tryCatchBlocks.size() > 0) {
            Map<AbstractInsnNode, Integer> positions = new IdentityHashMap<AbstractInsnNode, Integer>();
            for (int i = 0; i < insns.length; i++) {
                positions.put(insns[i], Integer.valueOf(i));
            }
            trapStart = new int[method.tryCatchBlocks.size()];
            trapEnd = new int[method.tryCatchBlocks.size()];
            trapHandler = new int[method.tryCatchBlocks.size()];
            for (int t = 0; t < method.tryCatchBlocks.size(); t++) {
                TryCatchBlockNode table = method.tryCatchBlocks.get(t);
                trapStart[t] = position(positions, table.start);
                trapEnd[t] = position(positions, table.end);
                trapHandler[t] = position(positions, table.handler);
            }
        }

        int hoisted = 0;
        List<int[]> removals = new ArrayList<int[]>();
        for (int p = 0; p < putPositions.size(); p++) {
            int put = putPositions.get(p).intValue();
            FieldInsnNode putInsn = (FieldInsnNode) insns[put];
            String key = putInsn.name + KEY_SEPARATOR + putInsn.desc;
            FieldNode field = own.get(key);
            if (field == null || field.value != null) {
                continue;
            }
            Integer putCount = puts.get(key);
            if (putCount == null || putCount.intValue() != 1) {
                continue;
            }
            if (gets.containsKey(key)) {
                continue;
            }
            int push = previousReal(insns, put);
            if (push < 0) {
                continue;
            }
            if (frames == null || push >= frames.length || put >= frames.length
                    || frames[push] == null || frames[put] == null) {
                continue;
            }
            if (frames[push].getStackSize() != 0) {
                continue;
            }
            // Frame#getStackSize counts values, not slots: a long or a double is
            // one value, so the constant is the only thing on the stack either way.
            if (frames[put].getStackSize() != 1) {
                continue;
            }
            Object constant = constantFor(insns[push], field.desc);
            if (constant == null) {
                continue;
            }
            boolean labelled = false;
            for (int i = push + 1; i <= put && i < insns.length; i++) {
                if (insns[i].getOpcode() < 0 && insns[i] instanceof org.objectweb.asm.tree.LabelNode) {
                    labelled = true;
                    break;
                }
            }
            if (labelled) {
                continue;
            }
            if (insideTrap(push, trapStart, trapEnd) || insideTrap(put, trapStart, trapEnd)) {
                continue;
            }
            if (crossesTrapBoundary(push, put, trapStart, trapEnd, trapHandler)) {
                continue;
            }
            removals.add(new int[] { push, put });
            pending.put(key, constant);
            hoisted++;
        }
        for (int r = 0; r < removals.size(); r++) {
            int[] pair = removals.get(r);
            method.instructions.remove(insns[pair[0]]);
            method.instructions.remove(insns[pair[1]]);
        }
        return hoisted;
    }

    private static int previousReal(AbstractInsnNode[] insns, int index) {
        for (int i = index - 1; i >= 0; i--) {
            if (insns[i].getOpcode() >= 0) {
                return i;
            }
        }
        return -1;
    }

    private static Object constantFor(AbstractInsnNode insn, String desc) {
        Object value = null;
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            value = Integer.valueOf(opcode - Opcodes.ICONST_0);
        } else if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            value = Integer.valueOf(((IntInsnNode) insn).operand);
        } else if (opcode == Opcodes.LCONST_0 || opcode == Opcodes.LCONST_1) {
            value = Long.valueOf(opcode == Opcodes.LCONST_1 ? 1L : 0L);
        } else if (opcode == Opcodes.FCONST_0 || opcode == Opcodes.FCONST_1
                || opcode == Opcodes.FCONST_2) {
            value = Float.valueOf(opcode - Opcodes.FCONST_0);
        } else if (opcode == Opcodes.DCONST_0 || opcode == Opcodes.DCONST_1) {
            value = Double.valueOf(opcode - Opcodes.DCONST_0);
        } else if (insn instanceof LdcInsnNode) {
            value = ((LdcInsnNode) insn).cst;
        } else if (insn instanceof TypeInsnNode) {
            return null;
        }
        if (value == null) {
            return null;
        }
        if ("I".equals(desc) || "B".equals(desc) || "S".equals(desc) || "C".equals(desc)
                || "Z".equals(desc)) {
            return value instanceof Integer ? value : null;
        }
        if ("J".equals(desc)) {
            return value instanceof Long ? value : null;
        }
        if ("F".equals(desc)) {
            return value instanceof Float ? value : null;
        }
        if ("D".equals(desc)) {
            return value instanceof Double ? value : null;
        }
        if ("Ljava/lang/String;".equals(desc)) {
            return value instanceof String ? value : null;
        }
        return null;
    }

    /** Applies the hoisted values to the class fields. */
    public static int applyConstants(ClassNode node, Map<String, Object> pending) {
        int applied = 0;
        for (int i = 0; i < node.fields.size(); i++) {
            FieldNode field = node.fields.get(i);
            String key = field.name + KEY_SEPARATOR + field.desc;
            if (!pending.containsKey(key)) {
                continue;
            }
            field.value = pending.get(key);
            applied++;
        }
        return applied;
    }
}
