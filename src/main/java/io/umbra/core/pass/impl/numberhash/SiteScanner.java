package io.umbra.core.pass.impl.numberhash;

import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.List;

/**
 * Finds and rewrites {@code int}/{@code long} constant pushes.
 *
 * <p>Only three instruction shapes carry a <em>value</em>:</p>
 * <ul>
 *   <li>{@code ICONST_M1 .. ICONST_5} ({@code InsnNode}),</li>
 *   <li>{@code BIPUSH} / {@code SIPUSH} ({@code IntInsnNode}),</li>
 *   <li>{@code LDC} of an {@code Integer} or {@code Long}.</li>
 * </ul>
 *
 * <p>Everything else that looks like a small number in the bytecode is an
 * <em>operand</em>, not a value, and must not be rewritten:</p>
 * <ul>
 *   <li>{@code NEWARRAY}'s element type - also an {@code IntInsnNode}, which is
 *       why the opcode is checked instead of the node class;</li>
 *   <li>{@code MULTIANEWARRAY}'s dimension count (an instruction field);</li>
 *   <li>{@code IINC}'s increment (an {@code IincInsnNode}, never a push);</li>
 *   <li>a {@code TABLESWITCH}/{@code LOOKUPSWITCH} key range, which lives in
 *       the switch instruction itself and is not a sequence of pushes.</li>
 * </ul>
 *
 * <p>A rewritten site becomes {@code push encode(value)} followed by the codec's
 * decoder. The decoder consumes and produces exactly one int, so the splice is
 * transparent to the surrounding expression; only the pushed constant changes.
 * For a {@code long} the two 32-bit halves are encoded separately and
 * reassembled as {@code ((long) high << 32) | (low & 0xFFFFFFFFL)}.</p>
 */
public final class SiteScanner {

    private SiteScanner() {
    }

    /** One constant push that can be rewritten. */
    public static final class Site {
        private final AbstractInsnNode instruction;
        private final long value;
        private final boolean longValue;

        Site(AbstractInsnNode instruction, long value, boolean longValue) {
            this.instruction = instruction;
            this.value = value;
            this.longValue = longValue;
        }

        public AbstractInsnNode instruction() {
            return instruction;
        }

        public long value() {
            return value;
        }

        public int intValue() {
            return (int) value;
        }

        public boolean isLong() {
            return longValue;
        }
    }

    /** Number of rewritable sites, without building the list. */
    public static int count(MethodNode method, boolean includeLong) {
        int found = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (isSite(insn, includeLong)) {
                found++;
            }
        }
        return found;
    }

    /** Collects the sites in instruction order (deterministic). */
    public static List<Site> collect(MethodNode method, boolean includeLong) {
        List<Site> sites = new ArrayList<Site>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!isSite(insn, includeLong)) {
                continue;
            }
            if (insn instanceof IntInsnNode) {
                int opcode = insn.getOpcode();
                if (opcode != Opcodes.BIPUSH && opcode != Opcodes.SIPUSH) {
                    continue;
                }
                sites.add(new Site(insn, ((IntInsnNode) insn).operand, false));
            } else if (insn instanceof LdcInsnNode) {
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof Integer) {
                    sites.add(new Site(insn, ((Integer) constant).intValue(), false));
                } else if (constant instanceof Long) {
                    sites.add(new Site(insn, ((Long) constant).longValue(), true));
                }
            } else if (insn instanceof InsnNode) {
                sites.add(new Site(insn, insn.getOpcode() - Opcodes.ICONST_0, false));
            }
        }
        return sites;
    }

    private static boolean isSite(AbstractInsnNode insn, boolean includeLong) {
        int opcode = insn.getOpcode();
        if (opcode < 0) {
            return false;
        }
        if (insn instanceof InsnNode && opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return true;
        }
        if (insn instanceof IntInsnNode) {
            return opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH;
        }
        if (insn instanceof LdcInsnNode) {
            Object constant = ((LdcInsnNode) insn).cst;
            if (constant instanceof Integer) {
                return true;
            }
            return includeLong && constant instanceof Long;
        }
        return false;
    }

    /**
     * Replaces one site with {@code push encode(value)} + decoder.
     *
     * <p>{@code insertBefore} + {@code remove} keeps any label that preceded the
     * constant in front of the new sequence, so a jump that targeted the constant
     * still lands on the encoded push (a jump into the middle of an expression is
     * unusual but legal, and obfuscated input does contain it).</p>
     */
    public static void splice(MethodNode method, Site site, NumberHashCodec codec, int slotBudget) {
        InsnList list = new InsnList();
        if (!site.isLong()) {
            AsmUtil.pushInt(list, codec.encode(site.intValue()));
            codec.emitDecode(list, slotBudget);
        } else {
            long value = site.value();
            int high = (int) (value >>> 32);
            int low = (int) value;
            AsmUtil.pushInt(list, codec.encode(high));
            codec.emitDecode(list, slotBudget);
            list.add(new InsnNode(Opcodes.I2L));
            AsmUtil.pushInt(list, 32);
            list.add(new InsnNode(Opcodes.LSHL));
            AsmUtil.pushInt(list, codec.encode(low));
            codec.emitDecode(list, slotBudget);
            list.add(new InsnNode(Opcodes.I2L));
            list.add(new LdcInsnNode(Long.valueOf(0xFFFFFFFFL)));
            list.add(new InsnNode(Opcodes.LAND));
            list.add(new InsnNode(Opcodes.LOR));
        }
        method.instructions.insertBefore(site.instruction(), list);
        method.instructions.remove(site.instruction());
    }
}
