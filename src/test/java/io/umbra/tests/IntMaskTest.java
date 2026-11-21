package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.pass.impl.integer.IntMask;
import io.umbra.core.pass.impl.integer.IntMaskCodec;
import io.umbra.core.pass.impl.integer.IntMaskStack;
import io.umbra.core.pass.impl.integer.masks.AddMask;
import io.umbra.core.pass.impl.integer.masks.AndMask;
import io.umbra.core.pass.impl.integer.masks.DivMask;
import io.umbra.core.pass.impl.integer.masks.LeftShiftMask;
import io.umbra.core.pass.impl.integer.masks.MulMask;
import io.umbra.core.pass.impl.integer.masks.NegMask;
import io.umbra.core.pass.impl.integer.masks.OrMask;
import io.umbra.core.pass.impl.integer.masks.RightShiftMask;
import io.umbra.core.pass.impl.integer.masks.SubMask;
import io.umbra.core.pass.impl.integer.masks.UShiftRightMask;
import io.umbra.core.pass.impl.integer.masks.XorMask;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
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
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * Self-test for the polymorphic integer mask engine ({@code io.umbra.core.pass.impl.integer}).
 *
 * <p>Plain {@code main} harness, no JUnit (CONTRACT §1). The suite covers:</p>
 *
 * <ol>
 *   <li>the algebra of all eleven mask families, including the deliberate absence
 *       of {@code applyInverse} on the lossy ones;</li>
 *   <li>chain semantics: forward/inverse order, chain round trips, detection of
 *       decode-only chains;</li>
 *   <li>real-JVM equivalence of the three dump shapes - {@code dump()},
 *       {@code dumpWithLocal()} and the {@code TABLEswitch} form of
 *       {@code dumpWithIndex()} - against their Java counterparts, over edge
 *       values and ten thousand random ones;</li>
 *   <li>an end-to-end integration exactly like the pass consumes the codec:
 *       masked payload table, {@code ... ^ key}, then {@code emitDecode(site)},
 *       checked with {@link CheckClassAdapter}, the real JVM verifier and
 *       reflective invocation against the baseline constants;</li>
 *   <li>determinism: the same seed produces the same encodings and the same
 *       instruction bytes, and the caller's walk order cannot change either.</li>
 * </ol>
 */
public final class IntMaskTest {

    private static final int[] EDGES = {
            0, 1, -1, 2, -2, 3, 7,
            Byte.MIN_VALUE, Byte.MAX_VALUE,
            Short.MIN_VALUE, Short.MAX_VALUE,
            Integer.MIN_VALUE, Integer.MIN_VALUE + 1, Integer.MAX_VALUE, Integer.MAX_VALUE - 1
    };

    private static int checks;
    private static int probes;

    private IntMaskTest() {
    }

    public static void main(String[] args) throws Exception {
        try {
            testMaskAlgebra();
            testStackSemantics();
            testDumpRuntime();
            testDumpWithLocal();
            testDumpWithIndex();
            testCodecEndToEnd();
            testCodecLong();
            testCodecDeterminism();
            System.out.println("IntMaskTest: " + checks + " checks passed");
        } catch (Throwable failure) {
            System.err.println("IntMaskTest: FAILED after " + checks + " checks: " + failure);
            failure.printStackTrace();
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------
    // 1. mask algebra
    // ------------------------------------------------------------------

    private static void testMaskAlgebra() {
        Random random = new Random(0x5A17L);
        IntMask<?>[] masks = new IntMask<?>[] {
                new AddMask(), new SubMask(), new XorMask(), new NegMask(),
                new MulMask(), new DivMask(), new LeftShiftMask(), new RightShiftMask(),
                new UShiftRightMask(), new OrMask(), new AndMask()
        };
        StringBuilder reversible = new StringBuilder();
        StringBuilder decodeOnly = new StringBuilder();
        for (int i = 0; i < masks.length; i++) {
            IntMask<?> mask = masks[i];
            boolean invertible = mask.invertible();
            if (invertible) {
                reversible.append(reversible.length() == 0 ? "" : ",").append(mask.family());
            } else {
                decodeOnly.append(decodeOnly.length() == 0 ? "" : ",").append(mask.family());
            }
            check(invertible == expectedInvertible(mask.family()),
                    "invertibility classification of " + mask.family());
            // Five thousand operands per family; pick() mixes the edge values in.
            for (int it = 0; it < 5000; it++) {
                mask.ofValue(operandFor(mask.family(), random));
                int x = pick(random);
                if (invertible) {
                    int encoded = mask.applyInverse(x);
                    check(mask.apply(encoded) == x, mask.family() + ": apply(applyInverse(x)) == x");
                } else {
                    boolean refused = false;
                    try {
                        mask.applyInverse(x);
                    } catch (UnsupportedOperationException expected) {
                        refused = true;
                    }
                    check(refused, mask.family() + ": applyInverse must be unsupported");
                }
            }
            // The emitted shape stays the donor's: one operand push plus one
            // arithmetic node, except for the operand-free negation.
            InsnList insns = mask.insns();
            int expectedSize = "neg".equals(mask.family()) ? 1 : 2;
            check(insns.size() == expectedSize,
                    mask.family() + ": insns() size is " + expectedSize);
            check(insns.getLast().getOpcode() == opcodeOf(mask.family()),
                    mask.family() + ": insns() ends with the family opcode");
            checkNoPseudo(insns, "insns()");
        }
        check("add,sub,xor,neg".equals(reversible.toString()),
                "reversible families are add,sub,xor,neg (got " + reversible + ")");
        check("mul,div,shl,shr,ushr,or,and".equals(decodeOnly.toString()),
                "decode-only families are mul,div,shl,shr,ushr,or,and (got " + decodeOnly + ")");

        // ofValue / ofRandomValue plumbing and the operand bound.
        XorMask xor = new XorMask().ofValue(0x1234);
        check(xor.value() == 0x1234, "ofValue stores the operand");
        XorMask drawn = new XorMask().ofRandomValue(random, IntMaskStack.OPERAND_BOUND);
        check(drawn.value() >= 0 && drawn.value() < IntMaskStack.OPERAND_BOUND,
                "ofRandomValue(bound) stays in [0, bound)");
        assertOperandBound(random);
    }

    private static void assertOperandBound(Random random) {
        for (int i = 0; i < 2000; i++) {
            IntMaskStack stack = IntMaskStack.random(random, 8, false);
            for (int m = 0; m < stack.size(); m++) {
                IntMask<?> mask = stack.masks().get(m);
                check(mask.value() >= 0 && mask.value() < IntMaskStack.OPERAND_BOUND,
                        "chain operand stays in [0, Character.MAX_VALUE)");
            }
        }
    }

    private static boolean expectedInvertible(String family) {
        return "add".equals(family) || "sub".equals(family) || "xor".equals(family)
                || "neg".equals(family);
    }

    private static int operandFor(String family, Random random) {
        if ("div".equals(family)) {
            return 1 + random.nextInt(IntMaskStack.OPERAND_BOUND);
        }
        if ("shl".equals(family) || "shr".equals(family) || "ushr".equals(family)) {
            return random.nextInt(32);
        }
        return random.nextInt();
    }

    private static int opcodeOf(String family) {
        if ("add".equals(family)) {
            return Opcodes.IADD;
        }
        if ("sub".equals(family)) {
            return Opcodes.ISUB;
        }
        if ("mul".equals(family)) {
            return Opcodes.IMUL;
        }
        if ("div".equals(family)) {
            return Opcodes.IDIV;
        }
        if ("shl".equals(family)) {
            return Opcodes.ISHL;
        }
        if ("shr".equals(family)) {
            return Opcodes.ISHR;
        }
        if ("ushr".equals(family)) {
            return Opcodes.IUSHR;
        }
        if ("xor".equals(family)) {
            return Opcodes.IXOR;
        }
        if ("or".equals(family)) {
            return Opcodes.IOR;
        }
        if ("and".equals(family)) {
            return Opcodes.IAND;
        }
        if ("neg".equals(family)) {
            return Opcodes.INEG;
        }
        throw new IllegalArgumentException(family);
    }

    // ------------------------------------------------------------------
    // 2. chain semantics
    // ------------------------------------------------------------------

    private static void testStackSemantics() {
        Random random = new Random(0xC0FFEEL);
        for (int iter = 0; iter < 400; iter++) {
            int count = 1 + random.nextInt(12);
            IntMaskStack stack = IntMaskStack.random(random, count, false);
            check(stack.size() == count, "chain has the requested length");
            check(stack.invertible(), "a random encodable chain is invertible");
            check(stack.families().split("\\+").length == count, "families() names every stage");
            for (int k = 0; k < 64; k++) {
                int x = pick(random);
                int encoded = stack.applyInverse(x);
                check(stack.apply(encoded) == x, "chain round trip: " + stack.describe());
            }
            // Forward order must equal the manual fold, and the inverse the
            // reversed fold: this pins the order the donor specifies.
            int value = pick(random);
            int manual = value;
            for (int m = 0; m < count; m++) {
                manual = stack.masks().get(m).apply(manual);
            }
            check(stack.apply(value) == manual, "apply() folds in insertion order");
            int inverse = value;
            for (int m = count - 1; m >= 0; m--) {
                inverse = stack.masks().get(m).applyInverse(inverse);
            }
            check(stack.applyInverse(value) == inverse, "applyInverse() folds in reverse order");
        }

        boolean sawDecodeOnly = false;
        for (int iter = 0; iter < 400 && !sawDecodeOnly; iter++) {
            IntMaskStack wide = IntMaskStack.random(random, 8, true);
            if (wide.invertible()) {
                continue;
            }
            sawDecodeOnly = true;
            boolean refused = false;
            try {
                wide.applyInverse(12345);
            } catch (UnsupportedOperationException expected) {
                refused = true;
            }
            check(refused, "a decode-only chain refuses encoding: " + wide.describe());
        }
        check(sawDecodeOnly, "the wide pool can produce decode-only chains");

        IntMaskStack identity = IntMaskStack.random(random, 0, false);
        check(identity.size() == 0 && identity.dump().size() == 0, "empty chain is the identity");
        check(identity.apply(0x1234) == 0x1234 && identity.applyInverse(0x1234) == 0x1234,
                "empty chain round trips");
        check(identity.describe().indexOf("loopKeys") < 0, "describe() omits an absent key table");

        IntMaskStack handMade = IntMaskStack.of(new AddMask().ofValue(5),
                new XorMask().ofValue(0x0F0F));
        check(handMade.apply(10) == ((10 + 5) ^ 0x0F0F), "of() keeps the given order");
        check(handMade.applyInverse(handMade.apply(10)) == 10, "hand-made chain round trips");
        check(handMade.toString().equals(handMade.describe()), "toString mirrors describe");
        check(handMade.describe().indexOf("add+xor") >= 0, "describe() lists the families");
    }

    // ------------------------------------------------------------------
    // 3. dump() in a real JVM
    // ------------------------------------------------------------------

    private static void testDumpRuntime() throws Exception {
        Random random = new Random(0xBEEFL);
        int total = 0;
        for (int iter = 0; iter < 40; iter++) {
            IntMaskStack stack = IntMaskStack.random(random, 1 + random.nextInt(12), false);
            MethodNode method = method(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "f", "(I)I");
            method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
            method.instructions.add(stack.dump());
            method.instructions.add(new InsnNode(Opcodes.IRETURN));
            Class<?> type = probe(method);
            Method handle = type.getDeclaredMethod("f", int.class);
            handle.setAccessible(true);
            checkNoSlotAccess(stack.dump(), "dump()");
            for (int k = 0; k < 250; k++) {
                int x = pick(random);
                check(invokeInt(handle, x) == stack.apply(x),
                        "dump() equals apply() at runtime: " + stack.describe());
                total++;
            }
        }
        check(total == 10000, "dump() verified over 10000 JVM invocations");
    }

    // ------------------------------------------------------------------
    // 4. dumpWithLocal() in a real JVM
    // ------------------------------------------------------------------

    private static void testDumpWithLocal() throws Exception {
        Random random = new Random(0xD00DL);
        for (int iter = 0; iter < 20; iter++) {
            IntMaskStack stack = IntMaskStack.random(random, 1 + random.nextInt(12), false);
            InsnList spilled = stack.dumpWithLocal(1);
            int stores = 0;
            int loads = 0;
            for (AbstractInsnNode insn = spilled.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn.getOpcode() == Opcodes.ISTORE) {
                    stores++;
                    check(((VarInsnNode) insn).var == 1, "the spill uses the caller's slot");
                } else if (insn.getOpcode() == Opcodes.ILOAD) {
                    loads++;
                }
            }
            check(stores == stack.size() && loads == stack.size(),
                    "dumpWithLocal spills and reloads after every stage");
            MethodNode method = method(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "g", "(I)I");
            method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
            method.instructions.add(spilled);
            method.instructions.add(new InsnNode(Opcodes.IRETURN));
            Class<?> type = probe(method);
            Method handle = type.getDeclaredMethod("g", int.class);
            handle.setAccessible(true);
            for (int k = 0; k < 200; k++) {
                int x = pick(random);
                check(invokeInt(handle, x) == stack.apply(x),
                        "dumpWithLocal() equals apply() at runtime");
            }
        }
    }

    // ------------------------------------------------------------------
    // 5. dumpWithIndex() (the TABLEswitch key table) in a real JVM
    // ------------------------------------------------------------------

    private static void testDumpWithIndex() throws Exception {
        Random random = new Random(0xFACEL);
        for (int iter = 0; iter < 20; iter++) {
            IntMaskStack stack = IntMaskStack.random(random, 1 + random.nextInt(12), false)
                    .withLoopKeys(random);
            int[] keys = stack.loopKeys();
            check(keys != null && keys.length >= IntMaskStack.LOOP_MIN_KEYS
                            && keys.length <= IntMaskStack.LOOP_MAX_KEYS,
                    "loop key table length is 4..32");
            for (int i = 0; i < keys.length; i++) {
                check(keys[i] >= 0 && keys[i] <= 255, "loop keys stay in [0, 255]");
            }

            MethodNode method = method(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "h", "(II)I");
            method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
            method.instructions.add(stack.dumpWithIndex(1));
            method.instructions.add(new InsnNode(Opcodes.IRETURN));
            check(countSwitches(method) == 1, "dumpWithIndex emits exactly one TABLESWITCH");
            Class<?> type = probe(method);
            Method handle = type.getDeclaredMethod("h", int.class, int.class);
            handle.setAccessible(true);
            int[] indices = {
                    0, 1, keys.length - 1, keys.length, keys.length + 1,
                    2 * keys.length + 3, 1000 * keys.length + 7,
                    -1, -keys.length, -keys.length - 1, Integer.MIN_VALUE, Integer.MAX_VALUE
            };
            for (int i = 0; i < indices.length; i++) {
                for (int k = 0; k < 16; k++) {
                    int x = pick(random);
                    int index = indices[i];
                    int expected = x ^ keys[normalize(keys.length, index)];
                    check(invokeInt(handle, x, index) == expected,
                            "dumpWithIndex selects keys[index % " + keys.length + "]");
                }
            }
            for (int k = 0; k < 64; k++) {
                int value = pick(random);
                int index = random.nextInt(keys.length * 3) - keys.length;
                int encoded = stack.applyLoopedInverse(value, index);
                check(stack.applyLooped(encoded, index) == value, "loop chain round trips");
                int looped = stack.applyLooped(value, index);
                check(stack.applyLoopedInverse(looped, index) == value,
                        "applyLoopedInverse is the inverse of applyLooped");
                int raw = stack.applyInverse(value);
                int payload = raw ^ keys[normalize(keys.length, index)];
                check(stack.apply(payload ^ keys[normalize(keys.length, index)]) == value,
                        "a keyed payload decodes back through the chain");
            }

            // dumpLooped() = dump() then the switch key: full decode of an array.
            MethodNode looped = method(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "p", "(II)I");
            looped.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
            looped.instructions.add(stack.dumpLooped(1));
            looped.instructions.add(new InsnNode(Opcodes.IRETURN));
            Class<?> loopedType = probe(looped);
            Method loopedHandle = loopedType.getDeclaredMethod("p", int.class, int.class);
            loopedHandle.setAccessible(true);
            for (int k = 0; k < 128; k++) {
                int x = pick(random);
                int index = random.nextInt(keys.length * 4) - keys.length;
                check(invokeInt(loopedHandle, x, index)
                                == (stack.apply(x) ^ keys[normalize(keys.length, index)]),
                        "dumpLooped() applies the chain and the keyed xor");
            }
        }
        IntMaskStack noLoop = IntMaskStack.random(random, 3, false);
        boolean refused = false;
        try {
            noLoop.dumpWithIndex(0);
        } catch (IllegalStateException expected) {
            refused = true;
        }
        check(refused, "dumpWithIndex refuses a chain without a key table");
    }

    private static int normalize(int length, int index) {
        int slot = index % length;
        return slot < 0 ? 0 : slot;
    }

    private static int countSwitches(MethodNode method) {
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof TableSwitchInsnNode) {
                count++;
            }
        }
        return count;
    }

    // ------------------------------------------------------------------
    // 6. end-to-end: payload encode + call-site decode (the pass integration)
    // ------------------------------------------------------------------

    private static void testCodecEndToEnd() throws Exception {
        final int sites = 50;
        final int key = 0x2B2B2B2B;
        PassContext context = context(0x51EEDL, true, 5);
        ClassNode owner = classNamed("test/IntMaskCodecTarget");
        IntMaskCodec codec = IntMaskCodec.create(context, owner, new Random(0x51EEDL), sites);
        check(codec.enabled(), "codec arms with integer.masks=true and count>0");
        check(codec.siteCount() == sites, "codec builds one chain per site");

        Random random = new Random(0x71E5L);
        int[] values = new int[sites];
        for (int i = 0; i < sites; i++) {
            values[i] = i < EDGES.length ? EDGES[i] : random.nextInt();
        }

        owner.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "payload", "[I", null, null));
        owner.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "key", "I", null, null));

        MethodNode clinit = method(Opcodes.ACC_STATIC, "<clinit>", "()V");
        AsmUtil.pushInt(clinit.instructions, key);
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner.name, "key", "I"));
        AsmUtil.pushInt(clinit.instructions, sites);
        clinit.instructions.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner.name, "payload", "[I"));
        for (int i = 0; i < sites; i++) {
            clinit.instructions.add(
                    new FieldInsnNode(Opcodes.GETSTATIC, owner.name, "payload", "[I"));
            AsmUtil.pushInt(clinit.instructions, i);
            // The payload carries encode(original) masked by the table key; the
            // call site's existing "^ key" then hands encode(original) to the
            // decode chain, exactly like the donor's numbers.add(...).
            AsmUtil.pushInt(clinit.instructions, codec.encode(values[i], i) ^ key);
            clinit.instructions.add(new InsnNode(Opcodes.IASTORE));
        }
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        owner.methods.add(clinit);

        for (int i = 0; i < sites; i++) {
            MethodNode accessor = method(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m" + i, "()I");
            accessor.instructions.add(
                    new FieldInsnNode(Opcodes.GETSTATIC, owner.name, "payload", "[I"));
            AsmUtil.pushInt(accessor.instructions, i);
            accessor.instructions.add(new InsnNode(Opcodes.IALOAD));
            accessor.instructions.add(
                    new FieldInsnNode(Opcodes.GETSTATIC, owner.name, "key", "I"));
            accessor.instructions.add(new InsnNode(Opcodes.IXOR));
            InsnList decode = codec.emitDecode(i);
            checkNoSlotAccess(decode, "emitDecode(" + i + ")");
            checkNoBranches(decode, "emitDecode(" + i + ")");
            check(decode.size() == codec.stack(i).size() * 2,
                    "emitDecode emits two nodes per stage");
            accessor.instructions.add(decode);
            accessor.instructions.add(new InsnNode(Opcodes.IRETURN));
            owner.methods.add(accessor);
        }

        byte[] bytes = write(owner);
        verify(bytes, "codec target");
        Class<?> type = define(owner.name, bytes);
        for (int i = 0; i < sites; i++) {
            Method method = type.getDeclaredMethod("m" + i);
            method.setAccessible(true);
            check(invokeInt(method) == values[i], "site " + i + " decodes back to " + values[i]);
        }

        Field payload = type.getDeclaredField("payload");
        payload.setAccessible(true);
        int[] stored = (int[]) payload.get(null);
        int masked = 0;
        for (int i = 0; i < sites; i++) {
            if (stored[i] != (values[i] ^ key)) {
                masked++;
            }
        }
        check(masked > sites / 2,
                "the payload really stores masked values (" + masked + "/" + sites + ")");

        check(codec.stats().sites() == sites, "stats count every site");
        check(codec.stats().total() >= sites * IntMaskCodec.DEFAULT_MIN_MASKS,
                "stats count every stage");
        check(codec.stats().familiesText().length() > 0, "stats record the family mix");
        codec.stats().report(context);
        Stats stats = context.stats();
        check(stats.snapshot().get("integer.masks.sites").longValue() == sites, "sites stat");
        check(stats.snapshot().get("integer.masks.total").longValue() >= sites, "total stat");
        check(stats.text("integer.masks.families") != null, "families text stat");
        check("mask".equals(codec.statsKey()), "statsKey names the plain shape");
        check(codec.describeSite(0).startsWith("site=0 masks="), "describeSite is informative");

        // Disabled codec: identity, no instructions, nothing to emit.
        PassContext off = context(0x51EEDL, false, 5);
        IntMaskCodec disabled = IntMaskCodec.create(off, owner, new Random(1L), sites);
        check(!disabled.enabled(), "the layer stays off unless both options are set");
        check(disabled.encode(12345, 7) == 12345, "a disabled codec encodes as identity");
        check(disabled.encodeLong(0x1122334455667788L, 7) == 0x1122334455667788L,
                "a disabled codec leaves longs alone");
        check(disabled.emitDecode(7).size() == 0, "a disabled codec emits no instructions");
        check(disabled.emitDecodeLong(7).size() == 0, "a disabled codec emits no long instructions");
        PassContext countOff = context(0x51EEDL, true, 0);
        check(!IntMaskCodec.create(countOff, owner, new Random(1L), 4).enabled(),
                "integer.masks.count=0 keeps the layer off");

        // An off codec must not consume the class stream: otherwise merely
        // constructing it would shift every later draw of an opted-out build.
        Random untouchedStream = new Random(99L);
        Random referenceStream = new Random(99L);
        IntMaskCodec.create(off, owner, untouchedStream, 10);
        check(untouchedStream.nextLong() == referenceStream.nextLong(),
                "an off codec leaves the class stream untouched");

        UmbraConfig config = context.config();
        check(config.optionBool("integer.masks", false), "option plumbing: integer.masks");
        check(config.optionInt("integer.masks.count", 0) == 5, "option plumbing: count");
        check(config.optionBool("integer.masks.random", true),
                "option plumbing: random size defaults to true");
        check(!config.optionBool("integer.masks.noninvertible", false),
                "option plumbing: non-invertible draws default to false");
    }

    // ------------------------------------------------------------------
    // 7. longs: payload halves and the long-domain decode
    // ------------------------------------------------------------------

    private static void testCodecLong() throws Exception {
        final int sites = 8;
        final long key = 0x0123456789ABCDEFL;
        PassContext context = context(0x10A66L, true, 6);
        ClassNode owner = classNamed("test/IntMaskLongTarget");
        IntMaskCodec codec = IntMaskCodec.create(context, owner, new Random(0x10A66L), sites);
        long[] values = {
                0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE, 0x1122334455667788L,
                -0x0123456789ABCDEFL, 42L
        };
        owner.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "payload", "[J", null, null));
        owner.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "key", "J", null, null));
        MethodNode clinit = method(Opcodes.ACC_STATIC, "<clinit>", "()V");
        clinit.instructions.add(new LdcInsnNode(Long.valueOf(key)));
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner.name, "key", "J"));
        AsmUtil.pushInt(clinit.instructions, sites);
        clinit.instructions.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG));
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner.name, "payload", "[J"));
        for (int i = 0; i < sites; i++) {
            long original = values[i];
            long encoded = codec.encodeLong(original, i) ^ key;
            long halves = ((((long) codec.encodeLongHigh(original, i)) << 32)
                    | (codec.encodeLongLow(original, i) & 0xFFFFFFFFL)) ^ key;
            check(halves == encoded, "encodeLongLow/High are the halves of encodeLong");
            clinit.instructions.add(
                    new FieldInsnNode(Opcodes.GETSTATIC, owner.name, "payload", "[J"));
            AsmUtil.pushInt(clinit.instructions, i);
            clinit.instructions.add(new LdcInsnNode(Long.valueOf(encoded)));
            clinit.instructions.add(new InsnNode(Opcodes.LASTORE));
        }
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        owner.methods.add(clinit);
        for (int i = 0; i < sites; i++) {
            MethodNode accessor = method(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "n" + i, "()J");
            accessor.instructions.add(
                    new FieldInsnNode(Opcodes.GETSTATIC, owner.name, "payload", "[J"));
            AsmUtil.pushInt(accessor.instructions, i);
            accessor.instructions.add(new InsnNode(Opcodes.LALOAD));
            accessor.instructions.add(
                    new FieldInsnNode(Opcodes.GETSTATIC, owner.name, "key", "J"));
            accessor.instructions.add(new InsnNode(Opcodes.LXOR));
            InsnList decode = codec.emitDecodeLong(i);
            checkNoSlotAccess(decode, "emitDecodeLong(" + i + ")");
            checkNoBranches(decode, "emitDecodeLong(" + i + ")");
            accessor.instructions.add(decode);
            accessor.instructions.add(new InsnNode(Opcodes.LRETURN));
            owner.methods.add(accessor);
        }
        byte[] bytes = write(owner);
        verify(bytes, "long target");
        Class<?> type = define(owner.name, bytes);
        for (int i = 0; i < sites; i++) {
            Method method = type.getDeclaredMethod("n" + i);
            method.setAccessible(true);
            check(invokeLong(method) == values[i], "long site " + i + " decodes back");
        }
    }

    // ------------------------------------------------------------------
    // 8. determinism
    // ------------------------------------------------------------------

    private static void testCodecDeterminism() throws Exception {
        PassContext context = context(0xDEADBEEFL, true, 5);
        ClassNode owner = classNamed("test/IntMaskDet");
        final int sites = 64;
        IntMaskCodec a = IntMaskCodec.create(context, owner, new Random(424242L), sites);
        IntMaskCodec b = IntMaskCodec.create(context, owner, new Random(424242L), sites);
        for (int i = 0; i < sites; i++) {
            check(a.encode(0x13579BDF, i) == b.encode(0x13579BDF, i),
                    "same seed, same encoding at site " + i);
        }
        check(Arrays.equals(decodeClass(a, sites), decodeClass(b, sites)),
                "same seed, same emitted bytes");
        IntMaskCodec other = IntMaskCodec.create(context, owner, new Random(424243L), sites);
        check(!Arrays.equals(decodeClass(a, sites), decodeClass(other, sites)),
                "a different seed changes the emitted bytes");

        // The eager build means the caller's walk order cannot leak into bytes.
        IntMaskCodec reordered = IntMaskCodec.create(context, owner, new Random(424242L), sites);
        int[] reversed = new int[sites];
        for (int i = sites - 1; i >= 0; i--) {
            reversed[i] = reordered.encode(0x13579BDF, i);
        }
        for (int i = 0; i < sites; i++) {
            check(reversed[i] == a.encode(0x13579BDF, i),
                    "call order does not change site " + i);
        }

        // Sites past siteCount derive an independent but stable stream.
        check(a.encode(7, 500) == b.encode(7, 500), "overflow sites are deterministic");
        check(a.encode(7, 500) != a.encode(7, 501), "overflow sites keep their own chain");
        check(a.encode(7, 500) == a.encode(7, 500) && a.encode(7, 500) == a.encode(7, 500),
                "repeated encode calls agree");
        check(a.encodeLong(0x0123456789ABCDEFL, 3) == b.encodeLong(0x0123456789ABCDEFL, 3),
                "long encoding is deterministic");
    }

    private static byte[] decodeClass(IntMaskCodec codec, int sites) {
        ClassNode node = classNamed("test/IntMaskShape");
        for (int i = 0; i < sites; i++) {
            MethodNode method = method(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "f" + i, "(I)I");
            method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
            method.instructions.add(codec.emitDecode(i));
            method.instructions.add(new InsnNode(Opcodes.IRETURN));
            node.methods.add(method);
        }
        return write(node);
    }

    // ------------------------------------------------------------------
    // harness helpers
    // ------------------------------------------------------------------

    private static PassContext context(long seed, boolean masks, int count) {
        try {
            UmbraConfig config = new UmbraConfig.Builder()
                    .input(Paths.get("in.jar"))
                    .output(Paths.get("out.jar"))
                    .seed(seed)
                    .option("integer.masks", String.valueOf(masks))
                    .option("integer.masks.count", String.valueOf(count))
                    .build();
            return new PassContext(config, new ClassPool(), new Hierarchy(),
                    new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(), false, false),
                    new DefaultRuntimeSupport(), new MappingSet(), new Stats(),
                    new Log(null, false), new Random(seed), ProgressListener.NONE);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ClassNode classNamed(String internalName) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = internalName;
        node.superName = "java/lang/Object";
        return node;
    }

    private static MethodNode method(int access, String name, String desc) {
        return new MethodNode(access, name, desc, null, null);
    }

    private static Class<?> probe(MethodNode method) throws Exception {
        String name = "test/IntMaskProbe" + (probes++);
        ClassNode node = classNamed(name);
        node.methods.add(method);
        byte[] bytes = write(node);
        verify(bytes, name);
        return define(name, bytes);
    }

    private static byte[] write(ClassNode node) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
            @Override
            protected String getCommonSuperClass(String a, String b) {
                return "java/lang/Object";
            }
        };
        node.accept(writer);
        return writer.toByteArray();
    }

    private static void verify(byte[] bytes, String what) {
        StringWriter writer = new StringWriter();
        CheckClassAdapter.verify(new ClassReader(bytes), false, new PrintWriter(writer));
        String errors = writer.toString();
        check(errors.isEmpty(), "CheckClassAdapter " + what + ": " + errors);
    }

    private static Class<?> define(String internalName, byte[] bytes) throws Exception {
        final Map<String, byte[]> classes = new HashMap<String, byte[]>();
        classes.put(internalName.replace('/', '.'), bytes);
        ClassLoader loader = new ClassLoader(IntMaskTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] data = classes.get(name);
                if (data != null) {
                    return defineClass(name, data, 0, data.length);
                }
                return super.findClass(name);
            }
        };
        return Class.forName(internalName.replace('/', '.'), true, loader);
    }

    private static int invokeInt(Method method) throws Exception {
        return invokeInt(method, new Object[0]);
    }

    private static int invokeInt(Method method, int argument) throws Exception {
        Object[] args = { Integer.valueOf(argument) };
        return invokeInt(method, args);
    }

    private static int invokeInt(Method method, int first, int second) throws Exception {
        Object[] args = { Integer.valueOf(first), Integer.valueOf(second) };
        return invokeInt(method, args);
    }

    private static int invokeInt(Method method, Object[] args) throws Exception {
        try {
            return ((Integer) method.invoke(null, args)).intValue();
        } catch (InvocationTargetException e) {
            throw new AssertionError("probe threw " + e.getCause(), e.getCause());
        }
    }

    private static long invokeLong(Method method) throws Exception {
        try {
            return ((Long) method.invoke(null)).longValue();
        } catch (InvocationTargetException e) {
            throw new AssertionError("probe threw " + e.getCause(), e.getCause());
        }
    }

    private static int pick(Random random) {
        int roll = random.nextInt(4);
        if (roll == 0) {
            return EDGES[random.nextInt(EDGES.length)];
        }
        return random.nextInt();
    }

    private static void checkNoSlotAccess(InsnList insns, String what) {
        for (AbstractInsnNode insn = insns.getFirst(); insn != null; insn = insn.getNext()) {
            check(!(insn instanceof VarInsnNode), what + " must not touch a local");
            check(!(insn instanceof LabelNode), what + " must not introduce a label");
        }
    }

    private static void checkNoBranches(InsnList insns, String what) {
        for (AbstractInsnNode insn = insns.getFirst(); insn != null; insn = insn.getNext()) {
            check(!(insn instanceof JumpInsnNode), what + " must not branch");
            check(!(insn instanceof TableSwitchInsnNode), what + " must not switch");
        }
    }

    private static void checkNoPseudo(InsnList insns, String what) {
        for (AbstractInsnNode insn = insns.getFirst(); insn != null; insn = insn.getNext()) {
            check(insn.getOpcode() >= 0, what + " must not contain pseudo instructions");
        }
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}
