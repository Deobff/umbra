package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.IntegerEncryptionPass;
import io.umbra.core.pass.impl.NumberHashPass;
import io.umbra.core.pass.impl.numberhash.Codecs;
import io.umbra.core.pass.impl.numberhash.Hashes;
import io.umbra.core.pass.impl.numberhash.NumberHashCodec;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Self-test for {@link NumberHashPass}.
 *
 * <p>Plain-main harness (no JUnit): a non-zero exit fails the build. It covers
 * the five things the pass contract asks for - codec algebra over the whole int
 * domain, a real JVM executing the transformed class, coexistence with the
 * integer-encryption layer that runs right after it, determinism for a fixed
 * seed, and the {@code JSR}/{@code RET} rollback path - plus a record of which
 * reference formulas are bijections and which are restricted (see {@link Hashes}).</p>
 */
public final class NumberHashTest {

    private static final String TARGET = "test/NumberHashTarget";
    private static final String TARGET_DOTTED = "test.NumberHashTarget";

    private static final String[] CODECS = {
            Codecs.SKID, Codecs.BITWISE, Codecs.INTELLIJ, Codecs.LEGACY,
            Codecs.XOR, Codecs.RANDOMSHIFT, Codecs.VM
    };

    private static int checks;

    private NumberHashTest() {
    }

    public static void main(String[] args) throws Exception {
        startWatchdog();
        testCodecRoundTrip();
        testStrictFormulas();
        testRealJvm(true);
        testRealJvm(false);
        testLongSites();
        testSingleSiteRemoval();
        testCoexistWithIntegerEncryption();
        testDeterminism();
        testJsrRollback();
        System.out.println("NumberHashTest: " + checks + " checks passed");
    }

    private static void startWatchdog() {
        final long timeout = Long.parseLong(System.getProperty("umbra.numberhashtest.watchdog", "180000"));
        Thread watchdog = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(timeout);
                } catch (InterruptedException ignored) {
                    return;
                }
                System.err.println("NumberHashTest WATCHDOG after " + timeout + "ms");
                Map<Thread, StackTraceElement[]> traces = Thread.getAllStackTraces();
                for (Map.Entry<Thread, StackTraceElement[]> entry : traces.entrySet()) {
                    System.err.println("THREAD " + entry.getKey().getName());
                    for (StackTraceElement element : entry.getValue()) {
                        System.err.println("  at " + element);
                    }
                }
                Runtime.getRuntime().halt(3);
            }
        }, "numberhash-test-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    // ------------------------------------------------------------------
    // 1. codec algebra
    // ------------------------------------------------------------------

    private static void testCodecRoundTrip() {
        System.out.println("NumberHashTest: codec round-trip");
        int[] interesting = {
                Integer.MIN_VALUE, Integer.MIN_VALUE + 1, -65537, -65536, -32769, -32768, -257,
                -256, -129, -128, -2, -1, 0, 1, 2, 127, 128, 129, 255, 256, 257, 32767, 32768,
                65535, 65536, 65537, Integer.MAX_VALUE - 1, Integer.MAX_VALUE
        };
        Random random = new Random(0x5EED5EEDL);
        for (int c = 0; c < CODECS.length; c++) {
            String name = CODECS[c];
            int checked = 0;
            for (int instance = 0; instance < 4; instance++) {
                NumberHashCodec codec = Codecs.create(name, new Random(0x9E37L * (instance + 1)));
                check(codec.bijective(), name + " must report itself bijective");
                for (int i = 0; i < interesting.length; i++) {
                    int value = interesting[i];
                    check(codec.decode(codec.encode(value)) == value,
                            name + " must round-trip " + value);
                    checked++;
                }
                for (int i = 0; i < 200000; i++) {
                    int value = random.nextInt();
                    if (codec.decode(codec.encode(value)) != value) {
                        throw new AssertionError(name + " round-trip failed for " + value);
                    }
                }
                check(true, name + " round-tripped 200000 random values (instance " + instance + ")");
                checked++;
            }
            check(checked > 0, name + " exercised");
        }

        // A denser sweep: 4M values per codec, which covers every low-bit pattern
        // that a rotation or a byte-table step can depend on.
        int sweep = 1 << 22;
        for (int c = 0; c < CODECS.length; c++) {
            NumberHashCodec codec = Codecs.create(CODECS[c], new Random(1234L + c));
            int step = 0x9E3779B9;
            int value = 1;
            for (int i = 0; i < sweep; i++) {
                value += step;
                if (codec.decode(codec.encode(value)) != value) {
                    throw new AssertionError(CODECS[c] + " sweep failed for " + value);
                }
            }
            check(true, CODECS[c] + " swept " + sweep + " values");
        }
    }

    // ------------------------------------------------------------------
    // 2. the reference formulas and their real domains
    // ------------------------------------------------------------------

    private static void testStrictFormulas() {
        System.out.println("NumberHashTest: reference hash domains");
        Random random = new Random(0xDEADL);

        // skid / intellij: an involution, therefore a bijection.
        for (int i = 0; i < 200000; i++) {
            int value = random.nextInt();
            if (Hashes.skidStrict(Hashes.skidStrict(value)) != value) {
                throw new AssertionError("skid hash must be an involution");
            }
        }
        check(Hashes.skidStrict(Hashes.skidStrict(0x12345678)) == 0x12345678,
                "skid/IntelliJ hash is an involution");
        check(Hashes.intellijStrict(0x7ABCDEF1) == Hashes.skidStrict(0x7ABCDEF1),
                "IntelliJ and the reference share the reference formula");

        // The reference emitted shift 29 while its constant side used 16.
        check(Hashes.skidDonorEmitted(0x20000000) != Hashes.skidStrict(0x20000000),
                "reference SkidHash emitted a different shift than it hashed with");

        // bitwise: agrees with a real rotate only for non-negative inputs.
        check(Hashes.bitwiseStrict(Integer.MAX_VALUE) == Hashes.rotateLeft3(Integer.MAX_VALUE),
                "bitwise hash matches rotateLeft on the non-negative domain");
        check(Hashes.bitwiseStrict(Integer.MIN_VALUE) != Hashes.rotateLeft3(Integer.MIN_VALUE),
                "bitwise hash collapses Integer.MIN_VALUE (arithmetic shift)");
        int[] inputs = new int[1 << 16];
        int[] hashed = new int[inputs.length];
        for (int i = 0; i < inputs.length; i++) {
            inputs[i] = Integer.MIN_VALUE + i;
            hashed[i] = Hashes.bitwiseStrict(inputs[i]);
        }
        int[] collision = Hashes.findCollision(inputs, hashed);
        check(collision != null,
                "bitwise hash is not injective on the negative domain (collision "
                        + (collision == null ? "none" : collision[0] + "/" + collision[1]) + ")");

        // legacy: zero-guarded and non-injective.
        check(Hashes.legacyStrict(0) == 0, "legacy hash keeps its x == 0 guard");
        check(Hashes.legacyStrict(1) == Hashes.legacyStrict(0),
                "legacy hash collides at 0 and 1 (it is not a codec)");

        // Every codec in the catalogue must be a bijection on the full domain.
        for (int c = 0; c < CODECS.length; c++) {
            check(Codecs.create(CODECS[c], new Random(c)).bijective(),
                    CODECS[c] + " codec is full-domain");
        }
        check(Codecs.MIX.equals(Codecs.canonical("nonsense")), "unknown codec falls back to mix");
        check(Codecs.LEGACY.equals(Codecs.canonical(" LEGACY ")), "codec names are trimmed and lower-cased");
    }

    // ------------------------------------------------------------------
    // 3. real JVM: define the transformed class and call it
    // ------------------------------------------------------------------

    private static void testRealJvm(boolean spill) throws Exception {
        System.out.println("NumberHashTest: real JVM (spill=" + spill + ")");
        int[] values = boundaryValues(2000);
        UmbraConfig config = config(20240101L,
                NumberHashPass.OPTION_ENABLED, "true",
                NumberHashPass.OPTION_RATE, "100",
                NumberHashPass.OPTION_MAX_PER_METHOD, "5000",
                NumberHashPass.OPTION_CODEC, "mix",
                NumberHashPass.OPTION_SPILL, String.valueOf(spill));

        Stats stats = new Stats();
        ClassNode node = buildTarget(values, null);
        int instructionsBefore = instructionCount(node, "values");
        PassContext context = context(config, node, stats);
        NumberHashPass pass = new NumberHashPass();
        check(pass.order() == 79, "number-hash runs before integer encryption");
        check("number-hash".equals(pass.name()), "pass name");
        pass.run(context);

        long sites = value(stats, "numberHash.sites");
        check(sites >= values.length, "every constant site is rewritten (sites=" + sites + ")");
        check(value(stats, "numberHash.methods") >= 1, "at least one method transformed");
        check(value(stats, "numberHash.maxPerMethodSkipped") == 0, "no site hit the per-method cap");
        long codecTotal = 0;
        for (int c = 0; c < CODECS.length; c++) {
            codecTotal += value(stats, "numberHash.codec." + CODECS[c]);
        }
        check(codecTotal == sites, "per-codec statistics add up to the site count");

        byte[] bytes = serialize(node);
        int[] actual = (int[]) invoke(load(bytes), "values");
        check(Arrays.equals(values, actual),
                "JVM returns the original constants" + describeMismatch(values, actual));
        int growth = instructionCount(node, "values") - instructionsBefore;
        check(growth >= values.length,
                "a decoder was spliced at every site (growth=" + growth + " for "
                        + values.length + " constants)");
    }

    private static void testLongSites() throws Exception {
        System.out.println("NumberHashTest: long constants");
        long[] longs = {
                0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE, 0x123456789ABCDEFL,
                -0x0123456789ABCDEFL, 1L << 40, -(1L << 40)
        };
        UmbraConfig config = config(777L,
                NumberHashPass.OPTION_ENABLED, "true",
                NumberHashPass.OPTION_RATE, "100",
                NumberHashPass.OPTION_MAX_PER_METHOD, "5000",
                NumberHashPass.OPTION_CODEC, Codecs.VM,
                NumberHashPass.OPTION_INCLUDE_LONG, "true");
        Stats stats = new Stats();
        ClassNode node = buildTarget(new int[] { 1, 2, 3 }, longs);
        NumberHashPass pass = new NumberHashPass();
        pass.run(context(config, node, stats));
        check(value(stats, "numberHash.longs") >= longs.length,
                "long sites are rewritten when includeLong is on ("
                        + value(stats, "numberHash.longs") + ")");
        byte[] bytes = serialize(node);
        long[] actual = (long[]) invoke(load(bytes), "longValues");
        check(Arrays.equals(longs, actual), "JVM returns the original long constants");

        // Off by default: a long must survive untouched.
        UmbraConfig off = config(777L,
                NumberHashPass.OPTION_ENABLED, "true",
                NumberHashPass.OPTION_MAX_PER_METHOD, "5000");
        Stats offStats = new Stats();
        ClassNode offNode = buildTarget(new int[] { 1, 2, 3 }, longs);
        pass.run(context(off, offNode, offStats));
        check(value(offStats, "numberHash.longs") == 0, "longs are skipped unless includeLong is set");
        long[] offActual = (long[]) invoke(load(serialize(offNode)), "longValues");
        check(Arrays.equals(longs, offActual), "untouched longs still round-trip");
    }

    // ------------------------------------------------------------------
    // 4. coexistence with the integer layer that runs at order 80
    // ------------------------------------------------------------------

    private static void testCoexistWithIntegerEncryption() throws Exception {
        System.out.println("NumberHashTest: coexistence with integer-encryption");
        int[] values = boundaryValues(600);
        UmbraConfig config = new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"))
                .seed(424242L)
                .integerEncryption(new UmbraConfig.IntegerEncryptionOptions(true, false))
                .option("integer.shape", "array")
                .option(NumberHashPass.OPTION_ENABLED, "true")
                .option(NumberHashPass.OPTION_RATE, "50")
                .option(NumberHashPass.OPTION_MAX_PER_METHOD, "5000")
                .option(NumberHashPass.OPTION_CODEC, "mix")
                .build();

        Stats stats = new Stats();
        ClassNode node = buildTarget(values, null);
        PassContext context = context(config, node, stats);
        new NumberHashPass().run(context);
        long hashSites = value(stats, "numberHash.sites");
        check(hashSites > 0, "number-hash hit sites before the integer layer (" + hashSites + ")");

        IntegerEncryptionPass integer = new IntegerEncryptionPass();
        check(integer.order() == 80 && integer.enabled(context),
                "integer-encryption is enabled and runs after number-hash");
        integer.run(context);
        long integerSites = value(stats, "constants.obfuscated");
        check(integerSites > 0, "integer-encryption still found literals to encrypt (" + integerSites + ")");

        byte[] bytes = serialize(node);
        int[] actual = (int[]) invoke(load(bytes), "values");
        check(Arrays.equals(values, actual),
                "both layers compose: the JVM still returns the original constants"
                        + describeMismatch(values, actual));
    }

    // ------------------------------------------------------------------
    // 5. determinism
    // ------------------------------------------------------------------

    private static void testDeterminism() throws Exception {
        System.out.println("NumberHashTest: determinism");
        int[] values = boundaryValues(400);
        UmbraConfig config = config(99991L,
                NumberHashPass.OPTION_ENABLED, "true",
                NumberHashPass.OPTION_CODEC, "mix",
                NumberHashPass.OPTION_MAX_PER_METHOD, "5000");
        ClassNode first = buildTarget(values, null);
        Stats firstStats = new Stats();
        new NumberHashPass().run(context(config, first, firstStats));
        ClassNode second = buildTarget(values, null);
        Stats secondStats = new Stats();
        new NumberHashPass().run(context(config, second, secondStats));

        check(Arrays.equals(serialize(first), serialize(second)),
                "same seed produces identical bytes");
        check(value(firstStats, "numberHash.sites") == value(secondStats, "numberHash.sites"),
                "same seed produces the same site count");
    }

    // ------------------------------------------------------------------
    // 6. JSR/RET rollback
    // ------------------------------------------------------------------

    private static void testJsrRollback() throws Exception {
        System.out.println("NumberHashTest: JSR/RET rollback");
        ClassNode node = buildSubroutineTarget();
        List<Integer> before = opcodes(method(node, "withSubroutine"));
        UmbraConfig config = config(5L,
                NumberHashPass.OPTION_ENABLED, "true",
                NumberHashPass.OPTION_CODEC, "mix",
                NumberHashPass.OPTION_MAX_PER_METHOD, "5000");
        Stats stats = new Stats();
        new NumberHashPass().run(context(config, node, stats));

        check(value(stats, "numberHash.skipped") >= 1, "the JSR method is skipped");
        check(opcodes(method(node, "withSubroutine")).equals(before),
                "the JSR method keeps its bytecode");
        check(value(stats, "numberHash.sites") > 0, "the rest of the class is still transformed");
        byte[] bytes = serialize(node);
        Class<?> type = load(bytes, false);
        check(((Integer) type.getMethod("normal").invoke(null)).intValue() == 424242,
                "the transformed sibling method still returns its value");
        check(((Integer) type.getMethod("withSubroutine").invoke(null)).intValue() == 5,
                "the untouched JSR method still runs");
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /**
     * Boundary probes used both as constants and as the "did the literal
     * survive?" probe set. They are deliberately values that a decoder's own
     * program constants (0xFF, -256, 16, 32, a rotation amount) cannot
     * coincidentally equal, so a survivor means the site was left alone.
     */
    private static int[] fixedProbes() {
        return new int[] {
                Integer.MIN_VALUE, Integer.MIN_VALUE + 1, Integer.MAX_VALUE,
                Integer.MAX_VALUE - 1, Byte.MIN_VALUE, Byte.MAX_VALUE, Short.MIN_VALUE,
                Short.MAX_VALUE, 0xFFFFFF00, 0xFFFF0000, 0x00010000, 0x0000FFFF,
                123456789, -987654321, 0xCAFEBABE, 0x5A5A5A5A
        };
    }

    private static int[] boundaryValues(int count) {
        int[] fixed = fixedProbes();
        int[] values = new int[count];
        Random random = new Random(0xC0FFEEL);
        for (int i = 0; i < count; i++) {
            if (i < fixed.length) {
                values[i] = fixed[i];
            } else {
                switch (i % 3) {
                    case 0:
                        values[i] = random.nextInt();
                        break;
                    case 1:
                        values[i] = (int) ((i + 1L) * 2654435761L);
                        break;
                    default:
                        values[i] = i - count / 2;
                        break;
                }
            }
        }
        return values;
    }

    private static ClassNode buildTarget(int[] values, long[] longs) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = TARGET;
        node.superName = "java/lang/Object";
        node.methods = new ArrayList<MethodNode>();

        MethodNode init = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        init.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object",
                "<init>", "()V", false));
        init.instructions.add(new InsnNode(Opcodes.RETURN));
        init.maxStack = 1;
        init.maxLocals = 1;
        node.methods.add(init);

        MethodNode array = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "values",
                "()[I", null, null);
        AsmUtil.pushInt(array.instructions, values.length);
        array.instructions.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        array.instructions.add(new VarInsnNode(Opcodes.ASTORE, 0));
        for (int i = 0; i < values.length; i++) {
            array.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            AsmUtil.pushInt(array.instructions, i);
            AsmUtil.pushInt(array.instructions, values[i]);
            array.instructions.add(new InsnNode(Opcodes.IASTORE));
        }
        array.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        array.instructions.add(new InsnNode(Opcodes.ARETURN));
        array.maxStack = 3;
        array.maxLocals = 1;
        node.methods.add(array);

        MethodNode expression = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "expression",
                "()I", null, null);
        AsmUtil.pushInt(expression.instructions, 12345);
        AsmUtil.pushInt(expression.instructions, 67890);
        expression.instructions.add(new InsnNode(Opcodes.IADD));
        AsmUtil.pushInt(expression.instructions, 3);
        expression.instructions.add(new InsnNode(Opcodes.IMUL));
        AsmUtil.pushInt(expression.instructions, 1);
        expression.instructions.add(new InsnNode(Opcodes.ISUB));
        expression.instructions.add(new InsnNode(Opcodes.IRETURN));
        expression.maxStack = 2;
        expression.maxLocals = 0;
        node.methods.add(expression);

        if (longs != null) {
            MethodNode longArray = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "longValues",
                    "()[J", null, null);
            AsmUtil.pushInt(longArray.instructions, longs.length);
            longArray.instructions.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG));
            longArray.instructions.add(new VarInsnNode(Opcodes.ASTORE, 0));
            for (int i = 0; i < longs.length; i++) {
                longArray.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
                AsmUtil.pushInt(longArray.instructions, i);
                longArray.instructions.add(new LdcInsnNode(Long.valueOf(longs[i])));
                longArray.instructions.add(new InsnNode(Opcodes.LASTORE));
            }
            longArray.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            longArray.instructions.add(new InsnNode(Opcodes.ARETURN));
            longArray.maxStack = 4;
            longArray.maxLocals = 1;
            node.methods.add(longArray);
        }
        return node;
    }

    private static ClassNode buildSubroutineTarget() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_5;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = TARGET;
        node.superName = "java/lang/Object";
        node.methods = new ArrayList<MethodNode>();

        MethodNode init = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        init.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object",
                "<init>", "()V", false));
        init.instructions.add(new InsnNode(Opcodes.RETURN));
        init.maxStack = 1;
        init.maxLocals = 1;
        node.methods.add(init);

        MethodNode normal = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "normal",
                "()I", null, null);
        AsmUtil.pushInt(normal.instructions, 424242);
        normal.instructions.add(new InsnNode(Opcodes.IRETURN));
        normal.maxStack = 1;
        normal.maxLocals = 0;
        node.methods.add(normal);

        MethodNode jsr = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "withSubroutine",
                "()I", null, null);
        LabelNode subroutine = new LabelNode();
        jsr.instructions.add(new JumpInsnNode(Opcodes.JSR, subroutine));
        AsmUtil.pushInt(jsr.instructions, 5);
        jsr.instructions.add(new InsnNode(Opcodes.IRETURN));
        jsr.instructions.add(subroutine);
        jsr.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
        jsr.instructions.add(new VarInsnNode(Opcodes.RET, 1));
        jsr.maxStack = 1;
        jsr.maxLocals = 2;
        node.methods.add(jsr);
        return node;
    }

    private static UmbraConfig config(long seed, String... options) throws Exception {
        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"))
                .seed(seed);
        for (int i = 0; i + 1 < options.length; i += 2) {
            builder.option(options[i], options[i + 1]);
        }
        return builder.build();
    }

    private static PassContext context(UmbraConfig config, ClassNode node, Stats stats) {
        ClassPool pool = new ClassPool();
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        byte[] original;
        try {
            original = UmbraClassWriter.toBytesPreservingFrames(node, hierarchy);
        } catch (RuntimeException ignored) {
            // A class with JSR/RET cannot always be re-serialized in preserve mode;
            // the stored original bytes are informational for this test.
            original = new byte[0];
        }
        pool.putClass(node.name + ".class", original, node);
        DefaultRuleSet rules = new DefaultRuleSet(new ArrayList<String>(),
                new ArrayList<String>(), false, false);
        return new PassContext(config, pool, hierarchy, rules, new DefaultRuntimeSupport(),
                new MappingSet(), stats, new Log(null, false), new Random(config.seed()),
                ProgressListener.NONE);
    }

    private static byte[] serialize(ClassNode node) {
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        return UmbraClassWriter.toBytes(node, hierarchy);
    }

    private static Class<?> load(byte[] bytes) {
        return load(bytes, true);
    }

    /**
     * @param checkAdapter run ASM's static analyzer first. Disabled for the
     *                     {@code JSR}/{@code RET} class: ASM's analyzer rejects
     *                     subroutines, while the real JVM verifier still accepts
     *                     them below version 51, which is exactly what that test
     *                     is about.
     */
    private static Class<?> load(byte[] bytes, boolean checkAdapter) {
        if (checkAdapter) {
            StringWriter writer = new StringWriter();
            CheckClassAdapter.verify(new ClassReader(bytes), false, new PrintWriter(writer));
            String errors = writer.toString();
            check(errors.isEmpty(), "CheckClassAdapter: " + errors);
        }
        final Map<String, byte[]> classes = new HashMap<String, byte[]>();
        classes.put(TARGET_DOTTED, bytes);
        ClassLoader loader = new ClassLoader(NumberHashTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] data = classes.get(name);
                if (data != null) {
                    return defineClass(name, data, 0, data.length);
                }
                return super.findClass(name);
            }
        };
        try {
            Class<?> type = Class.forName(TARGET_DOTTED, true, loader);
            type.getDeclaredMethods();
            return type;
        } catch (ClassNotFoundException e) {
            throw new AssertionError("cannot load the transformed class", e);
        }
    }

    private static Object invoke(Class<?> type, String name) throws Exception {
        Method method = type.getMethod(name);
        method.setAccessible(true);
        return method.invoke(null);
    }

    private static MethodNode method(ClassNode node, String name) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name)) {
                return method;
            }
        }
        throw new AssertionError("method not found: " + name);
    }

    private static List<Integer> opcodes(MethodNode method) {
        List<Integer> opcodes = new ArrayList<Integer>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            opcodes.add(Integer.valueOf(insn.getOpcode()));
        }
        return opcodes;
    }

    /**
     * A single, unambiguous site: with one codec and one constant, the literal
     * must be gone from the whole class, because nothing else can reintroduce
     * it. This is the precise version of "the pool no longer carries the value"
     * (the mixed-codec test cannot assert it directly: a rotation codec maps
     * small round numbers onto the very boundary values used as probes).
     */
    private static void testSingleSiteRemoval() throws Exception {
        System.out.println("NumberHashTest: single-site removal");
        final int probe = 0x13572468;
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = TARGET;
        node.superName = "java/lang/Object";
        node.methods = new ArrayList<MethodNode>();
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "probe", "()I",
                null, null);
        method.instructions.add(new LdcInsnNode(Integer.valueOf(probe)));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 0;
        node.methods.add(method);

        UmbraConfig config = config(31L,
                NumberHashPass.OPTION_ENABLED, "true",
                NumberHashPass.OPTION_CODEC, Codecs.SKID,
                NumberHashPass.OPTION_MAX_PER_METHOD, "10");
        Stats stats = new Stats();
        new NumberHashPass().run(context(config, node, stats));
        check(value(stats, "numberHash.sites") == 1, "exactly one site was rewritten");

        byte[] bytes = serialize(node);
        check(!hasPushOf(bytes, new int[] { probe }), "the single literal is gone from the class");
        check(((Integer) invoke(load(bytes), "probe")).intValue() == probe,
                "the decoder restores the original value");
    }

    /** Whether any method still pushes one of these values directly. */
    private static boolean hasPushOf(byte[] bytes, int[] values) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        java.util.Set<Integer> literals = new java.util.HashSet<Integer>();
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                Integer literal = intLiteralOf(insn);
                if (literal != null) {
                    literals.add(literal);
                }
            }
        }
        for (int i = 0; i < values.length; i++) {
            if (literals.contains(Integer.valueOf(values[i]))) {
                return true;
            }
        }
        return false;
    }

    private static int instructionCount(ClassNode node, String methodName) {
        int count = 0;
        for (AbstractInsnNode insn = method(node, methodName).instructions.getFirst();
                insn != null; insn = insn.getNext()) {
            count++;
        }
        return count;
    }

    private static Integer intLiteralOf(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (insn instanceof InsnNode && opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return Integer.valueOf(opcode - Opcodes.ICONST_0);
        }
        if (insn instanceof IntInsnNode && (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH)) {
            return Integer.valueOf(((IntInsnNode) insn).operand);
        }
        if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer) {
            return (Integer) ((LdcInsnNode) insn).cst;
        }
        return null;
    }

    private static String describeMismatch(int[] expected, int[] actual) {
        if (expected == null || actual == null) {
            return " (null array)";
        }
        if (expected.length != actual.length) {
            return " (length " + expected.length + " vs " + actual.length + ")";
        }
        int reported = 0;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < expected.length && reported < 8; i++) {
            if (expected[i] != actual[i]) {
                out.append(" [").append(i).append("] ").append(expected[i]).append(" != ").append(actual[i]);
                reported++;
            }
        }
        return out.toString();
    }

    private static long value(Stats stats, String key) {
        Long found = stats.snapshot().get(key);
        return found == null ? 0L : found.longValue();
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}
