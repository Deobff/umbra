package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.NocturnePass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Nocturne tests: polymorphic keyed-argument method shadows.
 *
 * <p>Synthesises a Java 8 class with static/instance/void/returning methods,
 * int/long/String/array/float/double parameters, loops, switches, recursion,
 * exceptions and try/catch; runs {@link NocturnePass}; verifies the result with
 * ASM and the real JVM verifier; compares behaviour against Java reference
 * implementations. Also checks variants/limits/skips, byte determinism, and
 * runs the CLI end-to-end on {@code demo/demo.jar} in exclusive mode.</p>
 */
public final class NocturneTest {

    private static final String TARGET = "test/NocturneTarget";
    private static final String TARGET_DOTTED = "test.NocturneTarget";
    private static final String SKIP_TARGET = "test/NocturneSkip";
    private static final String SKIP_DOTTED = "test.NocturneSkip";

    private static int checks;

    private NocturneTest() {
    }

    public static void main(String[] args) throws Exception {
        startWatchdog();
        testNocturnePass();
        testVariantCounts();
        testSkipsAndLimits();
        testBodySkipAndFrozen();
        testDeterminism();
        testDemoJar();
        System.out.println("NocturneTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------ main tests

    private static void testNocturnePass() throws Exception {
        ClassNode node = target();
        byte[] original = serialize(node);
        assertBehaviour(verifyAndLoad(original, "baseline", TARGET_DOTTED));
        PassContext context = context(original, node, 101L, 3, 4000, 0,
                new ArrayList<String>());
        new NocturnePass().run(context);
        Stats stats = context.stats();
        long methods = stat(stats, "nocturne.methods");
        long variants = stat(stats, "nocturne.variants");
        long instructions = stat(stats, "nocturne.instructions");
        check(methods >= 12, "transformed a useful number of methods: " + methods);
        check(variants == methods * 3, "three shadow variants per method: " + variants);
        check(instructions > methods, "shadow instructions were counted: " + instructions);
        check(stat(stats, "nocturne.skipped") >= 2,
                "synchronized and @Keep methods were skipped: " + stat(stats, "nocturne.skipped"));

        byte[] transformed = serialize(node, context.hierarchy());
        Class<?> type = verifyAndLoad(transformed, "nocturne", TARGET_DOTTED);
        assertBehaviour(type);

        // Shadow bodies exist and the dispatcher really is keyed.
        int addShadows = countShadows(node, "add", "(IIJ)I");
        check(addShadows == 3, "add has 3 keyed shadow clones: " + addShadows);
        MethodNode addDispatcher = find(node, "add", "(II)I");
        check(addDispatcher != null, "add dispatcher exists");
        check(hasThreadLocalRandom(addDispatcher), "dispatcher draws a runtime key");
        check(hasTableswitch(addDispatcher), "dispatcher switches across shadows");
        check(countShadows(node, "sync", null) == 0, "synchronized method is not shadowed");
        check(countShadows(node, "kept", null) == 0, "@Keep method is not shadowed");
        MethodNode mix = find(node, "mix", "(JI)J");
        check(mix.visibleAnnotations != null && mix.visibleAnnotations.size() == 1,
                "dispatcher keeps method annotations");
        check("<init>".equals(find(node, "<init>", "(I)V").name), "constructor untouched");
    }

    private static void testVariantCounts() throws Exception {
        int[] variantOptions = { 2, 3, 4 };
        for (int variants : variantOptions) {
            ClassNode node = target();
            byte[] original = serialize(node);
            PassContext context = context(original, node, 202L, variants, 4000, 0,
                    new ArrayList<String>());
            new NocturnePass().run(context);
            check(stat(context.stats(), "nocturne.variants")
                            == stat(context.stats(), "nocturne.methods") * variants,
                    "variant count " + variants + " honoured");
            check(countShadows(node, "add", "(IIJ)I") == variants,
                    "add has " + variants + " shadows");
            Class<?> type = verifyAndLoad(serialize(node, context.hierarchy()), "variants" + variants,
                    TARGET_DOTTED);
            check(((Integer) call(type, "add", new Class<?>[] { int.class, int.class }, 7, 8))
                    .intValue() == 15, "variant count " + variants + " keeps behaviour");
        }
    }

    private static void testSkipsAndLimits() throws Exception {
        // Over-limit method, synchronized method, @Keep method, native method.
        ClassNode node = skipTarget();
        byte[] original = serialize(node);
        PassContext context = context(original, node, 303L, 3, 10, 0, new ArrayList<String>());
        new NocturnePass().run(context);
        check(stat(context.stats(), "nocturne.methods") == 0,
                "no method is transformed with a 10-instruction budget");
        check(stat(context.stats(), "nocturne.skipped") >= 3,
                "large/sync/keep methods are counted as skips: " + stat(context.stats(), "nocturne.skipped"));
        verifyAndLoad(serialize(node, context.hierarchy()), "skips", SKIP_DOTTED);

        // Per-class method cap.
        ClassNode cap = capTarget();
        byte[] capBytes = serialize(cap);
        PassContext capContext = context(capBytes, cap, 404L, 2, 4000, 1, new ArrayList<String>());
        new NocturnePass().run(capContext);
        check(stat(capContext.stats(), "nocturne.methods") == 1,
                "nocturne.maxMethods caps transformed methods: " + stat(capContext.stats(), "nocturne.methods"));
        check(stat(capContext.stats(), "nocturne.variants") == 2, "cap still creates two shadows");
        verifyAndLoad(serialize(cap, capContext.hierarchy()), "cap", "test.NocturneCap");
    }

    private static void testBodySkipAndFrozen() throws Exception {
        ClassNode node = capTarget();
        byte[] bytes = serialize(node);
        List<String> skipGlobs = new ArrayList<String>();
        skipGlobs.add("test/NocturneCap");
        PassContext skipped = context(bytes, node, 505L, 3, 4000, 0, skipGlobs);
        new NocturnePass().run(skipped);
        check(stat(skipped.stats(), "nocturne.methods") == 0, "body-skip class is untouched");
        check(node.methods.size() == capTarget().methods.size(),
                "body-skip class gained no shadow methods");

        ClassNode frozenNode = capTarget();
        byte[] frozenBytes = serialize(frozenNode);
        PassContext frozen = context(frozenBytes, frozenNode, 606L, 3, 4000, 0,
                new ArrayList<String>());
        frozen.classes().freeze(frozenNode.name);
        new NocturnePass().run(frozen);
        check(stat(frozen.stats(), "nocturne.methods") == 0, "frozen class is untouched");
    }

    private static void testDeterminism() throws Exception {
        byte[] original = serialize(target());
        ClassNode first = read(original);
        ClassNode second = read(original);
        PassContext a = context(original, first, 707L, 3, 4000, 0, new ArrayList<String>());
        PassContext b = context(original, second, 707L, 3, 4000, 0, new ArrayList<String>());
        new NocturnePass().run(a);
        new NocturnePass().run(b);
        byte[] firstBytes = serialize(first, a.hierarchy());
        byte[] secondBytes = serialize(second, b.hierarchy());
        check(Arrays.equals(firstBytes, secondBytes),
                "same seed yields byte-identical Nocturne output");
        verifyAndLoad(firstBytes, "determinism", TARGET_DOTTED);

        ClassNode third = read(original);
        PassContext c = context(original, third, 708L, 3, 4000, 0, new ArrayList<String>());
        new NocturnePass().run(c);
        check(!Arrays.equals(firstBytes, serialize(third, c.hierarchy())),
                "different seed yields different shadow state");
    }

    // --------------------------------------------------------------- behaviour

    private static void assertBehaviour(Class<?> type) throws Exception {
        check(((Integer) call(type, "add", new Class<?>[] { int.class, int.class }, 7, 8))
                .intValue() == 15, "add");
        check(((Integer) call(type, "add", new Class<?>[] { int.class, int.class },
                Integer.MIN_VALUE, Integer.MAX_VALUE)).intValue() == -1, "add overflow");
        long[][] mixes = { { 0L, 0 }, { 5L, 3 }, { Long.MIN_VALUE, -7 }, { 123456789L, 42 } };
        for (long[] pair : mixes) {
            long actualMix = ((Long) call(type, "mix", new Class<?>[] { long.class, int.class },
                    pair[0], (int) pair[1])).longValue();
            check(actualMix == refMix(pair[0], (int) pair[1]),
                    "mix(" + pair[0] + "," + pair[1] + ") got " + actualMix
                            + " expected " + refMix(pair[0], (int) pair[1]));
        }
        check("x:2:5".equals(call(type, "concat", new Class<?>[] { String.class, int.class, long.class },
                "x", 2, 5L)), "concat positive");
        check("x".equals(call(type, "concat", new Class<?>[] { String.class, int.class, long.class },
                "x", 0, 5L)), "concat zero");
        int[] ints = { 1, 2, 3, 4 };
        check(((Integer) call(type, "arrays", new Class<?>[] { int[].class, long.class, String.class },
                ints, 3L, "abcd")).intValue() == 34, "arrays");
        check(((Integer) call(type, "loop", new Class<?>[] { int.class }, 10)).intValue() == 55, "loop");
        for (int i = 0; i < 6; i++) {
            check(((Integer) call(type, "switcher", new Class<?>[] { int.class }, i)).intValue()
                    == refSwitch(i), "switcher" + i);
        }
        check(((Integer) call(type, "div", new Class<?>[] { int.class, int.class }, 7, 2))
                .intValue() == 3, "div normal");
        check(((Integer) call(type, "div", new Class<?>[] { int.class, int.class }, 1, 0))
                .intValue() == -1, "div catch");
        check(((Integer) call(type, "recurse", new Class<?>[] { int.class }, 5)).intValue() == 120, "recursion");
        check(((Double) call(type, "wide", new Class<?>[] { double.class, long.class }, 2.5, 4L))
                .doubleValue() == 12.5, "double/long");
        check(((Float) call(type, "floats", new Class<?>[] { float.class, int.class }, 1.5f, 2))
                .floatValue() == 3.5f, "float/int");
        check(((Integer) call(type, "boom", new Class<?>[] { int.class }, 6)).intValue() == 12, "boom normal");
        try {
            call(type, "boom", new Class<?>[] { int.class }, -1);
            check(false, "boom(-1) must throw");
        } catch (InvocationTargetException e) {
            check(e.getCause() instanceof IllegalArgumentException, "boom exception type preserved");
            check("neg".equals(e.getCause().getMessage()), "boom exception message preserved");
        }
        Constructor<?> constructor = type.getDeclaredConstructor(int.class);
        Object instance = constructor.newInstance(5);
        Method bump = type.getDeclaredMethod("bump", int.class);
        bump.setAccessible(true);
        check(((Integer) bump.invoke(instance, 3)).intValue() == 8, "instance bump(+3)");
        check(((Integer) bump.invoke(instance, -2)).intValue() == 6, "instance bump(-2)");

        Method voidy = type.getDeclaredMethod("voidy", int.class);
        voidy.setAccessible(true);
        voidy.invoke(null, 4);
        check(((Integer) type.getField("total").get(null)).intValue() == 12, "void method writes field");
    }

    private static long refMix(long a, int b) {
        long s = a * 31 + b;
        s ^= (a >>> 3);
        return s;
    }

    private static int refSwitch(int value) {
        switch (value) {
            case 0: return 10;
            case 1: return 11;
            case 2: return 15;
            case 3: return 21;
            default: return -1;
        }
    }

    // --------------------------------------------------------------- demo jar

    private static void testDemoJar() throws Exception {
        Path root = findProjectRoot();
        if (root == null) {
            System.out.println("NocturneTest: demo/demo.jar not found, skipping end-to-end check");
            return;
        }
        Path outputDir = Files.createTempDirectory("umbra-nocturne-test");
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        String classpath = absoluteClasspath();
        Path firstJar = outputDir.resolve("nocturne-a.jar");
        String log = runIn(outputDir, java, "-cp", classpath, "io.umbra.cli.Main",
                "-i", root.resolve("demo/demo.jar").toString(),
                "-o", firstJar.toString(),
                "--set", "nocturne.enabled=true",
                "--verify", "--fixed-time", "--seed", "777");
        check(log.contains("nocturne: exclusive mode"),
                "Nocturne enabled the exclusive pipeline: " + tail(log));
        check(log.contains("nocturne: shadowed"), "Nocturne reported shadow coverage: " + tail(log));
        check(!log.contains("flattening:") && !log.contains("flow-obfuscation")
                        && !log.contains("virtualization") && !log.contains("mba[")
                        && !log.contains("native-code:"),
                "other method-body passes did not run in exclusive mode");
        String runOutput = runIn(outputDir, java, "-jar", firstJar.toString());
        check(runOutput.contains("OK"), "Nocturne demo output prints OK: " + tail(runOutput));
        check(countShadowMethods(firstJar) > 0, "output jar contains keyed shadow methods");

        Path secondJar = outputDir.resolve("nocturne-b.jar");
        runIn(outputDir, java, "-cp", classpath, "io.umbra.cli.Main",
                "-i", root.resolve("demo/demo.jar").toString(),
                "-o", secondJar.toString(),
                "--set", "nocturne.enabled=true",
                "--verify", "--fixed-time", "--seed", "777");
        check(Arrays.equals(classDigest(firstJar), classDigest(secondJar)),
                "Nocturne CLI output is byte-identical for the same seed");
    }

    // ------------------------------------------------------- class synthesis

    private static ClassNode target() {
        ClassNode node = baseClass(TARGET);
        node.fields.add(new FieldNode(Opcodes.ACC_PRIVATE, "value", "I", null, null));
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "total", "I", null, null));
        node.methods.add(constructor(TARGET));
        node.methods.add(binary("add", Opcodes.IADD));
        node.methods.add(mix());
        node.methods.add(concat());
        node.methods.add(arrays());
        node.methods.add(bump());
        node.methods.add(loop());
        node.methods.add(switcher());
        node.methods.add(div());
        node.methods.add(voidy());
        node.methods.add(wide());
        node.methods.add(floats());
        node.methods.add(recurse());
        node.methods.add(boom());
        MethodNode sync = binary("sync", Opcodes.IMUL);
        sync.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNCHRONIZED;
        node.methods.add(sync);
        MethodNode kept = method("kept", "(I)I");
        kept.visibleAnnotations = new ArrayList<AnnotationNode>();
        kept.visibleAnnotations.add(new AnnotationNode("Lio/umbra/annotations/Keep;"));
        kept.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        kept.instructions.add(new InsnNode(Opcodes.IRETURN));
        node.methods.add(kept);
        return node;
    }

    private static ClassNode skipTarget() {
        ClassNode node = baseClass(SKIP_TARGET);
        node.methods.add(defaultConstructor());
        MethodNode big = method("big", "(I)I");
        AsmUtil.pushInt(big.instructions, 0);
        for (int i = 1; i < 24; i++) {
            AsmUtil.pushInt(big.instructions, i);
            big.instructions.add(new InsnNode(Opcodes.IADD));
        }
        big.instructions.add(new InsnNode(Opcodes.IRETURN));
        node.methods.add(big);
        MethodNode sync = binary("sync", Opcodes.IADD);
        sync.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNCHRONIZED;
        node.methods.add(sync);
        MethodNode kept = method("kept", "(I)I");
        kept.visibleAnnotations = new ArrayList<AnnotationNode>();
        kept.visibleAnnotations.add(new AnnotationNode("Lio/umbra/annotations/Keep;"));
        kept.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        kept.instructions.add(new InsnNode(Opcodes.IRETURN));
        node.methods.add(kept);
        MethodNode nativeMethod = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_NATIVE,
                "nativeM", "()I", null, null);
        node.methods.add(nativeMethod);
        return node;
    }

    private static ClassNode capTarget() {
        ClassNode node = baseClass("test/NocturneCap");
        node.methods.add(binary("add", Opcodes.IADD));
        node.methods.add(binary("mul", Opcodes.IMUL));
        return node;
    }

    private static ClassNode baseClass(String name) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = name;
        node.superName = "java/lang/Object";
        return node;
    }

    private static MethodNode method(String name, String descriptor) {
        return new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, descriptor, null, null);
    }

    private static MethodNode binary(String name, int opcode) {
        MethodNode method = method(name, "(II)I");
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new InsnNode(opcode));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode constructor(String owner) {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "(I)V", null, null);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new FieldInsnNode(Opcodes.PUTFIELD, owner, "value", "I"));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        return method;
    }

    private static MethodNode defaultConstructor() {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        return method;
    }

    private static MethodNode mix() {
        MethodNode method = method("mix", "(JI)J");
        InsnList out = method.instructions;
        out.add(new VarInsnNode(Opcodes.LLOAD, 0));
        out.add(new LdcInsnNode(Long.valueOf(31L)));
        out.add(new InsnNode(Opcodes.LMUL));
        out.add(new VarInsnNode(Opcodes.ILOAD, 2));
        out.add(new InsnNode(Opcodes.I2L));
        out.add(new InsnNode(Opcodes.LADD));
        out.add(new VarInsnNode(Opcodes.LLOAD, 0));
        out.add(new InsnNode(Opcodes.ICONST_3));
        out.add(new InsnNode(Opcodes.LUSHR));
        out.add(new InsnNode(Opcodes.LXOR));
        out.add(new InsnNode(Opcodes.LRETURN));
        method.visibleAnnotations = new ArrayList<AnnotationNode>();
        method.visibleAnnotations.add(new AnnotationNode("Lio/umbra/annotations/FlowObfuscation;"));
        return method;
    }

    private static MethodNode concat() {
        MethodNode method = method("concat", "(Ljava/lang/String;IJ)Ljava/lang/String;");
        InsnList out = method.instructions;
        LabelNode positive = new LabelNode();
        out.add(new VarInsnNode(Opcodes.ILOAD, 1));
        out.add(new JumpInsnNode(Opcodes.IFGT, positive));
        out.add(new VarInsnNode(Opcodes.ALOAD, 0));
        out.add(new InsnNode(Opcodes.ARETURN));
        out.add(positive);
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder",
                "<init>", "()V", false));
        out.add(new VarInsnNode(Opcodes.ASTORE, 4));
        out.add(new VarInsnNode(Opcodes.ALOAD, 4));
        out.add(new VarInsnNode(Opcodes.ALOAD, 0));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        out.add(new LdcInsnNode(":"));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        out.add(new VarInsnNode(Opcodes.ILOAD, 1));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                "append", "(I)Ljava/lang/StringBuilder;", false));
        out.add(new LdcInsnNode(":"));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        out.add(new VarInsnNode(Opcodes.LLOAD, 2));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                "append", "(J)Ljava/lang/StringBuilder;", false));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                "toString", "()Ljava/lang/String;", false));
        out.add(new InsnNode(Opcodes.ARETURN));
        return method;
    }

    private static MethodNode arrays() {
        MethodNode method = method("arrays", "([IJLjava/lang/String;)I");
        InsnList out = method.instructions;
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        out.add(new InsnNode(Opcodes.ICONST_0));
        out.add(new VarInsnNode(Opcodes.ISTORE, 4));
        out.add(new InsnNode(Opcodes.ICONST_0));
        out.add(new VarInsnNode(Opcodes.ISTORE, 5));
        out.add(loop);
        out.add(new VarInsnNode(Opcodes.ILOAD, 5));
        out.add(new VarInsnNode(Opcodes.ALOAD, 0));
        out.add(new InsnNode(Opcodes.ARRAYLENGTH));
        out.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        out.add(new VarInsnNode(Opcodes.ILOAD, 4));
        out.add(new VarInsnNode(Opcodes.ALOAD, 0));
        out.add(new VarInsnNode(Opcodes.ILOAD, 5));
        out.add(new InsnNode(Opcodes.IALOAD));
        out.add(new InsnNode(Opcodes.IADD));
        out.add(new VarInsnNode(Opcodes.ISTORE, 4));
        out.add(new IincInsnNode(5, 1));
        out.add(new JumpInsnNode(Opcodes.GOTO, loop));
        out.add(end);
        out.add(new VarInsnNode(Opcodes.ILOAD, 4));
        out.add(new InsnNode(Opcodes.I2L));
        out.add(new VarInsnNode(Opcodes.LLOAD, 1));
        out.add(new InsnNode(Opcodes.LMUL));
        out.add(new InsnNode(Opcodes.L2I));
        out.add(new VarInsnNode(Opcodes.ALOAD, 3));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "length", "()I", false));
        out.add(new InsnNode(Opcodes.IADD));
        out.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode bump() {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "bump", "(I)I", null, null);
        InsnList out = method.instructions;
        out.add(new VarInsnNode(Opcodes.ALOAD, 0));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new FieldInsnNode(Opcodes.GETFIELD, TARGET, "value", "I"));
        out.add(new VarInsnNode(Opcodes.ILOAD, 1));
        out.add(new InsnNode(Opcodes.IADD));
        out.add(new FieldInsnNode(Opcodes.PUTFIELD, TARGET, "value", "I"));
        out.add(new VarInsnNode(Opcodes.ALOAD, 0));
        out.add(new FieldInsnNode(Opcodes.GETFIELD, TARGET, "value", "I"));
        out.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode loop() {
        MethodNode method = method("loop", "(I)I");
        InsnList out = method.instructions;
        LabelNode head = new LabelNode();
        LabelNode end = new LabelNode();
        out.add(new InsnNode(Opcodes.ICONST_0));
        out.add(new VarInsnNode(Opcodes.ISTORE, 1));
        out.add(new InsnNode(Opcodes.ICONST_1));
        out.add(new VarInsnNode(Opcodes.ISTORE, 2));
        out.add(head);
        out.add(new VarInsnNode(Opcodes.ILOAD, 2));
        out.add(new VarInsnNode(Opcodes.ILOAD, 0));
        out.add(new JumpInsnNode(Opcodes.IF_ICMPGT, end));
        out.add(new VarInsnNode(Opcodes.ILOAD, 1));
        out.add(new VarInsnNode(Opcodes.ILOAD, 2));
        out.add(new InsnNode(Opcodes.IADD));
        out.add(new VarInsnNode(Opcodes.ISTORE, 1));
        out.add(new IincInsnNode(2, 1));
        out.add(new JumpInsnNode(Opcodes.GOTO, head));
        out.add(end);
        out.add(new VarInsnNode(Opcodes.ILOAD, 1));
        out.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode switcher() {
        MethodNode method = method("switcher", "(I)I");
        InsnList out = method.instructions;
        LabelNode dflt = new LabelNode();
        LabelNode[] cases = new LabelNode[4];
        for (int i = 0; i < cases.length; i++) {
            cases[i] = new LabelNode();
        }
        out.add(new VarInsnNode(Opcodes.ILOAD, 0));
        out.add(new TableSwitchInsnNode(0, 3, dflt, cases));
        int[] values = { 10, 11, 15 };
        for (int i = 0; i < 3; i++) {
            out.add(cases[i]);
            AsmUtil.pushInt(out, values[i]);
            out.add(new InsnNode(Opcodes.IRETURN));
        }
        out.add(cases[3]);
        out.add(new VarInsnNode(Opcodes.ILOAD, 0));
        out.add(new LdcInsnNode(Integer.valueOf(7)));
        out.add(new InsnNode(Opcodes.IMUL));
        out.add(new InsnNode(Opcodes.IRETURN));
        out.add(dflt);
        out.add(new InsnNode(Opcodes.ICONST_M1));
        out.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode div() {
        MethodNode method = method("div", "(II)I");
        InsnList out = method.instructions;
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        out.add(start);
        out.add(new VarInsnNode(Opcodes.ILOAD, 0));
        out.add(new VarInsnNode(Opcodes.ILOAD, 1));
        out.add(new InsnNode(Opcodes.IDIV));
        out.add(new InsnNode(Opcodes.IRETURN));
        out.add(end);
        out.add(handler);
        out.add(new VarInsnNode(Opcodes.ASTORE, 2));
        out.add(new InsnNode(Opcodes.ICONST_M1));
        out.add(new InsnNode(Opcodes.IRETURN));
        method.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
        method.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler,
                "java/lang/ArithmeticException"));
        return method;
    }

    private static MethodNode voidy() {
        MethodNode method = method("voidy", "(I)V");
        method.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, TARGET, "total", "I"));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new LdcInsnNode(Integer.valueOf(3)));
        method.instructions.add(new InsnNode(Opcodes.IMUL));
        method.instructions.add(new InsnNode(Opcodes.IADD));
        method.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, TARGET, "total", "I"));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        return method;
    }

    private static MethodNode wide() {
        MethodNode method = method("wide", "(DJ)D");
        InsnList out = method.instructions;
        out.add(new VarInsnNode(Opcodes.DLOAD, 0));
        out.add(new VarInsnNode(Opcodes.LLOAD, 2));
        out.add(new InsnNode(Opcodes.L2D));
        out.add(new InsnNode(Opcodes.DMUL));
        out.add(new VarInsnNode(Opcodes.DLOAD, 0));
        out.add(new InsnNode(Opcodes.DADD));
        out.add(new InsnNode(Opcodes.DRETURN));
        return method;
    }

    private static MethodNode floats() {
        MethodNode method = method("floats", "(FI)F");
        InsnList out = method.instructions;
        out.add(new VarInsnNode(Opcodes.FLOAD, 0));
        out.add(new VarInsnNode(Opcodes.ILOAD, 1));
        out.add(new InsnNode(Opcodes.I2F));
        out.add(new InsnNode(Opcodes.FADD));
        out.add(new InsnNode(Opcodes.FRETURN));
        return method;
    }

    private static MethodNode recurse() {
        MethodNode method = method("recurse", "(I)I");
        InsnList out = method.instructions;
        LabelNode base = new LabelNode();
        out.add(new VarInsnNode(Opcodes.ILOAD, 0));
        out.add(new InsnNode(Opcodes.ICONST_1));
        out.add(new JumpInsnNode(Opcodes.IF_ICMPGT, base));
        out.add(new InsnNode(Opcodes.ICONST_1));
        out.add(new InsnNode(Opcodes.IRETURN));
        out.add(base);
        out.add(new VarInsnNode(Opcodes.ILOAD, 0));
        out.add(new VarInsnNode(Opcodes.ILOAD, 0));
        out.add(new InsnNode(Opcodes.ICONST_1));
        out.add(new InsnNode(Opcodes.ISUB));
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, TARGET, "recurse", "(I)I", false));
        out.add(new InsnNode(Opcodes.IMUL));
        out.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode boom() {
        MethodNode method = method("boom", "(I)I");
        InsnList out = method.instructions;
        LabelNode negative = new LabelNode();
        out.add(new VarInsnNode(Opcodes.ILOAD, 0));
        out.add(new JumpInsnNode(Opcodes.IFLT, negative));
        out.add(new VarInsnNode(Opcodes.ILOAD, 0));
        out.add(new InsnNode(Opcodes.ICONST_2));
        out.add(new InsnNode(Opcodes.IMUL));
        out.add(new InsnNode(Opcodes.IRETURN));
        out.add(negative);
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalArgumentException"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new LdcInsnNode("neg"));
        out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/IllegalArgumentException",
                "<init>", "(Ljava/lang/String;)V", false));
        out.add(new InsnNode(Opcodes.ATHROW));
        return method;
    }

    // ------------------------------------------------------------ inspection

    private static int countShadows(ClassNode node, String methodName, String descriptor) {
        int count = 0;
        for (MethodNode method : node.methods) {
            if (!method.name.startsWith(methodName + "$")) {
                continue;
            }
            if (descriptor != null && !descriptor.equals(method.desc)) {
                continue;
            }
            if ((method.access & Opcodes.ACC_SYNTHETIC) != 0) {
                count++;
            }
        }
        return count;
    }

    private static MethodNode find(ClassNode node, String name, String descriptor) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name) && method.desc.equals(descriptor)) {
                return method;
            }
        }
        return null;
    }

    private static boolean hasThreadLocalRandom(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;
                if ("java/util/concurrent/ThreadLocalRandom".equals(call.owner)
                        && "current".equals(call.name)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean hasTableswitch(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof TableSwitchInsnNode) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------ infrastructure

    private static PassContext context(byte[] originalBytes, ClassNode node, long seed, int variants,
                                       int maxInstructions, int maxMethods, List<String> bodySkip) {
        try {
            UmbraConfig config = new UmbraConfig.Builder()
                    .input(Paths.get("in.jar"))
                    .output(Paths.get("out.jar"))
                    .seed(seed)
                    .option("nocturne.enabled", "true")
                    .option("nocturne.variants", Integer.toString(variants))
                    .option("nocturne.maxInstructions", Integer.toString(maxInstructions))
                    .option("nocturne.maxMethods", Integer.toString(maxMethods))
                    .build();
            ClassPool pool = new ClassPool();
            pool.putClass(node.name + ".class", originalBytes, node);
            Hierarchy hierarchy = new Hierarchy();
            hierarchy.addInput(node);
            DefaultRuleSet rules = new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(),
                    false, false);
            for (String glob : bodySkip) {
                rules.addBodySkipGlob(glob);
            }
            return new PassContext(config, pool, hierarchy, rules, new DefaultRuntimeSupport(),
                    new MappingSet(), new Stats(), testLog(), new Random(seed),
                    ProgressListener.NONE);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Console log sink so verification/skip reasons surface while debugging. */
    private static Log testLog() {
        boolean verbose = System.getProperty("umbra.nocturne.verbose") != null;
        if (!verbose) {
            return new Log(null, false);
        }
        return new Log(new io.umbra.core.util.Log.Sink() {
            @Override
            public void line(String level, String message) {
                System.out.println("[" + level + "] " + message);
            }
        }, true);
    }

    private static long stat(Stats stats, String key) {
        Long value = stats.snapshot().get(key);
        return value == null ? 0L : value.longValue();
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static byte[] serialize(ClassNode node) {
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        return UmbraClassWriter.toBytes(node, hierarchy);
    }

    private static byte[] serialize(ClassNode node, Hierarchy hierarchy) {
        hierarchy.addInput(node);
        return UmbraClassWriter.toBytes(node, hierarchy);
    }

    private static Class<?> verifyAndLoad(byte[] bytes, String phase, String dottedName) {
        StringWriter writer = new StringWriter();
        CheckClassAdapter.verify(new ClassReader(bytes), false, new PrintWriter(writer));
        String errors = writer.toString();
        check(errors.isEmpty(), "CheckClassAdapter (" + phase + "): " + errors);
        final Map<String, byte[]> classes = new HashMap<String, byte[]>();
        classes.put(dottedName, bytes);
        ClassLoader loader = new ClassLoader(NocturneTest.class.getClassLoader()) {
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
            Class<?> type = Class.forName(dottedName, true, loader);
            type.getDeclaredMethods();
            return type;
        } catch (ClassNotFoundException e) {
            throw new AssertionError("Cannot load transformed class", e);
        }
    }

    private static Object call(Class<?> type, String name, Class<?>[] signature, Object... args)
            throws Exception {
        Method method = type.getDeclaredMethod(name, signature);
        method.setAccessible(true);
        return method.invoke(null, args);
    }

    private static Path findProjectRoot() {
        Path dir = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && dir != null; i++) {
            if (Files.exists(dir.resolve("demo").resolve("demo.jar"))) {
                return dir;
            }
            dir = dir.getParent();
        }
        return null;
    }

    private static String absoluteClasspath() {
        String raw = System.getProperty("java.class.path");
        StringBuilder result = new StringBuilder();
        for (String entry : raw.split(File.pathSeparator)) {
            if (entry.isEmpty()) {
                continue;
            }
            File file = new File(entry);
            if (!file.isAbsolute()) {
                file = new File(System.getProperty("user.dir"), entry);
            }
            if (result.length() > 0) {
                result.append(File.pathSeparatorChar);
            }
            result.append(file.getAbsolutePath());
        }
        return result.toString();
    }

    private static String runIn(Path directory, String... command) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(directory.toFile());
        builder.redirectErrorStream(true);
        Process process = builder.start();
        String output = readAll(process.getInputStream());
        int code = process.waitFor();
        check(code == 0, "command exited 0 (" + command[0] + "...): " + tail(output));
        return output;
    }

    private static String readAll(InputStream in) throws java.io.IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String tail(String value) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        return trimmed.length() <= 1500 ? trimmed : trimmed.substring(trimmed.length() - 1500);
    }

    /** SHA-256 over all class entries (sorted) of a jar. */
    private static byte[] classDigest(Path jar) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        ZipFile zip = new ZipFile(jar.toFile());
        try {
            List<String> names = new ArrayList<String>();
            java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
                    names.add(entry.getName());
                }
            }
            java.util.Collections.sort(names);
            for (String name : names) {
                digest.update(name.getBytes(StandardCharsets.UTF_8));
                InputStream in = zip.getInputStream(zip.getEntry(name));
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) >= 0) {
                    digest.update(buffer, 0, read);
                }
                in.close();
            }
        } finally {
            zip.close();
        }
        return digest.digest();
    }

    private static int countShadowMethods(Path jar) throws Exception {
        int count = 0;
        ZipFile zip = new ZipFile(jar.toFile());
        try {
            java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }
                ClassNode node = read(readAllBytes(zip.getInputStream(entry)));
                for (MethodNode method : node.methods) {
                    if ((method.access & Opcodes.ACC_SYNTHETIC) != 0
                            && method.desc.endsWith(")J") && method.name.indexOf('$') > 0) {
                        count++;
                    }
                }
            }
        } finally {
            zip.close();
        }
        return count;
    }

    private static byte[] readAllBytes(InputStream in) throws java.io.IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    /** Fails loudly instead of hanging forever if transformed code loops. */
    private static void startWatchdog() {
        final long timeout = Long.parseLong(System.getProperty("umbra.nocturne.watchdog", "60000"));
        Thread watchdog = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(timeout);
                } catch (InterruptedException ignored) {
                    return;
                }
                System.err.println("NocturneTest WATCHDOG after " + timeout + "ms");
                Map<Thread, StackTraceElement[]> traces = Thread.getAllStackTraces();
                for (Map.Entry<Thread, StackTraceElement[]> entry : traces.entrySet()) {
                    System.err.println("THREAD " + entry.getKey().getName());
                    for (StackTraceElement element : entry.getValue()) {
                        System.err.println("  at " + element);
                    }
                }
                Runtime.getRuntime().halt(3);
            }
        }, "nocturne-test-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}
