package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.SaltPass;
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
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

/**
 * Salt pass self test.
 *
 * <p>Two synthetic classes carry the behaviour: {@code test.SaltA} calls the
 * private/package-private methods of {@code test.SaltB} (so one descriptor change
 * has to be propagated across a class boundary) and holds an instance method, a
 * static method with a loop, and private instance/static helpers. Both are run
 * through {@link SaltPass} with every layer on, verified with
 * {@link CheckClassAdapter}, defined in a real class loader and compared
 * instruction by instruction against the untransformed baseline.</p>
 *
 * <p>Also covered: the class salt field and its {@code <clinit>} store, the strict
 * dispatcher resolving the value from the initialising class, the
 * double-read self-cancelling method salt, the descriptor propagation, an
 * abstract and a native method staying untouched, an interface not being salted,
 * {@code @Keep} being honoured, a class whose body cannot serialise rolling back as
 * a whole, determinism for a seed and salt values changing with the seed.</p>
 */
public final class SaltTest {

    private static final String A = "test/SaltA";
    private static final String B = "test/SaltB";
    private static final String ABSTRACT = "test/SaltAbstract";
    private static final String INTERFACE = "test/SaltItf";
    private static final String KEPT = "test/SaltKept";
    private static final String BROKEN = "test/SaltBroken";
    private static final String KEEP_DESC = "Lio/umbra/annotations/Keep;";

    private static int checks;

    private SaltTest() {
    }

    public static void main(String[] args) throws Exception {
        Map<String, byte[]> fixture = fixture();
        Map<String, byte[]> baseline = new LinkedHashMap<String, byte[]>();
        baseline.put(A, fixture.get(A));
        baseline.put(B, fixture.get(B));

        List<Integer> expected = observe(load(baseline), "baseline");

        PassContext context = run(fixture, 4242L, true);
        Stats stats = context.stats();

        // ---- structural expectations -----------------------------------------
        ClassNode a = context.classes().getClass(A);
        ClassNode b = context.classes().getClass(B);
        check(a != null && b != null, "both sample classes survived");

        FieldNode aSalt = saltField(a);
        FieldNode bSalt = saltField(b);
        check(aSalt != null, "class salt field added to SaltA");
        check(bSalt != null, "class salt field added to SaltB");
        check((aSalt.access & Opcodes.ACC_PUBLIC) != 0 && (aSalt.access & Opcodes.ACC_STATIC) != 0
                && (aSalt.access & Opcodes.ACC_FINAL) != 0, "class salt field is public static final");
        check("I".equals(aSalt.desc), "class salt field is an int");
        check(aSalt.name.length() >= 3, "class salt field name is generated");

        check(hasStore(a, aSalt.name), "SaltA <clinit> writes its salt field");
        check(hasStore(b, bSalt.name), "SaltB <clinit> writes its salt field");

        // ---- descriptor propagation ------------------------------------------
        check("(II)I".equals(desc(b, "scaled")), "private static helper gained an int parameter");
        check(desc(b, "scaled").indexOf("I)") > 0, "salted descriptor ends with I)");
        check("(II)I".equals(desc(b, "shift")),
                "final package-private static helper gained an int parameter");
        check("(I)I".equals(desc(b, "direct")), "public method keeps its descriptor");
        check("(I)I".equals(desc(a, "inst")), "instance method keeps its descriptor");
        check("(II)I".equals(desc(a, "helper")), "private static helper gained an int parameter");
        check("(II)I".equals(desc(a, "mix")), "private instance helper gained an int parameter");
        check("(II)I".equals(desc(a, "own")), "private instance helper gained an int parameter");

        // ---- the self-cancelling method salt reads the field twice -----------
        MethodNode inst = method(a, "inst", "(I)I");
        check(inst != null, "SaltA.inst still exists");
        check(readsSaltFieldTwice(inst, A, aSalt.name),
                "method salt reads the runtime class salt twice inside one expression");
        check(hasLocalStore(inst), "method salt is stored into a fresh local");

        // ---- dispatcher -------------------------------------------------------
        String dispatcher = generatedClass(context);
        check(dispatcher != null, "strict salt dispatcher was generated");
        check(context.classes().isGenerated(dispatcher), "dispatcher is registered as generated");
        check(stat(stats, "salt.dispatchers") == 1, "one dispatcher counted");
        ClassNode dispatcherNode = context.classes().getClass(dispatcher);
        int mapFields = 0;
        for (FieldNode field : dispatcherNode.fields) {
            if ("Ljava/util/Map;".equals(field.desc)) {
                mapFields++;
            }
        }
        check(mapFields == 2, "dispatcher owns the two map fields");

        // ---- untouched shapes -------------------------------------------------
        ClassNode abstractNode = context.classes().getClass(ABSTRACT);
        check("(I)I".equals(desc(abstractNode, "abs")), "abstract method keeps its descriptor");
        check("(I)I".equals(desc(abstractNode, "nat")), "native method keeps its descriptor");
        ClassNode interfaceNode = context.classes().getClass(INTERFACE);
        check("(I)I".equals(desc(interfaceNode, "itf")), "interface method keeps its descriptor");
        check(saltField(interfaceNode) == null, "interface receives no class salt field");
        check(method(interfaceNode, "<clinit>", "()V") == null, "interface receives no <clinit>");
        ClassNode keptNode = context.classes().getClass(KEPT);
        check(saltField(keptNode) == null, "@Keep class receives no class salt field");
        check(desc(keptNode, "hidden").equals("(I)I"), "@Keep class members keep their descriptor");
        check(method(keptNode, "<clinit>", "()V") == null, "@Keep class receives no <clinit>");

        // ---- statistics -------------------------------------------------------
        check(stat(stats, "salt.classes") >= 2, "class salts counted: " + stat(stats, "salt.classes"));
        check(stat(stats, "salt.fields") >= 2, "salt fields counted");
        check(stat(stats, "salt.methods") > 0, "method salts counted: " + stat(stats, "salt.methods"));
        check(stat(stats, "salt.methodParams") > 0,
                "parameter salts counted: " + stat(stats, "salt.methodParams"));
        check(stat(stats, "salt.methodParams.sites") > 0, "call sites rewritten");
        check(stat(stats, "salt.fakeValues") > 0, "fake values counted");
        check(stat(stats, "salt.skipped") > 0, "skipped shapes counted");
        check(stat(stats, "salt.skip.rollback") >= 1, "the unserialisable class rolled back");

        // ---- secrets ----------------------------------------------------------
        byte[] classSecret = context.secret("salt.class." + A);
        check(classSecret != null && classSecret.length == 4, "class salt exported as 4 bytes");
        check(context.secret("salt.method." + A + ".inst(I)I") != null,
                "method salt exported for the untouched descriptor");
        check(context.secret("salt.method." + A + ".helper(II)I") != null,
                "method salt exported for the salted descriptor");
        int declaredSalt = readInt(classSecret);

        // ---- the unserialisable class was left untouched ----------------------
        ClassNode brokenNode = context.classes().getClass(BROKEN);
        byte[] brokenAfter = UmbraClassWriter.toBytesWithoutComputation(brokenNode, context.hierarchy());
        check(Arrays.equals(brokenAfter, fixture.get(BROKEN)),
                "the class that cannot serialise is byte-identical after rollback");

        // ---- serialise, verify and execute -----------------------------------
        Map<String, byte[]> transformed = serialize(context, true);
        verifyAll(transformed);

        List<Integer> actual = observe(load(transformed), "salted");
        check(expected.size() == actual.size(), "same number of observations");
        for (int i = 0; i < expected.size(); i++) {
            check(expected.get(i).equals(actual.get(i)),
                    "observation " + i + " matches baseline: " + actual.get(i) + " vs " + expected.get(i));
        }
        check(expected.get(0).intValue() == reference(0), "plain Java reference agrees (input 0)");
        check(expected.get(12).intValue() == reference(17), "plain Java reference agrees (input 17)");

        // ---- the dispatcher really resolved the planned value ----------------
        MapLoader salted = load(transformed);
        Class<?> classA = salted.findClass0("test.SaltA");
        Class<?> classB = salted.findClass0("test.SaltB");
        Field saltFieldA = classA.getDeclaredField(aSalt.name);
        saltFieldA.setAccessible(true);
        check(saltFieldA.getInt(null) == declaredSalt,
                "dispatcher wrote the planned class salt into SaltA");
        Field saltFieldB = classB.getDeclaredField(bSalt.name);
        saltFieldB.setAccessible(true);
        int secretB = readInt(context.secret("salt.class." + B));
        check(saltFieldB.getInt(null) == secretB,
                "dispatcher wrote the planned class salt into SaltB");

        // ---- determinism ------------------------------------------------------
        PassContext again = run(fixture, 4242L, true);
        Map<String, byte[]> secondBytes = serialize(again, true);
        check(sameBytes(transformed, secondBytes), "the same seed produces byte-identical output");
        check(Arrays.equals(again.secret("salt.class." + A), classSecret),
                "the same seed produces the same salt value");

        PassContext other = run(fixture, 777L, true);
        Map<String, byte[]> otherBytes = serialize(other, true);
        check(!sameBytes(transformed, otherBytes), "a different seed changes the output");
        check(!Arrays.equals(other.secret("salt.class." + A), classSecret),
                "a different seed produces a different class salt");
        check(!Arrays.equals(other.secret("salt.method." + A + ".inst(I)I"),
                context.secret("salt.method." + A + ".inst(I)I")),
                "a different seed produces a different method salt");

        // ---- opt-in and constant fallback ------------------------------------
        PassContext bare = bareContext(fixture, 4242L);
        check(!new SaltPass().enabled(bare), "the pass is opt-in: salt.enabled defaults to false");
        PassContext disabled = context(fixture, 4242L, "salt.enabled", "false");
        check(!new SaltPass().enabled(disabled), "salt.enabled=false keeps the pass off");

        PassContext constant = runWith(fixture, 4242L, "salt.dispatcher", "false");
        check(generatedClass(constant) == null, "salt.dispatcher=false generates no dispatcher");
        ClassNode constantB = constant.classes().getClass(B);
        FieldNode constantField = saltField(constantB);
        check(constantField != null, "constant mode still adds the class salt field");
        check(hasConstantStore(constantB, constantField.name), "constant mode stores the value inline");
        Map<String, byte[]> constantBytes = serialize(constant, true);
        verifyAll(constantBytes);
        List<Integer> constantObserved = observe(load(constantBytes), "constant");
        for (int i = 0; i < expected.size(); i++) {
            check(expected.get(i).equals(constantObserved.get(i)),
                    "constant fallback keeps behaviour: observation " + i);
        }

        System.out.println("SaltTest: " + checks + " checks passed");
    }

    // --------------------------------------------------------------- execution

    private static List<Integer> observe(MapLoader loader, String phase) throws Exception {
        Class<?> classA = loader.findClass0("test.SaltA");
        Class<?> classB = loader.findClass0("test.SaltB");
        Method direct = classB.getDeclaredMethod("direct", int.class);
        Method stat = classA.getDeclaredMethod("stat", int.class);
        Method inst = classA.getDeclaredMethod("inst", int.class);
        direct.setAccessible(true);
        stat.setAccessible(true);
        inst.setAccessible(true);
        Object instance = classA.getDeclaredConstructor().newInstance();
        int[] inputs = { 0, 1, -1, 5, 17, 100, -37, Integer.MAX_VALUE, Integer.MIN_VALUE };
        List<Integer> values = new ArrayList<Integer>();
        for (int input : inputs) {
            values.add(Integer.valueOf(((Integer) inst.invoke(instance, Integer.valueOf(input))).intValue()));
            values.add(Integer.valueOf(((Integer) stat.invoke(null, Integer.valueOf(input))).intValue()));
            values.add(Integer.valueOf(((Integer) direct.invoke(null, Integer.valueOf(input))).intValue()));
        }
        if (values.isEmpty()) {
            throw new AssertionError("no observations for " + phase);
        }
        return values;
    }

    private static int reference(int input) {
        int scaled = input * 3 + 1;
        int shift = scaled + 7;
        int direct = shift + 11 + 5;
        int own = input * 2;
        int mix = input * 7 + 3;
        return direct + shift - own + mix;
    }

    // ------------------------------------------------------------------ fixture

    private static Map<String, byte[]> fixture() {
        List<ClassNode> nodes = new ArrayList<ClassNode>();
        nodes.add(saltB());
        nodes.add(saltA());
        nodes.add(saltAbstract());
        nodes.add(saltInterface());
        nodes.add(saltKept());
        nodes.add(saltBroken());
        Hierarchy hierarchy = new Hierarchy();
        for (ClassNode node : nodes) {
            hierarchy.addInput(node);
        }
        Map<String, byte[]> bytes = new LinkedHashMap<String, byte[]>();
        for (ClassNode node : nodes) {
            bytes.put(node.name, BROKEN.equals(node.name)
                    ? UmbraClassWriter.toBytesWithoutComputation(node, hierarchy)
                    : UmbraClassWriter.toBytes(node, hierarchy));
        }
        return bytes;
    }

    private static ClassNode classNode(String name, int access, String superName, int version) {
        ClassNode node = new ClassNode();
        node.version = version;
        node.access = access;
        node.name = name;
        node.superName = superName;
        return node;
    }

    private static MethodNode method(ClassNode owner, int access, String name, String desc) {
        MethodNode method = new MethodNode(access, name, desc, null, null);
        owner.methods.add(method);
        return method;
    }

    private static ClassNode saltB() {
        ClassNode node = classNode(B, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                "java/lang/Object", Opcodes.V1_8);
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "BASE", "I", null, null));

        MethodNode clinit = method(node, Opcodes.ACC_STATIC, "<clinit>", "()V");
        InsnList init = clinit.instructions;
        AsmUtil.pushInt(init, 5);
        init.add(new FieldInsnNode(Opcodes.PUTSTATIC, B, "BASE", "I"));
        init.add(new InsnNode(Opcodes.RETURN));

        MethodNode scaled = method(node, Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "scaled", "(I)I");
        InsnList scaledCode = scaled.instructions;
        scaledCode.add(new VarInsnNode(Opcodes.ILOAD, 0));
        AsmUtil.pushInt(scaledCode, 3);
        scaledCode.add(new InsnNode(Opcodes.IMUL));
        scaledCode.add(new InsnNode(Opcodes.ICONST_1));
        scaledCode.add(new InsnNode(Opcodes.IADD));
        scaledCode.add(new InsnNode(Opcodes.IRETURN));

        MethodNode shift = method(node, Opcodes.ACC_STATIC | Opcodes.ACC_FINAL, "shift", "(I)I");
        InsnList shiftCode = shift.instructions;
        shiftCode.add(new VarInsnNode(Opcodes.ILOAD, 0));
        shiftCode.add(new MethodInsnNode(Opcodes.INVOKESTATIC, B, "scaled", "(I)I", false));
        AsmUtil.pushInt(shiftCode, 7);
        shiftCode.add(new InsnNode(Opcodes.IADD));
        shiftCode.add(new InsnNode(Opcodes.IRETURN));

        MethodNode direct = method(node, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "direct", "(I)I");
        InsnList directCode = direct.instructions;
        directCode.add(new VarInsnNode(Opcodes.ILOAD, 0));
        directCode.add(new MethodInsnNode(Opcodes.INVOKESTATIC, B, "shift", "(I)I", false));
        AsmUtil.pushInt(directCode, 11);
        directCode.add(new InsnNode(Opcodes.IADD));
        directCode.add(new FieldInsnNode(Opcodes.GETSTATIC, B, "BASE", "I"));
        directCode.add(new InsnNode(Opcodes.IADD));
        directCode.add(new InsnNode(Opcodes.IRETURN));
        return node;
    }

    private static ClassNode saltA() {
        ClassNode node = classNode(A, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", Opcodes.V1_8);

        MethodNode init = method(node, Opcodes.ACC_PUBLIC, "<init>", "()V");
        init.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        init.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        init.instructions.add(new InsnNode(Opcodes.RETURN));

        // direct(x) + shift(x) - own(x) + mix(x)
        MethodNode inst = method(node, Opcodes.ACC_PUBLIC, "inst", "(I)I");
        InsnList code = inst.instructions;
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, B, "direct", "(I)I", false));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, B, "shift", "(I)I", false));
        code.add(new InsnNode(Opcodes.IADD));
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        code.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, A, "own", "(I)I", false));
        code.add(new InsnNode(Opcodes.ISUB));
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        code.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, A, "mix", "(I)I", false));
        code.add(new InsnNode(Opcodes.IADD));
        code.add(new InsnNode(Opcodes.IRETURN));

        // private int own(int) { return x * 2; }
        MethodNode own = method(node, Opcodes.ACC_PRIVATE, "own", "(I)I");
        own.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        own.instructions.add(new InsnNode(Opcodes.ICONST_2));
        own.instructions.add(new InsnNode(Opcodes.IMUL));
        own.instructions.add(new InsnNode(Opcodes.IRETURN));

        // private int mix(int) { return x * 7 + 3; }
        MethodNode mix = method(node, Opcodes.ACC_PRIVATE, "mix", "(I)I");
        AsmUtil.pushInt(mix.instructions, 7);
        mix.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        mix.instructions.add(new InsnNode(Opcodes.IMUL));
        AsmUtil.pushInt(mix.instructions, 3);
        mix.instructions.add(new InsnNode(Opcodes.IADD));
        mix.instructions.add(new InsnNode(Opcodes.IRETURN));

        // private static int helper(int) { return SaltB.direct(x) ^ (x + 1); }
        MethodNode helper = method(node, Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "helper", "(I)I");
        helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        helper.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, B, "direct", "(I)I", false));
        helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        helper.instructions.add(new InsnNode(Opcodes.ICONST_1));
        helper.instructions.add(new InsnNode(Opcodes.IADD));
        helper.instructions.add(new InsnNode(Opcodes.IXOR));
        helper.instructions.add(new InsnNode(Opcodes.IRETURN));

        // public static int stat(int) { int s = 0; for (int i = 1; i <= 3; i++) s += helper(x + i); return s; }
        MethodNode stat = method(node, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "stat", "(I)I");
        InsnList statCode = stat.instructions;
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        statCode.add(new InsnNode(Opcodes.ICONST_0));
        statCode.add(new VarInsnNode(Opcodes.ISTORE, 1));
        statCode.add(new InsnNode(Opcodes.ICONST_1));
        statCode.add(new VarInsnNode(Opcodes.ISTORE, 2));
        statCode.add(loop);
        statCode.add(new VarInsnNode(Opcodes.ILOAD, 2));
        AsmUtil.pushInt(statCode, 3);
        statCode.add(new JumpInsnNode(Opcodes.IF_ICMPGT, end));
        statCode.add(new VarInsnNode(Opcodes.ILOAD, 1));
        statCode.add(new VarInsnNode(Opcodes.ILOAD, 0));
        statCode.add(new VarInsnNode(Opcodes.ILOAD, 2));
        statCode.add(new InsnNode(Opcodes.IADD));
        statCode.add(new MethodInsnNode(Opcodes.INVOKESTATIC, A, "helper", "(I)I", false));
        statCode.add(new InsnNode(Opcodes.IADD));
        statCode.add(new VarInsnNode(Opcodes.ISTORE, 1));
        statCode.add(new IincInsnNode(2, 1));
        statCode.add(new JumpInsnNode(Opcodes.GOTO, loop));
        statCode.add(end);
        statCode.add(new VarInsnNode(Opcodes.ILOAD, 1));
        statCode.add(new InsnNode(Opcodes.IRETURN));
        return node;
    }

    private static ClassNode saltAbstract() {
        ClassNode node = classNode(ABSTRACT,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_SUPER,
                "java/lang/Object", Opcodes.V1_8);
        method(node, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "abs", "(I)I");
        method(node, Opcodes.ACC_PUBLIC | Opcodes.ACC_NATIVE, "nat", "(I)I");
        return node;
    }

    private static ClassNode saltInterface() {
        ClassNode node = classNode(INTERFACE,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT,
                "java/lang/Object", Opcodes.V1_8);
        method(node, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "itf", "(I)I");
        return node;
    }

    private static ClassNode saltKept() {
        ClassNode node = classNode(KEPT, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", Opcodes.V1_8);
        node.visibleAnnotations = new ArrayList<AnnotationNode>();
        node.visibleAnnotations.add(new AnnotationNode(KEEP_DESC));
        MethodNode hidden = method(node, Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "hidden", "(I)I");
        hidden.instructions.add(new InsnNode(Opcodes.ICONST_0));
        hidden.instructions.add(new InsnNode(Opcodes.IRETURN));
        return node;
    }

    private static ClassNode saltBroken() {
        ClassNode node = classNode(BROKEN, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", Opcodes.V1_8);
        // A JSR/RET subroutine: ASM refuses to compute frames for it, so the class
        // cannot be serialised by the frame-computing writer and the whole class has
        // to roll back (it still writes in verbatim-copy mode, which is what the
        // fixture uses).
        MethodNode broken = method(node, Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "broken", "(I)I");
        LabelNode subroutine = new LabelNode();
        broken.instructions.add(new JumpInsnNode(Opcodes.JSR, subroutine));
        broken.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        broken.instructions.add(new InsnNode(Opcodes.IRETURN));
        broken.instructions.add(subroutine);
        broken.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
        broken.instructions.add(new VarInsnNode(Opcodes.RET, 1));
        broken.maxStack = 2;
        broken.maxLocals = 2;
        MethodNode fine = method(node, Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "fine", "(I)I");
        fine.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        fine.instructions.add(new InsnNode(Opcodes.IRETURN));
        return node;
    }

    // -------------------------------------------------------------------- pass

    private static PassContext run(Map<String, byte[]> fixture, long seed, boolean enabled) {
        return runWith(fixture, seed, "salt.enabled", String.valueOf(enabled));
    }

    private static PassContext runWith(Map<String, byte[]> fixture, long seed, String key, String value) {
        PassContext context = context(fixture, seed, key, value);
        new SaltPass().run(context);
        return context;
    }

    private static PassContext bareContext(Map<String, byte[]> fixture, long seed) {
        try {
            UmbraConfig config = new UmbraConfig.Builder()
                    .input(Paths.get("in.jar"))
                    .output(Paths.get("out.jar"))
                    .seed(seed)
                    .build();
            ClassPool pool = new ClassPool();
            Hierarchy hierarchy = new Hierarchy();
            for (Map.Entry<String, byte[]> entry : fixture.entrySet()) {
                ClassNode node = read(entry.getValue());
                pool.putClass(entry.getKey() + ".class", entry.getValue(), node);
                hierarchy.addInput(node);
            }
            return new PassContext(config, pool, hierarchy,
                    new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(), false, false),
                    new DefaultRuntimeSupport(), new MappingSet(), new Stats(), new Log(null, false),
                    new Random(seed), ProgressListener.NONE);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static PassContext context(Map<String, byte[]> fixture, long seed, String key, String value) {
        try {
            UmbraConfig.Builder builder = new UmbraConfig.Builder()
                    .input(Paths.get("in.jar"))
                    .output(Paths.get("out.jar"))
                    .seed(seed)
                    .option("salt.enabled", "true")
                    .option("salt.methodParams", "true")
                    .option("salt.dispatcher", "true")
                    .option("salt.method.public", "true")
                    .option(key, value);
            UmbraConfig config = builder.build();
            ClassPool pool = new ClassPool();
            Hierarchy hierarchy = new Hierarchy();
            for (Map.Entry<String, byte[]> entry : fixture.entrySet()) {
                ClassNode node = read(entry.getValue());
                pool.putClass(entry.getKey() + ".class", entry.getValue(), node);
                hierarchy.addInput(node);
            }
            DefaultRuleSet rules = new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(),
                    false, false);
            return new PassContext(config, pool, hierarchy, rules, new DefaultRuntimeSupport(),
                    new MappingSet(), new Stats(), new Log(null, false), new Random(seed),
                    ProgressListener.NONE);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, byte[]> serialize(PassContext context, boolean skipBroken) {
        Map<String, byte[]> out = new TreeMap<String, byte[]>();
        for (ClassNode node : context.classes().classes().values()) {
            if (skipBroken && BROKEN.equals(node.name)) {
                continue;
            }
            if (BROKEN.equals(node.name)) {
                out.put(node.name, UmbraClassWriter.toBytesWithoutComputation(node, context.hierarchy()));
            } else {
                out.put(node.name, UmbraClassWriter.toBytes(node, context.hierarchy()));
            }
        }
        return out;
    }

    // --------------------------------------------------------------- assertions

    private static void verifyAll(Map<String, byte[]> classes) {
        final Map<String, byte[]> byName = new LinkedHashMap<String, byte[]>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            byName.put(entry.getKey().replace('/', '.'), entry.getValue());
        }
        ClassLoader loader = new ClassLoader(SaltTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] data = byName.get(name);
                if (data != null) {
                    return defineClass(name, data, 0, data.length);
                }
                return super.findClass(name);
            }
        };
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            StringWriter errors = new StringWriter();
            CheckClassAdapter.verify(new ClassReader(entry.getValue()), loader, false,
                    new PrintWriter(errors));
            check(errors.toString().trim().isEmpty(),
                    "CheckClassAdapter(" + entry.getKey() + "): " + errors.toString().trim());
        }
    }

    private static MapLoader load(Map<String, byte[]> classes) {
        Map<String, byte[]> byName = new LinkedHashMap<String, byte[]>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            byName.put(entry.getKey().replace('/', '.'), entry.getValue());
        }
        return new MapLoader(byName);
    }

    private static final class MapLoader extends ClassLoader {
        private final Map<String, byte[]> classes;

        MapLoader(Map<String, byte[]> classes) {
            super(SaltTest.class.getClassLoader());
            this.classes = classes;
        }

        Class<?> findClass0(String name) throws ClassNotFoundException {
            return Class.forName(name, true, this);
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] data = classes.get(name);
            if (data != null) {
                return defineClass(name, data, 0, data.length);
            }
            return super.findClass(name);
        }
    }

    private static FieldNode saltField(ClassNode node) {
        for (FieldNode field : node.fields) {
            if ("I".equals(field.desc) && (field.access & Opcodes.ACC_STATIC) != 0
                    && (field.access & Opcodes.ACC_FINAL) != 0 && !"BASE".equals(field.name)) {
                return field;
            }
        }
        return null;
    }

    private static boolean hasStore(ClassNode node, String fieldName) {
        MethodNode clinit = method(node, "<clinit>", "()V");
        if (clinit == null) {
            return false;
        }
        for (AbstractInsnNode insn = clinit.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof FieldInsnNode) {
                FieldInsnNode field = (FieldInsnNode) insn;
                if (field.getOpcode() == Opcodes.PUTSTATIC && node.name.equals(field.owner)
                        && fieldName.equals(field.name)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean hasConstantStore(ClassNode node, String fieldName) {
        MethodNode clinit = method(node, "<clinit>", "()V");
        if (clinit == null) {
            return false;
        }
        boolean pushesInt = false;
        for (AbstractInsnNode insn = clinit.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (isIntPush(insn)) {
                pushesInt = true;
                continue;
            }
            if (insn instanceof FieldInsnNode) {
                FieldInsnNode field = (FieldInsnNode) insn;
                if (field.getOpcode() == Opcodes.PUTSTATIC && fieldName.equals(field.name)) {
                    return pushesInt;
                }
                pushesInt = false;
            }
        }
        return false;
    }

    private static boolean isIntPush(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return true;
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return true;
        }
        return insn instanceof org.objectweb.asm.tree.LdcInsnNode
                && ((org.objectweb.asm.tree.LdcInsnNode) insn).cst instanceof Integer;
    }

    private static boolean readsSaltFieldTwice(MethodNode method, String owner, String fieldName) {
        int reads = 0;
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null && count < 16;
                insn = insn.getNext(), count++) {
            if (insn instanceof FieldInsnNode) {
                FieldInsnNode field = (FieldInsnNode) insn;
                if (field.getOpcode() == Opcodes.GETSTATIC && owner.equals(field.owner)
                        && fieldName.equals(field.name)) {
                    reads++;
                }
            }
        }
        return reads == 2;
    }

    private static boolean hasLocalStore(MethodNode method) {
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null && count < 20;
                insn = insn.getNext(), count++) {
            if (insn.getOpcode() == Opcodes.ISTORE) {
                return true;
            }
        }
        return false;
    }

    private static MethodNode method(ClassNode node, String name, String desc) {
        if (node == null) {
            return null;
        }
        for (MethodNode method : node.methods) {
            if (method.name.equals(name) && method.desc.equals(desc)) {
                return method;
            }
        }
        return null;
    }

    private static String desc(ClassNode node, String name) {
        if (node == null) {
            return "<missing class>";
        }
        for (MethodNode method : node.methods) {
            if (method.name.equals(name)) {
                return method.desc;
            }
        }
        return "<missing method " + name + ">";
    }

    private static String generatedClass(PassContext context) {
        for (String name : context.classes().classes().keySet()) {
            if (context.classes().isGenerated(name)) {
                return name;
            }
        }
        return null;
    }

    private static long stat(Stats stats, String key) {
        Long value = stats.snapshot().get(key);
        return value == null ? 0L : value.longValue();
    }

    private static boolean sameBytes(Map<String, byte[]> left, Map<String, byte[]> right) {
        if (!left.keySet().equals(right.keySet())) {
            return false;
        }
        for (Map.Entry<String, byte[]> entry : left.entrySet()) {
            if (!Arrays.equals(entry.getValue(), right.get(entry.getKey()))) {
                return false;
            }
        }
        return true;
    }

    private static int readInt(byte[] value) {
        if (value == null || value.length != 4) {
            return -1;
        }
        return ((value[0] & 0xFF) << 24) | ((value[1] & 0xFF) << 16) | ((value[2] & 0xFF) << 8)
                | (value[3] & 0xFF);
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}