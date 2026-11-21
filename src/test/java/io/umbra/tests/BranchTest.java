package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.BranchShapePass;
import io.umbra.core.pass.impl.DefinalizePass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.RecordComponentNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Self test for {@link BranchShapePass} (order 89) and {@link DefinalizePass}
 * (order 39).
 *
 * <p>Plain-main harness, no JUnit: a non-zero exit fails the build.</p>
 *
 * <p>Coverage:</p>
 * <ol>
 *   <li>the sixteen conditional branch opcodes are pinned against
 *       {@link Opcodes} itself (reflection), so a missing or asymmetric inverse
 *       cannot hide behind a hand-written list;</li>
 *   <li>a synthetic class exercising every conditional opcode - including
 *       {@code lcmp}/{@code fcmpl}/{@code fcmpg}/{@code dcmpl}/{@code dcmpg}
 *       feeding {@code IF&lt;cond&gt;} - is negated at rate 100 and every method
 *       result is compared with the untouched baseline over a wide input
 *       table;</li>
 *   <li>a {@code tableswitch}, a {@code lookupswitch}, an adjacent
 *       {@code IF_ICMPEQ} chain and the javac if/else chain shape are pushed
 *       through both directions and the switch count is asserted to actually
 *       change;</li>
 *   <li>final class/method/field flags are cleared, a migrated
 *       {@code ConstantValue} still reads back through reflection, and records,
 *       enums, interfaces and module descriptors keep their flags;</li>
 *   <li>same seed, twice, byte for byte;</li>
 *   <li>a method with an unresolvable reference is rejected by the gate while
 *       the class still serialises.</li>
 * </ol>
 * <p>Every transformed class is checked with {@link CheckClassAdapter} and then
 * loaded by a real class loader before it is called.</p>
 */
public final class BranchTest {

    private static final String TARGET = "test/BranchTarget";
    private static final String TARGET_DOTTED = "test.BranchTarget";
    private static final String BOGUS = "test/BranchBogus";
    private static final String BOGUS_DOTTED = "test.BranchBogus";
    private static final String FINAL_TARGET = "test/FinalTarget";
    private static final String FINAL_TARGET_DOTTED = "test.FinalTarget";
    private static final String RECORD_LIKE = "test/RecordLike";
    private static final String ENUM_LIKE = "test/EnumLike";
    private static final String IFACE_LIKE = "test/IfaceLike";
    private static final String MODULE_LIKE = "module-info";

    private static final String[] INT_METHODS = {
            "ifEq", "ifNe", "ifLt", "ifGe", "ifGt", "ifLe",
            "nested", "loop", "tryBranch", "degenerate",
            "tableSwitch", "lookSwitch", "eqChain", "neChain"
    };
    private static final String[] IINT_METHODS = {
            "icmpEq", "icmpNe", "icmpLt", "icmpGe", "icmpGt", "icmpLe"
    };
    private static final String[] FLOAT_METHODS = {"fcmpgJump", "fcmplJump"};
    private static final String[] LONG_METHODS = {"lcmpJump"};
    private static final String[] DOUBLE_METHODS = {"dcmpgJump", "dcmplJump"};

    private static int checks;

    private BranchTest() {
    }

    public static void main(String[] args) throws Exception {
        testOpcodeTable();
        testNegation();
        testSwitchToIf();
        testIfToSwitch();
        testDefinalize();
        testDefinalizeSkips();
        testDeterminism();
        testGateRollback();
        System.out.println("BranchTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------ opcode table

    private static void testOpcodeTable() throws Exception {
        Map<Integer, String> declared = new HashMap<Integer, String>();
        for (java.lang.reflect.Field field : Opcodes.class.getFields()) {
            if (field.getType() != int.class || !field.getName().startsWith("IF")) {
                continue;
            }
            int value = field.getInt(null);
            if (value < 0 || value > 255) {
                continue;
            }
            declared.put(Integer.valueOf(value), field.getName());
            check(BranchShapePass.isConditionalJump(value),
                    "conditional opcode covered: " + field.getName());
            int inverse = BranchShapePass.inverseOpcode(value);
            check(inverse >= 0, "inverse exists for " + field.getName());
            check(BranchShapePass.inverseOpcode(inverse) == value,
                    "inverse is an involution for " + field.getName());
            check(inverse != value, "inverse differs from itself for " + field.getName());
        }
        check(declared.size() == 16, "the JVM has exactly sixteen conditional branches, saw "
                + declared.size() + ": " + declared.values());

        int[] notBranches = {
                Opcodes.LCMP, Opcodes.FCMPL, Opcodes.FCMPG, Opcodes.DCMPL, Opcodes.DCMPG,
                Opcodes.GOTO, Opcodes.JSR, Opcodes.RET, Opcodes.IRETURN, Opcodes.ARETURN,
                Opcodes.TABLESWITCH, Opcodes.LOOKUPSWITCH
        };
        for (int opcode : notBranches) {
            check(!BranchShapePass.isConditionalJump(opcode),
                    "opcode " + opcode + " is not a conditional branch");
            check(BranchShapePass.inverseOpcode(opcode) == -1,
                    "no inverse for opcode " + opcode);
        }
    }

    // --------------------------------------------------------------- negation

    private static void testNegation() throws Exception {
        ClassNode node = target();
        byte[] original = serialize(node);
        verify(original, TARGET, "baseline");
        Class<?> baselineType = load(original, TARGET, TARGET_DOTTED);
        List<String> baseline = observe(baselineType);

        int expected = countNegatableJumps(node);
        check(expected >= 24, "the synthetic class carries a useful number of branches: "
                + expected);

        PassContext context = context(Arrays.asList(node), 9001L,
                "branch.enabled", "true",
                "branch.negateRate", "100",
                "branch.switchMode", "none");
        new BranchShapePass().run(context);

        check(stat(context, "branch.negated") == expected,
                "every conditional branch was negated: " + stat(context, "branch.negated")
                        + " vs " + expected);
        check(stat(context, "branch.sites") == expected, "sites match the negated count");
        check(stat(context, "branch.switchToIf") == 0, "toIf disabled for this run");
        check(stat(context, "branch.ifToSwitch") == 0, "toSwitch disabled for this run");
        check(stat(context, "branch.methods") > 0, "at least one method was rewritten");
        check(stat(context, "branch.classes") == 1, "exactly one class was rewritten");
        check(stat(context, "branch.skipped.clinit") == 1, "<clinit> is protected by default");
        check(stat(context, "branch.skipped.bridge") == 1, "the bridge method was skipped");
        check(stat(context, "branch.skipped.sites") >= 1, "the degenerate branch was skipped");
        check(stat(context, "branch.skip.rollback") == 0, "nothing rolled back");

        byte[] transformed = serialize(node);
        verify(transformed, TARGET, "negate");
        check(countConditional(transformed) == countConditional(original),
                "negation keeps the number of conditional branches");
        check(countOpcode(transformed, Opcodes.GOTO)
                        == countOpcode(original, Opcodes.GOTO) + expected,
                "negation added exactly one GOTO per negated branch");
        check(countJumps(transformed, "<clinit>") == countJumps(original, "<clinit>"),
                "<clinit> bytecode untouched");
        check(countJumps(transformed, "bridge") == countJumps(original, "bridge"),
                "bridge bytecode untouched");
        check(countJumps(transformed, "degenerate") == 1, "the degenerate branch kept its shape");
        checkNegatedShape(transformed, "ifEq");

        Class<?> type = load(transformed, TARGET, TARGET_DOTTED);
        compareObservations(baseline, observe(type), "negation");
        // The pre-super branch had to survive with uninitializedThis carried across
        // the rewritten edge: constructing proves the verifier accepted it.
        type.getDeclaredConstructor(int.class).newInstance(Integer.valueOf(1));
        type.getDeclaredConstructor(int.class).newInstance(Integer.valueOf(0));
        checks++;
    }

    private static void checkNegatedShape(byte[] bytes, String name) {
        MethodNode method = findMethod(bytes, name);
        List<AbstractInsnNode> real = realInstructions(method);
        check(real.size() == 7, name + " grew by exactly one instruction: " + real.size());
        check(real.get(1).getOpcode() == Opcodes.IFNE, name + " condition was inverted");
        check(real.get(2).getOpcode() == Opcodes.GOTO, name + " gained the jump back to target");
        LabelNode skip = ((JumpInsnNode) real.get(1)).label;
        check(firstRealFrom(skip) == real.get(3),
                name + " skip label sits on the original fallthrough");
    }

    // ------------------------------------------------------------ switch to if

    private static void testSwitchToIf() throws Exception {
        ClassNode node = target();
        byte[] original = serialize(node);
        List<String> baseline = observe(load(original, TARGET, TARGET_DOTTED));
        int before = countOpcode(original, Opcodes.IF_ICMPEQ);
        int switchesBefore = countSwitchNodes(original);
        check(switchesBefore == 2, "the synthetic class has two switches: " + switchesBefore);

        PassContext context = context(Arrays.asList(node), 9002L,
                "branch.enabled", "true",
                "branch.negateRate", "0",
                "branch.switchMode", "toIf");
        new BranchShapePass().run(context);

        check(stat(context, "branch.switchToIf") == 2, "both switches became if chains: "
                + stat(context, "branch.switchToIf"));
        check(stat(context, "branch.ifToSwitch") == 0, "no if chain was merged back");
        check(stat(context, "branch.negated") == 0, "negation disabled for this run");

        byte[] transformed = serialize(node);
        verify(transformed, TARGET, "toIf");
        check(countSwitchNodes(transformed) == 0, "no switch instruction survived");
        check(countOpcode(transformed, Opcodes.IF_ICMPEQ) == before + 9,
                "each case became one comparison (5 + 4): "
                        + countOpcode(transformed, Opcodes.IF_ICMPEQ) + " vs " + (before + 9));
        compareObservations(baseline, observe(load(transformed, TARGET, TARGET_DOTTED)), "toIf");
    }

    // ------------------------------------------------------------ if to switch

    private static void testIfToSwitch() throws Exception {
        ClassNode node = target();
        byte[] original = serialize(node);
        List<String> baseline = observe(load(original, TARGET, TARGET_DOTTED));
        int switchesBefore = countSwitchNodes(original);

        PassContext context = context(Arrays.asList(node), 9003L,
                "branch.enabled", "true",
                "branch.negateRate", "0",
                "branch.switchMode", "toSwitch");
        new BranchShapePass().run(context);

        check(stat(context, "branch.ifToSwitch") == 2, "both chains became switches: "
                + stat(context, "branch.ifToSwitch"));
        check(stat(context, "branch.switchToIf") == 0, "no switch became an if chain");
        check(stat(context, "branch.negated") == 0, "negation disabled for this run");

        byte[] transformed = serialize(node);
        verify(transformed, TARGET, "toSwitch");
        check(countSwitchNodes(transformed) == switchesBefore + 2,
                "two switches were added: " + countSwitchNodes(transformed));
        check(countConditionalInMethod(transformed, "eqChain") == 0,
                "the adjacent IF_ICMPEQ chain was consumed");
        check(countConditionalInMethod(transformed, "neChain") == 0,
                "the javac if/else chain was consumed");
        check(hasSwitchKind(transformed, "tableSwitch", true), "tableswitch survived");
        check(hasSwitchKind(transformed, "lookSwitch", false), "lookupswitch survived");
        check(hasSwitchKind(transformed, "eqChain", true),
                "contiguous keys became a table switch");
        check(hasSwitchKind(transformed, "neChain", false),
                "sparse keys became a lookup switch");
        compareObservations(baseline, observe(load(transformed, TARGET, TARGET_DOTTED)),
                "toSwitch");
    }

    // -------------------------------------------------------------- definalize

    private static void testDefinalize() throws Exception {
        ClassNode node = finalTarget();
        byte[] original = serialize(node);
        verify(original, FINAL_TARGET, "final-baseline");
        Class<?> before = load(original, FINAL_TARGET, FINAL_TARGET_DOTTED);
        check((before.getModifiers() & Modifier.FINAL) != 0, "the baseline class is final");
        check(before.getField("C").getInt(null) == 7, "the baseline constant reads back");

        PassContext context = context(Arrays.asList(node), 9004L,
                "definalize.enabled", "true");
        new DefinalizePass().run(context);

        check(stat(context, "definalize.classes") == 1, "the class lost its final flag");
        check(stat(context, "definalize.methods") == 2, "both final methods were cleared: "
                + stat(context, "definalize.methods"));
        check(stat(context, "definalize.fields") == 5, "all five final fields were cleared: "
                + stat(context, "definalize.fields"));
        check(stat(context, "definalize.skip.rollback") == 0, "nothing rolled back");

        byte[] transformed = serialize(node);
        verify(transformed, FINAL_TARGET, "definalize");
        for (FieldNode field : node.fields) {
            check((field.access & Opcodes.ACC_FINAL) == 0, field.name + " is no longer final");
        }
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) || "<init>".equals(method.name)) {
                continue;
            }
            check((method.access & Opcodes.ACC_FINAL) == 0, method.name + " is no longer final");
        }
        check(findField(node, "C").value == null, "the ConstantValue attribute was migrated");

        Class<?> type = load(transformed, FINAL_TARGET, FINAL_TARGET_DOTTED);
        check((type.getModifiers() & Modifier.FINAL) == 0, "reflection sees a non-final class");
        check((type.getField("C").getModifiers() & Modifier.FINAL) == 0,
                "reflection sees a non-final field");
        check(type.getField("C").getInt(null) == 7,
                "the migrated constant still initialises the field: "
                        + type.getField("C").getInt(null));
        check("hi".equals(type.getField("S").get(null)), "the migrated String constant survived");
        check(type.getField("L").getLong(null) == 123456789012L, "the migrated long survived");
        check(type.getField("D").getDouble(null) == 2.5, "the migrated double survived");
        check(findField(node, "S").value == null, "the String ConstantValue was migrated too");

        Object instance = type.getDeclaredConstructor().newInstance();
        check(((Integer) type.getMethod("m").invoke(instance)).intValue() == 43,
                "the instance method still computes through the instance field");
        check((type.getMethod("m").getModifiers() & Modifier.FINAL) == 0,
                "reflection sees a non-final method");
        check(((Integer) type.getMethod("k").invoke(null)).intValue() == 99,
                "the static method still runs");
    }

    private static void testDefinalizeSkips() throws Exception {
        ClassNode record = recordLike();
        ClassNode enumNode = enumLike();
        ClassNode iface = interfaceLike();
        ClassNode module = moduleLike();

        List<ClassNode> nodes = Arrays.asList(record, enumNode, iface, module);
        PassContext context = context(nodes, 9005L, "definalize.enabled", "true");
        new DefinalizePass().run(context);

        check(stat(context, "definalize.skipped.record") == 1, "the record was skipped: "
                + stat(context, "definalize.skipped.record"));
        check((record.access & Opcodes.ACC_FINAL) != 0, "the record kept its final flag");
        check((findField(record, "x").access & Opcodes.ACC_FINAL) != 0,
                "the record component field kept its final flag");
        check(record.recordComponents != null && record.recordComponents.size() == 1,
                "the record component survived");
        byte[] recordBytes = serialize(record);
        ClassNode recordBack = read(recordBytes);
        check(recordBack.recordComponents != null && recordBack.recordComponents.size() == 1,
                "the serialised record still carries its Record attribute");

        check(stat(context, "definalize.skipped.enum") >= 1, "the enum constant was skipped");
        check((findField(enumNode, "A").access & Opcodes.ACC_FINAL) != 0,
                "the enum constant kept its final flag");
        check((enumNode.access & Opcodes.ACC_FINAL) == 0,
                "the enum class itself was definalised");
        verify(serialize(enumNode), ENUM_LIKE, "enum-definalize");

        check(stat(context, "definalize.skipped.interface") == 1, "the interface was skipped");
        check((findField(iface, "K").access & Opcodes.ACC_FINAL) != 0,
                "the interface constant kept its final flag");
        check(findField(iface, "K").value != null, "the interface constant kept its value");

        check(stat(context, "definalize.skipped.module") == 1, "module-info was skipped");
        check((module.access & Opcodes.ACC_FINAL) != 0, "module-info kept its flags");
        check(stat(context, "definalize.classes") == 1,
                "only the enum class was definalised in this run: "
                        + stat(context, "definalize.classes"));
    }

    // ------------------------------------------------------------ determinism

    private static void testDeterminism() throws Exception {
        byte[] original = serialize(target());

        ClassNode first = read(original);
        ClassNode second = read(original);
        PassContext a = context(Arrays.asList(first), 777L,
                "branch.enabled", "true",
                "branch.negateRate", "70",
                "branch.switchMode", "mix",
                "branch.switchRate", "80");
        PassContext b = context(Arrays.asList(second), 777L,
                "branch.enabled", "true",
                "branch.negateRate", "70",
                "branch.switchMode", "mix",
                "branch.switchRate", "80");
        new BranchShapePass().run(a);
        new BranchShapePass().run(b);
        byte[] firstBytes = serialize(first);
        byte[] secondBytes = serialize(second);
        check(Arrays.equals(firstBytes, secondBytes),
                "branch-shape is deterministic for a fixed seed");
        check(stat(a, "branch.sites") > 0, "the mixed run rewrote something: "
                + stat(a, "branch.sites"));
        check(stat(a, "branch.sites") == stat(b, "branch.sites"), "both runs agreed on the count");
        verify(firstBytes, TARGET, "determinism");
        compareObservations(observe(load(serialize(read(original)), TARGET, TARGET_DOTTED)),
                observe(load(firstBytes, TARGET, TARGET_DOTTED)), "mixed");

        ClassNode finalFirst = read(serialize(finalTarget()));
        ClassNode finalSecond = read(serialize(finalTarget()));
        new DefinalizePass().run(context(Arrays.asList(finalFirst), 778L,
                "definalize.enabled", "true"));
        new DefinalizePass().run(context(Arrays.asList(finalSecond), 778L,
                "definalize.enabled", "true"));
        check(Arrays.equals(serialize(finalFirst), serialize(finalSecond)),
                "definalize is deterministic for a fixed seed");
    }

    // ---------------------------------------------------------- gate rollback

    private static void testGateRollback() throws Exception {
        ClassNode target = target();
        ClassNode bogus = bogus();
        byte[] originalBogus = serialize(bogus);
        int before = bogus.methods.get(0).instructions.size();

        PassContext context = context(Arrays.asList(target, bogus), 9006L,
                "branch.enabled", "true",
                "branch.negateRate", "100",
                "branch.switchMode", "toIf");
        new BranchShapePass().run(context);

        check(stat(context, "branch.skipped.gate") >= 1,
                "the unresolvable method was rejected by the gate: "
                        + stat(context, "branch.skipped.gate"));
        check(bogus.methods.get(0).instructions.size() == before,
                "the rejected method kept its original bytecode");
        check(stat(context, "branch.negated") > 0, "the healthy class was still transformed");
        byte[] bogusBytes = serialize(bogus);
        check(bogusBytes.length == originalBogus.length,
                "the untouched class serialises to the same size");
        check(countConditional(bogusBytes) == countConditional(originalBogus),
                "the untouched class keeps its branch shape");
    }

    // ------------------------------------------------------------- the target

    private static ClassNode target() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = TARGET;
        node.superName = "java/lang/Object";
        node.methods.add(constructor(TARGET));
        node.methods.add(superBranchConstructor(TARGET));
        node.methods.add(clinit());
        node.methods.add(intJump("ifEq", Opcodes.IFEQ));
        node.methods.add(intJump("ifNe", Opcodes.IFNE));
        node.methods.add(intJump("ifLt", Opcodes.IFLT));
        node.methods.add(intJump("ifGe", Opcodes.IFGE));
        node.methods.add(intJump("ifGt", Opcodes.IFGT));
        node.methods.add(intJump("ifLe", Opcodes.IFLE));
        node.methods.add(cmpJump("icmpEq", Opcodes.IF_ICMPEQ));
        node.methods.add(cmpJump("icmpNe", Opcodes.IF_ICMPNE));
        node.methods.add(cmpJump("icmpLt", Opcodes.IF_ICMPLT));
        node.methods.add(cmpJump("icmpGe", Opcodes.IF_ICMPGE));
        node.methods.add(cmpJump("icmpGt", Opcodes.IF_ICMPGT));
        node.methods.add(cmpJump("icmpLe", Opcodes.IF_ICMPLE));
        node.methods.add(acmpJump("acmpEq", Opcodes.IF_ACMPEQ));
        node.methods.add(acmpJump("acmpNe", Opcodes.IF_ACMPNE));
        node.methods.add(nullJump("ifNull", Opcodes.IFNULL));
        node.methods.add(nullJump("ifNonNull", Opcodes.IFNONNULL));
        node.methods.add(fcmpJump("fcmpgJump", Opcodes.FCMPG, Opcodes.IFGT));
        node.methods.add(fcmpJump("fcmplJump", Opcodes.FCMPL, Opcodes.IFLT));
        node.methods.add(lcmpJump("lcmpJump"));
        node.methods.add(dcmpJump("dcmpgJump", Opcodes.DCMPG, Opcodes.IFLE));
        node.methods.add(dcmpJump("dcmplJump", Opcodes.DCMPL, Opcodes.IFGE));
        node.methods.add(nested());
        node.methods.add(loop());
        node.methods.add(tryBranch());
        node.methods.add(degenerate());
        node.methods.add(tableSwitch());
        node.methods.add(lookSwitch());
        node.methods.add(eqChain());
        node.methods.add(neChain());
        node.methods.add(bridge());
        return node;
    }

    private static MethodNode constructor(String owner) {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object",
                "<init>", "()V", false));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        return method;
    }

    /**
     * A constructor whose branch sits in the window before {@code super()}.
     * javac never emits this, but obfuscated input does, and it is the case where
     * a rewritten branch has to carry {@code uninitializedThis} across two blocks.
     */
    private static MethodNode superBranchConstructor(String owner) {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "(I)V", null, null);
        LabelNode other = new LabelNode();
        LabelNode end = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new JumpInsnNode(Opcodes.IFEQ, other));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object",
                "<init>", "()V", false));
        method.instructions.add(new JumpInsnNode(Opcodes.GOTO, end));
        method.instructions.add(other);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object",
                "<init>", "()V", false));
        method.instructions.add(end);
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        method.maxStack = 1;
        method.maxLocals = 2;
        return method;
    }

    private static MethodNode clinit() {
        MethodNode method = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        LabelNode skip = new LabelNode();
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new JumpInsnNode(Opcodes.IFEQ, skip));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        method.instructions.add(skip);
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        method.maxStack = 1;
        method.maxLocals = 0;
        return method;
    }

    private static MethodNode intJump(String name, int opcode) {
        MethodNode method = staticMethod(name, "(I)I");
        LabelNode yes = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new JumpInsnNode(opcode, yes));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(yes);
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        return method;
    }

    private static MethodNode cmpJump(String name, int opcode) {
        MethodNode method = staticMethod(name, "(II)I");
        LabelNode yes = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new JumpInsnNode(opcode, yes));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(yes);
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 2;
        return method;
    }

    private static MethodNode acmpJump(String name, int opcode) {
        MethodNode method = staticMethod(name, "(Ljava/lang/String;Ljava/lang/String;)I");
        LabelNode yes = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 1));
        method.instructions.add(new JumpInsnNode(opcode, yes));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(yes);
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 2;
        return method;
    }

    private static MethodNode nullJump(String name, int opcode) {
        MethodNode method = staticMethod(name, "(Ljava/lang/Object;)I");
        LabelNode yes = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new JumpInsnNode(opcode, yes));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(yes);
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        return method;
    }

    private static MethodNode fcmpJump(String name, int cmpOpcode, int jumpOpcode) {
        MethodNode method = staticMethod(name, "(F)I");
        LabelNode yes = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.FLOAD, 0));
        method.instructions.add(new InsnNode(Opcodes.FCONST_0));
        method.instructions.add(new InsnNode(cmpOpcode));
        method.instructions.add(new JumpInsnNode(jumpOpcode, yes));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(yes);
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 1;
        return method;
    }

    private static MethodNode lcmpJump(String name) {
        MethodNode method = staticMethod(name, "(JJ)I");
        LabelNode yes = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.LLOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.LLOAD, 2));
        method.instructions.add(new InsnNode(Opcodes.LCMP));
        method.instructions.add(new JumpInsnNode(Opcodes.IFEQ, yes));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(yes);
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 4;
        method.maxLocals = 4;
        return method;
    }

    private static MethodNode dcmpJump(String name, int cmpOpcode, int jumpOpcode) {
        MethodNode method = staticMethod(name, "(DD)I");
        LabelNode yes = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.DLOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.DLOAD, 2));
        method.instructions.add(new InsnNode(cmpOpcode));
        method.instructions.add(new JumpInsnNode(jumpOpcode, yes));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(yes);
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 4;
        method.maxLocals = 4;
        return method;
    }

    private static MethodNode nested() {
        MethodNode method = staticMethod("nested", "(I)I");
        LabelNode outer = new LabelNode();
        LabelNode inner = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new JumpInsnNode(Opcodes.IFLE, outer));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new InsnNode(Opcodes.ICONST_2));
        method.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPGT, inner));
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 50));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(inner);
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 51));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(outer);
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 52));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 1;
        return method;
    }

    private static MethodNode loop() {
        MethodNode method = staticMethod("loop", "(I)I");
        LabelNode head = new LabelNode();
        LabelNode end = new LabelNode();
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 1));
        method.instructions.add(head);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IADD));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 1));
        method.instructions.add(new JumpInsnNode(Opcodes.GOTO, head));
        method.instructions.add(end);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 2;
        return method;
    }

    private static MethodNode tryBranch() {
        MethodNode method = staticMethod("tryBranch", "(I)I");
        LabelNode start = new LabelNode();
        LabelNode ok = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        method.instructions.add(start);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new JumpInsnNode(Opcodes.IFGE, ok));
        method.instructions.add(new org.objectweb.asm.tree.TypeInsnNode(Opcodes.NEW,
                "java/lang/IllegalArgumentException"));
        method.instructions.add(new InsnNode(Opcodes.DUP));
        method.instructions.add(new LdcInsnNode("neg"));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/IllegalArgumentException", "<init>", "(Ljava/lang/String;)V", false));
        method.instructions.add(new InsnNode(Opcodes.ATHROW));
        method.instructions.add(ok);
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 100));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new InsnNode(Opcodes.IDIV));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 1));
        method.instructions.add(end);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(handler);
        method.instructions.add(new VarInsnNode(Opcodes.ASTORE, 2));
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, -7));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
        method.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler,
                "java/lang/ArithmeticException"));
        method.maxStack = 3;
        method.maxLocals = 3;
        return method;
    }

    private static MethodNode degenerate() {
        MethodNode method = staticMethod("degenerate", "(I)I");
        LabelNode next = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new JumpInsnNode(Opcodes.IFEQ, next));
        method.instructions.add(next);
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        return method;
    }

    private static MethodNode tableSwitch() {
        MethodNode method = staticMethod("tableSwitch", "(I)I");
        LabelNode dflt = new LabelNode();
        LabelNode[] cases = new LabelNode[5];
        for (int i = 0; i < cases.length; i++) {
            cases[i] = new LabelNode();
        }
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new TableSwitchInsnNode(0, 4, dflt, cases));
        for (int i = 0; i < cases.length; i++) {
            method.instructions.add(cases[i]);
            push(method, 10 + i);
            method.instructions.add(new InsnNode(Opcodes.IRETURN));
        }
        method.instructions.add(dflt);
        method.instructions.add(new InsnNode(Opcodes.ICONST_M1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        return method;
    }

    private static MethodNode lookSwitch() {
        MethodNode method = staticMethod("lookSwitch", "(I)I");
        LabelNode dflt = new LabelNode();
        LabelNode[] labels = new LabelNode[4];
        for (int i = 0; i < labels.length; i++) {
            labels[i] = new LabelNode();
        }
        int[] keys = {-100, 7, 1000, 100000};
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new LookupSwitchInsnNode(dflt, keys, labels));
        for (int i = 0; i < labels.length; i++) {
            method.instructions.add(labels[i]);
            push(method, 20 + i);
            method.instructions.add(new InsnNode(Opcodes.IRETURN));
        }
        method.instructions.add(dflt);
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, -2));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        return method;
    }

    private static MethodNode eqChain() {
        MethodNode method = staticMethod("eqChain", "(I)I");
        LabelNode c1 = new LabelNode();
        LabelNode c2 = new LabelNode();
        LabelNode c3 = new LabelNode();
        for (int key = 1; key <= 3; key++) {
            method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
            method.instructions.add(new InsnNode(Opcodes.ICONST_0 + key));
            method.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPEQ,
                    key == 1 ? c1 : key == 2 ? c2 : c3));
        }
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, -3));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(c1);
        push(method, 30);
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(c2);
        push(method, 31);
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(c3);
        push(method, 32);
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 1;
        return method;
    }

    private static MethodNode neChain() {
        MethodNode method = staticMethod("neChain", "(I)I");
        LabelNode l2 = new LabelNode();
        LabelNode l3 = new LabelNode();
        LabelNode l4 = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPNE, l2));
        push(method, 40);
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(l2);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 5));
        method.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPNE, l3));
        push(method, 41);
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(l3);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new IntInsnNode(Opcodes.SIPUSH, 1000));
        method.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPNE, l4));
        push(method, 42);
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(l4);
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, -4));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 1;
        return method;
    }

    private static MethodNode bridge() {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_BRIDGE
                        | Opcodes.ACC_SYNTHETIC | Opcodes.ACC_FINAL,
                "bridge", "(II)I", null, null);
        LabelNode yes = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, yes));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(yes);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 2;
        return method;
    }

    private static ClassNode bogus() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = BOGUS;
        node.superName = "java/lang/Object";
        node.methods.add(constructor(BOGUS));
        // A switch-arm that returns an int where the method declares an object:
        // ASM's frame computation does not type-check so the class still writes,
        // but the verifier rejects it and MethodGate must drop the method.
        // (A merely unresolvable reference would NOT do: the JVM verifier tolerates
        // missing classes, which is exactly why MethodGate has that tolerance flag.)
        MethodNode method = staticMethod("broken", "(I)Ljava/lang/Object;");
        LabelNode yes = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new JumpInsnNode(Opcodes.IFEQ, yes));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.instructions.add(yes);
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        node.methods.add(method);
        return node;
    }

    private static ClassNode finalTarget() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER;
        node.name = FINAL_TARGET;
        node.superName = "java/lang/Object";
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "C", "I", null, Integer.valueOf(7)));
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "S", "Ljava/lang/String;", null, "hi"));
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "L", "J", null, Long.valueOf(123456789012L)));
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "D", "D", null, Double.valueOf(2.5)));
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                "inst", "I", null, null));

        MethodNode init = constructor(FINAL_TARGET);
        init.instructions.insertBefore(init.instructions.getLast(),
                new VarInsnNode(Opcodes.ALOAD, 0));
        init.instructions.insertBefore(init.instructions.getLast(),
                new IntInsnNode(Opcodes.BIPUSH, 42));
        init.instructions.insertBefore(init.instructions.getLast(),
                new FieldInsnNode(Opcodes.PUTFIELD, FINAL_TARGET, "inst", "I"));
        init.maxStack = 2;
        node.methods.add(init);

        MethodNode m = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, "m", "()I",
                null, null);
        m.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        m.instructions.add(new FieldInsnNode(Opcodes.GETFIELD, FINAL_TARGET, "inst", "I"));
        m.instructions.add(new InsnNode(Opcodes.ICONST_1));
        m.instructions.add(new InsnNode(Opcodes.IADD));
        m.instructions.add(new InsnNode(Opcodes.IRETURN));
        m.maxStack = 2;
        m.maxLocals = 1;
        node.methods.add(m);

        MethodNode k = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL, "k", "()I",
                null, null);
        k.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 99));
        k.instructions.add(new InsnNode(Opcodes.IRETURN));
        k.maxStack = 1;
        k.maxLocals = 0;
        node.methods.add(k);
        return node;
    }

    private static ClassNode recordLike() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V16;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER;
        node.name = RECORD_LIKE;
        node.superName = "java/lang/Object";
        node.recordComponents = new ArrayList<RecordComponentNode>();
        node.recordComponents.add(new RecordComponentNode("x", "I", null));
        node.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL, "x", "I",
                null, null));

        MethodNode init = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "(I)V", null, null);
        init.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        init.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object",
                "<init>", "()V", false));
        init.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        init.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        init.instructions.add(new FieldInsnNode(Opcodes.PUTFIELD, RECORD_LIKE, "x", "I"));
        init.instructions.add(new InsnNode(Opcodes.RETURN));
        init.maxStack = 2;
        init.maxLocals = 2;
        node.methods.add(init);

        MethodNode accessor = new MethodNode(Opcodes.ACC_PUBLIC, "x", "()I", null, null);
        accessor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        accessor.instructions.add(new FieldInsnNode(Opcodes.GETFIELD, RECORD_LIKE, "x", "I"));
        accessor.instructions.add(new InsnNode(Opcodes.IRETURN));
        accessor.maxStack = 1;
        accessor.maxLocals = 1;
        node.methods.add(accessor);
        return node;
    }

    private static ClassNode enumLike() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER
                | Opcodes.ACC_ENUM;
        node.name = ENUM_LIKE;
        node.superName = "java/lang/Enum";
        node.fields.add(new FieldNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_ENUM,
                "A", "L" + ENUM_LIKE + ";", null, null));
        return node;
    }

    private static ClassNode interfaceLike() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT;
        node.name = IFACE_LIKE;
        node.superName = "java/lang/Object";
        node.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "K", "I", null, Integer.valueOf(5)));
        return node;
    }

    private static ClassNode moduleLike() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_MODULE | Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL;
        node.name = MODULE_LIKE;
        node.superName = "java/lang/Object";
        return node;
    }

    // ---------------------------------------------------------------- helpers

    private static MethodNode staticMethod(String name, String desc) {
        return new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, desc, null, null);
    }

    private static void push(MethodNode method, int value) {
        if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, value));
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            method.instructions.add(new IntInsnNode(Opcodes.SIPUSH, value));
        } else {
            method.instructions.add(new LdcInsnNode(Integer.valueOf(value)));
        }
    }

    private static FieldNode findField(ClassNode node, String name) {
        for (FieldNode field : node.fields) {
            if (field.name.equals(name)) {
                return field;
            }
        }
        throw new IllegalStateException("no field " + name + " in " + node.name);
    }

    private static List<String> observe(Class<?> type) {
        List<String> out = new ArrayList<String>();
        int[] values = {Integer.MIN_VALUE, -1001, -1, 0, 1, 2, 3, 5, 100, Integer.MAX_VALUE};
        int[][] pairs = {{0, 0}, {1, 2}, {2, 1}, {-1, 0}, {Integer.MIN_VALUE, Integer.MAX_VALUE}};
        for (String name : INT_METHODS) {
            for (int value : values) {
                out.add(name + "#" + value + "="
                        + invoke(type, name, new Class<?>[]{int.class}, value));
            }
        }
        for (String name : IINT_METHODS) {
            for (int[] pair : pairs) {
                out.add(name + "#" + pair[0] + "," + pair[1] + "="
                        + invoke(type, name, new Class<?>[]{int.class, int.class},
                        Integer.valueOf(pair[0]), Integer.valueOf(pair[1])));
            }
        }
        String[] left = {null, "x", "y"};
        String[] right = {null, "x", "z"};
        for (String name : new String[]{"acmpEq", "acmpNe"}) {
            for (int i = 0; i < left.length; i++) {
                out.add(name + "#" + left[i] + "," + right[i] + "="
                        + invoke(type, name, new Class<?>[]{String.class, String.class},
                        left[i], right[i]));
            }
        }
        for (String name : new String[]{"ifNull", "ifNonNull"}) {
            for (Object value : new Object[]{null, "x"}) {
                out.add(name + "#" + value + "="
                        + invoke(type, name, new Class<?>[]{Object.class}, value));
            }
        }
        float[] floats = {Float.NaN, -1.5f, 0.0f, 1.5f};
        for (String name : FLOAT_METHODS) {
            for (float value : floats) {
                out.add(name + "#" + value + "="
                        + invoke(type, name, new Class<?>[]{float.class},
                        Float.valueOf(value)));
            }
        }
        long[][] longs = {{0L, 0L}, {1L, 2L}, {-1L, 0L}};
        for (String name : LONG_METHODS) {
            for (long[] pair : longs) {
                out.add(name + "#" + pair[0] + "," + pair[1] + "="
                        + invoke(type, name, new Class<?>[]{long.class, long.class},
                        Long.valueOf(pair[0]), Long.valueOf(pair[1])));
            }
        }
        double[][] doubles = {{0.0d, 0.0d}, {1.5d, 1.5d}, {2.5d, 1.0d}};
        for (String name : DOUBLE_METHODS) {
            for (double[] pair : doubles) {
                out.add(name + "#" + pair[0] + "," + pair[1] + "="
                        + invoke(type, name, new Class<?>[]{double.class, double.class},
                        Double.valueOf(pair[0]), Double.valueOf(pair[1])));
            }
        }
        return out;
    }

    private static String invoke(Class<?> type, String name, Class<?>[] signature,
                                 Object... args) {
        try {
            Method method = type.getDeclaredMethod(name, signature);
            method.setAccessible(true);
            return String.valueOf(method.invoke(null, args));
        } catch (InvocationTargetException failure) {
            return "!" + failure.getCause().getClass().getName();
        } catch (Exception failure) {
            return "#" + failure.getClass().getSimpleName();
        }
    }

    private static void compareObservations(List<String> baseline, List<String> actual,
                                            String phase) {
        check(baseline.size() == actual.size(),
                phase + ": observation count " + actual.size() + " vs " + baseline.size());
        for (int i = 0; i < baseline.size(); i++) {
            if (!baseline.get(i).equals(actual.get(i))) {
                check(false, phase + ": behaviour changed at " + baseline.get(i)
                        + " -> " + actual.get(i));
            }
        }
        checks++;
        check(!baseline.isEmpty(), phase + ": nothing was observed");
    }

    private static PassContext context(List<ClassNode> nodes, long seed, String... options) {
        try {
            UmbraConfig.Builder builder = new UmbraConfig.Builder()
                    .input(Paths.get("in.jar"))
                    .output(Paths.get("out.jar"))
                    .seed(seed);
            for (int i = 0; i + 1 < options.length; i += 2) {
                builder.option(options[i], options[i + 1]);
            }
            UmbraConfig config = builder.build();
            ClassPool pool = new ClassPool();
            Hierarchy hierarchy = new Hierarchy();
            for (ClassNode node : nodes) {
                pool.putClass(node.name + ".class", serialize(node), node);
                hierarchy.addInput(node);
            }
            return new PassContext(config, pool, hierarchy,
                    new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(),
                            false, false),
                    new DefaultRuntimeSupport(), new MappingSet(), new Stats(),
                    new Log(null, false), new Random(seed), ProgressListener.NONE);
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static long stat(PassContext context, String key) {
        Long value = context.stats().snapshot().get(key);
        return value == null ? 0L : value.longValue();
    }

    private static byte[] serialize(ClassNode node) {
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        return UmbraClassWriter.toBytes(node, hierarchy);
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static void verify(byte[] bytes, final String internalName, String phase) {
        final byte[] data = bytes;
        ClassLoader loader = new ClassLoader(BranchTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (name.replace('.', '/').equals(internalName)) {
                    return defineClass(name, data, 0, data.length);
                }
                return super.findClass(name);
            }
        };
        StringWriter errors = new StringWriter();
        try {
            CheckClassAdapter.verify(new ClassReader(bytes), loader, false,
                    new PrintWriter(errors));
        } catch (Throwable failure) {
            check(false, "CheckClassAdapter (" + phase + ") threw: " + failure);
        }
        check(errors.toString().isEmpty(),
                "CheckClassAdapter (" + phase + "): " + errors.toString().trim());
    }

    private static Class<?> load(byte[] bytes, String internalName, String dotted) {
        final byte[] data = bytes;
        final String internal = internalName;
        ClassLoader loader = new ClassLoader(BranchTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (name.replace('.', '/').equals(internal)) {
                    return defineClass(name, data, 0, data.length);
                }
                return super.findClass(name);
            }
        };
        try {
            return Class.forName(dotted, true, loader);
        } catch (ClassNotFoundException failure) {
            throw new AssertionError("cannot load " + dotted, failure);
        }
    }

    private static boolean isConditional(int opcode) {
        return (opcode >= Opcodes.IFEQ && opcode <= Opcodes.IF_ACMPNE)
                || opcode == Opcodes.IFNULL || opcode == Opcodes.IFNONNULL;
    }

    private static int countNegatableJumps(ClassNode node) {
        int count = 0;
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name)) {
                continue;
            }
            if ((method.access & Opcodes.ACC_BRIDGE) != 0) {
                continue;
            }
            if ((method.access & Opcodes.ACC_SYNTHETIC) != 0
                    && (method.access & Opcodes.ACC_FINAL) != 0) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof JumpInsnNode)) {
                    continue;
                }
                if (!isConditional(insn.getOpcode())) {
                    continue;
                }
                if (targetNext((JumpInsnNode) insn)) {
                    continue;
                }
                count++;
            }
        }
        return count;
    }

    private static boolean targetNext(JumpInsnNode jump) {
        AbstractInsnNode real = jump.getNext();
        while (real != null && real.getOpcode() < 0) {
            if (real == jump.label) {
                return true;
            }
            real = real.getNext();
        }
        return false;
    }

    private static int countConditional(byte[] bytes) {
        int count = 0;
        for (MethodNode method : read(bytes).methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof JumpInsnNode && isConditional(insn.getOpcode())) {
                    count++;
                }
            }
        }
        return count;
    }

    private static int countConditionalInMethod(byte[] bytes, String name) {
        int count = 0;
        MethodNode method = findMethod(bytes, name);
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode && isConditional(insn.getOpcode())) {
                count++;
            }
        }
        return count;
    }

    private static int countJumps(byte[] bytes, String name) {
        MethodNode method = findMethod(bytes, name);
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode) {
                count++;
            }
        }
        return count;
    }

    private static MethodNode findMethod(byte[] bytes, String name) {
        for (MethodNode method : read(bytes).methods) {
            if (method.name.equals(name)) {
                return method;
            }
        }
        throw new IllegalStateException("no method " + name);
    }

    private static int countSwitchNodes(byte[] bytes) {
        int count = 0;
        for (MethodNode method : read(bytes).methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof TableSwitchInsnNode || insn instanceof LookupSwitchInsnNode) {
                    count++;
                }
            }
        }
        return count;
    }

    private static boolean hasSwitchKind(byte[] bytes, String methodName, boolean table) {
        MethodNode method = findMethod(bytes, methodName);
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (table && insn instanceof TableSwitchInsnNode) {
                return true;
            }
            if (!table && insn instanceof LookupSwitchInsnNode) {
                return true;
            }
        }
        return false;
    }

    private static int countOpcode(byte[] bytes, int opcode) {
        int count = 0;
        for (MethodNode method : read(bytes).methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn.getOpcode() == opcode) {
                    count++;
                }
            }
        }
        return count;
    }

    private static List<AbstractInsnNode> realInstructions(MethodNode method) {
        List<AbstractInsnNode> out = new ArrayList<AbstractInsnNode>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn.getOpcode() >= 0) {
                out.add(insn);
            }
        }
        return out;
    }

    private static AbstractInsnNode firstRealFrom(AbstractInsnNode node) {
        AbstractInsnNode cursor = node;
        while (cursor != null && cursor.getOpcode() < 0) {
            cursor = cursor.getNext();
        }
        return cursor;
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}
