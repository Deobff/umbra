package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.VirtualizationPass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.runtime.vm2.Vm2Format;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.FileObject;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileManager;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import io.umbra.core.util.RuntimeNames;

/**
 * Plain-main test harness for the method-virtualization engines.
 *
 * <p>The fixtures are compiled in memory with the JDK compiler, passed through
 * {@link VirtualizationPass}, reloaded by a private class loader and executed
 * next to the untouched originals. Covered: translation of arithmetic, branches,
 * loops, switches, arrays, fields, static/virtual/interface calls, try/catch
 * (typed, catch-all, finally, nested), monitors, constructors ({@code vm2.news}),
 * char/boolean values crossing reflective invocations, determinism, payload
 * hardening (no readable references in holders), the classic engine, and the
 * tamper guards.</p>
 */
public final class VmTest {

    private static int checks;
    private static int failures;

    private static final String FIXTURE_SOURCE =
            "package fixture;\n"
            + "public final class VmFixture {\n"
            + "  static int staticField;\n"
            + "  int instanceField;\n"
            + "  boolean boolField;\n"
            + "  char charField;\n"
            + "  public VmFixture() { }\n"
            + "  public static int arithmetic(int a, int b) {\n"
            + "    return (a + b) * (a - b) + (a ^ b) - (a >>> 1);\n"
            + "  }\n"
            + "  public static long longArithmetic(long a, long b) {\n"
            + "    long value = (a * b) ^ (a << 3) ^ (b >>> 2);\n"
            + "    return value + (a - b) / 3L - (a % 7L);\n"
            + "  }\n"
            + "  public static float floatArithmetic(float a, float b) {\n"
            + "    return (a + b) * (a - b) / 3.0f + (float) Math.sqrt(a);\n"
            + "  }\n"
            + "  public static double doubleArithmetic(double a, double b) {\n"
            + "    return (a + b) / (a - b) + (a % b) - Math.hypot(a, b);\n"
            + "  }\n"
            + "  public static int conversions(int a) {\n"
            + "    long l = a; float f = l; double d = f; int back = (int) d;\n"
            + "    byte b = (byte) back; char c = (char) b; short s = (short) c;\n"
            + "    return back + b + c + s;\n"
            + "  }\n"
            + "  public static boolean boolOps(boolean a, boolean b) {\n"
            + "    return (a && !b) || (a ^ b);\n"
            + "  }\n"
            + "  public static boolean boolChain(boolean a, boolean b, boolean c) {\n"
            + "    return a ? (b || c) : (b && c);\n"
            + "  }\n"
            + "  public static char charOps(char c) {\n"
            + "    char next = (char) (c + 1);\n"
            + "    return (char) (next ^ 0x20);\n"
            + "  }\n"
            + "  public static int charToInt(char c) { return c + 1; }\n"
            + "  public static String charText(char c) { return String.valueOf(c); }\n"
            + "  public static int charPredicate(char c) {\n"
            + "    return Character.isDigit(c) ? 1 : (Character.isLetter(c) ? 2 : 3);\n"
            + "  }\n"
            + "  public static int sumLoop(int n) {\n"
            + "    int total = 0;\n"
            + "    for (int i = 1; i <= n; i++) { total += i * 3 + (i & 7); }\n"
            + "    return total;\n"
            + "  }\n"
            + "  public static long fibonacci(int n) {\n"
            + "    long a = 0L; long b = 1L;\n"
            + "    for (int i = 0; i < n; i++) { long next = a + b; a = b; b = next; }\n"
            + "    return a;\n"
            + "  }\n"
            + "  public static int collatz(int n) {\n"
            + "    long value = n; int steps = 0;\n"
            + "    while (value != 1L) {\n"
            + "      if ((value & 1L) == 0L) { value /= 2L; } else { value = 3L * value + 1L; }\n"
            + "      steps++;\n"
            + "    }\n"
            + "    return steps;\n"
            + "  }\n"
            + "  public static int loopWithContinue(int n) {\n"
            + "    int total = 0;\n"
            + "    for (int i = 0; i < n; i++) { if ((i & 1) == 0) { continue; } total += i; }\n"
            + "    return total;\n"
            + "  }\n"
            + "  public static int nestedLoop(int n) {\n"
            + "    int total = 0;\n"
            + "    for (int a = 0; a < n; a++) {\n"
            + "      for (int b = 0; b < n; b++) { if ((a * b) % 3 == 0) { total += a + b; } }\n"
            + "    }\n"
            + "    return total;\n"
            + "  }\n"
            + "  public static int branchy(int x) {\n"
            + "    if (x < -5) { return -1; } else if (x == 0) { return 0; }\n"
            + "    else if (x > 5) { return 1; } else { return 2; }\n"
            + "  }\n"
            + "  public static int switchDense(int v) {\n"
            + "    switch (v) { case -1: return 10; case 0: return 11; case 1: return 12;\n"
            + "      case 2: return 13; default: return 14; }\n"
            + "  }\n"
            + "  public static int switchSparse(int v) {\n"
            + "    switch (v) { case -1000: return 1; case 0: return 2; case 777: return 3;\n"
            + "      case 100000: return 4; default: return 5; }\n"
            + "  }\n"
            + "  public static int switchString(String s) {\n"
            + "    switch (s) { case \"alpha\": return 1; case \"beta\": return 2; default: return 3; }\n"
            + "  }\n"
            + "  public static int[] arrayOps(int[] input) {\n"
            + "    int[] out = new int[input.length];\n"
            + "    for (int i = 0; i < input.length; i++) { out[i] = input[i] * 2 + i; }\n"
            + "    return out;\n"
            + "  }\n"
            + "  public static Object[] arrayObject(int n) {\n"
            + "    Object[] values = new Object[n];\n"
            + "    for (int i = 0; i < n; i++) { values[i] = Integer.valueOf(i); }\n"
            + "    return values;\n"
            + "  }\n"
            + "  public static int[][] multiArray(int rows, int cols) {\n"
            + "    int[][] grid = new int[rows][cols];\n"
            + "    for (int r = 0; r < rows; r++) {\n"
            + "      for (int c = 0; c < cols; c++) { grid[r][c] = r * cols + c; }\n"
            + "    }\n"
            + "    return grid;\n"
            + "  }\n"
            + "  public static int multiArraySum(int rows, int cols) {\n"
            + "    int[][] grid = multiArray(rows, cols);\n"
            + "    int total = 0;\n"
            + "    for (int r = 0; r < rows; r++) { for (int c = 0; c < cols; c++) total += grid[r][c]; }\n"
            + "    return total;\n"
            + "  }\n"
            + "  public static int arrayLength(int[] values) { return values.length + values[0]; }\n"
            + "  public static int fieldOps(int delta) {\n"
            + "    staticField = staticField + delta;\n"
            + "    return staticField;\n"
            + "  }\n"
            + "  public static void resetFields() { staticField = 0; }\n"
            + "  public int instanceOps(int delta) {\n"
            + "    instanceField = instanceField + delta;\n"
            + "    return instanceField;\n"
            + "  }\n"
            + "  public boolean flagFieldOps(boolean value) {\n"
            + "    boolField = value;\n"
            + "    return boolField;\n"
            + "  }\n"
            + "  public char charFieldOps(char value) {\n"
            + "    charField = value;\n"
            + "    return charField;\n"
            + "  }\n"
            + "  public static int callStatic(int value) { return helper(value) + 1; }\n"
            + "  static int helper(int value) { return value * 3 - 2; }\n"
            + "  public static int callInterface(VmIface value) {\n"
            + "    return value.id() * 2 + value.name().length();\n"
            + "  }\n"
            + "  public static int callVirtual(VmBase value) { return value.value() + 7; }\n"
            + "  public static int callCharHelper(char c) { return charEcho(c) + 1; }\n"
            + "  static char charEcho(char c) { return (char) (c + 2); }\n"
            + "  public static boolean callBoolHelper(boolean z) { return boolEcho(z); }\n"
            + "  static boolean boolEcho(boolean z) { return !z; }\n"
            + "  public static int safeDivide(int a, int b) {\n"
            + "    try { return a / b; } catch (ArithmeticException e) { return -1; }\n"
            + "  }\n"
            + "  public static int tryFinally(int a) {\n"
            + "    int x = 0;\n"
            + "    try { x = 10 / a; } catch (ArithmeticException e) { x = 7; } finally { x += 100; }\n"
            + "    return x;\n"
            + "  }\n"
            + "  public static int catchSupertype(int a) {\n"
            + "    try { return 10 / a; } catch (RuntimeException e) { return -2; } finally { staticField++; }\n"
            + "  }\n"
            + "  public static int nestedTry(int a, int b) {\n"
            + "    try {\n"
            + "      try { return a / b; } catch (ArithmeticException e) { return 42; }\n"
            + "    } finally { staticField++; }\n"
            + "  }\n"
            + "  public static int parseOrZero(String s) {\n"
            + "    try { return Integer.parseInt(s); } catch (NumberFormatException e) { return 0; }\n"
            + "  }\n"
            + "  public static int rethrowFromCatch(int a) throws RuntimeException {\n"
            + "    try { return 10 / a; } catch (ArithmeticException e) { throw new IllegalStateException(); }\n"
            + "  }\n"
            + "  public static int synchronizedBlock(int value) {\n"
            + "    synchronized (VmFixture.class) { return value + 1; }\n"
            + "  }\n"
            + "  public static synchronized int synchronizedMethod(int value) { return value * 2; }\n"
            + "  public static int reflectionInside(int value) throws Exception {\n"
            + "    java.lang.reflect.Method method = VmFixture.class.getDeclaredMethod(\"helper\", int.class);\n"
            + "    method.setAccessible(true);\n"
            + "    return ((Integer) method.invoke(null, Integer.valueOf(value))).intValue();\n"
            + "  }\n"
            + "  public static int listSize(int n) {\n"
            + "    java.util.ArrayList<String> list = new java.util.ArrayList<String>();\n"
            + "    for (int i = 0; i < n; i++) { list.add(String.valueOf(i)); }\n"
            + "    return list.size();\n"
            + "  }\n"
            + "  public static int listValue(int n) {\n"
            + "    java.util.ArrayList<Integer> list = new java.util.ArrayList<Integer>();\n"
            + "    for (int i = 0; i < n; i++) { list.add(Integer.valueOf(i * 2)); }\n"
            + "    return list.get(n - 1).intValue();\n"
            + "  }\n"
            + "  public static String newString(int n) {\n"
            + "    String value = new String(new char[] { 'a', 'b', 'c', 'd' });\n"
            + "    return value.substring(0, n);\n"
            + "  }\n"
            + "  public static int[] cloneArray(int[] input) {\n"
            + "    int[] copy = input.clone();\n"
            + "    copy[0] = 99;\n"
            + "    return copy;\n"
            + "  }\n"
            + "  public static Object[] cloneObjectArray(Object[] input) {\n"
            + "    return input.clone();\n"
            + "  }\n"
            + "  public static int tryCatchFunctional(java.util.function.IntUnaryOperator op, int value) {\n"
            + "    try { return 100 / op.applyAsInt(value); }\n"
            + "    catch (ArithmeticException e) { return -1; }\n"
            + "  }\n"
            + "  public static int lambdaInsideTry(int value) {\n"
            + "    try {\n"
            + "      java.util.function.IntUnaryOperator op = x -> x * 2 + 1;\n"
            + "      return op.applyAsInt(value) + 10;\n"
            + "    } catch (RuntimeException e) { return -2; }\n"
            + "  }\n"
            + "  public static int lambdaOnly(int value) {\n"
            + "    java.util.function.IntUnaryOperator op = x -> x * 2 + 1;\n"
            + "    return op.applyAsInt(value) + 10;\n"
            + "  }\n"
            + "  public static int lambdaInTry(int a, int b) {\n"
            + "    try {\n"
            + "      java.util.function.IntUnaryOperator op = x -> x + b;\n"
            + "      return 100 / op.applyAsInt(a);\n"
            + "    } catch (ArithmeticException e) { return -1; }\n"
            + "  }\n"
            + "}\n";

    private static final String[][] SUPPORT_SOURCES = {
            { "fixture.VmIface", "package fixture;\npublic interface VmIface { int id(); String name(); }\n" },
            { "fixture.VmBase", "package fixture;\npublic class VmBase { public int value() { return 1; } }\n" },
            { "fixture.VmSub", "package fixture;\npublic class VmSub extends VmBase {"
                    + " public int value() { return 2; } }\n" },
            { "fixture.VmImpl", "package fixture;\npublic class VmImpl implements VmIface {"
                    + " public int id() { return 9; } public String name() { return \"impl\"; } }\n" },
            { "fixture.VmOp", "package fixture;\npublic class VmOp"
                    + " implements java.util.function.IntUnaryOperator {"
                    + " public int applyAsInt(int value) { return value + 3; } }\n" },
            { "fixture.VmConstructed", "package fixture;\npublic class VmConstructed {"
                    + " int value; String text;"
                    + " public VmConstructed(int value) { this.value = value * 3;"
                    + " this.text = String.valueOf(value); }"
                    + " public int getValue() { return value; }"
                    + " public String getText() { return text; } }\n" },
            { "fixture.VmFinalCtor", "package fixture;\npublic class VmFinalCtor {"
                    + " final int fixed;"
                    + " public VmFinalCtor(int value) { this.fixed = value + 1; }"
                    + " public int fixed() { return fixed; } }\n" },
            { "fixture.VmThrowingCtor", "package fixture;\npublic class VmThrowingCtor {"
                    + " int value;"
                    + " public VmThrowingCtor(int value) {"
                    + " if (value < 0) { throw new IllegalArgumentException(); }"
                    + " this.value = value; }"
                    + " public int getValue() { return value; } }\n" }
    };

    private VmTest() {
    }

    public static void main(String[] args) throws Exception {
        Map<String, byte[]> compiled = compileFixture();
        check(compiled.containsKey("fixture.VmFixture"), "fixture compiled in memory");
        testVm2Execution(compiled, false);
        testVm2Execution(compiled, true);
        testIndyBridges(compiled);
        testConstructors(compiled);
        testPayloadSize(compiled);
        testClassicExecution(compiled);
        testDeterminism(compiled);
        testEligibility(compiled);
        testHardening(compiled);
        testGuards(compiled);
        testDispatchIndirection(compiled);
        testInterpreterTemplate();

        if (failures > 0) {
            System.out.println("VmTest: " + failures + " FAILURES out of " + checks + " checks");
            System.exit(1);
        }
        System.out.println("VmTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------------
    // invokedynamic bridges / constructor bodies / payload size
    // ------------------------------------------------------------------

    private static void testIndyBridges(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        Transform transform = transform(compiled, 9001L, options);
        check(stat(transform.stats, "virtualization.vm2.indyBridges") > 0,
                "default vm2 run creates indy bridges");
        MethodNode lambda = findMethod(transform, "fixture/VmFixture", "lambdaOnly");
        check(lambda != null && callsInterpreter(lambda) && !containsForeignInvokeDynamic(lambda),
                "lambda-only method is virtualized through a bridge");
        int bridges = 0;
        ClassNode node = transform.pool.getClass("fixture/VmFixture");
        for (MethodNode method : node.methods) {
            if (method.name.startsWith("umbra$i")) {
                bridges++;
                check(containsInvokeDynamic(method),
                        "bridge " + method.name + " keeps exactly the original invokedynamic");
            }
        }
        check(bridges > 0, "bridge methods live in the original owner class");

        ClassLoader originalLoader = new ByteLoader(VmTest.class.getClassLoader(), compiled);
        ClassLoader transformedLoader = new ByteLoader(VmTest.class.getClassLoader(),
                transform.output);
        Class<?> original = Class.forName("fixture.VmFixture", true, originalLoader);
        Class<?> changed = Class.forName("fixture.VmFixture", true, transformedLoader);
        compare("indy", "lambdaOnly", invoke(original, null, "lambdaOnly", 7),
                invoke(changed, null, "lambdaOnly", 7));
        compare("indy", "lambdaInTry", invoke(original, null, "lambdaInTry", 20, 3),
                invoke(changed, null, "lambdaInTry", 20, 3));
        compare("indy", "lambdaInTryCatch", invoke(original, null, "lambdaInTry", 1, -1),
                invoke(changed, null, "lambdaInTry", 1, -1));

        Map<String, String> disabled = new LinkedHashMap<String, String>();
        disabled.put("vm2.enabled", "true");
        disabled.put("vm2.indy", "false");
        Transform noIndy = transform(compiled, 9001L, disabled);
        MethodNode skipped = findMethod(noIndy, "fixture/VmFixture", "lambdaOnly");
        check(skipped != null && containsInvokeDynamic(skipped) && !callsInterpreter(skipped),
                "vm2.indy=false keeps invokedynamic methods as ordinary bytecode");
        check(stat(noIndy.stats, "virtualization.vm2.indyBridges") == 0,
                "vm2.indy=false emits no bridges");
        Class<?> plain = Class.forName("fixture.VmFixture", true,
                new ByteLoader(VmTest.class.getClassLoader(), noIndy.output));
        compare("indy-off", "lambdaOnly", Integer.valueOf(25), invoke(plain, null, "lambdaOnly", 7));
    }

    private static void testConstructors(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        options.put("vm2.constructors", "true");
        Transform transform = transform(compiled, 9001L, options);
        check(stat(transform.stats, "virtualization.vm2.constructorsExtracted") > 0,
                "constructor bodies are extracted when vm2.constructors=true");
        check(stat(transform.stats, "virtualization.vm2.constructorBodies") > 0,
                "extracted constructor bodies are virtualized");

        ClassLoader loader = new ByteLoader(VmTest.class.getClassLoader(), transform.output);
        Class<?> constructed = Class.forName("fixture.VmConstructed", true, loader);
        Object instance = constructed.getDeclaredConstructor(int.class).newInstance(7);
        compare("constructors", "field", Integer.valueOf(21),
                invoke(constructed, instance, "getValue"));
        compare("constructors", "string", "7", invoke(constructed, instance, "getText"));

        Class<?> finalCtor = Class.forName("fixture.VmFinalCtor", true, loader);
        Object finalInstance = finalCtor.getDeclaredConstructor(int.class).newInstance(5);
        compare("constructors", "finalField", Integer.valueOf(6),
                invoke(finalCtor, finalInstance, "fixed"));

        Class<?> throwing = Class.forName("fixture.VmThrowingCtor", true, loader);
        Object ok = throwing.getDeclaredConstructor(int.class).newInstance(3);
        compare("constructors", "throwingOk", Integer.valueOf(3),
                invoke(throwing, ok, "getValue"));
        String thrown = captureConstructorThrowable(throwing, -1);
        check(thrown != null && thrown.contains("IllegalArgumentException"),
                "constructor exception semantics are preserved");

        Map<String, String> off = new LinkedHashMap<String, String>();
        off.put("vm2.enabled", "true");
        Transform plain = transform(compiled, 9001L, off);
        check(stat(plain.stats, "virtualization.vm2.constructorsExtracted") == 0,
                "vm2.constructors=false leaves constructors untouched");
        Class<?> plainConstructed = Class.forName("fixture.VmConstructed", true,
                new ByteLoader(VmTest.class.getClassLoader(), plain.output));
        Object plainInstance = plainConstructed.getDeclaredConstructor(int.class).newInstance(4);
        compare("constructors-off", "field", Integer.valueOf(12),
                invoke(plainConstructed, plainInstance, "getValue"));
    }

    private static String captureConstructorThrowable(Class<?> type, int value) {
        try {
            type.getDeclaredConstructor(int.class).newInstance(value);
            return null;
        } catch (InvocationTargetException e) {
            return String.valueOf(e.getCause());
        } catch (Throwable failure) {
            return String.valueOf(failure);
        }
    }

    private static void testPayloadSize(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        Transform transform = transform(compiled, 9001L, options);
        ClassLoader loader = new ByteLoader(VmTest.class.getClassLoader(), transform.output);
        int checked = 0;
        for (ClassNode node : transform.pool.classes().values()) {
            if (!transform.pool.isGenerated(node.name) || isInterpreter(node)
                    || node.name.startsWith(RuntimeNames.path("M"))) {
                continue;
            }
            Class<?> holder = loadHolder(loader, node.name);
            if (holder == null) {
                continue;
            }
            int[] values = null;
            for (FieldNode field : node.fields) {
                if ("[I".equals(field.desc)) {
                    int[] candidate = (int[]) readStatic(holder, field);
                    if (candidate != null && candidate.length != 8) {
                        values = candidate;
                    }
                }
            }
            if (values == null || values.length < 64) {
                continue;
            }
            String encoded = Vm2Format.encodeBlock(values);
            check(encoded.length() == values.length * Vm2Format.CHARS_PER_INT,
                    "block string uses six chars per int");
            check(java.util.Arrays.equals(values, Vm2Format.decodeBlock(encoded)),
                    "block string round-trips through the decoder");
            MethodNode clinit = null;
            for (MethodNode method : node.methods) {
                if ("<clinit>".equals(method.name)) {
                    clinit = method;
                }
            }
            check(clinit != null && clinit.instructions.size() < 300,
                    "chunk holder <clinit> is a constant-size loop");
            byte[] classBytes = transform.output.get(node.name);
            check(classBytes.length < 4096 + values.length * 8,
                    "chunk holder class stays near six bytes per payload int");
            checked++;
            if (checked >= 3) {
                break;
            }
        }
        check(checked > 0, "payload block holders were checked");
        check(Vm2Format.FORMAT == 3, "payload format version is 3 (shared opcode map)");
    }


    // ------------------------------------------------------------------
    // Execution round trips
    // ------------------------------------------------------------------

    private static void testVm2Execution(Map<String, byte[]> compiled, boolean news) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        options.put("vm2.news", String.valueOf(news));
        Transform transform = transform(compiled, 9001L, options);
        check(stat(transform.stats, "virtualization.methods") >= 20,
                "vm2 virtualized a substantial part of the fixture (news=" + news + ")");
        check(stat(transform.stats, "virtualization.instructions") > 100,
                "vm2 translated instructions (news=" + news + ")");
        check(stat(transform.stats, "virtualization.skipped") == 0,
                "vm2 does not skip plain fixture methods (news=" + news + ")");
        check(stat(transform.stats, "virtualization.vm2.encryptedPayloads")
                        == stat(transform.stats, "virtualization.methods"),
                "each vm2 payload is encrypted");
        check(stat(transform.stats, "virtualization.vm2.nestedPayloads")
                        == stat(transform.stats, "virtualization.methods"),
                "each vm2 payload is nested");
        check(stat(transform.stats, "virtualization.vm2.handlers") >= 3,
                "try/catch methods produced handler tables");

        ClassLoader originalLoader = new ByteLoader(VmTest.class.getClassLoader(), compiled);
        ClassLoader transformedLoader = new ByteLoader(VmTest.class.getClassLoader(),
                transform.output);
        Class<?> original = Class.forName("fixture.VmFixture", true, originalLoader);
        Class<?> changed = Class.forName("fixture.VmFixture", true, transformedLoader);

        runScenarios("vm2", original, changed, originalLoader, transformedLoader);

        MethodNode tryCatchMethod = findMethod(transform, "fixture/VmFixture", "tryCatchFunctional");
        check(tryCatchMethod != null && callsInterpreter(tryCatchMethod),
                "vm2 virtualizes a method with try/catch and an interface call (news=" + news + ")");
        MethodNode lambdaMethod = findMethod(transform, "fixture/VmFixture", "lambdaInsideTry");
        check(lambdaMethod != null && callsInterpreter(lambdaMethod)
                        && !containsForeignInvokeDynamic(lambdaMethod),
                "vm2 virtualizes a try/catch method containing invokedynamic through a bridge");
        check(stat(transform.stats, "virtualization.vm2.indyBridges") > 0,
                "vm2 emitted indy bridge methods");
        MethodNode cloneMethod = findMethod(transform, "fixture/VmFixture", "cloneArray");
        check(cloneMethod != null && callsInterpreter(cloneMethod),
                "vm2 virtualizes array clone calls");

        Object firstOriginal = original.getDeclaredConstructor().newInstance();
        Object firstChanged = changed.getDeclaredConstructor().newInstance();
        compare("vm2", "instanceOps", invoke(original, firstOriginal, "instanceOps", 5),
                invoke(changed, firstChanged, "instanceOps", 5));
        compare("vm2", "instanceOps2", invoke(original, firstOriginal, "instanceOps", 7),
                invoke(changed, firstChanged, "instanceOps", 7));
        compare("vm2", "flagFieldOps", invoke(original, firstOriginal, "flagFieldOps", true),
                invoke(changed, firstChanged, "flagFieldOps", true));
        compare("vm2", "charFieldOps", invoke(original, firstOriginal, "charFieldOps", 'q'),
                invoke(changed, firstChanged, "charFieldOps", 'q'));
        compare("vm2", "synchronizedBlock", invoke(original, null, "synchronizedBlock", 3),
                invoke(changed, null, "synchronizedBlock", 3));
        compare("vm2", "synchronizedMethod", invoke(original, null, "synchronizedMethod", 3),
                invoke(changed, null, "synchronizedMethod", 3));
        compare("vm2", "reflectionInside", invoke(original, null, "reflectionInside", 4),
                invoke(changed, null, "reflectionInside", 4));

        // Constructors / NEW are only interpreted when vm2.news is on; either way
        // the calls must behave exactly like the original.
        compare("vm2", "listSize", invoke(original, null, "listSize", 5),
                invoke(changed, null, "listSize", 5));
        compare("vm2", "listValue", invoke(original, null, "listValue", 5),
                invoke(changed, null, "listValue", 5));
        compare("vm2", "newString", invoke(original, null, "newString", 2),
                invoke(changed, null, "newString", 2));

        checkThrows("vm2", original, changed, "rethrowFromCatch", new Object[] { 0 });

        if (news) {
            check(stat(transform.stats, "virtualization.methods")
                            > countVm2Methods(compiled, false),
                    "vm2.news makes constructor methods eligible");
        }
    }

    private static int countVm2Methods(Map<String, byte[]> compiled, boolean news) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        options.put("vm2.news", String.valueOf(news));
        return (int) stat(transform(compiled, 9001L, options).stats, "virtualization.methods");
    }

    private static void testClassicExecution(Map<String, byte[]> compiled) throws Exception {
        Transform transform = transform(compiled, 9001L, new LinkedHashMap<String, String>());
        check(stat(transform.stats, "virtualization.methods") >= 10,
                "classic engine virtualized fixture methods");
        check(stat(transform.stats, "virtualization.instructions") > 50,
                "classic engine translated instructions");
        ClassLoader originalLoader = new ByteLoader(VmTest.class.getClassLoader(), compiled);
        ClassLoader transformedLoader = new ByteLoader(VmTest.class.getClassLoader(),
                transform.output);
        Class<?> original = Class.forName("fixture.VmFixture", true, originalLoader);
        Class<?> changed = Class.forName("fixture.VmFixture", true, transformedLoader);
        runScenarios("classic", original, changed, originalLoader, transformedLoader);
        checkThrows("classic", original, changed, "rethrowFromCatch", new Object[] { 0 });
    }

    /** True when the method body was replaced by a VM2 dispatch call site. */
    private static boolean callsInterpreter(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof InvokeDynamicInsnNode
                    && "([Ljava/lang/Object;)Ljava/lang/Object;"
                            .equals(((InvokeDynamicInsnNode) insn).desc)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsInvokeDynamic(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof InvokeDynamicInsnNode) {
                return true;
            }
        }
        return false;
    }

    /** True when the body still contains an invokedynamic that is not the VM2 dispatch. */
    private static boolean containsForeignInvokeDynamic(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof InvokeDynamicInsnNode
                    && !"([Ljava/lang/Object;)Ljava/lang/Object;"
                            .equals(((InvokeDynamicInsnNode) insn).desc)) {
                return true;
            }
        }
        return false;
    }

    private static MethodNode findMethod(Transform transform, String internalName, String name) {
        ClassNode node = transform.pool.getClass(internalName);
        if (node == null) {
            return null;
        }
        for (MethodNode method : node.methods) {
            if (method.name.equals(name)) {
                return method;
            }
        }
        return null;
    }

    /** Runs the deterministic fixture scenario list on both class versions. */
    private static void runScenarios(String label, Class<?> original, Class<?> changed,
                                     ClassLoader originalLoader, ClassLoader transformedLoader)
            throws Exception {
        scenario(label, original, changed, "arithmetic", 17, 5);
        scenario(label, original, changed, "arithmetic", -13, 7);
        scenario(label, original, changed, "longArithmetic", 123456789L, 98765L);
        scenario(label, original, changed, "floatArithmetic", 3.5f, 1.25f);
        scenario(label, original, changed, "doubleArithmetic", 7.5d, 2.5d);
        scenario(label, original, changed, "conversions", 1234);
        scenario(label, original, changed, "conversions", -77);
        scenario(label, original, changed, "boolOps", true, false);
        scenario(label, original, changed, "boolOps", false, false);
        scenario(label, original, changed, "boolChain", true, false, true);
        scenario(label, original, changed, "boolChain", false, true, true);
        scenario(label, original, changed, "charOps", 'a');
        scenario(label, original, changed, "charOps", 'Z');
        scenario(label, original, changed, "charToInt", 'A');
        scenario(label, original, changed, "charText", 'x');
        scenario(label, original, changed, "charPredicate", '7');
        scenario(label, original, changed, "charPredicate", 'q');
        scenario(label, original, changed, "charPredicate", '#');
        scenario(label, original, changed, "sumLoop", 100);
        scenario(label, original, changed, "fibonacci", 40);
        scenario(label, original, changed, "collatz", 27);
        scenario(label, original, changed, "loopWithContinue", 25);
        scenario(label, original, changed, "nestedLoop", 7);
        scenario(label, original, changed, "branchy", -9);
        scenario(label, original, changed, "branchy", 0);
        scenario(label, original, changed, "branchy", 9);
        scenario(label, original, changed, "switchDense", 2);
        scenario(label, original, changed, "switchDense", 42);
        scenario(label, original, changed, "switchSparse", 777);
        scenario(label, original, changed, "switchSparse", 123);
        scenario(label, original, changed, "switchString", "beta");
        scenario(label, original, changed, "switchString", "omega");
        scenario(label, original, changed, "arrayOps", new int[] { 1, 2, 3, 4 });
        scenario(label, original, changed, "arrayObject", 4);
        scenario(label, original, changed, "multiArray", 3, 4);
        scenario(label, original, changed, "multiArraySum", 3, 4);
        scenario(label, original, changed, "arrayLength", new int[] { 5, 6, 7 });
        scenario(label, original, changed, "callStatic", 11);
        scenario(label, original, changed, "callCharHelper", 'a');
        scenario(label, original, changed, "callBoolHelper", true);
        scenario(label, original, changed, "safeDivide", 84, 4);
        scenario(label, original, changed, "safeDivide", 84, 0);
        scenario(label, original, changed, "tryFinally", 5);
        scenario(label, original, changed, "tryFinally", 0);
        scenario(label, original, changed, "catchSupertype", 4);
        scenario(label, original, changed, "catchSupertype", 0);
        scenario(label, original, changed, "nestedTry", 9, 3);
        scenario(label, original, changed, "nestedTry", 9, 0);
        scenario(label, original, changed, "parseOrZero", "345");
        scenario(label, original, changed, "parseOrZero", "nope");
        scenario(label, original, changed, "cloneArray", new int[] { 1, 2, 3, 4 });
        scenario(label, original, changed, "cloneObjectArray",
                (Object) new Object[] { Integer.valueOf(1), "two" });
        scenario(label, original, changed, "lambdaInsideTry", 5);
        scenario(label, original, changed, "lambdaOnly", 7);
        scenario(label, original, changed, "lambdaInTry", 20, 3);
        scenario(label, original, changed, "lambdaInTry", 1, -1);

        Object originalOp = Class.forName("fixture.VmOp", true, originalLoader)
                .getDeclaredConstructor().newInstance();
        Object changedOp = Class.forName("fixture.VmOp", true, transformedLoader)
                .getDeclaredConstructor().newInstance();
        compare(label, "tryCatchFunctional",
                invoke(original, null, "tryCatchFunctional", originalOp, 20),
                invoke(changed, null, "tryCatchFunctional", changedOp, 20));
        compare(label, "tryCatchFunctionalCatch",
                invoke(original, null, "tryCatchFunctional", originalOp, -3),
                invoke(changed, null, "tryCatchFunctional", changedOp, -3));

        Object originalImpl = Class.forName("fixture.VmImpl", true, originalLoader)
                .getDeclaredConstructor().newInstance();
        Object changedImpl = Class.forName("fixture.VmImpl", true, transformedLoader)
                .getDeclaredConstructor().newInstance();
        compare(label, "callInterface",
                invoke(original, null, "callInterface", originalImpl),
                invoke(changed, null, "callInterface", changedImpl));

        Object originalSub = Class.forName("fixture.VmSub", true, originalLoader)
                .getDeclaredConstructor().newInstance();
        Object changedSub = Class.forName("fixture.VmSub", true, transformedLoader)
                .getDeclaredConstructor().newInstance();
        compare(label, "callVirtual",
                invoke(original, null, "callVirtual", originalSub),
                invoke(changed, null, "callVirtual", changedSub));

        invoke(original, null, "resetFields");
        invoke(changed, null, "resetFields");
        compare(label, "fieldOps", invoke(original, null, "fieldOps", 3),
                invoke(changed, null, "fieldOps", 3));
        compare(label, "fieldOps2", invoke(original, null, "fieldOps", 4),
                invoke(changed, null, "fieldOps", 4));
    }

    private static void scenario(String label, Class<?> original, Class<?> changed, String name,
                                 Object... args) throws Exception {
        compare(label, name, invoke(original, null, name, args), invoke(changed, null, name, args));
    }

    // ------------------------------------------------------------------
    // Determinism
    // ------------------------------------------------------------------

    private static void testDeterminism(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        Transform first = transform(compiled, 424242L, options);
        Transform second = transform(compiled, 424242L, options);
        check(first.fingerprint.equals(second.fingerprint), "vm2 output is deterministic per seed");

        Map<String, String> classic = new LinkedHashMap<String, String>();
        Transform firstClassic = transform(compiled, 424242L, classic);
        Transform secondClassic = transform(compiled, 424242L, classic);
        check(firstClassic.fingerprint.equals(secondClassic.fingerprint),
                "classic output is deterministic per seed");

        Transform otherSeed = transform(compiled, 777L, options);
        check(!first.fingerprint.equals(otherSeed.fingerprint),
                "different vm2 seeds produce different payloads");
    }

    // ------------------------------------------------------------------
    // Eligibility
    // ------------------------------------------------------------------

    private static void testEligibility(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        options.put("vm2.trys", "false");
        Transform noTrys = transform(compiled, 9001L, options);
        check(stat(noTrys.stats, "virtualization.vm2.handlers") == 0,
                "vm2.trys=false removes handler tables");
        check(stat(noTrys.stats, "virtualization.methods") < countVm2Methods(compiled, false),
                "vm2.trys=false skips try/catch methods");

        options.clear();
        options.put("vm2.enabled", "true");
        options.put("vm2.opcodeMap", "false");
        Transform noMap = transform(compiled, 9001L, options);
        Class<?> fixture = Class.forName("fixture.VmFixture", true,
                new ByteLoader(VmTest.class.getClassLoader(), noMap.output));
        compare("vm2-nomap", "arithmetic", Integer.valueOf(1062),
                invoke(fixture, null, "arithmetic", 33, 7));

        options.clear();
        options.put("vm2.enabled", "true");
        options.put("vm2.encryptPayload", "false");
        Transform plain = transform(compiled, 9001L, options);
        check(stat(plain.stats, "virtualization.vm2.encryptedPayloads") == 0,
                "vm2.encryptPayload=false keeps payloads unencrypted");
        Class<?> plainFixture = Class.forName("fixture.VmFixture", true,
                new ByteLoader(VmTest.class.getClassLoader(), plain.output));
        compare("vm2-plain", "switchSparse", Integer.valueOf(3),
                invoke(plainFixture, null, "switchSparse", 777));
    }

    // ------------------------------------------------------------------
    // Interpreter template constraints
    // ------------------------------------------------------------------

    /**
     * The injected interpreter is a single class file: it must not reference
     * the obfuscator's own classes (they are not in the output jar) and must
     * not declare nested classes (the injector copies only one class file).
     */
    private static void testInterpreterTemplate() throws Exception {
        java.io.InputStream in = io.umbra.core.runtime.vm2.UmbraVM2.class
                .getResourceAsStream("UmbraVM2.class");
        check(in != null, "interpreter template class bytes are available");
        if (in == null) {
            return;
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = in.read(chunk)) >= 0) {
            buffer.write(chunk, 0, read);
        }
        in.close();
        String constantPool = new String(buffer.toByteArray(),
                java.nio.charset.StandardCharsets.ISO_8859_1);
        check(!constantPool.contains("io/umbra/core/api/"),
                "interpreter template does not reference the obfuscator API");
        check(!constantPool.contains("io/umbra/core/util/"),
                "interpreter template does not reference obfuscator utilities");
        check(!constantPool.contains("io/umbra/core/runtime/vm2/Vm2Format"),
                "interpreter template does not reference pass-side VM2 helpers");
        check(!constantPool.contains("UmbraVM2$"),
                "interpreter template declares no nested classes");
    }

    // ------------------------------------------------------------------
    // Payload hardening
    // ------------------------------------------------------------------

    private static void testHardening(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        Transform transform = transform(compiled, 9001L, options);
        ClassLoader holderLoader = new ByteLoader(VmTest.class.getClassLoader(), transform.output);

        int holders = 0;
        int chunks = 0;
        for (ClassNode node : transform.pool.classes().values()) {
            if (!transform.pool.isGenerated(node.name) || isInterpreter(node)) {
                continue;
            }
            Class<?> holder = loadHolder(holderLoader, node.name);
            if (holder == null) {
                continue;
            }
            for (FieldNode field : node.fields) {
                if ("[I".equals(field.desc)) {
                    int[] values = (int[]) readStatic(holder, field);
                    if (values != null && values.length == Vm2Format.META_LEN
                            && values[0] == Vm2Format.magicFor(values)) {
                        holders++;
                    } else if (values != null) {
                        chunks++;
                    }
                }
            }
            byte[] bytes = transform.output.get(node.name);
            if (bytes != null) {
                check(!containsReadableReference(bytes),
                        "holder " + node.name + " contains no readable reference records");
            }
        }
        long methods = stat(transform.stats, "virtualization.methods");
        check(holders == methods, "one meta holder per virtualized method");
        check(chunks >= methods * 2, "payload split across several chunk holders");
        check(stat(transform.stats, "virtualization.holders") == holders + chunks,
                "holder statistics match emitted classes");
    }

    /**
     * True for the injected interpreter (the only generated class with a static
     * {@code run(int[],int[][],Object[])}). The method name is randomized by the
     * pass, so it is matched by descriptor.
     */
    private static boolean isInterpreter(ClassNode node) {
        for (MethodNode method : node.methods) {
            if ("([I[I[[I[Ljava/lang/Object;)Ljava/lang/Object;".equals(method.desc)
                    && (method.access & Opcodes.ACC_STATIC) != 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Reference records are {@code "M|owner|name|desc"} strings. They are
     * encrypted inside the payload, so only tokens that could not appear by
     * chance in random payload ints are checked here.
     */
    private static boolean containsReadableReference(byte[] bytes) {
        String content = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
        String[] tokens = {
                "M|fixture", "F|fixture", "T|Lfixture", "|VMFixture|",
                "|helper|", "|charEcho|", "|switchString|", "|callStatic|",
                "|listSize|", "|charOps|", "|multiArray|"
        };
        for (String token : tokens) {
            if (content.contains(token)) {
                return true;
            }
        }
        return false;
    }

    private static Class<?> loadHolder(ClassLoader loader, String internalName) {
        try {
            return Class.forName(internalName.replace('/', '.'), true, loader);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Object readStatic(Class<?> holder, FieldNode field) {
        try {
            Field reflected = holder.getDeclaredField(field.name);
            reflected.setAccessible(true);
            return reflected.get(null);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Rebuilds the block array of a payload from its holder entry. The entry is
     * what the interpreter dispatcher calls: it reads the private meta field and
     * assembles the blocks through the per-block accessors, which are the only
     * way to reach them from outside.
     */
    private static int[][] payloadBlocks(ClassLoader loader, ClassNode holder) {
        MethodNode entry = null;
        for (MethodNode method : holder.methods) {
            if ("([Ljava/lang/Object;)Ljava/lang/Object;".equals(method.desc)) {
                entry = method;
            }
        }
        if (entry == null) {
            return null;
        }
        boolean assembly = false;
        List<int[]> blocks = new ArrayList<int[]>();
        for (AbstractInsnNode insn = entry.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof TypeInsnNode && insn.getOpcode() == Opcodes.ANEWARRAY
                    && "[I".equals(((TypeInsnNode) insn).desc)) {
                assembly = true;
            } else if (assembly && insn instanceof MethodInsnNode
                    && insn.getOpcode() == Opcodes.INVOKESTATIC
                    && "()[I".equals(((MethodInsnNode) insn).desc)) {
                int[] values = readAccessor(loader, (MethodInsnNode) insn);
                if (values == null) {
                    return null;
                }
                blocks.add(values);
            }
        }
        return blocks.isEmpty() ? null : blocks.toArray(new int[0][]);
    }

    private static int[] readAccessor(ClassLoader loader, MethodInsnNode call) {
        try {
            Class<?> owner = Class.forName(call.owner.replace('/', '.'), true, loader);
            Method accessor = owner.getDeclaredMethod(call.name);
            accessor.setAccessible(true);
            return (int[]) accessor.invoke(null);
        } catch (Throwable ignored) {
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Tamper guards
    // ------------------------------------------------------------------

    private static void testGuards(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        Transform transform = transform(compiled, 9001L, options);
        ClassLoader holderLoader = new ByteLoader(VmTest.class.getClassLoader(), transform.output);

        Method run = null;
        int[] opcodeMap = null;
        for (ClassNode node : transform.pool.classes().values()) {
            if (!transform.pool.isGenerated(node.name)) {
                continue;
            }
            for (MethodNode method : node.methods) {
                if ("([I[I[[I[Ljava/lang/Object;)Ljava/lang/Object;".equals(method.desc)
                        && (method.access & Opcodes.ACC_STATIC) != 0) {
                    Class<?> type = loadHolder(holderLoader, node.name);
                    if (type == null) {
                        continue;
                    }
                    run = type.getDeclaredMethod(method.name, int[].class, int[].class,
                            int[][].class, Object[].class);
                    run.setAccessible(true);
                }
            }
            if (node.name.startsWith(RuntimeNames.path("M"))) {
                Class<?> mapHolder = loadHolder(holderLoader, node.name);
                if (mapHolder != null) {
                    for (FieldNode field : node.fields) {
                        if ("[I".equals(field.desc)) {
                            int[] values = (int[]) readStatic(mapHolder, field);
                            if (values != null && values.length == 256) {
                                opcodeMap = values;
                            }
                        }
                    }
                }
            }
        }
        check(run != null, "interpreter entry point was injected");
        check(opcodeMap != null, "shared opcode map holder was injected");

        int tested = 0;
        int guarded = 0;
        int skipped = 0;
        for (ClassNode node : transform.pool.classes().values()) {
            if (tested >= 5) {
                break;
            }
            if (!transform.pool.isGenerated(node.name) || isInterpreter(node)) {
                continue;
            }
            Class<?> holder = loadHolder(holderLoader, node.name);
            if (holder == null) {
                continue;
            }
            int[] meta = null;
            for (FieldNode field : node.fields) {
                if ("[I".equals(field.desc)) {
                    int[] values = (int[]) readStatic(holder, field);
                    if (values != null && values.length == Vm2Format.META_LEN
                            && values[0] == Vm2Format.magicFor(values)) {
                        meta = values;
                    }
                }
            }
            if (meta == null) {
                continue;
            }
            int[][] blocks = payloadBlocks(holderLoader, node);
            if (blocks == null || blocks.length == 0) {
                skipped++;
                continue;
            }
            try {
                run.invoke(null, meta, opcodeMap, blocks, new Object[64]);
                tested++;
            } catch (InvocationTargetException e) {
                // Dummy null arguments can fail inside the payload; try the next
                // holder instead of failing the test.
                continue;
            } catch (IllegalAccessException e) {
                continue;
            } catch (RuntimeException e) {
                // Newer JDKs wrap accessor-level errors differently; a payload
                // probe with null arguments is allowed to fail.
                continue;
            }
            // The probe above cached the decoded state under the payload's meta
            // array; the tampered probe uses a fresh meta identity so the
            // modified blocks are decoded (and rejected) instead of being
            // served from that cache.
            int[] tamperedMeta = meta.clone();
            int[][] tampered = new int[blocks.length][];
            for (int i = 0; i < blocks.length; i++) {
                tampered[i] = blocks[i].clone();
            }
            tampered[0][tampered[0].length - 1] ^= 0x5A5A5A5A;
            try {
                run.invoke(null, tamperedMeta, opcodeMap, tampered, new Object[64]);
                check(false, "tampered payload " + node.name + " was accepted");
            } catch (InvocationTargetException e) {
                String message = String.valueOf(e.getCause());
                guarded++;
                check(message.contains("rejected") || message.contains("Umbra VM2"),
                        "tamper guard throws a payload error: " + message);
            } catch (IllegalAccessException e) {
                check(false, "guard invocation failed for " + node.name);
            } catch (RuntimeException e) {
                String message = String.valueOf(e);
                guarded++;
                check(message.contains("rejected") || message.contains("Umbra VM2"),
                        "tamper guard throws a payload error: " + message);
            }
        }
        check(tested > 0, "at least one payload executes through the interpreter");
        check(guarded > 0, "tampered payloads are rejected by the integrity guard");
        check(skipped == 0, "every payload holder exposes its blocks through accessors");
    }

    /**
     * A business class must not call the injected runtime directly: every
     * virtualized method carries exactly one {@code invokedynamic} whose target
     * the JVM resolves through the bootstrap, so the call sites reveal neither
     * the interpreter nor the holders.
     */
    private static void testDispatchIndirection(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        Transform transform = transform(compiled, 9001L, options);
        int direct = 0;
        int callSites = 0;
        for (ClassNode node : transform.pool.classes().values()) {
            if (transform.pool.isGenerated(node.name)) {
                continue;
            }
            for (MethodNode method : node.methods) {
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                     insn = insn.getNext()) {
                    if (insn instanceof MethodInsnNode) {
                        if (RuntimeNames.isRuntime(((MethodInsnNode) insn).owner)) {
                            direct++;
                        }
                    } else if (insn instanceof InvokeDynamicInsnNode
                            && "([Ljava/lang/Object;)Ljava/lang/Object;"
                                    .equals(((InvokeDynamicInsnNode) insn).desc)) {
                        callSites++;
                    }
                }
            }
        }
        check(direct == 0, "business classes contain no direct call into the injected runtime");
        check(callSites == (int) stat(transform.stats, "virtualization.methods"),
                "every virtualized method carries exactly one dispatch call site");
    }

    // ------------------------------------------------------------------    // Pass invocation
    // ------------------------------------------------------------------

    private static Transform transform(Map<String, byte[]> input, long seed,
                                       Map<String, String> options) throws Exception {
        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"))
                .seed(seed)
                .methodVirtualization(new UmbraConfig.VirtualizationOptions(true, 4000, 0));
        for (Map.Entry<String, String> entry : options.entrySet()) {
            builder.option(entry.getKey(), entry.getValue());
        }
        UmbraConfig config = builder.build();

        ClassPool pool = new ClassPool();
        Hierarchy hierarchy = new Hierarchy();
        List<String> names = new ArrayList<String>(input.keySet());
        Collections.sort(names);
        for (String name : names) {
            byte[] bytes = input.get(name);
            ClassNode node = new ClassNode();
            new ClassReader(bytes).accept(node, ClassReader.EXPAND_FRAMES);
            pool.putClass(name.replace('.', '/') + ".class", bytes, node);
            hierarchy.addInput(node);
        }

        Stats stats = new Stats();
        Log log = new Log(new Log.Sink() {
            @Override
            public void line(String level, String message) {
                // silent: failures are reported through assertions
            }
        }, false);
        PassContext context = new PassContext(config, pool, hierarchy,
                new DefaultRuleSet(Collections.<String>emptyList(),
                        Collections.<String>emptyList(), false, false),
                new DefaultRuntimeSupport(), new MappingSet(), stats, log, new Random(seed),
                ProgressListener.NONE);
        new VirtualizationPass().run(context);

        Map<String, byte[]> output = new LinkedHashMap<String, byte[]>();
        StringBuilder fingerprint = new StringBuilder();
        List<String> classNames = new ArrayList<String>(pool.classes().keySet());
        Collections.sort(classNames);
        for (String name : classNames) {
            ClassNode node = pool.getClass(name);
            byte[] bytes = UmbraClassWriter.toBytes(node, hierarchy);
            output.put(name, bytes);
            fingerprint.append(name).append(':').append(bytes.length).append(':')
                    .append(hash(bytes)).append(';');
        }
        return new Transform(pool, stats, output, fingerprint.toString());
    }

    private static String hash(byte[] bytes) {
        long value = 0xCBF29CE484222325L;
        for (byte b : bytes) {
            value ^= b & 0xFF;
            value *= 0x100000001B3L;
        }
        return Long.toHexString(value);
    }

    private static long stat(Stats stats, String key) {
        Long value = stats.snapshot().get(key);
        return value == null ? 0L : value.longValue();
    }

    // ------------------------------------------------------------------
    // Execution helpers
    // ------------------------------------------------------------------

    private static Object invoke(Class<?> owner, Object target, String name, Object... args)
            throws Exception {
        Method method = find(owner, name, args);
        method.setAccessible(true);
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e.getCause());
        }
    }

    private static Method find(Class<?> owner, String name, Object[] args) {
        for (Method method : owner.getDeclaredMethods()) {
            if (!method.getName().equals(name) || method.getParameterCount() != args.length) {
                continue;
            }
            Class<?>[] types = method.getParameterTypes();
            boolean compatible = true;
            for (int i = 0; i < types.length; i++) {
                if (!compatible(types[i], args[i])) {
                    compatible = false;
                    break;
                }
            }
            if (compatible) {
                return method;
            }
        }
        throw new IllegalArgumentException("no method " + owner.getName() + "#" + name
                + "/" + args.length);
    }

    private static boolean compatible(Class<?> type, Object arg) {
        if (arg == null) {
            return !type.isPrimitive();
        }
        if (!type.isPrimitive()) {
            return type.isInstance(arg);
        }
        if (type == int.class) {
            return arg instanceof Integer;
        }
        if (type == long.class) {
            return arg instanceof Long;
        }
        if (type == boolean.class) {
            return arg instanceof Boolean;
        }
        if (type == char.class) {
            return arg instanceof Character;
        }
        if (type == float.class) {
            return arg instanceof Float;
        }
        if (type == double.class) {
            return arg instanceof Double;
        }
        if (type == byte.class) {
            return arg instanceof Byte;
        }
        if (type == short.class) {
            return arg instanceof Short;
        }
        return false;
    }

    private static void compare(String label, String what, Object expected, Object actual) {
        if (deepEquals(expected, actual)) {
            checks++;
        } else {
            failures++;
            System.out.println("FAIL: [" + label + "] " + what + ": expected " + describe(expected)
                    + " but was " + describe(actual));
        }
    }

    private static void checkThrows(String label, Class<?> original, Class<?> changed, String name,
                                    Object[] args) throws Exception {
        String expected = captureThrowable(original, name, args);
        String actual = captureThrowable(changed, name, args);
        check(expected != null, "[" + label + "] " + name + " throws in the original");
        check(expected != null && expected.equals(actual),
                "[" + label + "] " + name + " throws the same type (" + expected + " vs " + actual + ")");
    }

    private static String captureThrowable(Class<?> owner, String name, Object[] args) {
        try {
            Method method = find(owner, name, args);
            method.setAccessible(true);
            method.invoke(null, args);
            return null;
        } catch (InvocationTargetException e) {
            return e.getCause() == null ? null : e.getCause().getClass().getName();
        } catch (Throwable failure) {
            return failure.getClass().getName();
        }
    }

    private static boolean deepEquals(Object first, Object second) {
        if (first == null || second == null) {
            return first == second;
        }
        if (first instanceof int[] && second instanceof int[]) {
            return Arrays.equals((int[]) first, (int[]) second);
        }
        if (first instanceof long[] && second instanceof long[]) {
            return Arrays.equals((long[]) first, (long[]) second);
        }
        if (first instanceof Object[] && second instanceof Object[]) {
            return Arrays.deepEquals((Object[]) first, (Object[]) second);
        }
        if (first instanceof int[][] && second instanceof int[][]) {
            return Arrays.deepEquals((int[][]) first, (int[][]) second);
        }
        if (first.getClass().isArray() && second.getClass().isArray()) {
            int length = Array.getLength(first);
            if (length != Array.getLength(second)) {
                return false;
            }
            for (int i = 0; i < length; i++) {
                if (!deepEquals(Array.get(first, i), Array.get(second, i))) {
                    return false;
                }
            }
            return true;
        }
        return first.equals(second);
    }

    private static String describe(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof int[]) {
            return Arrays.toString((int[]) value);
        }
        if (value instanceof Object[]) {
            return Arrays.deepToString((Object[]) value);
        }
        if (value instanceof int[][]) {
            return Arrays.deepToString((int[][]) value);
        }
        return String.valueOf(value);
    }

    private static void check(boolean condition, String what) {
        checks++;
        if (!condition) {
            failures++;
            System.out.println("FAIL: " + what);
        }
    }

    // ------------------------------------------------------------------
    // In-memory fixture compilation
    // ------------------------------------------------------------------

    private static Map<String, byte[]> compileFixture() throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("VmTest requires a JDK (javax.tools compiler missing)");
        }
        final Map<String, ByteArrayOutputStream> outputs =
                new LinkedHashMap<String, ByteArrayOutputStream>();
        StandardJavaFileManager standard = compiler.getStandardFileManager(null, null, null);
        JavaFileManager manager = new ForwardingJavaFileManager<JavaFileManager>(standard) {
            @Override
            public JavaFileObject getJavaFileForOutput(Location location, final String className,
                                                       JavaFileObject.Kind kind, FileObject sibling) {
                final ByteArrayOutputStream sink = new ByteArrayOutputStream();
                outputs.put(className, sink);
                return new SimpleJavaFileObject(URI.create("mem:///" + className.replace('.', '/')
                        + kind.extension), kind) {
                    @Override
                    public OutputStream openOutputStream() {
                        return sink;
                    }
                };
            }
        };
        List<JavaFileObject> sources = new ArrayList<JavaFileObject>();
        sources.add(source("fixture.VmFixture", FIXTURE_SOURCE));
        for (String[] support : SUPPORT_SOURCES) {
            sources.add(source(support[0], support[1]));
        }
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<JavaFileObject>();
        List<String> options = Arrays.asList("-proc:none");
        boolean success = compiler.getTask(null, manager, diagnostics, options, null, sources).call();
        if (!success) {
            StringBuilder message = new StringBuilder("fixture compilation failed");
            for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
                message.append('\n').append(diagnostic);
            }
            throw new IllegalStateException(message.toString());
        }
        Map<String, byte[]> compiled = new LinkedHashMap<String, byte[]>();
        for (Map.Entry<String, ByteArrayOutputStream> entry : outputs.entrySet()) {
            compiled.put(entry.getKey(), entry.getValue().toByteArray());
        }
        return compiled;
    }

    private static JavaFileObject source(final String className, final String content) {
        return new SimpleJavaFileObject(URI.create("mem:///" + className.replace('.', '/')
                + ".java"), JavaFileObject.Kind.SOURCE) {
            @Override
            public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                return content;
            }
        };
    }

    /** Result of one pass invocation. */
    private static final class Transform {
        final ClassPool pool;
        final Stats stats;
        final Map<String, byte[]> output;
        final String fingerprint;

        Transform(ClassPool pool, Stats stats, Map<String, byte[]> output, String fingerprint) {
            this.pool = pool;
            this.stats = stats;
            this.output = output;
            this.fingerprint = fingerprint;
        }
    }

    /** Loads a class map in isolation. */
    private static final class ByteLoader extends ClassLoader {
        private final Map<String, byte[]> classes;

        ByteLoader(ClassLoader parent, Map<String, byte[]> classes) {
            super(parent);
            this.classes = classes;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] bytes = classes.get(name);
            if (bytes == null) {
                bytes = classes.get(name.replace('.', '/'));
            }
            if (bytes == null) {
                throw new ClassNotFoundException(name);
            }
            return defineClass(name, bytes, 0, bytes.length);
        }
    }
}
