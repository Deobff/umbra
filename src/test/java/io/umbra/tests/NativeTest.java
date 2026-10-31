package io.umbra.tests;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.jni.CGenerator;
import io.umbra.core.jni.JniNames;
import io.umbra.core.jni.NativeCompiler;
import io.umbra.core.jni.NativeMethodTranslator;
import io.umbra.core.jni.NativeSettings;
import io.umbra.core.util.Log;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/**
 * Plain-main test harness for the native (JNI) code generation layer.
 *
 * <p>Checks the JNI symbol mangling rules, the descriptor splitter, the
 * bytecode-to-C translator on hand-built synthetic methods (no C toolchain
 * required) and, when a C compiler and the JNI headers are available, compiles a
 * tiny generated translation unit into a shared library.</p>
 */
public final class NativeTest {

    private static int checks;

    private NativeTest() {
    }

    public static void main(String[] args) throws Exception {
        testMangling();
        testDescriptors();
        testModifiedUtf8();
        testTranslatorArithmetic();
        testOverloadExports();
        testTranslatorControlFlow();
        testTranslatorCallsAndFields();
        testTranslatorArrays();
        testTranslatorSwitch();
        testTranslatorExceptions();
        testTranslatorRejections();
        testFilters();
        testToolchainCompile();
        System.out.println("NativeTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------------
    // JNI name mangling
    // ------------------------------------------------------------------

    private static void testMangling() {
        check("java_lang_String".equals(JniNames.mangle("java/lang/String")),
                "slash becomes underscore");
        check("a_1b".equals(JniNames.mangle("a_b")), "underscore becomes _1");
        check("_1_1".equals(JniNames.mangle("__")), "repeated underscores escape");
        check("_2".equals(JniNames.mangle(";")), "semicolon becomes _2");
        check("_3I".equals(JniNames.mangle("[I")), "bracket becomes _3");
        check("_00024".equals(JniNames.mangle("$")), "dollar uses _0 + four lower-case hex digits");
        check("_04e2d".equals(JniNames.mangle("\u4e2d")),
                "non-ASCII code unit uses lower-case hex escape");
        check("_0d83d_0de00".equals(JniNames.mangle("\ud83d\ude00")),
                "surrogate pair is escaped per UTF-16 code unit");
        check("_0002d".equals(JniNames.mangle("-")), "hyphen is escaped");
        check("_0".equals(JniNames.mangle("0")) == false, "digits are kept");
        check("a1Z".equals(JniNames.mangle("a1Z")), "alphanumerics are kept");

        check("Java_demo_Main_sum".equals(JniNames.shortName("demo/Main", "sum")),
                "short native name");
        check("Java_pkg_Cls_f__ILjava_lang_String_2".equals(
                        JniNames.longName("pkg/Cls", "f", "(ILjava/lang/String;)V")),
                "long native name mangles the argument signature");
        check("Java_pkg_Cls_f__".equals(JniNames.longName("pkg/Cls", "f", "()V")),
                "long native name without arguments ends with two underscores");
        check("Java_pkg_Cls_g___3I_3J".equals(JniNames.longName("pkg/Cls", "g", "([I[J)V")),
                "array arguments are mangled");
        check("Java_Outer_00024Inner_m".equals(JniNames.shortName("Outer$Inner", "m")),
                "inner class dollar sign is escaped");
        check("Java_umbra_runtime_Nabc_method".equals(
                        JniNames.shortName("umbra/runtime/Nabc", "method")),
                "generated runtime class names mangle like any other class");
    }

    // ------------------------------------------------------------------
    // Descriptor splitter
    // ------------------------------------------------------------------

    private static void testDescriptors() {
        List<String> types = JniNames.splitTypes("(IJ[Ljava/lang/String;[[D)Z");
        check(types.equals(Arrays.asList("I", "J", "[Ljava/lang/String;", "[[D", "Z")),
                "method descriptor split (arguments then return type)");
        check("Z".equals(JniNames.returnType("(IJ[Ljava/lang/String;[[D)Z")),
                "return type extracted");
        check(JniNames.argumentTypes("(Lfoo/Bar;II)V").equals(
                        Arrays.asList("Lfoo/Bar;", "I", "I")),
                "argument types extracted");
        check(JniNames.argumentTypes("()V").isEmpty(), "no arguments");
        check(JniNames.splitTypes("Ljava/util/List;").equals(Arrays.asList("Ljava/util/List;")),
                "field descriptor split");
        check(JniNames.splitTypes("[[I").equals(Arrays.asList("[[I")), "array descriptor split");
        check("Ljava/lang/String;I".equals(JniNames.argumentSignature(
                        "(Ljava/lang/String;I)V")), "argument signature has no parentheses");
        boolean thrown = false;
        try {
            JniNames.splitTypes("(Q)V");
        } catch (IllegalArgumentException expected) {
            thrown = true;
        }
        check(thrown, "invalid descriptor rejected");
    }

    private static void testModifiedUtf8() {
        byte[] ascii = CGenerator.modifiedUtf8("OK");
        check(ascii.length == 2 && ascii[0] == 'O' && ascii[1] == 'K', "ASCII passthrough");
        byte[] chinese = CGenerator.modifiedUtf8("\u4e2d");
        check(chinese.length == 3 && (chinese[0] & 0xFF) == 0xE4
                && (chinese[1] & 0xFF) == 0xB8 && (chinese[2] & 0xFF) == 0xAD,
                "UTF-16 code unit encoded as three-byte modified UTF-8");
        byte[] zero = CGenerator.modifiedUtf8("\u0000");
        check(zero.length == 2 && (zero[0] & 0xFF) == 0xC0 && (zero[1] & 0xFF) == 0x80,
                "NUL encoded as C0 80 (no NUL byte in the literal)");
        String literal = CGenerator.cString("a\"b");
        check(literal.startsWith("\"") && literal.endsWith("\""), "C string literal quoted");
        check(!literal.substring(1, literal.length() - 1).replace("\\\"", "").contains("\""),
                "quote escaped inside C string literal");
    }

    // ------------------------------------------------------------------
    // Translation of synthetic methods
    // ------------------------------------------------------------------

    /** Instruction count reported by the last {@link #translate} call (diagnostics). */
    private static int lastInstructionCount;

    private static CGenerator.MethodC translate(ClassNode owner, MethodNode method)
            throws Exception {
        CGenerator generator = new CGenerator();
        NativeMethodTranslator translator =
                new NativeMethodTranslator(owner.name, method, generator);
        CGenerator.MethodC result = translator.translate();
        lastInstructionCount = translator.instructionCount();
        return result;
    }

    private static ClassNode syntheticClass() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC;
        node.name = "synthetic/Probe";
        node.superName = "java/lang/Object";
        return node;
    }

    private static MethodNode syntheticMethod(String name, String descriptor, int access,
                                              int maxStack, int maxLocals) {
        MethodNode method = new MethodNode(access, name, descriptor, null, null);
        method.maxStack = maxStack;
        method.maxLocals = maxLocals;
        return method;
    }

    private static void testTranslatorArithmetic() throws Exception {
        ClassNode owner = syntheticClass();
        MethodNode method = syntheticMethod("add", "(II)I", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                2, 2);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new InsnNode(Opcodes.IADD));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        CGenerator.MethodC generated = translate(owner, method);
        check(generated.body.contains("st[sp].i"), "integer operation uses the value stack");
        check(generated.body.contains("sp += 1"), "value stack slot accounting");
        check(generated.body.contains("lc[0].i = _a0"), "arguments copied into locals");
        check(generated.body.contains("st[sp].i = (jint)("), "result of the add pushed back");
        check(lastInstructionCount == 4, "instruction count reported");
        check("jint".equals(generated.cReturn), "int return type mapped");
        check(generated.staticMethod, "static method marked static");
        check(generated.cArguments.size() == 2, "two C arguments generated");
        check("I".equals(JniNames.returnType(method.desc)), "return descriptor");

        CGenerator generator = new CGenerator();
        new NativeMethodTranslator(owner.name, method, generator).translate();
        generator.addMethod(generated);
        String source = generator.finish();
        check(source.contains("JNI_OnLoad"), "JNI_OnLoad emitted");
        check(source.contains("RegisterNatives"), "bindings are registered, not symbol-looked-up");
        check(!source.contains("JNIEXPORT jint JNICALL Java_"), "no plaintext Java_* JNI export");
        check(source.contains("static int umbra_bind_0("), "per-owner registrar emitted");
        check(source.contains("m[0].fnPtr = (void*)(&umbra_native_"), "wrapper address registered");
        check(source.contains("RegisterNatives(env, cls, m, 1)"), "registrar binds one method");
        check(source.contains("static jclass umbra_classes["), "class cache table emitted");
        check(source.contains("static UMBRA_ID umbra_ids["), "id cache table emitted");
    }

    private static void testOverloadExports() throws Exception {
        // Two native methods with the same name but different descriptors used to be
        // ambiguous under JNI name mangling: only the descriptor-mangled long names
        // could be exported, or the VM would bind every overload to the first
        // function it found (this regressed demo.Checks.eq overloads when renaming
        // was disabled). Registration passes (name, descriptor) pairs, so both
        // overloads are listed unambiguously in one table.
        ClassNode owner = syntheticClass();
        MethodNode intOverload = syntheticMethod("eq", "(II)V",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 0, 2);
        intOverload.instructions.add(new InsnNode(Opcodes.RETURN));
        MethodNode longOverload = syntheticMethod("eq", "(JJ)V",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 0, 4);
        longOverload.instructions.add(new InsnNode(Opcodes.RETURN));
        CGenerator generator = new CGenerator();
        generator.addMethod(new NativeMethodTranslator(owner.name, intOverload, generator).translate());
        generator.addMethod(new NativeMethodTranslator(owner.name, longOverload, generator).translate());
        String source = generator.finish();
        check(!source.contains("Java_synthetic_Probe_eq"),
                "no mangled Java_* symbol for an overloaded native method name");
        check(source.contains("JNINativeMethod m[2]"), "overload table holds both entries");
        check(source.contains("RegisterNatives(env, cls, m, 2)"), "both overloads registered");
        check(source.contains("m[0].signature = umbra_r0_sigs[0]")
                        && source.contains("m[1].signature = umbra_r0_sigs[1]"),
                "each overload carries its own decoded descriptor");
        check(source.contains("m[0].fnPtr = (void*)(&umbra_native_0)")
                        && source.contains("m[1].fnPtr = (void*)(&umbra_native_1)"),
                "each overload binds a distinct wrapper");

        // A class with one native method still registers exactly one entry and
        // exports nothing.
        ClassNode owner2 = syntheticClass();
        MethodNode unique = syntheticMethod("only", "()V",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 0, 0);
        unique.instructions.add(new InsnNode(Opcodes.RETURN));
        CGenerator generator2 = new CGenerator();
        generator2.addMethod(new NativeMethodTranslator(owner2.name, unique, generator2).translate());
        String source2 = generator2.finish();
        check(!source2.contains("Java_synthetic_Probe_only"), "unique name is not exported either");
        check(source2.contains("JNINativeMethod m[1]"), "single-entry table for a unique name");
        check(source2.contains("RegisterNatives(env, cls, m, 1)"), "unique name registered once");
    }

    private static void testTranslatorControlFlow() throws Exception {
        ClassNode owner = syntheticClass();
        // static int loop(int n) { int s = 0; while (n > 0) { s += n; n--; } return s; }
        MethodNode method = syntheticMethod("loop", "(I)I", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                2, 2);
        LabelNode head = new LabelNode();
        LabelNode done = new LabelNode();
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 1));
        method.instructions.add(head);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new JumpInsnNode(Opcodes.IFLE, done));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new InsnNode(Opcodes.IADD));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 1));
        method.instructions.add(new IincInsnNode(0, -1));
        method.instructions.add(new JumpInsnNode(Opcodes.GOTO, head));
        method.instructions.add(done);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        CGenerator.MethodC generated = translate(owner, method);
        check(generated.body.contains("goto L"), "branches become goto labels");
        check(generated.body.contains("if ("), "conditional branch emitted");
    }

    private static void testTranslatorCallsAndFields() throws Exception {
        ClassNode owner = syntheticClass();
        // static String call(String s) { return String.valueOf(s.length()) + System.out; }
        MethodNode method = syntheticMethod("call", "(Ljava/lang/String;)Ljava/lang/String;",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 4, 1);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "length", "()I", false));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/String",
                "valueOf", "(I)Ljava/lang/String;", false));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        CGenerator.MethodC generated = translate(owner, method);
        check(generated.body.contains("CallIntMethodA"), "instance call translated");
        check(generated.body.contains("CallStaticObjectMethodA"), "static call translated");
        check(generated.body.contains("GetMethodID"), "method id resolution emitted");

        ClassNode owner2 = syntheticClass();
        MethodNode field = syntheticMethod("field", "()I", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                1, 0);
        field.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Integer",
                "MAX_VALUE", "I"));
        field.instructions.add(new InsnNode(Opcodes.IRETURN));
        CGenerator.MethodC fieldGenerated = translate(owner2, field);
        check(fieldGenerated.body.contains("GetStaticFieldID"), "static field id resolution");
        check(fieldGenerated.body.contains("GetStaticIntField"), "static field read");

        MethodNode put = syntheticMethod("put", "(Ljava/io/PrintStream;)V",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 1, 1);
        put.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        put.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, "java/lang/System", "out",
                "Ljava/io/PrintStream;"));
        put.instructions.add(new InsnNode(Opcodes.RETURN));
        CGenerator.MethodC putGenerated = translate(syntheticClass(), put);
        check(putGenerated.body.contains("SetStaticObjectField"), "static reference field write");
        check(putGenerated.body.contains("GetStaticFieldID"), "static field resolution emitted");

        MethodNode get = syntheticMethod("get", "()Ljava/lang/String;",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 1, 0);
        get.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "out",
                "Ljava/io/PrintStream;"));
        get.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream",
                "toString", "()Ljava/lang/String;", false));
        get.instructions.add(new InsnNode(Opcodes.ARETURN));
        CGenerator.MethodC getGenerated = translate(syntheticClass(), get);
        check(getGenerated.body.contains("GetStaticObjectField"), "static reference field read");
        check(getGenerated.body.contains("CallObjectMethodA"), "reference returning call");
    }

    private static void testTranslatorArrays() throws Exception {
        ClassNode owner = syntheticClass();
        // static int arrays(int[] a) { int[][] m = new int[2][3]; return a[0] + m[1][2]; }
        MethodNode method = syntheticMethod("arrays", "([I)I", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                4, 2);
        method.instructions.add(new InsnNode(Opcodes.ICONST_2));
        method.instructions.add(new InsnNode(Opcodes.ICONST_3));
        method.instructions.add(new MultiANewArrayInsnNode("[[I", 2));
        method.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new InsnNode(Opcodes.IALOAD));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 1));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.AALOAD));
        method.instructions.add(new InsnNode(Opcodes.ICONST_2));
        method.instructions.add(new InsnNode(Opcodes.IALOAD));
        method.instructions.add(new InsnNode(Opcodes.IADD));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        CGenerator.MethodC generated = translate(owner, method);
        check(generated.body.contains("umbra_multi"), "multidimensional array helper used");
        check(generated.body.contains("GetIntArrayRegion"), "primitive array load");
        check(generated.body.contains("GetObjectArrayElement"), "object array load");

        MethodNode primitive = syntheticMethod("newArray", "(I)[B",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 1, 1);
        primitive.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        primitive.instructions.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        primitive.instructions.add(new InsnNode(Opcodes.ARETURN));
        CGenerator.MethodC primitiveGenerated = translate(owner, primitive);
        check(primitiveGenerated.body.contains("NewByteArray"), "primitive array allocation");

        MethodNode objectArray = syntheticMethod("objectArray", "(I)[Ljava/lang/String;",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 1, 1);
        objectArray.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        objectArray.instructions.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"));
        objectArray.instructions.add(new InsnNode(Opcodes.ARETURN));
        CGenerator.MethodC objectGenerated = translate(owner, objectArray);
        check(objectGenerated.body.contains("NewObjectArray"), "object array allocation");
    }

    private static void testTranslatorExceptions() throws Exception {
        ClassNode owner = syntheticClass();
        // static int safe(int x) { try { return 10 / x; } catch (ArithmeticException e) { return -1; } }
        MethodNode method = syntheticMethod("safe", "(I)I", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                2, 2);
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        method.instructions.add(start);
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 10));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new InsnNode(Opcodes.IDIV));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(end);
        method.instructions.add(handler);
        method.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
        method.instructions.add(new InsnNode(Opcodes.ICONST_M1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler,
                "java/lang/ArithmeticException"));
        CGenerator.MethodC generated = translate(owner, method);
        check(generated.body.contains("umbra_idiv"), "division helper used");
        check(generated.body.contains("ExceptionCheck"), "JNI exceptions are checked");
        check(generated.body.contains("UMBRA_EXC_0"), "catch handler dispatch emitted");
        check(generated.body.contains("IsInstanceOf"), "handler matching by exception type");
        check(generated.body.contains("ExceptionOccurred"), "pending exception captured");
        check(generated.body.contains("goto L"), "handler label jump emitted");

        MethodNode thrower = syntheticMethod("thrower", "(Ljava/lang/Throwable;)V",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 1, 1);
        thrower.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        thrower.instructions.add(new InsnNode(Opcodes.ATHROW));
        CGenerator.MethodC throwGenerated = translate(owner, thrower);
        check(throwGenerated.body.contains("Throw(env"), "athrow translated to JNI Throw");
        check(throwGenerated.body.contains("ThrowNew"), "null athrow throws NullPointerException");

        // try/finally is a catch-all handler with a null catch type.
        ClassNode owner2 = syntheticClass();
        MethodNode finallyMethod = syntheticMethod("fin", "(Ljava/lang/Object;)V",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 2, 2);
        LabelNode start2 = new LabelNode();
        LabelNode end2 = new LabelNode();
        LabelNode handler2 = new LabelNode();
        finallyMethod.instructions.add(start2);
        finallyMethod.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        finallyMethod.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Object", "toString", "()Ljava/lang/String;", false));
        finallyMethod.instructions.add(new InsnNode(Opcodes.POP));
        finallyMethod.instructions.add(new InsnNode(Opcodes.RETURN));
        finallyMethod.instructions.add(end2);
        finallyMethod.instructions.add(handler2);
        finallyMethod.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
        finallyMethod.instructions.add(new InsnNode(Opcodes.RETURN));
        finallyMethod.tryCatchBlocks.add(new TryCatchBlockNode(start2, end2, handler2, null));
        CGenerator.MethodC finallyGenerated = translate(owner2, finallyMethod);
        check(finallyGenerated.body.contains("UMBRA_EXC_0"), "catch-all finally handler");
        check(finallyGenerated.body.contains("umbra_ex = _e"), "exception object carried to handler");
        check(!finallyGenerated.body.contains("IsInstanceOf"),
                "catch-all handler needs no type dispatch");
    }

    private static void testTranslatorRejections() {
        ClassNode owner = syntheticClass();
        MethodNode indy = syntheticMethod("indy", "()V", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 1, 0);
        indy.instructions.add(new InvokeDynamicInsnNode("run", "()V",
                new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/LambdaMetafactory", "metafactory",
                        "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                                + "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;"
                                + "Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
                                + "Ljava/lang/invoke/CallSite;", false)));
        indy.instructions.add(new InsnNode(Opcodes.RETURN));
        checkRejected(owner, indy, "invokedynamic");

        MethodNode monitor = syntheticMethod("monitor", "()V",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 1, 1);
        monitor.instructions.add(new InsnNode(Opcodes.ACONST_NULL));
        monitor.instructions.add(new InsnNode(Opcodes.MONITORENTER));
        monitor.instructions.add(new InsnNode(Opcodes.RETURN));
        checkRejected(syntheticClass(), monitor, "monitor");

        MethodNode constructor = syntheticMethod("<init>", "()V", Opcodes.ACC_PUBLIC, 1, 1);
        constructor.instructions.add(new InsnNode(Opcodes.RETURN));
        checkRejected(syntheticClass(), constructor, "constructor");

        MethodNode nativeMethod = syntheticMethod("alreadyNative", "()V",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_NATIVE, 1, 0);
        checkRejected(syntheticClass(), nativeMethod, "already native");

        MethodNode ldc = syntheticMethod("badLdc", "()V", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 1, 0);
        ldc.instructions.add(new LdcInsnNode(new Handle(Opcodes.H_INVOKESTATIC, "java/lang/Object",
                "hashCode", "()I", false)));
        ldc.instructions.add(new InsnNode(Opcodes.RETURN));
        checkRejected(syntheticClass(), ldc, "method handle constant");
    }

    private static void testTranslatorSwitch() throws Exception {
        ClassNode owner = syntheticClass();
        // static String pick(int x) { switch (x) { case 1: return "one"; case 2: return "two"; } }
        MethodNode method = syntheticMethod("pick", "(I)Ljava/lang/String;",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 1, 1);
        LabelNode caseOne = new LabelNode();
        LabelNode caseTwo = new LabelNode();
        LabelNode fallthrough = new LabelNode();
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        method.instructions.add(new TableSwitchInsnNode(1, 2, fallthrough, caseOne, caseTwo));
        method.instructions.add(caseOne);
        method.instructions.add(new LdcInsnNode("one"));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.instructions.add(caseTwo);
        method.instructions.add(new LdcInsnNode("two"));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.instructions.add(fallthrough);
        method.instructions.add(new InsnNode(Opcodes.ACONST_NULL));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        CGenerator.MethodC generated = translate(owner, method);
        check(generated.body.contains("switch ("), "tableswitch becomes a C switch");
        check(generated.body.contains("case 1:"), "case label emitted");
        check(generated.body.contains("NewStringUTF"), "string constants become NewStringUTF");
        check(generated.body.contains("umbra_str_"), "string constant table referenced");
    }

    private static void checkRejected(ClassNode owner, MethodNode method, String label) {
        try {
            translate(owner, method);
            throw new AssertionError("FAILED: " + label + " should be rejected");
        } catch (NativeMethodTranslator.UnsupportedException expected) {
            checks++;
        } catch (Exception other) {
            throw new AssertionError("FAILED: " + label + " rejected with unexpected " + other, other);
        }
    }

    // ------------------------------------------------------------------
    // Filters
    // ------------------------------------------------------------------

    private static void testFilters() throws Exception {
        UmbraConfig defaults = new UmbraConfig.Builder()
                .input(java.nio.file.Paths.get("in.jar"))
                .output(java.nio.file.Paths.get("out.jar"))
                .option("native.enabled", "true")
                .build();
        NativeSettings settings = NativeSettings.from(defaults);
        check(settings.maxInstructions() > 0, "instruction budget default");
        check(settings.atomic(), "atomic fallback on by default");
        check(settings.accepts("demo/Main", "demo/Main", "main", "([Ljava/lang/String;)V"),
                "default filter accepts any method");
        check(settings.target().equals("windows") || settings.target().length() > 0,
                "target default");

        UmbraConfig filtered = new UmbraConfig.Builder()
                .input(java.nio.file.Paths.get("in.jar"))
                .output(java.nio.file.Paths.get("out.jar"))
                .option("native.methods", "demo.**#get*")
                .option("native.exclude", "**#getSecret")
                .option("native.maxInstructions", "42")
                .option("native.maxMethodsPerClass", "3")
                .build();
        NativeSettings narrow = NativeSettings.from(filtered);
        check(narrow.maxInstructions() == 42, "maxInstructions parsed");
        check(narrow.maxMethodsPerClass() == 3, "maxMethodsPerClass parsed");
        check(narrow.accepts("demo/Main", "demo/Main", "getName", "()Ljava/lang/String;"),
                "include glob accepts matching method");
        check(!narrow.accepts("other/Main", "other/Main", "getName", "()Ljava/lang/String;"),
                "include glob rejects other packages");
        check(!narrow.accepts("demo/Main", "demo/Main", "getSecret", "()I"),
                "exclude glob wins");
        check(!narrow.accepts("demo/Main", "demo/Main", "run", "()V"),
                "include glob rejects non-matching method");
        check(NativeSettings.wildcard("get*", "getName"), "wildcard matcher matches prefix");
        check(!NativeSettings.wildcard("get*", "setName"), "wildcard matcher rejects other names");
    }

    // ------------------------------------------------------------------
    // Toolchain smoke test
    // ------------------------------------------------------------------

    private static void testToolchainCompile() throws Exception {
        Log log = new Log(null, false);
        String compiler = NativeCompiler.resolve("", log);
        if (compiler == null) {
            System.out.println("NativeTest: no C compiler found, skipping DLL compilation smoke test");
            return;
        }
        if (!NativeCompiler.hasJniHeaders()) {
            System.out.println("NativeTest: JNI headers not found, skipping DLL compilation smoke test");
            return;
        }
        check(!NativeCompiler.jniIncludeDirectories().isEmpty(), "JNI include directories found");
        List<String> command = NativeCompiler.command(compiler, java.nio.file.Paths.get("x.c"),
                java.nio.file.Paths.get("x.dll"), target(), "");
        check(command.size() > 2, "compiler command generated");
        check(command.get(0).equals(compiler), "compiler first argument");

        ClassNode owner = syntheticClass();
        MethodNode method = syntheticMethod("fortyTwo", "()I",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 1, 0);
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 42));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        CGenerator generator = new CGenerator();
        generator.addMethod(new NativeMethodTranslator(owner.name, method, generator).translate());
        String source = generator.finish();

        Path directory = Files.createTempDirectory("umbra-native-test");
        try {
            Path sourceFile = directory.resolve("umbra_native.c");
            Path library = directory.resolve("umbra_native" + librarySuffix());
            Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));
            NativeCompiler.Result result = NativeCompiler.compile(compiler, sourceFile, library,
                    target(), "", log);
            check(result.success(), "generated C compiles: " + result.output());
            check(Files.isRegularFile(result.library()), "compiled library file exists");
            check(Files.size(result.library()) > 0, "compiled library is not empty");
            check(result.command().contains("umbra_native"), "compiler command reported");
            System.out.println("NativeTest: compiled a " + Files.size(result.library())
                    + "-byte test library with " + compiler);
        } finally {
            deleteRecursively(directory);
        }
    }

    private static String target() {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (os.contains("win")) {
            return "windows";
        }
        if (os.contains("mac")) {
            return "macos";
        }
        return "linux";
    }

    private static String librarySuffix() {
        String target = target();
        if ("windows".equals(target)) {
            return ".dll";
        }
        if ("macos".equals(target)) {
            return ".dylib";
        }
        return ".so";
    }

    private static void deleteRecursively(Path path) {
        try {
            if (!Files.exists(path)) {
                return;
            }
            Files.walk(path)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (java.io.IOException ignored) {
                            // best effort
                        }
                    });
        } catch (java.io.IOException ignored) {
            // best effort
        }
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}
