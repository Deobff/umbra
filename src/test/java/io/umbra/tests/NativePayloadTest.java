package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.jni.CGenerator;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.pass.impl.NativeCodePass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.jni.NativeCompiler;
import io.umbra.core.jni.NativeMethodTranslator;
import io.umbra.core.jni.intrinsic.IntrinsicTable;
import io.umbra.core.jni.payload.Lzma2Stream;
import io.umbra.core.jni.payload.Lzma2Writer;
import io.umbra.core.jni.payload.PayloadCodec;
import io.umbra.core.jni.payload.PayloadLayout;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/**
 * End-to-end harness for the native (java2c) payload work.
 *
 * <p>Unlike {@code NativeTest}, which only checks that generated C compiles, this
 * test <em>loads</em> the produced library and calls it through JNI, so every
 * semantic claim is checked against the Java reference result. The generated
 * translation unit is given exported wrappers whose symbol names match the
 * {@code native} declarations below; that is the same JNI binding the pass uses
 * ({@code Java_<mangled>}) without needing the injected loader.</p>
 *
 * <p>Covered: frem/drem (NaN, infinities, signed zero, negatives), UTF-16 string
 * literals (NUL, emoji, lone surrogate, 1000 units), member-id deduplication,
 * LZMA2 store-chunk round trip and slice extraction, the java-agent guard, class
 * initializer translation, and the three intrinsics.</p>
 */
public final class NativePayloadTest {

    private static final String PROBE = "io/umbra/tests/NativePayloadTest";

    private static final String CLINIT_OWNER = "io/umbra/tests/NativePayloadTest$ClinitTarget";

    private static int checks;

    private static final String LONG_STRING = buildLongString();

    /** Real natives bound by the exported wrappers of the generated unit. */
    private static native float probeFrem(float a, float b);
    private static native double probeDrem(double a, double b);
    private static native String probeStr0();
    private static native String probeStr1();
    private static native String probeStr2();
    private static native String probeStr3();
    private static native String probeStr4();
    private static native String probeStr5();
    private static native int probeDedupe();
    private static native int probeLength(String value);
    private static native boolean probeEquals(String left, String right);
    private static native void probeClinit();

    /** Target of the translated class initializer. */
    static final class ClinitTarget {
        static int value;
        static String text;
    }

    private NativePayloadTest() {
    }

    public static void main(String[] args) throws Exception {
        PayloadCheck payload = new PayloadCheck();
        payload.dedupeChecks();
        payload.payloadChecks();
        payload.runtimeDecoderChecks();
        payload.agentChecks();

        String compiler = resolveCompiler();
        if (compiler == null) {
            System.out.println("NativePayloadTest: FAILED - no C compiler (set UMBRA_CC)");
            System.exit(1);
            return;
        }
        if (!NativeCompiler.hasJniHeaders()) {
            System.out.println("NativePayloadTest: FAILED - JNI headers not found");
            System.exit(1);
            return;
        }
        CGenerator generator = new CGenerator();
        StringBuilder wrappers = new StringBuilder();
        Build build = new Build(generator, wrappers);
        build.floatRemainder();
        build.strings();
        build.dedupeSites();
        build.intrinsics();
        build.classInitializer();
        String source = generator.finish() + wrappers;
        sourceChecks(source, generator);

        Path directory = Files.createTempDirectory("umbra-payload-test");
        try {
            Path sourceFile = directory.resolve("umbra_native.c");
            Path library = directory.resolve("umbra_native" + librarySuffix());
            Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));
            Log log = new Log(null, true);
            NativeCompiler.Result result = NativeCompiler.compile(compiler, sourceFile, library,
                    target(), "", log);
            check(result.success(), "generated C compiles with " + compiler + ": "
                    + firstLines(result.output(), 12));
            check(Files.isRegularFile(library), "compiled library exists");
            byte[] libraryBytes = Files.readAllBytes(library);
            check(libraryBytes.length > 0, "compiled library is not empty");

            // Payload check against the real library: encode -> decode -> same digest.
            byte[] encoded = Lzma2Writer.encode(libraryBytes);
            byte[] decoded = PayloadCodec.decodeAll(encoded);
            check(Arrays.equals(libraryBytes, decoded),
                    "LZMA2 store mode round-trips the compiled library byte for byte");
            check(hex(sha256(libraryBytes)).equals(hex(sha256(decoded))),
                    "decoded payload SHA-256 equals the original library digest");
            check(encoded.length > libraryBytes.length,
                    "store-mode payload keeps the framing overhead (" + encoded.length
                            + " vs " + libraryBytes.length + " bytes)");
            check((encoded[0] & 0xFF) == 1, "first chunk resets the dictionary");
            check(encoded[encoded.length - 1] == 0, "stream ends with the end marker");

            System.load(library.toAbsolutePath().toString());
            check(true, "library loaded through System.load");
            behaviour(encoded, libraryBytes);
            new EndToEnd(compiler).run();
        } finally {
            deleteRecursively(directory);
        }

        System.out.println("NativePayloadTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------------ build

    private static final class Build {
        private final CGenerator generator;
        private final StringBuilder wrappers;

        Build(CGenerator generator, StringBuilder wrappers) {
            this.generator = generator;
            this.wrappers = wrappers;
        }

        CGenerator.MethodC add(String owner, MethodNode method) throws Exception {
            CGenerator.MethodC generated = new NativeMethodTranslator(owner, method, generator)
                    .translate();
            generator.addMethod(generated);
            return generated;
        }

        void binding(String javaName, CGenerator.MethodC method) {
            wrappers.append(wrapper("Java_io_umbra_tests_NativePayloadTest_" + javaName, method));
        }

        void floatRemainder() throws Exception {
            ClassNode owner = owner(PROBE);
            MethodNode frem = method("frem", "(FF)F", 2, 2);
            frem.instructions.add(new VarInsnNode(Opcodes.FLOAD, 0));
            frem.instructions.add(new VarInsnNode(Opcodes.FLOAD, 1));
            frem.instructions.add(new InsnNode(Opcodes.FREM));
            frem.instructions.add(new InsnNode(Opcodes.FRETURN));
            binding("probeFrem", add(owner.name, frem));

            MethodNode drem = method("drem", "(DD)D", 4, 4);
            drem.instructions.add(new VarInsnNode(Opcodes.DLOAD, 0));
            drem.instructions.add(new VarInsnNode(Opcodes.DLOAD, 2));
            drem.instructions.add(new InsnNode(Opcodes.DREM));
            drem.instructions.add(new InsnNode(Opcodes.DRETURN));
            binding("probeDrem", add(owner.name, drem));
        }

        void strings() throws Exception {
            ClassNode owner = owner(PROBE);
            for (int i = 0; i < 6; i++) {
                MethodNode node = method("str" + i, "()Ljava/lang/String;", 1, 0);
                node.instructions.add(new LdcInsnNode(stringConstant(i)));
                node.instructions.add(new InsnNode(Opcodes.ARETURN));
                binding("probeStr" + i, add(owner.name, node));
            }
        }

        void dedupeSites() throws Exception {
            ClassNode owner = owner(PROBE);
            MethodNode node = method("dedupe", "()I", 1, 0);
            for (int i = 0; i < 3; i++) {
                node.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Integer",
                        "MAX_VALUE", "I"));
                node.instructions.add(new InsnNode(Opcodes.POP));
            }
            node.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Integer",
                    "MAX_VALUE", "I"));
            node.instructions.add(new InsnNode(Opcodes.IRETURN));
            binding("probeDedupe", add(owner.name, node));
        }

        void intrinsics() throws Exception {
            ClassNode owner = owner(PROBE);
            MethodNode length = method("length", "(Ljava/lang/String;)I", 1, 1);
            length.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            length.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                    "length", "()I", false));
            length.instructions.add(new InsnNode(Opcodes.IRETURN));
            binding("probeLength", add(owner.name, length));

            MethodNode equals = method("equals",
                    "(Ljava/lang/String;Ljava/lang/String;)Z", 2, 2);
            equals.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            equals.instructions.add(new VarInsnNode(Opcodes.ALOAD, 1));
            equals.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                    "equals", "(Ljava/lang/Object;)Z", false));
            equals.instructions.add(new InsnNode(Opcodes.IRETURN));
            binding("probeEquals", add(owner.name, equals));
        }

        void classInitializer() throws Exception {
            ClassNode owner = owner(CLINIT_OWNER);
            MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.maxStack = 1;
            clinit.maxLocals = 0;
            clinit.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 42));
            clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, CLINIT_OWNER, "value", "I"));
            clinit.instructions.add(new LdcInsnNode("clinit-ok"));
            clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, CLINIT_OWNER, "text",
                    "Ljava/lang/String;"));
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            owner.methods.add(clinit);

            boolean rejectedWithoutFlag = false;
            try {
                new NativeMethodTranslator(owner.name, clinit, generator).translate();
            } catch (NativeMethodTranslator.UnsupportedException expected) {
                rejectedWithoutFlag = true;
            }
            check(rejectedWithoutFlag, "<clinit> is rejected unless the caller opts in");

            CGenerator.MethodC generated = new NativeMethodTranslator(owner.name, clinit,
                    generator, true).translate();
            generator.addMethod(generated);
            binding("probeClinit", generated);
        }
    }

    private static String wrapper(String export, CGenerator.MethodC method) {
        StringBuilder out = new StringBuilder();
        out.append("JNIEXPORT ").append(method.cReturn).append(" JNICALL ").append(export)
                .append("(JNIEnv* env, ").append(method.staticMethod ? "jclass" : "jobject")
                .append(" self");
        for (int i = 0; i < method.cArguments.size(); i++) {
            out.append(", ").append(method.cArguments.get(i)).append(" a").append(i);
        }
        out.append(") {\n    ");
        if (!"void".equals(method.cReturn)) {
            out.append("return ");
        }
        out.append(method.functionName).append("(env, self");
        for (int i = 0; i < method.cArguments.size(); i++) {
            out.append(", a").append(i);
        }
        out.append(");\n}\n\n");
        return out.toString();
    }

    private static ClassNode owner(String name) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC;
        node.name = name;
        node.superName = "java/lang/Object";
        return node;
    }

    private static MethodNode method(String name, String descriptor, int maxStack, int maxLocals) {
        MethodNode node = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, descriptor,
                null, null);
        node.maxStack = maxStack;
        node.maxLocals = maxLocals;
        return node;
    }

    private static String stringConstant(int index) {
        switch (index) {
            case 0:
                return "ASCII-only";
            case 1:
                return "\u4e2d\u6587\u6d4b\u8bd5";
            case 2:
                return "\ud83d\ude00\ud83d\ude00 emoji";
            case 3:
                return "a\u0000b";
            case 4:
                return "\ud800";
            default:
                return LONG_STRING;
        }
    }

    private static String buildLongString() {
        StringBuilder out = new StringBuilder(1000);
        for (int i = 0; i < 1000; i++) {
            out.append((char) ('a' + (i % 26)));
        }
        return out.toString();
    }

    // ------------------------------------------------------------- behaviours

    private static void behaviour(byte[] encoded, byte[] libraryBytes) throws Exception {
        ClinitTarget.value = 0;
        ClinitTarget.text = null;
        probeClinit();
        check(ClinitTarget.value == 42, "translated <clinit> assigns the static int field");
        check("clinit-ok".equals(ClinitTarget.text), "translated <clinit> assigns the static String");

        float[] floats = {1.0f, -1.0f, 0.0f, -0.0f, 7.5f, -7.5f, Float.NaN,
                Float.POSITIVE_INFINITY, Float.NEGATIVE_INFINITY, 3.4e38f, 1.0e-38f};
        for (float a : floats) {
            for (float b : floats) {
                float expected = a % b;
                float actual = probeFrem(a, b);
                check(Float.floatToRawIntBits(expected) == Float.floatToRawIntBits(actual),
                        "frem(" + a + ", " + b + ") matches Java");
            }
        }
        double[] doubles = {1.0, -1.0, 0.0, -0.0, 7.5, -7.5, Double.NaN,
                Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, 1.7e308, 4.9e-324};
        for (double a : doubles) {
            for (double b : doubles) {
                double expected = a % b;
                double actual = probeDrem(a, b);
                check(Double.doubleToRawLongBits(expected) == Double.doubleToRawLongBits(actual),
                        "drem(" + a + ", " + b + ") matches Java");
            }
        }

        check("ASCII-only".equals(probeStr0()), "ASCII literal survives");
        check("\u4e2d\u6587\u6d4b\u8bd5".equals(probeStr1()), "Chinese literal survives");
        check("\ud83d\ude00\ud83d\ude00 emoji".equals(probeStr2()), "surrogate pair literal survives");
        check("a\u0000b".equals(probeStr3()), "NUL inside a literal survives");
        check(probeStr3().length() == 3, "NUL literal keeps its length");
        check("\ud800".equals(probeStr4()), "lone surrogate survives");
        check(LONG_STRING.equals(probeStr5()), "1000-unit literal survives");
        check(probeStr5().length() == 1000, "1000-unit literal keeps its length");

        check(probeDedupe() == Integer.MAX_VALUE, "deduplicated field site reads the same value");
        check(probeLength("\u4e2d\u6587\ud83d\ude00") == 4, "intrinsic String.length");
        check(probeEquals("abc", "abc"), "intrinsic String.equals true case");
        check(!probeEquals("abc", "abd"), "intrinsic String.equals false case");
        check(!probeEquals("abc", null), "intrinsic String.equals null case");
        check(probeEquals("\u4e2d\u6587", "\u4e2d\u6587"), "intrinsic String.equals Unicode");

        check(encoded.length > 0 && libraryBytes.length > 0, "payload bytes available for stats");
    }

    // ------------------------------------------------------------- unit parts

    private static final class PayloadCheck {

        void dedupeChecks() throws Exception {
            CGenerator generator = new CGenerator();
            ClassNode owner = owner(PROBE);
            MethodNode node = method("dedupe", "()I", 1, 0);
            for (int i = 0; i < 4; i++) {
                node.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Integer",
                        "MAX_VALUE", "I"));
                node.instructions.add(new InsnNode(Opcodes.POP));
            }
            node.instructions.add(new InsnNode(Opcodes.ICONST_0));
            node.instructions.add(new InsnNode(Opcodes.IRETURN));
            CGenerator.MethodC generated = new NativeMethodTranslator(owner.name, node, generator)
                    .translate();
            check(generator.idSiteCount() == 4, "four call sites counted");
            check(generator.uniqueIdCount() == 1, "one shared id slot per member");
            check(generator.idSiteCount() - generator.uniqueIdCount() == 3, "dedup statistic");
            check(!generated.body.contains("__attribute__((const))"),
                    "no invalid const attribute on JNI helpers");
        }

        void payloadChecks() throws Exception {
            check(Lzma2Writer.encode(new byte[0]).length == 1,
                    "empty payload is just the end marker");
            check(PayloadCodec.decodeAll(Lzma2Writer.encode(new byte[0])).length == 0,
                    "empty payload decodes to empty");

            byte[] random = new byte[200 * 1024 + 17];
            new Random(0xC0FFEEL).nextBytes(random);
            byte[] encoded = Lzma2Writer.encode(random);
            check((encoded[0] & 0xFF) == 1, "first stored chunk resets the dictionary");
            int chunks = 0;
            int index = 0;
            while (index < encoded.length && encoded[index] != 0) {
                int kind = encoded[index] & 0xFF;
                check(kind == 1 || kind == 2, "stored chunk kind " + kind);
                int size = (((encoded[index + 1] & 0xFF) << 8)
                        | (encoded[index + 2] & 0xFF)) + 1;
                check(size >= 1 && size <= 65536, "chunk size within the LZMA2 limit");
                index += 3 + size;
                chunks++;
            }
            check(chunks == 4, "200 KiB needs four chunks, saw " + chunks);
            check(Arrays.equals(random, PayloadCodec.decodeAll(encoded)),
                    "200 KiB round trip is byte identical");
            check(hex(sha256(random)).equals(hex(sha256(PayloadCodec.decodeAll(encoded)))),
                    "round-tripped digest matches");

            // Two "platforms" folded into one payload with a layout table.
            byte[] first = new byte[1000];
            byte[] second = new byte[777];
            new Random(7L).nextBytes(first);
            new Random(9L).nextBytes(second);
            byte[] combined = PayloadCodec.concat(Arrays.asList(first, second));
            byte[] folded = Lzma2Writer.encode(combined);
            StringBuilder layout = new StringBuilder();
            layout.append(PayloadLayout.line("WINDOWS_X86_64", 0, first.length));
            layout.append(PayloadLayout.line("LINUX_X86_64", first.length, combined.length));
            PayloadLayout parsed = PayloadLayout.parse(layout.toString());
            check(parsed.size() == 2, "layout parsed two targets");
            long[] windows = parsed.range("WINDOWS_X86_64");
            long[] linux = parsed.range("LINUX_X86_64");
            check(windows != null && linux != null, "both target ranges present");
            check(Arrays.equals(first,
                            PayloadCodec.decodeSlice(folded, windows[0], windows[1])),
                    "windows slice extracted");
            check(Arrays.equals(second, PayloadCodec.decodeSlice(folded, linux[0], linux[1])),
                    "linux slice extracted");
            check(PayloadLayout.targetFor("Windows 11", "amd64").equals("WINDOWS_X86_64"),
                    "target mapping for windows/amd64");
            check(PayloadLayout.targetFor("Mac OS X", "aarch64").equals("MACOS_AARCH64"),
                    "target mapping for macos/aarch64");
            check(PayloadLayout.targetFor("Linux", "x86_64").equals("LINUX_X86_64"),
                    "target mapping for linux/x86_64");

            byte[] broken = Arrays.copyOf(folded, folded.length - 2);
            boolean failed = false;
            try {
                PayloadCodec.decodeAll(broken);
            } catch (java.io.IOException expected) {
                failed = true;
            }
            check(failed, "truncated payload is rejected");
        }

        /**
         * Drives the decoder that actually runs inside the protected program.
         *
         * <p>{@code UmbraNativeLoader} must stay a single self-contained class, so it
         * carries its own stored-chunk decoder instead of the payload package. This
         * check patches the layout placeholder (the build normally does that) and
         * calls the private decoder directly, so the runtime path is exercised and
         * not just the build-side {@link PayloadCodec}.</p>
         */
        void runtimeDecoderChecks() throws Exception {
            Class<?> loader = Class.forName("io.umbra.core.runtime.UmbraNativeLoader");
            byte[] original = readClass(loader);
            byte[] patched = patchRuntimePlaceholders(original, "runtime/layout-test.lay");
            ClassLoader child = new SingleClassLoader(loader.getName(), patched);
            Class<?> patchedType = Class.forName(loader.getName(), true, child);
            Method decode = patchedType.getDeclaredMethod("decodePayload", byte[].class);
            decode.setAccessible(true);

            byte[] sample = new byte[400];
            new Random(11L).nextBytes(sample);
            byte[] stream = Lzma2Writer.encode(sample);
            check(Arrays.equals(sample, (byte[]) decode.invoke(null, stream)),
                    "runtime inline decoder round-trips a stored payload");

            byte[] big = new byte[150 * 1024];
            new Random(12L).nextBytes(big);
            check(Arrays.equals(big, (byte[]) decode.invoke(null, Lzma2Writer.encode(big))),
                    "runtime inline decoder handles multiple chunks");

            byte[] legacy = {(byte) 0x4D, (byte) 0x5A, (byte) 0x90, 0x00, 0x03, 0x00};
            boolean rawRefused = false;
            try {
                decode.invoke(null, legacy);
            } catch (java.lang.reflect.InvocationTargetException wrapped) {
                rawRefused = wrapped.getCause() instanceof java.io.IOException;
            }
            check(rawRefused, "payload=1 refuses a raw library instead of writing it out");

            Class<?> rawType = Class.forName(loader.getName(), true,
                    new SingleClassLoader(loader.getName(),
                            patchRuntimePlaceholders(original, "runtime/layout-test.lay", "0")));
            Method rawDecode = rawType.getDeclaredMethod("decodePayload", byte[].class);
            rawDecode.setAccessible(true);
            check(Arrays.equals(legacy, (byte[]) rawDecode.invoke(null, legacy)),
                    "payload=0 keeps the raw-library mode other passes still produce");

            boolean unsupported = false;
            try {
                decode.invoke(null, new byte[]{(byte) 0xE0, 0x00, 0x00, 1, 2});
            } catch (java.lang.reflect.InvocationTargetException wrapped) {
                unsupported = wrapped.getCause() instanceof java.io.IOException;
            }
            check(unsupported, "an LZMA chunk the store decoder cannot read fails closed");

            boolean truncated = false;
            try {
                decode.invoke(null, Arrays.copyOf(stream, stream.length - 2));
            } catch (java.lang.reflect.InvocationTargetException wrapped) {
                truncated = wrapped.getCause() instanceof java.io.IOException;
            }
            check(truncated, "a truncated payload fails closed");
        }

        void agentChecks() throws Exception {
            Class<?> loader = Class.forName("io.umbra.core.runtime.UmbraNativeLoader");
            Method predicate = loader.getDeclaredMethod("agentAttached", List.class);
            predicate.setAccessible(true);
            check(Boolean.TRUE.equals(predicate.invoke(null,
                            Arrays.asList("-javaagent:C:/x.jar"))),
                    "colon form of -javaagent is detected");
            check(Boolean.TRUE.equals(predicate.invoke(null,
                            Arrays.asList("-agentlib:jdwp=transport=dt_socket"))),
                    "colon form of -agentlib is detected");
            check(Boolean.TRUE.equals(predicate.invoke(null, Arrays.asList("-javaagent"))),
                    "bare -javaagent is detected");
            check(Boolean.FALSE.equals(predicate.invoke(null,
                            Arrays.asList("-Xmx1g", "-Dfoo=bar"))),
                    "ordinary flags are not treated as agents");
            check(Boolean.FALSE.equals(predicate.invoke(null, new ArrayList<String>())),
                    "empty argument list is not an agent");
            Method current = loader.getDeclaredMethod("agentAttached");
            current.setAccessible(true);
            check(Boolean.FALSE.equals(current.invoke(null)),
                    "the test JVM itself runs without an agent");

            // The refusal must happen before anything is read or written: find the
            // first call inside loadLibrary and require it to be agentAttached.
            byte[] bytes = readClass(loader);
            ClassNode node = new ClassNode();
            new ClassReader(bytes).accept(node, ClassReader.SKIP_DEBUG);
            MethodNode loadLibrary = null;
            for (MethodNode candidate : node.methods) {
                if ("loadLibrary".equals(candidate.name)) {
                    loadLibrary = candidate;
                }
            }
            check(loadLibrary != null, "loadLibrary present in the loader template");
            String firstCall = null;
            boolean writesFirst = false;
            for (AbstractInsnNode insn = loadLibrary.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof MethodInsnNode)) {
                    continue;
                }
                MethodInsnNode call = (MethodInsnNode) insn;
                if (firstCall == null) {
                    firstCall = call.name;
                }
                if ("writeLibrary".equals(call.name) || "readResource".equals(call.name)) {
                    writesFirst = firstCall == null || !"agentAttached".equals(firstCall);
                    break;
                }
            }
            check("agentAttached".equals(firstCall),
                    "agent guard is the first call in loadLibrary, saw " + firstCall);
            check(!writesFirst, "guard runs before the payload is read or written");
        }
    }

    private static void sourceChecks(String source, CGenerator generator) {
        check(source.contains("#include <math.h>"), "math.h included for fmod");
        check(source.contains("umbra_frem"), "frem uses the fmodf helper");
        check(source.contains("umbra_drem"), "drem uses the fmod helper");
        check(!source.contains("(a % b)"), "no invalid floating-point remainder operator");
        check(source.contains("UMBRA_ATOMIC_LOAD"), "id cache uses acquire loads");
        check(source.contains("UMBRA_ATOMIC_STORE"), "id cache publishes with release stores");
        check(source.contains("UMBRA_ATOMIC_CAS"), "id cache uses a compare-and-swap");
        check(source.contains("GetStringLength"), "String.length intrinsic uses GetStringLength");
        check(source.contains("GetStringRegion"), "String.equals intrinsic compares regions");
        check(source.contains("IsSameObject"), "String.equals intrinsic has the identity fast path");
        check(!source.contains("static const char umbra_str_"),
                "the plaintext static const char literal table is gone");
        check(!source.contains("NewStringUTF(env, umbra_str_"),
                "literals are no longer fed through NewStringUTF");
        check(source.contains("umbra_str_recover"), "string literals are reconstructed from the pool");
        check(source.contains("NewString(env"), "string literals are built as UTF-16");
        check(!source.contains("\"\u4e2d\u6587\u6d4b\u8bd5\""),
                "the Chinese literal does not appear in plaintext");
        check(generator.intrinsicCount() == 2,
                "two intrinsic call sites recorded, saw " + generator.intrinsicCount());
        check(IntrinsicTable.size() == 3, "three intrinsic handlers registered");
        check(IntrinsicTable.lookup(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/String", "length", "()I", false)) != null,
                "String.length is in the intrinsic table");
        check(IntrinsicTable.lookup(new MethodInsnNode(Opcodes.INVOKEINTERFACE,
                "java/lang/CharSequence", "length", "()I", true)) == null,
                "a look-alike method is not matched");
    }

    /**
     * Subprocess end-to-end: run the real pass, write a real jar, fork a real JVM
     * and require the protected program to print results produced by native code.
     *
     * <p>A "System.load did not throw" test cannot see a payload that was written
     * out undecoded, nor a JNI_OnLoad that returned JNI_ERR. The child exits 0 only
     * when the payload decoded, the layout slice (or the whole payload when the
     * layout is absent) was written out, the entry points registered and the
     * translated methods returned the right values.</p>
     */
    private static final class EndToEnd {
        private final String compiler;

        EndToEnd(String compiler) {
            this.compiler = compiler;
        }

        void run() throws Exception {
            Path directory = Files.createTempDirectory("umbra-native-e2e");
            try {
                ClassPool pool = new ClassPool();
                Hierarchy hierarchy = new Hierarchy();
                ClassNode demo = demoClass();
                pool.putClass("e2e/NativeDemo.class", write(demo), demo);
                hierarchy.addInput(demo);

                UmbraConfig config = new UmbraConfig.Builder()
                        .input(directory.resolve("in.jar"))
                        .output(directory.resolve("out.jar"))
                        .option("native.enabled", "true")
                        .option("native.compiler", this.compiler)
                        .option("native.target", target())
                        .option("native.antiDump", "true")
                        .option("native.antiBackfill", "true")
                        .build();
                DefaultRuleSet rules = new DefaultRuleSet(new ArrayList<String>(),
                        new ArrayList<String>(), false, false);
                PassContext context = new PassContext(config, pool, hierarchy, rules,
                        new io.umbra.core.runtime.DefaultRuntimeSupport(), new MappingSet(),
                        new Stats(), new Log(null, false), new Random(97531L),
                        new ProgressListener() {
                            @Override
                            public void onProgress(int percent, String message) {
                            }
                        });
                new NativeCodePass().run(context);

                ClassNode after = pool.getClass("e2e/NativeDemo");
                check(after != null, "e2e: demo class survives the pass");
                check(isNative(after, "add", "(II)I"), "e2e: add(II)I became native");
                check(isNative(after, "$umbraClinit", "()V"), "e2e: <clinit> body became native");
                MethodNode clinit = findMethod(after, "<clinit>", "()V");
                check(clinit != null, "e2e: Java <clinit> synthesised");
                boolean callsClinit = false;
                for (AbstractInsnNode insn = clinit.instructions.getFirst(); insn != null;
                     insn = insn.getNext()) {
                    if (insn instanceof MethodInsnNode
                            && "$umbraClinit".equals(((MethodInsnNode) insn).name)) {
                        callsClinit = true;
                    }
                }
                check(callsClinit, "e2e: Java <clinit> calls $umbraClinit()");

                String payloadName = null;
                String layoutName = null;
                for (String name : pool.resources().keySet()) {
                    if (name.endsWith(".dat")) {
                        payloadName = name;
                    }
                    if (name.endsWith(".lay")) {
                        layoutName = name;
                    }
                }
                check(payloadName != null, "e2e: payload resource written");
                check(layoutName != null, "e2e: layout resource written for a single target");
                byte[] payload = pool.resource(payloadName).bytes();
                check((payload[0] & 0xFF) == 1, "e2e: payload starts with a dictionary reset");
                byte[] decoded = PayloadCodec.decodeAll(payload);
                check(decoded.length > 64, "e2e: payload decodes to a library");
                check(decoded[0] == 'M' && decoded[1] == 'Z', "e2e: decoded payload is a PE image");
                String layoutText = new String(pool.resource(layoutName).bytes(),
                        StandardCharsets.UTF_8);
                PayloadLayout layout = PayloadLayout.parse(layoutText);
                long[] range = layout.range(PayloadLayout.targetForHost(target(), "auto"));
                check(range != null, "e2e: layout has a row for the host target");
                check(range[1] - range[0] == decoded.length,
                        "e2e: layout range matches the decoded length");

                Path jar = directory.resolve("native-demo.jar");
                writeJar(jar, pool, "e2e.NativeDemo");
                RunResult withLayout = runJar(jar, true);
                check(withLayout.exit == 0, "e2e: protected jar exits 0 (with layout), stderr: "
                        + withLayout.stderr);
                check(withLayout.stdout.contains("counter=7"),
                        "e2e: translated <clinit> set the static int, stdout: " + withLayout.stdout);
                check(withLayout.stdout.contains("ready"),
                        "e2e: translated <clinit> set the static String");
                check(withLayout.stdout.contains("sum=12"),
                        "e2e: native method returned the right value");
                check(withLayout.stderr.contains("register_natives=0"),
                        "e2e: JNI_OnLoad registered the entry points, stderr: " + withLayout.stderr);
                check(withLayout.stderr.contains("layout="),
                        "e2e: loader reports which extraction path it used");

                Path stripped = directory.resolve("native-demo-nolayout.jar");
                stripEntry(jar, stripped, layoutName);
                RunResult withoutLayout = runJar(stripped, true);
                check(withoutLayout.exit == 0,
                        "e2e: missing layout still decodes the whole payload, stderr: "
                                + withoutLayout.stderr);
                check(withoutLayout.stdout.contains("counter=7")
                                && withoutLayout.stdout.contains("sum=12"),
                        "e2e: native code runs without a layout table");
                check(withoutLayout.stderr.contains("layout=missing"),
                        "e2e: loader states that it decoded the whole payload");
            } finally {
                deleteRecursively(directory);
            }
        }
    }

    private static final class RunResult {
        final int exit;
        final String stdout;
        final String stderr;

        RunResult(int exit, String stdout, String stderr) {
            this.exit = exit;
            this.stdout = stdout;
            this.stderr = stderr;
        }
    }

    /** Fixture: a class whose clinit sets statics and whose method must run natively. */
    private static ClassNode demoClass() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC;
        node.name = "e2e/NativeDemo";
        node.superName = "java/lang/Object";
        node.fields.add(new org.objectweb.asm.tree.FieldNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "counter", "I", null, null));
        node.fields.add(new org.objectweb.asm.tree.FieldNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "tag", "Ljava/lang/String;", null, null));

        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, "e2e/NativeDemo",
                "counter", "I"));
        clinit.instructions.add(new LdcInsnNode("ready"));
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, "e2e/NativeDemo",
                "tag", "Ljava/lang/String;"));
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.maxStack = 1;
        clinit.maxLocals = 0;
        node.methods.add(clinit);

        MethodNode add = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "add",
                "(II)I", null, null);
        add.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        add.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        add.instructions.add(new InsnNode(Opcodes.IADD));
        add.instructions.add(new InsnNode(Opcodes.IRETURN));
        add.maxStack = 2;
        add.maxLocals = 2;
        node.methods.add(add);

        MethodNode main = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main",
                "([Ljava/lang/String;)V", null, null);
        main.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "out",
                "Ljava/io/PrintStream;"));
        main.instructions.add(new LdcInsnNode("counter="));
        main.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream",
                "print", "(Ljava/lang/String;)V", false));
        main.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "out",
                "Ljava/io/PrintStream;"));
        main.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "e2e/NativeDemo",
                "counter", "I"));
        main.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream",
                "println", "(I)V", false));
        main.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "out",
                "Ljava/io/PrintStream;"));
        main.instructions.add(new LdcInsnNode("sum="));
        main.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream",
                "print", "(Ljava/lang/String;)V", false));
        main.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "out",
                "Ljava/io/PrintStream;"));
        main.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 5));
        main.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        main.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "e2e/NativeDemo", "add",
                "(II)I", false));
        main.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream",
                "println", "(I)V", false));
        main.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "out",
                "Ljava/io/PrintStream;"));
        main.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, "e2e/NativeDemo", "tag",
                "Ljava/lang/String;"));
        main.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream",
                "println", "(Ljava/lang/String;)V", false));
        main.instructions.add(new InsnNode(Opcodes.RETURN));
        main.maxStack = 3;
        main.maxLocals = 1;
        node.methods.add(main);
        return node;
    }

    private static boolean isNative(ClassNode node, String name, String descriptor) {
        MethodNode method = findMethod(node, name, descriptor);
        return method != null && (method.access & Opcodes.ACC_NATIVE) != 0;
    }

    private static MethodNode findMethod(ClassNode node, String name, String descriptor) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name) && method.desc.equals(descriptor)) {
                return method;
            }
        }
        return null;
    }

    private static byte[] write(ClassNode node) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        return writer.toByteArray();
    }

    private static void writeJar(Path jar, ClassPool pool, String mainClass) throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, mainClass);
        JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar));
        try {
            out.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
            manifest.write(out);
            out.closeEntry();
            for (ClassNode node : pool.classes().values()) {
                out.putNextEntry(new JarEntry(node.name + ".class"));
                out.write(write(node));
                out.closeEntry();
            }
            for (ClassPool.Resource resource : pool.resources().values()) {
                out.putNextEntry(new JarEntry(resource.name()));
                out.write(resource.bytes());
                out.closeEntry();
            }
        } finally {
            out.close();
        }
    }

    /** Copies the jar without one entry, to prove the loader copes. */
    private static void stripEntry(Path source, Path target, String entryName) throws Exception {
        java.util.zip.ZipFile zip = new java.util.zip.ZipFile(source.toFile());
        JarOutputStream out = new JarOutputStream(Files.newOutputStream(target));
        try {
            java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                java.util.zip.ZipEntry entry = entries.nextElement();
                if (entry.getName().equals(entryName)) {
                    continue;
                }
                out.putNextEntry(new JarEntry(entry.getName()));
                out.write(PayloadCodec.readAll(zip.getInputStream(entry)));
                out.closeEntry();
            }
        } finally {
            out.close();
            zip.close();
        }
    }

    private static RunResult runJar(Path jar, boolean debug) throws Exception {
        File bin = new File(System.getProperty("java.home"), "bin");
        File executable = new File(bin, "java.exe");
        if (!executable.isFile()) {
            executable = new File(bin, "java");
        }
        List<String> command = new ArrayList<String>();
        command.add(executable.getPath());
        if (debug) {
            command.add("-Dumbra.debug=true");
        }
        command.add("-jar");
        command.add(jar.toAbsolutePath().toString());
        ProcessBuilder builder = new ProcessBuilder(command);
        if (debug) {
            builder.environment().put("UMBRA_NATIVE_DEBUG", "1");
        }
        Process process = builder.start();
        String stdout = drain(process.getInputStream());
        String stderr = drain(process.getErrorStream());
        boolean finished = process.waitFor(120, java.util.concurrent.TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            return new RunResult(-1, stdout, stderr + " [timed out]");
        }
        return new RunResult(process.exitValue(), stdout, stderr);
    }

    private static String drain(java.io.InputStream in) throws Exception {
        StringBuilder out = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append((char) 10);
            }
        } finally {
            reader.close();
        }
        return out.toString();
    }


    // ------------------------------------------------------------------ utils

    private static String resolveCompiler() {
        Log log = new Log(null, false);
        String resolved = NativeCompiler.resolve("", log);
        if (resolved != null) {
            return resolved;
        }
        String configured = System.getenv("UMBRA_CC");
        if (configured != null && !configured.trim().isEmpty()) {
            return configured.trim();
        }
        File bundled = new File("E:\\1111\\bin\\gcc.exe");
        return bundled.isFile() ? bundled.getAbsolutePath() : null;
    }

    /**
     * Rewrites the two runtime placeholders so the decoder takes the payload path:
     * the pass substitutes both, and a test that only patched the layout name would
     * leave {@code payloadEnabled()} false and exercise the raw branch instead.
     */
    private static byte[] patchRuntimePlaceholders(byte[] bytes, String replacement) {
        return patchRuntimePlaceholders(bytes, replacement, "1");
    }

    private static byte[] patchRuntimePlaceholders(byte[] bytes, String replacement,
                                                  String payloadFlag) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) insn;
                    if ("@@LAYOUT@@".equals(ldc.cst)) {
                        ldc.cst = replacement;
                    }
                    if ("@@PAYLOAD@@".equals(ldc.cst)) {
                        ldc.cst = payloadFlag;
                    }
                }
            }
        }
        for (org.objectweb.asm.tree.FieldNode field : node.fields) {
            if ("@@LAYOUT@@".equals(field.value)) {
                field.value = replacement;
            }
            if ("@@PAYLOAD@@".equals(field.value)) {
                field.value = payloadFlag;
            }
        }
        org.objectweb.asm.ClassWriter writer = new org.objectweb.asm.ClassWriter(0);
        node.accept(writer);
        return writer.toByteArray();
    }

    /** Defines exactly one class, so the patched loader does not leak globally. */
    private static final class SingleClassLoader extends ClassLoader {
        private final String name;
        private final byte[] bytes;

        SingleClassLoader(String name, byte[] bytes) {
            super(NativePayloadTest.class.getClassLoader());
            this.name = name;
            this.bytes = bytes;
        }

        @Override
        protected Class<?> loadClass(String requested, boolean resolve)
                throws ClassNotFoundException {
            // Child-first for the one patched name: Class.forName would otherwise
            // hand back the unpatched class already visible to the parent loader.
            if (this.name.equals(requested)) {
                Class<?> defined = findLoadedClass(requested);
                if (defined == null) {
                    defined = defineClass(requested, this.bytes, 0, this.bytes.length);
                }
                if (resolve) {
                    resolveClass(defined);
                }
                return defined;
            }
            return super.loadClass(requested, resolve);
        }
    }

    private static byte[] readClass(Class<?> type) throws Exception {
        String resource = type.getSimpleName() + ".class";
        java.io.InputStream in = type.getResourceAsStream(resource);
        check(in != null, "class resource readable: " + resource);
        try {
            return PayloadCodec.readAll(in);
        } finally {
            in.close();
        }
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static String hex(byte[] data) {
        StringBuilder out = new StringBuilder(data.length * 2);
        for (byte value : data) {
            out.append(Character.forDigit((value >> 4) & 0xF, 16));
            out.append(Character.forDigit(value & 0xF, 16));
        }
        return out.toString();
    }

    private static String firstLines(String text, int count) {
        if (text == null) {
            return "<no output>";
        }
        String[] lines = text.split("\\R");
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < lines.length && i < count; i++) {
            out.append(lines[i]).append(" | ");
        }
        return out.length() > 1600 ? out.substring(0, 1600) : out.toString();
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
            Files.walk(path).sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
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
