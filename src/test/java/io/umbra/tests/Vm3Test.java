package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.engine.Stats;
import io.umbra.core.engine.UmbraVerifier;
import io.umbra.core.jni.NativeCompiler;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.pass.impl.VirtualizationPass;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.runtime.vm2.UmbraVM2;
import io.umbra.core.runtime.vm2.Vm2Format;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.util.Log;
import io.umbra.core.model.UmbraClassWriter;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

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
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * VM2 v3 + native hardening tests.
 *
 * <p>Covers the new payload format 4 (rolling opcode key) against a reference
 * decoder and against the legacy format-3 reader path, superinstruction
 * semantics versus the equivalent unfused instruction runs, fusion statistics
 * and determinism at pass level, Cantrip/nested compatibility, extra opcode
 * coverage (lookupswitch/multi-dimensional arrays), the native anti-dump
 * fingerprint/backfill refusals (positive and negative) and the native
 * constructor/invokedynamic coverage gains.</p>
 *
 * <p>Run with {@code java -cp "<classes>;<test-classes>;<lib>" io.umbra.tests.Vm3Test}.
 * The native end-to-end part is skipped with an explicit message when no C
 * toolchain/JNI headers are available; it is never silently reported as
 * passed.</p>
 */
public final class Vm3Test {

    private static int checks;
    private static final String GCC = "E:\\1111\\bin\\gcc.exe";

    private Vm3Test() {
    }

    public static void main(String[] args) throws Exception {
        testPayloadFormat();
        testSuperInstructions();
        Map<String, byte[]> compiled = compileFixture();
        testFusion(compiled);
        testDeterminism(compiled);
        testCantripAndNested(compiled);
        testOpcodeCoverage(compiled);
        testLazyClassConstants(compiled);
        testNativeEndToEnd();
        System.out.println("Vm3Test: " + checks + " checks passed");
    }

    // ------------------------------------------------------------------
    // Payload format 4: rolling opcode key, legacy reader, tamper, reference
    // ------------------------------------------------------------------

    private static void testPayloadFormat() {
        check(Vm2Format.FORMAT == 3, "legacy payload format constant stays 3");
        check(Vm2Format.ROLLING_FORMAT == 4, "current payload format is 4");
        check(Vm2Format.SUPER_BASE > 201 && Vm2Format.SUPER_LAST < 256,
                "superinstructions use reserved opcode numbers below 256");

        // static int add(int a, int b) { return a + b; }
        Vm2Format.Program program = addProgram();
        long maskKey = 0x0F1E2D3C4B5A6978L;
        Object[] locals = { Integer.valueOf(31), Integer.valueOf(11) };
        Object expected = Integer.valueOf(42);

        Vm2Format.Encoded rolling = Vm2Format.serialize(program, maskKey);
        Vm2Format.Encoded legacy = Vm2Format.serializeLegacy(program, maskKey);
        check(rolling.payload[1] == 4, "serialize emits payload format 4");
        check(legacy.payload[1] == 3, "serializeLegacy emits payload format 3");
        check(rolling.payload.length == legacy.payload.length,
                "rolling layer does not change the payload size");
        check(!Arrays.equals(codeRegion(rolling.payload, 2), codeRegion(legacy.payload, 2)),
                "rolling layer changes the encoded instruction stream");

        // Reference decoder: unmask + walk the rolling chain exactly like the
        // interpreter and compare with the source instruction stream.
        int[] decoded = decodeReference(rolling.payload, maskKey, null);
        check(Arrays.equals(new int[] { Opcodes.ILOAD, Opcodes.ILOAD, Opcodes.IADD,
                        Opcodes.IRETURN }, decoded),
                "reference decoder recovers the instruction stream from a format-4 payload");

        Wire rollingWire = wire(program, 0x1111222233334444L, 2, false);
        Wire legacyWire = wire(program, 0x1111222233334444L, 2, true);
        check(rollingWire.meta[1] == legacyWire.meta[1]
                        && (rollingWire.payload[1] == 4) && (legacyWire.payload[1] == 3),
                "execution wires carry the expected payload versions");
        check(expected.equals(runWire(rollingWire, 2, locals)),
                "format-4 payload executes (rolling decode)");
        check(expected.equals(runWire(legacyWire, 2, locals)),
                "format-3 payload still executes (old reader path)");

        // Same program/key => identical bytes; different key => different bytes.
        Vm2Format.Encoded again = Vm2Format.serialize(program, maskKey);
        check(Arrays.equals(rolling.payload, again.payload),
                "format-4 serialization is deterministic for a fixed key");
        Vm2Format.Encoded other = Vm2Format.serialize(program, maskKey ^ 0x5A5A5A5A5A5A5A5AL);
        check(!Arrays.equals(codeRegion(rolling.payload, 2), codeRegion(other.payload, 2)),
                "a different key produces a different opcode stream");

        // Tampering with the code region must be rejected by the integrity guard.
        Wire tamperWire = wire(program, 0x7777888899990000L, 2, false);
        tamperWire.payload[tamperWire.payload.length - 1] ^= 0x40000000;
        boolean rejected = false;
        try {
            runPayload(tamperWire, 2, locals);
        } catch (RuntimeException error) {
            rejected = String.valueOf(error).contains("rejected")
                    || String.valueOf(error).contains("Umbra VM2");
        }
        check(rejected, "tampered format-4 payload is rejected");

        // Invalid format version must be refused, not silently decoded.
        Wire badWire = wire(program, 0xABCDEF0123456789L, 2, false);
        badWire.payload[1] = 99;
        boolean versionRejected = false;
        try {
            runPayload(badWire, 2, locals);
        } catch (RuntimeException error) {
            versionRejected = String.valueOf(error).contains("rejected")
                    || String.valueOf(error).contains("format");
        }
        check(versionRejected, "unknown payload version is refused");
    }

    private static Vm2Format.Program addProgram() {
        return new Vm2Format.Program(
                new int[] { Opcodes.ILOAD, 0, Opcodes.ILOAD, 1, Opcodes.IADD, Opcodes.IRETURN },
                new Object[0], new String[0], new int[0], 2, 2,
                new int[] { Vm2Format.KIND_INT, Vm2Format.KIND_INT }, 32, 0,
                new int[] { 0, 2, 4, 5 });
    }

    /** Code ints of a serialized payload for a no-constant/no-ref/no-handler program. */
    private static int[] codeRegion(int[] payload, int argSlots) {
        int start = Vm2Format.HEADER + argSlots;
        int[] code = new int[payload.length - start];
        System.arraycopy(payload, start, code, 0, code.length);
        return code;
    }

    /**
     * Independent reference decoder: unmasks the operand mask, walks the rolling
     * opcode-key chain and the permutation table, and returns the real opcodes in
     * memory order. Used to prove the rolling layer round-trips without going
     * through the interpreter.
     */
    private static int[] decodeReference(int[] payload, long maskKey, int[] map) {
        int codeLen = payload[3];
        int start = payload.length - codeLen;
        int[] code = new int[codeLen];
        System.arraycopy(payload, start, code, 0, codeLen);
        for (int i = 0; i < codeLen; i++) {
            code[i] ^= Vm2Format.mask(maskKey, i);
        }
        boolean rolling = payload[1] >= Vm2Format.ROLLING_FORMAT;
        long roll = rolling ? Vm2Format.rollSeed(maskKey) : 0L;
        List<Integer> opcodes = new ArrayList<Integer>();
        int scan = 0;
        while (scan < codeLen) {
            int encoded = rolling ? (code[scan] ^ Vm2Format.rollMask(roll)) : code[scan];
            int op = map == null ? encoded : map[encoded];
            opcodes.add(Integer.valueOf(op));
            if (rolling) {
                roll = Vm2Format.rollStep(roll, encoded);
            }
            scan += 1 + Vm2Format.operandSlots(op, code, scan);
        }
        int[] result = new int[opcodes.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = opcodes.get(i).intValue();
        }
        return result;
    }

    /**
     * Builds the full wire representation (holder meta, payload and split blocks)
     * for a program: the mask/rolling key is derived from the meta, exactly like
     * {@code VirtualizationPass} does it.
     */
    private static Wire wire(Vm2Format.Program program, long marker, int blockCount,
                             boolean legacy) {
        int[] meta = new int[8];
        meta[0] = Vm2Format.MAGIC;
        meta[1] = (int) marker;
        meta[2] = (int) (marker >>> 32);
        meta[4] = blockCount;
        meta[6] = program.flags | (1 << 16);
        meta[7] = (int) (marker >>> 17);
        long stage = Vm2Format.metaKey(meta);
        Vm2Format.Encoded encoded = legacy
                ? Vm2Format.serializeLegacy(program, stage)
                : Vm2Format.serialize(program, stage);
        meta[3] = encoded.payload.length;
        meta[5] = encoded.integrity;
        return new Wire(meta, encoded.payload, blockCount);
    }

    private static Object runWire(Wire wire, int blockCount, Object[] locals) {
        return runPayload(wire, blockCount, locals);
    }

    private static Object runPayload(Wire wire, int blockCount, Object[] locals) {
        java.util.List<int[]> blocks = Vm2Format.split(wire.payload,
                Math.min(Math.max(1, blockCount), wire.payload.length));
        return UmbraVM2.run(wire.meta, null, blocks.toArray(new int[0][]), locals);
    }

    /** One hand-built payload plus the holder meta that decodes it. */
    private static final class Wire {
        final int[] meta;
        final int[] payload;
        final int blockCount;

        Wire(int[] meta, int[] payload, int blockCount) {
            this.meta = meta;
            this.payload = payload.clone();
            this.blockCount = blockCount;
        }
    }

    // ------------------------------------------------------------------
    // Superinstruction semantics
    // ------------------------------------------------------------------

    private static void testSuperInstructions() {
        // ILOAD a; ILOAD b; IADD -> SUPER_IADD_LL
        int[] fusedCode = { Vm2Format.SUPER_IADD_LL, 0, 1, Opcodes.IRETURN };
        int[] plainCode = { Opcodes.ILOAD, 0, Opcodes.ILOAD, 1, Opcodes.IADD, Opcodes.IRETURN };
        Vm2Format.Program fused = program(fusedCode, new int[] { 0, 3 }, 2,
                new int[] { Vm2Format.KIND_INT, Vm2Format.KIND_INT });
        Vm2Format.Program plain = program(plainCode, new int[] { 0, 2, 4, 5 }, 2,
                new int[] { Vm2Format.KIND_INT, Vm2Format.KIND_INT });
        Random random = new Random(7L);
        for (int i = 0; i < 8; i++) {
            int a = random.nextInt();
            int b = random.nextInt();
            Object[] locals = { Integer.valueOf(a), Integer.valueOf(b) };
            compare("fused IADD", Integer.valueOf(a + b),
                    runWire(wire(fused, 0x1000L + i, 2, false), 2, locals));
            compare("plain IADD", Integer.valueOf(a + b),
                    runWire(wire(plain, 0x1000L + i, 2, false), 2, locals));
        }
        check(Arrays.equals(new int[] { Vm2Format.SUPER_IADD_LL, Opcodes.IRETURN },
                        referenceOps(fused)),
                "fused IADD stream is exactly one superinstruction");

        // ILOAD a; const; IMUL -> SUPER_ILOAD_CONST_MUL
        Vm2Format.Program constMul = program(
                new int[] { Vm2Format.SUPER_ILOAD_CONST_MUL, 0, 7, Opcodes.IRETURN },
                new int[] { 0, 3 }, 1, new int[] { Vm2Format.KIND_INT });
        for (int i = 0; i < 4; i++) {
            int a = random.nextInt(1000) - 500;
            compare("fused ILOAD_CONST_MUL", Integer.valueOf(a * 7),
                    runWire(wire(constMul, 0x2000L + i, 2, false), 2,
                            new Object[] { Integer.valueOf(a) }));
        }

        // ILOAD a; ILOAD b; IF_ICMPEQ -> SUPER_IF_ICMPEQ_LL
        int[] branchCode = {
                Vm2Format.SUPER_IF_ICMPEQ_LL, 0, 1, 6,
                Opcodes.ICONST_0, Opcodes.IRETURN,
                Opcodes.ICONST_1, Opcodes.IRETURN
        };
        Vm2Format.Program branch = program(branchCode, new int[] { 0, 4, 5, 6, 7 }, 2,
                new int[] { Vm2Format.KIND_INT, Vm2Format.KIND_INT });
        for (int[] pair : new int[][] { { 5, 5 }, { 5, 6 }, { -3, -3 }, { -3, 3 } }) {
            compare("fused IF_ICMPEQ", Integer.valueOf(pair[0] == pair[1] ? 1 : 0),
                    runWire(wire(branch, 0x3000L + pair[0], 2, false), 2,
                            new Object[] { Integer.valueOf(pair[0]), Integer.valueOf(pair[1]) }));
        }

        // LLOAD a; LLOAD b; LADD -> SUPER_LADD_LL
        Vm2Format.Program longAdd = program(
                new int[] { Vm2Format.SUPER_LADD_LL, 0, 2, Opcodes.LRETURN },
                new int[] { 0, 3 }, 4,
                new int[] { Vm2Format.KIND_LONG, Vm2Format.KIND_UNUSED,
                        Vm2Format.KIND_LONG, Vm2Format.KIND_UNUSED });
        long left = 0x0123456789ABCDEFL;
        long right = 0x1111111111111111L;
        compare("fused LADD", Long.valueOf(left + right),
                runWire(wire(longAdd, 0x4000L, 2, false), 2,
                        new Object[] { Long.valueOf(left), null, Long.valueOf(right) }));

        // ICONST 5; ISTORE 1 -> SUPER_CONST_ISTORE
        Vm2Format.Program constStore = program(
                new int[] { Vm2Format.SUPER_CONST_ISTORE, 5, 1, Opcodes.ILOAD, 1,
                        Opcodes.IRETURN },
                new int[] { 0, 3, 5 }, 2, new int[] { Vm2Format.KIND_INT });
        compare("fused CONST_ISTORE", Integer.valueOf(5),
                runWire(wire(constStore, 0x5000L, 2, false), 2,
                        new Object[] { Integer.valueOf(-1) }));
    }

    private static Vm2Format.Program program(int[] code, int[] opcodePositions, int maxLocals,
                                             int[] argKinds) {
        int argSlots = argKinds.length;
        return new Vm2Format.Program(code, new Object[0], new String[0], new int[0], maxLocals,
                argSlots, argKinds, 32, 0, opcodePositions);
    }

    private static int[] referenceOps(Vm2Format.Program program) {
        long maskKey = 0x6000L;
        Vm2Format.Encoded encoded = Vm2Format.serialize(program, maskKey);
        return decodeReference(encoded.payload, maskKey, null);
    }

    // ------------------------------------------------------------------
    // Pass-level: fusion statistics + execution equivalence
    // ------------------------------------------------------------------

    private static void testFusion(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        Transform on = transform(compiled, 20240601L, options);
        check(stat(on.stats, "virtualization.vm2.fusion") == 1, "fusion is on by default");
        check(stat(on.stats, "virtualization.vm2.format") == 4,
                "VM2 emits payload format 4 (rolling opcode key)");
        check(stat(on.stats, "virtualization.vm2.fused") > 0,
                "fusion replaced instruction runs with superinstructions");
        check(stat(on.stats, "virtualization.methods") >= 10,
                "fixture methods are virtualized with fusion on");

        Map<String, String> off = new LinkedHashMap<String, String>(options);
        off.put("vm2.fusion", "false");
        Transform without = transform(compiled, 20240601L, off);
        check(stat(without.stats, "virtualization.vm2.fused") == 0,
                "vm2.fusion=false disables superinstructions");
        check(stat(without.stats, "virtualization.instructions")
                        > stat(on.stats, "virtualization.instructions"),
                "fusion reduces the translated instruction count");

        ClassLoader originalLoader = new ByteLoader(Vm3Test.class.getClassLoader(), compiled);
        ClassLoader fusedLoader = new ByteLoader(Vm3Test.class.getClassLoader(), on.output);
        ClassLoader plainLoader = new ByteLoader(Vm3Test.class.getClassLoader(), without.output);
        Class<?> original = Class.forName("fixture3.Vm3Fixture", true, originalLoader);
        Class<?> fused = Class.forName("fixture3.Vm3Fixture", true, fusedLoader);
        Class<?> plain = Class.forName("fixture3.Vm3Fixture", true, plainLoader);
        compare("fusion", invoke(original, null, "arithmetic", 17, 5),
                invoke(fused, null, "arithmetic", 17, 5));
        compare("fusion", invoke(original, null, "arithmetic", 17, 5),
                invoke(plain, null, "arithmetic", 17, 5));
        compare("no-fusion", invoke(original, null, "constArith", 12),
                invoke(plain, null, "constArith", 12));
        compare("fusion", invoke(original, null, "constArith", 12),
                invoke(fused, null, "constArith", 12));
        compare("fusion", invoke(original, null, "branchy", 3, 4),
                invoke(fused, null, "branchy", 3, 4));
        compare("fusion", invoke(original, null, "branchy", 4, 4),
                invoke(fused, null, "branchy", 4, 4));
        compare("fusion", invoke(original, null, "longArith", 123456789L, 98765L),
                invoke(fused, null, "longArith", 123456789L, 98765L));
        compare("fusion", invoke(original, null, "sumLoop", 40),
                invoke(fused, null, "sumLoop", 40));
        Object originalInstance = original.getDeclaredConstructor(int.class).newInstance(9);
        Object fusedInstance = fused.getDeclaredConstructor(int.class).newInstance(9);
        compare("fusion-instance", invoke(original, originalInstance, "instanceOps", 4),
                invoke(fused, fusedInstance, "instanceOps", 4));
    }

    private static void testDeterminism(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        Transform first = transform(compiled, 4242L, options);
        Transform second = transform(compiled, 4242L, options);
        check(first.fingerprint.equals(second.fingerprint),
                "VM2 v3 output is deterministic per seed");
        Transform other = transform(compiled, 777L, options);
        check(!first.fingerprint.equals(other.fingerprint),
                "different seeds produce different VM2 v3 payloads");
    }

    private static void testCantripAndNested(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        options.put("cantrip.enabled", "true");
        options.put("cantrip.level", "2");
        Transform transform = transform(compiled, 9001L, options);
        check(stat(transform.stats, "cantrip.programs") > 0,
                "Cantrip reconstructs v3 payload chunks (including the opcode map)");
        check(stat(transform.stats, "virtualization.vm2.nestedPayloads") > 0,
                "nested payload layer stays enabled with fusion");
        check(stat(transform.stats, "virtualization.vm2.fused") > 0,
                "fusion works together with Cantrip/nested payloads");
        ClassLoader originalLoader = new ByteLoader(Vm3Test.class.getClassLoader(), compiled);
        ClassLoader cantripLoader = new ByteLoader(Vm3Test.class.getClassLoader(),
                transform.output);
        Class<?> original = Class.forName("fixture3.Vm3Fixture", true, originalLoader);
        Class<?> cantrip = Class.forName("fixture3.Vm3Fixture", true, cantripLoader);
        compare("cantrip", invoke(original, null, "arithmetic", -9, 4),
                invoke(cantrip, null, "arithmetic", -9, 4));
        compare("cantrip", invoke(original, null, "sumLoop", 25),
                invoke(cantrip, null, "sumLoop", 25));
        compare("cantrip", invoke(original, null, "lambdaCall", 6),
                invoke(cantrip, null, "lambdaCall", 6));
    }

    private static void testOpcodeCoverage(Map<String, byte[]> compiled) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("vm2.enabled", "true");
        Transform transform = transform(compiled, 5150L, options);
        check(callsInterpreter(transform, "fixture3/Vm3Fixture", "switchSparse"),
                "lookupswitch method is virtualized");
        check(callsInterpreter(transform, "fixture3/Vm3Fixture", "multiArraySum"),
                "multi-dimensional array method is virtualized");
        check(callsInterpreter(transform, "fixture3/Vm3Fixture", "longArith"),
                "long arithmetic method is virtualized");
        check(callsInterpreter(transform, "fixture3/Vm3Fixture", "lambdaCall"),
                "invokedynamic method is virtualized through a bridge");
        ClassLoader originalLoader = new ByteLoader(Vm3Test.class.getClassLoader(), compiled);
        ClassLoader transformedLoader = new ByteLoader(Vm3Test.class.getClassLoader(),
                transform.output);
        Class<?> original = Class.forName("fixture3.Vm3Fixture", true, originalLoader);
        Class<?> changed = Class.forName("fixture3.Vm3Fixture", true, transformedLoader);
        for (int value : new int[] { -100, 0, 777, 5, 100000 }) {
            compare("switch", invoke(original, null, "switchSparse", value),
                    invoke(changed, null, "switchSparse", value));
        }
        compare("multiArray", invoke(original, null, "multiArraySum", 4, 5),
                invoke(changed, null, "multiArraySum", 4, 5));
        compare("lambda", invoke(original, null, "lambdaCall", 11),
                invoke(changed, null, "lambdaCall", 11));
        compare("tableswitch", invoke(original, null, "switchDense", -2),
                invoke(changed, null, "switchDense", -2));
    }

    // ------------------------------------------------------------------
    // Lazy program-class constants (nested archive layouts)
    // ------------------------------------------------------------------

    /**
     * Generated holder classes live at the archive root while program classes may
     * live in BOOT-INF/classes or WEB-INF/classes and be loaded by a child
     * container loader. Eager {@code ldc class <programClass>} in a holder
     * {@code <clinit>} therefore fails on such layouts; constants must be stored
     * as descriptors and resolved on first execution through the context class
     * loader chain. Reproduced with a split root/child class loader pair.
     */
    private static void testLazyClassConstants(Map<String, byte[]> compiled) throws Exception {
        Transform classic = transform(compiled, 31337L, new LinkedHashMap<String, String>());
        check(stat(classic.stats, "virtualization.methods") > 0,
                "classic engine virtualized fixture methods for the lazy-constant test");
        check(countEagerProgramClassLiterals(classic) == 0,
                "classic engine holder <clinit> has no eager program class literal");
        Object[] none = new Object[0];
        Class<?> originalClass = Class.forName("fixture3.Vm3Fixture", true,
                new ByteLoader(Vm3Test.class.getClassLoader(), compiled));
        compare("nested-layout classic class literal",
                invoke(originalClass, null, "classLiteralNameLength", none),
                runNestedLayoutScenario(compiled, classic, "classLiteralNameLength", none));

        Map<String, String> vm2Options = new LinkedHashMap<String, String>();
        vm2Options.put("vm2.enabled", "true");
        Transform vm2 = transform(compiled, 31338L, vm2Options);
        check(stat(vm2.stats, "virtualization.methods") > 0,
                "VM2 virtualized fixture methods for the lazy-constant test");
        check(countEagerProgramClassLiterals(vm2) == 0,
                "VM2 holder <clinit> has no eager program class literal");
        compare("nested-layout VM2 class literal",
                invoke(originalClass, null, "classLiteralNameLength", none),
                runNestedLayoutScenario(compiled, vm2, "classLiteralNameLength", none));
        compare("nested-layout VM2 arithmetic",
                invoke(originalClass, null, "arithmetic", new Object[] { 9, 4 }),
                runNestedLayoutScenario(compiled, vm2, "arithmetic", new Object[] { 9, 4 }));
    }

    /** Counts {@code ldc class <fixture3 class>} instructions in generated <clinit>s. */
    private static int countEagerProgramClassLiterals(Transform transform) {
        int literals = 0;
        for (ClassNode node : transform.pool.classes().values()) {
            if (!transform.pool.isGenerated(node.name)) {
                continue;
            }
            for (MethodNode method : node.methods) {
                if (!"<clinit>".equals(method.name) || method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                     insn = insn.getNext()) {
                    if (!(insn instanceof LdcInsnNode)) {
                        continue;
                    }
                    Object constant = ((LdcInsnNode) insn).cst;
                    if (constant instanceof org.objectweb.asm.Type) {
                        String descriptor = ((org.objectweb.asm.Type) constant).getDescriptor();
                        if (descriptor.contains("fixture3/")) {
                            literals++;
                        }
                    }
                }
            }
        }
        return literals;
    }

    /**
     * Loads generated helper classes with a root loader and program classes with
     * a child loader (the Spring Boot/WAR shape), then invokes a program method
     * that needs a lazily resolved class constant.
     */
    private static Object runNestedLayoutScenario(Map<String, byte[]> compiled, Transform transform,
                                                  String methodName, Object[] args)
            throws Exception {
        Map<String, byte[]> generated = new LinkedHashMap<String, byte[]>();
        Map<String, byte[]> program = new LinkedHashMap<String, byte[]>();
        for (Map.Entry<String, byte[]> entry : transform.output.entrySet()) {
            if (transform.pool.isGenerated(entry.getKey())) {
                generated.put(entry.getKey(), entry.getValue());
            } else {
                program.put(entry.getKey(), entry.getValue());
            }
        }
        check(!generated.isEmpty() && !program.isEmpty(),
                "split loader scenario has root helpers and child program classes");
        ClassLoader root = new ByteLoader(Vm3Test.class.getClassLoader(), generated);
        ClassLoader child = new ByteLoader(root, program);
        ClassLoader previous = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(child);
            Class<?> changed = Class.forName("fixture3.Vm3Fixture", true, child);
            return invoke(changed, null, methodName, args);
        } finally {
            Thread.currentThread().setContextClassLoader(previous);
        }
    }
    // ------------------------------------------------------------------
    // Native end-to-end: coverage gains, anti-dump positive/negative
    // ------------------------------------------------------------------

    private static void testNativeEndToEnd() throws Exception {
        String compiler = NativeCompiler.resolve(GCC, new Log(null, false));
        if (compiler == null || !NativeCompiler.hasJniHeaders() || !isWindows()) {
            System.out.println("Vm3Test: native end-to-end skipped (no C toolchain/JNI headers "
                    + "or non-Windows host)");
            return;
        }
        Path directory = Files.createTempDirectory("umbra-vm3-native-");
        try {
            Path input = buildAppJar(directory);
            Path output = directory.resolve("protected.jar");
            EngineResult result = protect(input, output, 20240602L, compiler, true);
            Map<String, Long> stats = result.stats().snapshot();
            check(stat(stats, "virtualization.methods") > 0,
                    "e2e: VM2 virtualized application methods");
            check(stat(stats, "virtualization.vm2.fused") > 0,
                    "e2e: fusion superinstructions emitted");
            check(stat(stats, "native.methods") > 0, "e2e: methods transpiled to native code");
            check(stat(stats, "native.constructors") > 0,
                    "e2e: constructor bodies extracted for native translation");
            check(stat(stats, "native.constructorBodies") > 0,
                    "e2e: constructor bodies translated to native code");
            check(stat(stats, "native.antiDump") == 1, "e2e: anti-dump enabled by default");
            check(stat(stats, "native.antiDump.fingerprint") == 1,
                    "e2e: library fingerprint embedded");
            check(stat(stats, "native.antiBackfill") == 1,
                    "e2e: backfill table/challenge enabled by default");
            check(stat(stats, "native.antiBackfill.entries") > 0,
                    "e2e: native method backfill table has entries");
            check(UmbraVerifier.verify(output).isEmpty(), "e2e: protected jar verifies");

            String control = runJar(input);
            String protectedOutput = runJar(output);
            check(control.contains("VM3-OK"), "e2e: control application prints its marker");
            check(protectedOutput.contains("VM3-OK"),
                    "e2e: protected application runs and prints the same marker");
            check(control.trim().equals(protectedOutput.trim()),
                    "e2e: protected application output equals the control output");

            // Native-only run: with VM2 disabled every remaining Java method is
            // eligible for the native transpiler, which exercises the
            // invokedynamic bridge path end to end.
            Path nativeOnly = directory.resolve("native-only.jar");
            EngineResult nativeResult = protect(input, nativeOnly, 20240604L, compiler, false);
            Map<String, Long> nativeStats = nativeResult.stats().snapshot();
            check(stat(nativeStats, "native.methods") > 0,
                    "e2e: native-only build translates methods");
            check(stat(nativeStats, "native.indyBridges") > 0,
                    "e2e: invokedynamic (lambda) bridged for native translation");
            check(stat(nativeStats, "native.constructorBodies") > 0,
                    "e2e: native-only build translates constructor bodies");
            String nativeOutput = runJar(nativeOnly);
            check(control.trim().equals(nativeOutput.trim()),
                    "e2e: native-only protected application output equals the control output");

            // Cross-JDK: protected output must run on the installed JDK 8/21/26.
            for (String home : new String[] {
                    "C:\\Program Files\\Zulu\\zulu-8",
                    "C:\\Program Files\\Zulu\\zulu-21",
                    "C:\\Program Files\\Java\\jdk-26.0.1" }) {
                Path java = Paths.get(home, "bin", "java.exe");
                if (!Files.isRegularFile(java)) {
                    continue;
                }
                String outputText = runJarWith(java, output);
                check(outputText.contains("VM3-OK"),
                        "e2e: protected output runs on " + home);
            }
            testAntiDumpFingerprintRefusal(directory, input, output, compiler);
            testAntiBackfillRefusal(directory, nativeOnly, input, compiler);
        } finally {
            delete(directory);
        }
    }

    /** Rebuilds the embedded DLL and expects the loader to refuse it. */
    private static void testAntiDumpFingerprintRefusal(Path directory, Path input, Path output,
                                                       String compiler) throws Exception {
        Path keptSource = Paths.get(output.toAbsolutePath() + ".native.c");
        check(Files.isRegularFile(keptSource), "e2e: kept C source available for the dump test");
        String source = new String(Files.readAllBytes(keptSource), StandardCharsets.UTF_8);
        source += "\n/* tamper marker: a rebuilt library must be refused */\n"
                + "void umbra_tamper_marker(void) { }\n";
        Path tamperedSource = directory.resolve("tampered.c");
        Files.write(tamperedSource, source.getBytes(StandardCharsets.UTF_8));
        Path tamperedDll = directory.resolve("tampered.dll");
        Process process = new ProcessBuilder(compiler, "-shared", "-static-libgcc",
                "-Wl,--image-base,0x10000000", "-Wl,--no-insert-timestamp", "-O2", "-fwrapv",
                "-fno-strict-aliasing", "-o", tamperedDll.toString(), tamperedSource.toString(),
                "-I" + jdkHome() + "\\include", "-I" + jdkHome() + "\\include\\win32")
                .redirectErrorStream(true).start();
        String rebuildLog = readAll(process.getInputStream());
        int exit = process.waitFor();
        check(exit == 0, "e2e: rebuilt (dumped) library compiles: " + rebuildLog);
        byte[] tamperedBytes = Files.readAllBytes(tamperedDll);
        Path repacked = directory.resolve("repacked.jar");
        replaceNativeResource(output, repacked, tamperedBytes);
        check(Files.size(repacked) != Files.size(output) || !Arrays.equals(
                        Files.readAllBytes(output), Files.readAllBytes(repacked)),
                "e2e: repacked jar differs from the original");
        String refused = runJar(repacked, false);
        check(refused.contains("refused"),
                "e2e: dumped/rebuilt native library is refused: " + firstLines(refused, 4));
        check(refused.contains("fingerprint mismatch") || refused.contains("rejected"),
                "e2e: refusal names the fingerprint mismatch");
        check(!refused.contains("VM3-OK"),
                "e2e: refused library does not let the protected program run");
    }

    /**
     * Replaces the embedded DLL with the DLL of a *different* protected build and
     * rewrites the loader's fingerprint constants so the file-level check passes;
     * the keyed backfill challenge must still refuse the foreign library.
     */
    private static void testAntiBackfillRefusal(Path directory, Path nativeOnly, Path input,
                                                String compiler) throws Exception {
        Path second = directory.resolve("second.jar");
        protect(input, second, 20240603L, compiler, false);
        byte[] firstDll = readNativeResource(nativeOnly);
        byte[] secondDll = readNativeResource(second);
        check(firstDll.length > 0 && secondDll.length > 0, "e2e: both builds embed a library");
        check(!Arrays.equals(firstDll, secondDll),
                "e2e: different seeds produce different native libraries");

        Path repacked = directory.resolve("foreign.jar");
        replaceNativeResourceAndPatchFingerprint(nativeOnly, repacked, secondDll,
                sha256(firstDll));
        String refused = runJar(repacked, false);
        check(refused.contains("refused"),
                "e2e: foreign library with patched fingerprint is refused: "
                        + firstLines(refused, 4));
        check(refused.contains("backfill") || refused.contains("challenge")
                        || refused.contains("UnsatisfiedLinkError")
                        || refused.contains("rejected"),
                "e2e: refusal comes from the keyed backfill challenge");
        check(!refused.contains("VM3-OK"),
                "e2e: foreign library does not let the protected program run");
    }

    private static EngineResult protect(Path input, Path output, long seed, String compiler,
                                        boolean virtualize) throws Exception {
        Map<String, String> options = new LinkedHashMap<String, String>();
        if (virtualize) {
            options.put("methodVirtualization.enabled", "true");
            options.put("vm2.enabled", "true");
        }
        options.put("native.enabled", "true");
        options.put("native.compiler", compiler);
        options.put("native.keepDll", "true");
        options.put("flowObfuscation.enabled", "false");
        options.put("exceptionObfuscation.enabled", "false");
        options.put("antiLlm.enabled", "false");
        options.put("noise.enabled", "false");
        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(input)
                .output(output)
                .seed(seed)
                .methodVirtualization(new UmbraConfig.VirtualizationOptions(virtualize, 4000, 0));
        for (Map.Entry<String, String> entry : options.entrySet()) {
            builder.option(entry.getKey(), entry.getValue());
        }
        UmbraConfig config = builder.build();
        return new UmbraEngine(new Log(null, false)).run(config, ProgressListener.NONE);
    }

    private static Path buildAppJar(Path directory) throws Exception {
        String source = "public final class Vm3App {\n"
                + "    private int base;\n"
                + "    public Vm3App(int base) { this.base = base * 2 + 1; }\n"
                + "    static int sum(int n) {\n"
                + "        int total = 0;\n"
                + "        for (int i = 1; i <= n; i++) { total += i * 3 + (i & 7); }\n"
                + "        return total;\n"
                + "    }\n"
                + "    static long mix(long a, long b) {\n"
                + "        long value = (a * b) ^ (a << 3) ^ (b >>> 2);\n"
                + "        return value + (a - b) / 3L - (a % 7L);\n"
                + "    }\n"
                + "    static int sw(int v) {\n"
                + "        switch (v) { case -5: return 10; case 0: return 20;\n"
                + "            case 77: return 30; default: return 40; }\n"
                + "    }\n"
                + "    int lambda(int v) {\n"
                + "        java.util.function.IntUnaryOperator op = x -> x * 2 + base;\n"
                + "        return op.applyAsInt(v);\n"
                + "    }\n"
                + "    int lambdaWithNew(int v) {\n"
                + "        java.util.concurrent.atomic.AtomicInteger box = new java.util.concurrent.atomic.AtomicInteger(v);\n"
                + "        java.util.function.IntUnaryOperator op = x -> x * 2 + base;\n"
                + "        return op.applyAsInt(box.get()) + helper(box.get());\n"
                + "    }\n"
                + "    static int helper(int value) { return value * 3 - 2; }\n"
                + "    public static void main(String[] args) {\n"
                + "        Vm3App app = new Vm3App(3);\n"
                + "        System.out.println(\"VM3-OK \" + sum(10) + \" \" + mix(7L, 5L)\n"
                + "                + \" \" + sw(77) + \" \" + app.lambda(4) + \" \" + app.base\n"
                + "                + \" \" + app.lambdaWithNew(5));\n"
                + "    }\n"
                + "}\n";
        Path sourceFile = directory.resolve("Vm3App.java");
        Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));
        Path classes = directory.resolve("classes");
        Files.createDirectories(classes);
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        if (javac == null) {
            throw new IllegalStateException("Vm3Test native e2e requires a JDK compiler");
        }
        int exit = javac.run(null, null, null, "-proc:none", "-d", classes.toString(),
                sourceFile.toString());
        check(exit == 0, "e2e: test application compiles");
        Path jar = directory.resolve("app.jar");
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, "Vm3App");
        JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar), manifest);
        try {
            Files.walk(classes).filter(Files::isRegularFile).sorted().forEach(path -> {
                try {
                    String name = classes.relativize(path).toString().replace('\\', '/');
                    out.putNextEntry(new JarEntry(name));
                    out.write(Files.readAllBytes(path));
                    out.closeEntry();
                } catch (Exception error) {
                    throw new IllegalStateException(error);
                }
            });
        } finally {
            out.close();
        }
        return jar;
    }

    private static byte[] readNativeResource(Path jar) throws Exception {
        JarInputStream in = new JarInputStream(Files.newInputStream(jar));
        try {
            JarEntry entry;
            while ((entry = in.getNextJarEntry()) != null) {
                if (entry.getName().startsWith("umbra/native/") && entry.getName().endsWith(".dat")) {
                    return readAllBytes(in);
                }
            }
        } finally {
            in.close();
        }
        return new byte[0];
    }

    private static void replaceNativeResource(Path jar, Path repacked, byte[] dll) throws Exception {
        ZipInputStream in = new ZipInputStream(Files.newInputStream(jar));
        ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(repacked));
        try {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                String name = entry.getName();
                byte[] data = name.startsWith("umbra/native/") && name.endsWith(".dat")
                        ? dll : readAllBytes(in);
                out.putNextEntry(new ZipEntry(name));
                out.write(data);
                out.closeEntry();
            }
        } finally {
            in.close();
            out.close();
        }
    }

    private static void replaceNativeResourceAndPatchFingerprint(Path jar, Path repacked,
                                                                 byte[] dll, String oldSha)
            throws Exception {
        String newSha = sha256(dll);
        ZipInputStream in = new ZipInputStream(Files.newInputStream(jar));
        ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(repacked));
        try {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                String name = entry.getName();
                byte[] data = readAllBytes(in);
                if (name.startsWith("umbra/native/") && name.endsWith(".dat")) {
                    data = dll;
                } else if (name.startsWith("umbra/runtime/N") && name.endsWith(".class")) {
                    data = patchLoaderFingerprint(data, oldSha, newSha);
                }
                out.putNextEntry(new ZipEntry(name));
                out.write(data);
                out.closeEntry();
            }
        } finally {
            in.close();
            out.close();
        }
    }

    /** Rewrites the loader's fingerprint constants from one SHA-256 to another. */
    private static byte[] patchLoaderFingerprint(byte[] classBytes, String oldSha,
                                                 String newSha) {
        ClassNode node = new ClassNode();
        new ClassReader(classBytes).accept(node, 0);
        boolean patched = false;
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof LdcInsnNode)) {
                    continue;
                }
                LdcInsnNode ldc = (LdcInsnNode) insn;
                if (!(ldc.cst instanceof String)) {
                    continue;
                }
                String value = (String) ldc.cst;
                if (value.equals(oldSha)) {
                    ldc.cst = newSha;
                    patched = true;
                } else if (value.length() == 24 && oldSha.startsWith(value)) {
                    ldc.cst = newSha.substring(0, 24);
                    patched = true;
                } else if (value.length() == 20 && oldSha.endsWith(value)) {
                    ldc.cst = newSha.substring(44);
                    patched = true;
                }
            }
        }
        for (FieldNode field : node.fields) {
            if (!(field.value instanceof String)) {
                continue;
            }
            String value = (String) field.value;
            if (value.equals(oldSha.substring(0, 24))) {
                field.value = newSha.substring(0, 24);
                patched = true;
            } else if (value.equals(oldSha.substring(24, 44))) {
                field.value = newSha.substring(24, 44);
                patched = true;
            } else if (value.equals(oldSha.substring(44))) {
                field.value = newSha.substring(44);
                patched = true;
            } else if (value.equals(oldSha)) {
                field.value = newSha;
                patched = true;
            }
        }
        if (!patched) {
            return classBytes;
        }
        ClassWriter writer = new ClassWriter(0);
        node.accept(writer);
        return writer.toByteArray();
    }

    private static String sha256(byte[] data) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder out = new StringBuilder(64);
        for (byte value : hash) {
            out.append(Character.forDigit((value >>> 4) & 0x0F, 16));
            out.append(Character.forDigit(value & 0x0F, 16));
        }
        return out.toString();
    }

    private static String jdkHome() {
        String home = System.getProperty("java.home");
        if (home != null && home.endsWith("jre")) {
            home = home.substring(0, home.length() - 4);
        }
        return home;
    }

    private static String runJar(Path jar) throws Exception {
        return runJar(jar, true);
    }

    private static String runJar(Path jar, boolean expectSuccess) throws Exception {
        Process process = new ProcessBuilder("java", "-jar", jar.toString())
                .redirectErrorStream(true).start();
        String output = readAll(process.getInputStream());
        int exit = process.waitFor();
        if (expectSuccess) {
            check(exit == 0, "protected jar exits 0 (exit was " + exit + ", output: "
                    + firstLines(output, 6) + ")");
        }
        return output;
    }

    private static String runJarWith(Path java, Path jar) throws Exception {
        Process process = new ProcessBuilder(java.toString(), "-jar", jar.toString())
                .redirectErrorStream(true).start();
        String output = readAll(process.getInputStream());
        int exit = process.waitFor();
        check(exit == 0, jar.getFileName() + " exits 0 on " + java + " (output: "
                + firstLines(output, 6) + ")");
        return output;
    }

    private static byte[] readAllBytes(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static String readAll(InputStream in) throws Exception {
        return new String(readAllBytes(in), StandardCharsets.UTF_8);
    }

    private static String firstLines(String text, int count) {
        String[] lines = text.split("\n");
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < Math.min(count, lines.length); i++) {
            if (i > 0) {
                out.append(" | ");
            }
            out.append(lines[i].trim());
        }
        return out.toString();
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT)
                .contains("win");
    }

    // ------------------------------------------------------------------
    // Fixture compilation / pass invocation
    // ------------------------------------------------------------------

    private static final String FIXTURE_SOURCE =
            "package fixture3;\n"
            + "import java.util.function.IntUnaryOperator;\n"
            + "public final class Vm3Fixture {\n"
            + "  static int state;\n"
            + "  int instance;\n"
            + "  public Vm3Fixture() { this(1); }\n"
            + "  public Vm3Fixture(int seed) { this.instance = seed * 3; state += seed; }\n"
            + "  public static int arithmetic(int a, int b) {\n"
            + "    return (a + b) * (a - b) + 7;\n"
            + "  }\n"
            + "  public static int constArith(int a) {\n"
            + "    return (a + 7) * 3 - (a ^ 5) + (a & 12);\n"
            + "  }\n"
            + "  public static int branchy(int a, int b) {\n"
            + "    if (a < b) { return 1; } else if (a == b) { return 2; } else { return 3; }\n"
            + "  }\n"
            + "  public static long longArith(long a, long b) {\n"
            + "    return a * b + (a << 2) - (b >>> 1);\n"
            + "  }\n"
            + "  public static int switchSparse(int v) {\n"
            + "    switch (v) { case -100: return 1; case 0: return 2; case 777: return 3;\n"
            + "      default: return 4; }\n"
            + "  }\n"
            + "  public static int switchDense(int v) {\n"
            + "    switch (v) { case -1: return 5; case 0: return 6; case 1: return 7;\n"
            + "      default: return 8; }\n"
            + "  }\n"
            + "  public static int multiArraySum(int rows, int cols) {\n"
            + "    int[][] grid = new int[rows][cols];\n"
            + "    for (int r = 0; r < rows; r++) {\n"
            + "      for (int c = 0; c < cols; c++) { grid[r][c] = r * cols + c; }\n"
            + "    }\n"
            + "    int total = 0;\n"
            + "    for (int r = 0; r < rows; r++) {\n"
            + "      for (int c = 0; c < cols; c++) { total += grid[r][c]; }\n"
            + "    }\n"
            + "    return total;\n"
            + "  }\n"
            + "  public static int sumLoop(int n) {\n"
            + "    int total = 0;\n"
            + "    for (int i = 1; i <= n; i++) { total += i * 3 + (i & 7); }\n"
            + "    return total;\n"
            + "  }\n"
            + "  static int helper(int value) { return value * 3 - 2; }\n"
            + "  public static int callStatic(int value) { return helper(value) + 1; }\n"
            + "  public static int lambdaCall(int value) {\n"
            + "    IntUnaryOperator op = x -> x * 2 + 3;\n"
            + "    return op.applyAsInt(value) + helper(value);\n"
            + "  }\n"
            + "  public int instanceOps(int delta) { instance += delta; return instance; }\n"
            + "  public static int classLiteralNameLength() {\n"
            + "    return Vm3Fixture.class.getName().length();\n"
            + "  }\n"
            + "}\n";

    private static Map<String, byte[]> compileFixture() throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("Vm3Test requires a JDK (javax.tools compiler)");
        }
        final Map<String, ByteArrayOutputStream> outputs =
                new LinkedHashMap<String, ByteArrayOutputStream>();
        StandardJavaFileManager standard = compiler.getStandardFileManager(null, null, null);
        JavaFileManager manager = new ForwardingJavaFileManager<JavaFileManager>(standard) {
            @Override
            public JavaFileObject getJavaFileForOutput(Location location, String className,
                                                       JavaFileObject.Kind kind,
                                                       FileObject sibling) {
                final ByteArrayOutputStream sink = new ByteArrayOutputStream();
                outputs.put(className, sink);
                return new SimpleJavaFileObject(URI.create("mem:///"
                        + className.replace('.', '/') + kind.extension), kind) {
                    @Override
                    public OutputStream openOutputStream() {
                        return sink;
                    }
                };
            }
        };
        List<JavaFileObject> sources = new ArrayList<JavaFileObject>();
        sources.add(new SimpleJavaFileObject(URI.create("mem:///fixture3/Vm3Fixture.java"),
                JavaFileObject.Kind.SOURCE) {
            @Override
            public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                return FIXTURE_SOURCE;
            }
        });
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<JavaFileObject>();
        boolean success = compiler.getTask(null, manager, diagnostics,
                Arrays.asList("-proc:none"), null, sources).call();
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
        Log log = new Log(null, false);
        PassContext context = new PassContext(config, pool, hierarchy,
                new DefaultRuleSet(Collections.<String>emptyList(),
                        Collections.<String>emptyList(), false, false),
                new DefaultRuntimeSupport(), new MappingSet(), stats, log,
                new Random(seed), ProgressListener.NONE);
        new VirtualizationPass().run(context);
        Map<String, byte[]> output = new LinkedHashMap<String, byte[]>();
        StringBuilder fingerprint = new StringBuilder();
        List<String> classNames = new ArrayList<String>(pool.classes().keySet());
        Collections.sort(classNames);
        for (String name : classNames) {
            ClassNode node = pool.getClass(name);
            byte[] bytes = UmbraClassWriter.toBytes(node, hierarchy);
            output.put(name, bytes);
            fingerprint.append(name).append(':').append(hash(bytes)).append(';');
        }
        return new Transform(pool, stats, output, fingerprint.toString());
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static boolean callsInterpreter(Transform transform, String internalName,
                                            String methodName) {
        ClassNode node = transform.pool.getClass(internalName);
        if (node == null) {
            return false;
        }
        for (MethodNode method : node.methods) {
            if (!method.name.equals(methodName)) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode call = (MethodInsnNode) insn;
                    if ("([I[I[[I[Ljava/lang/Object;)Ljava/lang/Object;".equals(call.desc)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static Object invoke(Class<?> owner, Object target, String name, Object... args)
            throws Exception {
        for (java.lang.reflect.Method method : owner.getDeclaredMethods()) {
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
            if (!compatible) {
                continue;
            }
            method.setAccessible(true);
            try {
                return method.invoke(target, args);
            } catch (java.lang.reflect.InvocationTargetException error) {
                throw new RuntimeException(error.getCause());
            }
        }
        throw new IllegalArgumentException("no method " + owner.getName() + "#" + name);
    }

    private static boolean compatible(Class<?> type, Object value) {
        if (value == null) {
            return !type.isPrimitive();
        }
        if (!type.isPrimitive()) {
            return type.isInstance(value);
        }
        if (type == int.class) {
            return value instanceof Integer;
        }
        if (type == long.class) {
            return value instanceof Long;
        }
        if (type == boolean.class) {
            return value instanceof Boolean;
        }
        if (type == char.class) {
            return value instanceof Character;
        }
        if (type == float.class) {
            return value instanceof Float;
        }
        if (type == double.class) {
            return value instanceof Double;
        }
        if (type == byte.class) {
            return value instanceof Byte;
        }
        if (type == short.class) {
            return value instanceof Short;
        }
        return false;
    }

    private static long stat(Stats stats, String key) {
        Long value = stats.snapshot().get(key);
        return value == null ? 0L : value.longValue();
    }

    private static long stat(Map<String, Long> stats, String key) {
        Long value = stats.get(key);
        return value == null ? 0L : value.longValue();
    }

    private static void compare(String label, Object expected, Object actual) {
        check(deepEquals(expected, actual), label + " mismatch: expected " + expected
                + " but got " + actual);
    }

    private static boolean deepEquals(Object first, Object second) {
        if (first == second) {
            return true;
        }
        if (first == null || second == null) {
            return false;
        }
        if (first instanceof Object[] && second instanceof Object[]) {
            return Arrays.deepEquals((Object[]) first, (Object[]) second);
        }
        if (first instanceof int[] && second instanceof int[]) {
            return Arrays.equals((int[]) first, (int[]) second);
        }
        if (first instanceof long[] && second instanceof long[]) {
            return Arrays.equals((long[]) first, (long[]) second);
        }
        return first.equals(second);
    }

    private static String hash(byte[] bytes) {
        long value = 0xCBF29CE484222325L;
        for (byte b : bytes) {
            value ^= b & 0xFF;
            value *= 0x100000001B3L;
        }
        return Long.toHexString(value);
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }

    private static void delete(Path directory) {
        try {
            if (!Files.exists(directory)) {
                return;
            }
            Files.walk(directory).sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ignored) {
                    // best effort
                }
            });
        } catch (Exception ignored) {
            // best effort
        }
    }

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
