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
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Log;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Integration test for the polymorphic integer mask chains inside
 * {@link IntegerEncryptionPass}.
 *
 * <p>Every shape the pass can emit is exercised with the mask layer armed and
 * disarmed; the transformed class must load on the real JVM and every constant
 * must round-trip to the exact original value.</p>
 */
public final class IntMaskIntegrationTest {

    private static int checks;

    private IntMaskIntegrationTest() {
    }

    public static void main(String[] args) throws Exception {
        int[] values = sampleInts();
        long[] longs = sampleLongs();
        for (String shape : new String[] {"string", "array", "indy", "xor", "lookup2"}) {
            runShape(shape, values, longs, true, null);
            runShape(shape, values, longs, false, null);
        }
        for (String pool : new String[] {"localArray", "fieldArray", "lookupMethod",
                "lookupMethodDes", "indyEntry"}) {
            runShape("string", values, longs, true, pool);
        }
        System.out.println("IntMaskIntegrationTest: " + checks + " checks passed");
    }

    private static void runShape(String shape, int[] values, long[] longs, boolean masks,
                                 String shapePool) throws Exception {
        String owner = "test/IntTarget";
        ClassNode node = target(owner, values, longs);
        Hierarchy h0 = new Hierarchy();
        h0.addInput(node);
        byte[] original = UmbraClassWriter.toBytes(node, h0);

        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"))
                .seed(4242L)
                .integerEncryption(new UmbraConfig.IntegerEncryptionOptions(true, true))
                .option("integer.shape", shape)
                .option("integer.masks", String.valueOf(masks))
                .option("integer.masks.count", "5")
                .option("integer.masks.random", "true");
        if (shapePool != null) {
            builder.option("shape.pool", shapePool);
        }
        UmbraConfig config = builder.build();

        ClassPool pool = new ClassPool();
        pool.putClass(owner + ".class", original, node);
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        DefaultRuleSet rules = new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(),
                false, false);
        PassContext context = new PassContext(config, pool, hierarchy, rules,
                new DefaultRuntimeSupport(), new MappingSet(), new Stats(), new Log(null, false),
                new Random(4242L), ProgressListener.NONE);
        new IntegerEncryptionPass().run(context);

        byte[] transformed = serialize(node, context.hierarchy());
        Class<?> type = load("test.IntTarget", transformed);
        long expected = 0L;
        for (int value : values) {
            expected += value;
        }
        for (long value : longs) {
            expected += value;
        }
        Object result;
        try {
            result = type.getDeclaredMethod("sum").invoke(null);
        } catch (java.lang.reflect.InvocationTargetException failure) {
            throw new IllegalStateException("shape " + shape + " masks " + masks
                    + " pool " + shapePool + " threw " + failure.getCause(), failure.getCause());
        }
        check(((Long) result).longValue() == expected,
                "shape " + shape + " pool " + (shapePool == null ? "-" : shapePool) + " masks " + masks
                        + " sums to the expected value (expected " + expected + ", got " + result + ")");
        if (masks) {
            Long sites = context.stats().snapshot().get("integer.masks.sites");
            check(sites != null && sites.longValue() > 0,
                    "shape " + shape + " reports masked sites");
        }
    }

    private static int[] sampleInts() {
        return new int[] {0, 1, -1, 2, 127, -128, 32767, -32768, Integer.MAX_VALUE,
                Integer.MIN_VALUE, 65535, -65536, 123456789, -987654321, 42, -42};
    }

    private static long[] sampleLongs() {
        return new long[] {0L, 1L, -1L, Long.MAX_VALUE, Long.MIN_VALUE, 0x123456789ABCDEFL,
                -0x123456789ABCDEFL, 7L};
    }

    private static ClassNode target(String owner, int[] values, long[] longs) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = owner;
        node.superName = "java/lang/Object";
        node.interfaces = new ArrayList<String>();

        MethodNode sum = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "sum", "()J",
                null, null);
        sum.instructions.add(new InsnNode(Opcodes.LCONST_0));
        for (int value : values) {
            pushInt(sum, value);
            sum.instructions.add(new InsnNode(Opcodes.I2L));
            sum.instructions.add(new InsnNode(Opcodes.LADD));
        }
        for (long value : longs) {
            sum.instructions.add(new LdcInsnNode(Long.valueOf(value)));
            sum.instructions.add(new InsnNode(Opcodes.LADD));
        }
        sum.instructions.add(new InsnNode(Opcodes.LRETURN));
        sum.maxStack = 4;
        sum.maxLocals = 0;
        node.methods.add(sum);

        MethodNode per = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "each", "()[I",
                null, null);
        pushIntRaw(per, values.length);
        per.instructions.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        for (int i = 0; i < values.length; i++) {
            per.instructions.add(new InsnNode(Opcodes.DUP));
            pushIntRaw(per, i);
            pushInt(per, values[i]);
            per.instructions.add(new InsnNode(Opcodes.IASTORE));
        }
        per.instructions.add(new InsnNode(Opcodes.ARETURN));
        per.maxStack = 4;
        per.maxLocals = 0;
        node.methods.add(per);
        return node;
    }

    private static void pushInt(MethodNode method, int value) {
        pushIntRaw(method, value);
    }

    private static void pushIntRaw(MethodNode method, int value) {
        io.umbra.core.util.AsmUtil.pushInt(method.instructions, value);
    }

    private static byte[] serialize(ClassNode node, Hierarchy hierarchy) {
        hierarchy.addInput(node);
        return UmbraClassWriter.toBytes(node, hierarchy);
    }

    private static Class<?> load(String name, byte[] bytes) throws Exception {
        final Map<String, byte[]> all = new LinkedHashMap<String, byte[]>();
        all.put(name, bytes);
        ClassLoader loader = new ClassLoader(IntMaskIntegrationTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String className) throws ClassNotFoundException {
                byte[] data = all.get(className);
                if (data == null) {
                    return super.findClass(className);
                }
                return defineClass(className, data, 0, data.length);
            }
        };
        return loader.loadClass(name);
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new IllegalStateException("IntMaskIntegrationTest FAILED: " + message);
        }
    }
}
