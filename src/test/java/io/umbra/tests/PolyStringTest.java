package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.model.UmbraClassWriter;
import io.umbra.core.pass.impl.polystring.PolyStringPass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Log;
import io.umbra.core.util.RuntimeNames;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Self test for {@link PolyStringPass}.
 *
 * <p>Builds classes whose methods return string constants, runs the pass, loads
 * the result on the real JVM and compares every returned value with the original.
 * The carriers are exercised in both loop shapes and every codec, and the class
 * file of a transformed class is scanned to prove the plaintext is gone.</p>
 */
public final class PolyStringTest {

    private static int checks;

    private PolyStringTest() {
    }

    public static void main(String[] args) throws Exception {
        testCodec("mask", "for", 1001L);
        testCodec("mask", "dowhile", 1002L);
        testCodec("caesar", "for", 1003L);
        testCodec("iv", "dowhile", 1004L);
        testCodec("pool", "for", 1005L);
        testPlaintextGone();
        testDeterminism();
        testCoexistenceWithClassicPass();
        System.out.println("PolyStringTest: " + checks + " checks passed");
    }

    private static void testCodec(String codec, String loop, long seed) throws Exception {
        String owner = "test/PolyTarget";
        List<String> values = sampleStrings();
        ClassNode node = target(owner, values);
        byte[] original = serialize(node);

        PassContext context = context(original, node, seed, codec, loop);
        new PolyStringPass().run(context);

        Map<String, byte[]> extra = new LinkedHashMap<String, byte[]>();
        for (String name : context.classes().classes().keySet()) {
            if (!name.equals(owner)) {
                extra.put(name.replace('/', '.'), serialize(context.classes().getClass(name),
                        context.hierarchy()));
            }
        }
        byte[] transformed = serialize(node, context.hierarchy());
        Class<?> type = load("test.PolyTarget", transformed, extra);
        for (int i = 0; i < values.size(); i++) {
            Method method = type.getDeclaredMethod("m" + i);
            Object result = method.invoke(null);
            check(values.get(i).equals(result), codec + "/" + loop + " string " + i
                    + " round-trips (expected length " + values.get(i).length() + ", got "
                    + (result == null ? "null" : String.valueOf(((String) result).length())) + ")");
        }
        check(context.stats().snapshot().get("polyStrings.sites").longValue() > 0,
                codec + "/" + loop + " encrypted at least one site");
        check(context.stats().snapshot().get("polyStrings.skip.rollback").longValue() == 0,
                codec + "/" + loop + " kept every class it touched");
    }

    private static void testPlaintextGone() throws Exception {
        String owner = "test/PolySecrets";
        List<String> values = Arrays.asList("SuperSecretTokenValue", "another-plaintext-longer",
                "com.example.internal.Name", "https://example.invalid/path");
        ClassNode node = target(owner, values);
        byte[] original = serialize(node);
        PassContext context = context(original, node, 2002L, "mask", "for");
        new PolyStringPass().run(context);
        byte[] transformed = serialize(node, context.hierarchy());
        String raw = new String(transformed, StandardCharsets.ISO_8859_1);
        for (String value : values) {
            check(!raw.contains(value), "plaintext '" + value + "' is absent from the class file");
        }
    }

    private static void testDeterminism() throws Exception {
        String owner = "test/PolyDeterministic";
        List<String> values = sampleStrings();
        byte[] first;
        byte[] second;
        {
            ClassNode node = target(owner, values);
            byte[] original = serialize(node);
            PassContext context = context(original, node, 3003L, "mask", "mix");
            new PolyStringPass().run(context);
            first = serialize(node, context.hierarchy());
        }
        {
            ClassNode node = target(owner, values);
            byte[] original = serialize(node);
            PassContext context = context(original, node, 3003L, "mask", "mix");
            new PolyStringPass().run(context);
            second = serialize(node, context.hierarchy());
        }
        check(Arrays.equals(first, second), "same seed produces identical bytes");
    }

    private static void testCoexistenceWithClassicPass() throws Exception {
        String owner = "test/PolyCoexist";
        List<String> values = sampleStrings();
        ClassNode node = target(owner, values);
        byte[] original = serialize(node);
        PassContext context = context(original, node, 4004L, "mask", "for");
        new PolyStringPass().run(context);
        new io.umbra.core.pass.impl.StringEncryptionPass().run(context);
        Map<String, byte[]> extra = new LinkedHashMap<String, byte[]>();
        for (String name : context.classes().classes().keySet()) {
            if (!name.equals(owner)) {
                extra.put(name.replace('/', '.'), serialize(context.classes().getClass(name),
                        context.hierarchy()));
            }
        }
        byte[] transformed = serialize(node, context.hierarchy());
        Class<?> type = load("test.PolyCoexist", transformed, extra);
        for (int i = 0; i < values.size(); i++) {
            Object result = type.getDeclaredMethod("m" + i).invoke(null);
            check(values.get(i).equals(result), "coexistence string " + i + " round-trips");
        }
    }

    private static List<String> sampleStrings() {
        List<String> values = new ArrayList<String>();
        values.add("a");
        values.add("ab");
        values.add("hello world");
        values.add("\u4e2d\u6587\u5b57\u7b26\u4e32");
        values.add("\uD83D\uDE00 emoji \uD83D\uDD25");
        values.add("line\nbreak\ttab\rcr");
        StringBuilder longText = new StringBuilder();
        Random random = new Random(0x5EEDL);
        for (int i = 0; i < 1000; i++) {
            longText.append((char) ('a' + random.nextInt(26)));
        }
        values.add(longText.toString());
        StringBuilder wide = new StringBuilder();
        for (int i = 0; i < 255; i++) {
            wide.append((char) (0x0100 + i));
        }
        values.add(wide.toString());
        return values;
    }

    private static ClassNode target(String owner, List<String> values) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = owner;
        node.superName = "java/lang/Object";
        node.interfaces = new ArrayList<String>();
        for (int i = 0; i < values.size(); i++) {
            MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m" + i,
                    "()Ljava/lang/String;", null, null);
            InsnList body = method.instructions;
            body.add(new LdcInsnNode(values.get(i)));
            body.add(new InsnNode(Opcodes.ARETURN));
            method.maxStack = 1;
            method.maxLocals = 0;
            node.methods.add(method);
        }
        MethodNode loop = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "looped",
                "(I)Ljava/lang/String;", null, null);
        InsnList body = loop.instructions;
        org.objectweb.asm.tree.LabelNode caseA = new org.objectweb.asm.tree.LabelNode();
        org.objectweb.asm.tree.LabelNode caseB = new org.objectweb.asm.tree.LabelNode();
        org.objectweb.asm.tree.LabelNode dflt = new org.objectweb.asm.tree.LabelNode();
        org.objectweb.asm.tree.LabelNode end = new org.objectweb.asm.tree.LabelNode();
        body.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 0));
        body.add(new org.objectweb.asm.tree.TableSwitchInsnNode(0, 1, dflt,
                new org.objectweb.asm.tree.LabelNode[] {caseA, caseB}));
        body.add(caseA);
        body.add(new LdcInsnNode("branch-alpha"));
        body.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.GOTO, end));
        body.add(caseB);
        body.add(new LdcInsnNode("branch-beta"));
        body.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.GOTO, end));
        body.add(dflt);
        body.add(new LdcInsnNode("branch-default"));
        body.add(end);
        body.add(new InsnNode(Opcodes.ARETURN));
        loop.maxStack = 1;
        loop.maxLocals = 1;
        node.methods.add(loop);
        return node;
    }

    private static PassContext context(byte[] original, ClassNode node, long seed, String codec,
                                       String loop) throws Exception {
        UmbraConfig config = new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"))
                .seed(seed)
                .option("polyStrings.enabled", "true")
                .option("polyStrings.ratio", "100")
                .option("polyStrings.codec", codec)
                .option("polyStrings.loop", loop)
                .option("polyStrings.masks", "3")
                .option("polyStrings.traceKey", "true")
                .option("polyStrings.minLength", "1")
                .build();
        ClassPool pool = new ClassPool();
        pool.putClass(node.name + ".class", original, node);
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);
        DefaultRuleSet rules = new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(),
                false, false);
        RuntimeNames.reset();
        return new PassContext(config, pool, hierarchy, rules, new DefaultRuntimeSupport(),
                new MappingSet(), new Stats(), new Log(null, false), new Random(seed),
                ProgressListener.NONE);
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

    private static Class<?> load(String name, byte[] primary, Map<String, byte[]> extra)
            throws Exception {
        final Map<String, byte[]> all = new LinkedHashMap<String, byte[]>(extra);
        all.put(name, primary);
        ClassLoader loader = new ClassLoader(PolyStringTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String className) throws ClassNotFoundException {
                byte[] bytes = all.get(className);
                if (bytes == null) {
                    return super.findClass(className);
                }
                return defineClass(className, bytes, 0, bytes.length);
            }
        };
        Class<?> type = loader.loadClass(name);
        for (Method method : type.getDeclaredMethods()) {
            if (method.getName().startsWith("m") || method.getName().equals("looped")) {
                method.setAccessible(true);
            }
        }
        return type;
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new IllegalStateException("PolyStringTest FAILED: " + message);
        }
    }
}
