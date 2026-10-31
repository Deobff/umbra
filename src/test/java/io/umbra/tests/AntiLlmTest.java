package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.pass.impl.AntiLlmPass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Log;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * Regression covers for the anti-LLM pass.
 *
 * <p>The pass is a camouflage layer, and camouflage fails in ways that tests have
 * to pin down explicitly: generated members that do not look like renamed
 * program members, decoys that nobody references, decoys that all share one
 * shape, and call-site predicates a static analyser can fold away. Each check
 * below corresponds to one of those failure modes.</p>
 */
public final class AntiLlmTest {

    private static int checks;

    private AntiLlmTest() {
    }

    public static void main(String[] args) throws Exception {
        testDecoysLookLikeRenamedMembers();
        testDecoysAreReferenced();
        testDecoysUseSeveralShapes();
        testCallSitePredicateIsRuntimeOnly();
        testVocabularyIsNotShipped();
        System.out.println("AntiLlmTest: " + checks + " checks passed");
    }

    private static void testDecoysLookLikeRenamedMembers() throws Exception {
        ClassNode node = runPass();
        List<MethodNode> decoys = decoysOf(node);
        check(!decoys.isEmpty(), "decoys were added");
        for (MethodNode decoy : decoys) {
            String name = decoy.name;
            check(name.matches("[A-Za-z][A-Za-z0-9]{1,9}"),
                    "decoy name looks generated: " + name);
            check(!name.startsWith("s$") && !name.startsWith("z$") && !name.startsWith("a$"),
                    "decoy name has no fixed prefix: " + name);
            check(!name.matches("(?i).*(expand|derive|mix|schedule|decode|inflate|parse|checksum)"
                            + ".*"),
                    "decoy name is not semantic: " + name);
        }
        for (FieldNode field : node.fields) {
            if ((field.access & Opcodes.ACC_SYNTHETIC) != 0) {
                check(field.name.matches("[A-Za-z][A-Za-z0-9]{1,9}"),
                        "synthetic seed field uses a generated name: " + field.name);
                check(!field.name.startsWith("s$"),
                        "seed field has no fixed prefix: " + field.name);
            }
        }
    }

    private static void testDecoysAreReferenced() throws Exception {
        ClassNode node = runPass();
        Set<String> called = new HashSet<String>();
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode call = (MethodInsnNode) insn;
                    if (node.name.equals(call.owner)
                            && (call.getOpcode() == Opcodes.INVOKESTATIC
                            || call.getOpcode() == Opcodes.INVOKESPECIAL)) {
                        called.add(call.name);
                    }
                }
            }
        }
        List<MethodNode> decoys = decoysOf(node);
        int referenced = 0;
        for (MethodNode decoy : decoys) {
            if (called.contains(decoy.name)) {
                referenced++;
            }
        }
        check(referenced > 0, "at least one decoy is referenced from program code");
        // The static initializer anchors a reference even when the ordinary call
        // sites are later moved into a VM payload by virtualization.
        MethodNode clinit = findMethod(node, "<clinit>");
        check(clinit != null, "class has a static initializer");
        boolean anchored = false;
        for (AbstractInsnNode insn = clinit.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;
                if (node.name.equals(call.owner) && called.contains(call.name)
                        && call.desc.startsWith("(Ljava/lang/String;)")) {
                    anchored = true;
                }
            }
        }
        check(anchored, "static initializer anchors a guarded decoy reference");
    }

    private static void testDecoysUseSeveralShapes() throws Exception {
        ClassNode node = runPass();
        Set<String> descriptors = new HashSet<String>();
        for (MethodNode decoy : decoysOf(node)) {
            descriptors.add(decoy.desc);
        }
        check(descriptors.size() >= 2,
                "decoys do not all share one signature: " + descriptors);
        for (String desc : descriptors) {
            check(desc.startsWith("(Ljava/lang/String;)"),
                    "decoy takes a String: " + desc);
        }
    }

    private static void testCallSitePredicateIsRuntimeOnly() throws Exception {
        ClassNode node = runPass();
        // No constant in the class may make the guard foldable: the seed has to come
        // from a runtime-only source.
        boolean nanoTime = false;
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode call = (MethodInsnNode) insn;
                    if ("java/lang/System".equals(call.owner) && "nanoTime".equals(call.name)) {
                        nanoTime = true;
                    }
                }
            }
        }
        check(nanoTime, "guard seed is derived from System.nanoTime");
        // The seed must branch on a field load, not on a compiler constant.
        MethodNode clinit = findMethod(node, "<clinit>");
        boolean loadsSeed = false;
        for (AbstractInsnNode insn = clinit.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof FieldInsnNode) {
                FieldInsnNode field = (FieldInsnNode) insn;
                if (field.getOpcode() == Opcodes.GETSTATIC && node.name.equals(field.owner)
                        && "I".equals(field.desc)) {
                    loadsSeed = true;
                }
            }
        }
        check(loadsSeed, "guarded call site tests the runtime seed field");
        check(hasSeedInit(clinit), "seed field is assigned in the static initializer");
    }

    private static void testVocabularyIsNotShipped() throws Exception {
        ClassNode node = runPass();
        String[] banned = {
                "AES/CBC/PKCS5Padding", "HmacSHA256", "TLS_AES_256_GCM_SHA384",
                "Content-Encoding: gzip", "GET /api/v2/session HTTP/1.1", "image/png;base64",
                "RGBA8888", "SELECT * FROM accounts WHERE token = ?", "inflateWindow",
                "expandRoundKey", "decodeScanline", "mergeIndexPage"
        };
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof LdcInsnNode)) {
                    continue;
                }
                Object value = ((LdcInsnNode) insn).cst;
                if (!(value instanceof String)) {
                    continue;
                }
                for (String needle : banned) {
                    check(!((String) value).equals(needle),
                            "decoy does not ship the old vocabulary: " + needle);
                }
            }
        }
    }

    private static boolean hasSeedInit(MethodNode clinit) {
        for (AbstractInsnNode insn = clinit.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof FieldInsnNode) {
                FieldInsnNode field = (FieldInsnNode) insn;
                if (field.getOpcode() == Opcodes.PUTSTATIC && "I".equals(field.desc)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Builds one probe class, runs the pass on it and returns it. */
    private static ClassNode runPass() throws Exception {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = "probe/Subject";
        node.superName = "java/lang/Object";

        node.fields.add(new FieldNode(Opcodes.ACC_STATIC, "counter", "I", null, null));

        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new InsnNode(Opcodes.ICONST_3));
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, "counter", "I"));
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.maxStack = 1;
        clinit.maxLocals = 0;
        node.methods.add(clinit);

        // Two ordinary methods with a literal so the decoys reuse program constants.
        for (int i = 0; i < 2; i++) {
            MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "work" + i, "(Ljava/lang/String;)I", null, null);
            method.instructions.add(new LdcInsnNode("session-token"));
            method.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                    "java/lang/String", "length", "()I", false));
            method.instructions.add(new InsnNode(Opcodes.IRETURN));
            method.maxStack = 1;
            method.maxLocals = 1;
            node.methods.add(method);
        }

        ClassPool pool = new ClassPool();
        pool.putClass("probe/Subject.class", null, node);
        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(node);

        UmbraConfig config = new UmbraConfig.Builder()
                .input(java.nio.file.Paths.get("in.jar"))
                .output(java.nio.file.Paths.get("out.jar"))
                .seed(424242L)
                .option("antiLlm.enabled", "true")
                .option("antiLlm.decoyMethodsPerClass", "4")
                .option("antiLlm.decoyCallSitesPerClass", "2")
                .option("antiLlm.wrapperLayers", "2")
                .option("antiLlm.maxWrappedMethodsPerClass", "2")
                .build();
        PassContext context = new PassContext(config, pool, hierarchy,
                new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(), false, false),
                new DefaultRuntimeSupport(), new MappingSet(), new Stats(), new Log(null, false),
                new Random(424242L), ProgressListener.NONE);
        new AntiLlmPass().run(context);
        return node;
    }

    private static List<MethodNode> decoysOf(ClassNode node) {
        List<MethodNode> decoys = new ArrayList<MethodNode>();
        for (MethodNode method : node.methods) {
            // Decoys are private unless a cross-class call site references them;
            // those are promoted to package access so the call site links.
            if ((method.access & Opcodes.ACC_STATIC) == 0
                    || (method.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0) {
                continue;
            }
            if (method.desc.startsWith("(Ljava/lang/String;)")
                    && (method.desc.endsWith(")I") || method.desc.endsWith(")J")
                    || method.desc.endsWith(")Z")
                    || method.desc.endsWith(")Ljava/lang/String;"))) {
                decoys.add(method);
            }
        }
        return decoys;
    }

    private static MethodNode findMethod(ClassNode node, String name) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name)) {
                return method;
            }
        }
        return null;
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}
