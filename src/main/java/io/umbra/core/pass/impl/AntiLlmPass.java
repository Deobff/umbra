package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * Countermeasures aimed at automated / LLM-assisted static analysis.
 *
 * <p>The pass is a JVM approximation of the ideas behind Matryoshka Wall,
 * Double Fond, Dispatch Maze and SemAder-style semantic decoys:</p>
 * <ul>
 *   <li><b>Semantic decoys</b> (Double Fond / SemAder): plausible crypto,
 *       network, image, database or compression helpers are added to real
 *       classes. They are never reached in practice but look like live code.</li>
 *   <li><b>Guarded call sites</b> (Dispatch Maze): real methods call a decoy
 *       behind an opaque predicate whose seed is computed by another method.</li>
 *   <li><b>Nested forwarding walls</b> (Matryoshka): a method body is moved
 *       behind one or more private forwarding layers, so a decompiler/LLM sees
 *       a chain of methods instead of the original body.</li>
 * </ul>
 *
 * <p>This raises the token/compute cost of static analysis. It is not a
 * security proof, and dynamic execution plus a human analyst can still recover
 * the logic. The pass must run after renaming and before virtualization so the
 * generated code is still string-encrypted and can be virtualized.</p>
 */
public final class AntiLlmPass implements Pass {

    private static final String[] CRYPTO_NAMES = {
            "expandRoundKey", "deriveAesState", "mixColumns", "scheduleKey"
    };
    private static final String[] NETWORK_NAMES = {
            "parseTlsRecord", "decodeHttpHeader", "checksumFrame", "routePacket"
    };
    private static final String[] IMAGE_NAMES = {
            "decodeScanline", "blendRgbaRows", "resamplePlane", "unpackPixels"
    };
    private static final String[] DATABASE_NAMES = {
            "mergeIndexPage", "scanBTreeLeaf", "decodeRowHeader", "prepareStatement"
    };
    private static final String[] COMPRESSION_NAMES = {
            "inflateWindow", "rebuildHuffman", "decodeBlockHeader", "restoreDictionary"
    };
    private static final String[][] NAMES = {
            CRYPTO_NAMES, NETWORK_NAMES, IMAGE_NAMES, DATABASE_NAMES, COMPRESSION_NAMES
    };

    private static final String[] CRYPTO_STRINGS = {
            "AES/CBC/PKCS5Padding", "HmacSHA256", "TLS_AES_256_GCM_SHA384"
    };
    private static final String[] NETWORK_STRINGS = {
            "Content-Encoding: gzip", "GET /api/v2/session HTTP/1.1", "TLSv1.3"
    };
    private static final String[] IMAGE_STRINGS = {
            "image/png;base64", "RGBA8888", "IHDR"
    };
    private static final String[] DATABASE_STRINGS = {
            "SELECT * FROM accounts WHERE token = ?", "jdbc:mysql://", "PRIMARY KEY"
    };
    private static final String[] COMPRESSION_STRINGS = {
            "deflate", "gzip", "zstd"
    };
    private static final String[][] STRINGS = {
            CRYPTO_STRINGS, NETWORK_STRINGS, IMAGE_STRINGS, DATABASE_STRINGS, COMPRESSION_STRINGS
    };

    @Override
    public String name() {
        return "anti-llm";
    }

    @Override
    public int order() {
        return 55;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().antiLlm().enabled();
    }

    @Override
    public void run(PassContext context) {
        int decoys = 0;
        int callSites = 0;
        int wrapperLayers = 0;
        int seeds = 0;
        int classes = 0;
        Random random = context.random();

        for (ClassNode node : new ArrayList<ClassNode>(context.classes().classes().values())) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
                if (context.rules().skipBodyTransform(node.name)) {
                    continue;
                }
            if ("module-info".equals(node.name)) {
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) {
                continue;
            }
            if (!context.rules().transformClass(node)) {
                continue;
            }

            List<MethodNode> originals = new ArrayList<MethodNode>(node.methods);
            Set<String> added = new HashSet<String>();
            boolean touched = false;

            int decoyCount = context.config().antiLlm().decoyMethodsPerClass();
            if (decoyCount > 0) {
                touched = true;
                List<String> decoyNames = new ArrayList<String>();
                List<String> decoyStrings = new ArrayList<String>();
                for (int i = 0; i < decoyCount; i++) {
                    int category = random.nextInt(NAMES.length);
                    String name = uniqueMethodName(node, NAMES[category][random.nextInt(NAMES[category].length)]);
                    node.methods.add(createDecoy(name, category, random));
                    added.add(name);
                    decoyNames.add(name);
                    decoyStrings.add(STRINGS[category][random.nextInt(STRINGS[category].length)]);
                    decoys++;
                }

                String seedField = uniqueFieldName(node);
                String seedMethod = uniqueMethodName(node, "deriveState");
                node.methods.add(createSeed(seedMethod, random));
                added.add(seedMethod);
                addSeedInit(node, seedField, seedMethod);
                seeds++;

                int sites = Math.min(context.config().antiLlm().decoyCallSitesPerClass(), decoyNames.size());
                int inserted = 0;
                for (MethodNode method : originals) {
                    if (inserted >= sites) {
                        break;
                    }
                    if (!callSiteEligible(method) || added.contains(method.name)) {
                        continue;
                    }
                    insertDecoyCall(node, method, seedField,
                            decoyNames.get(inserted), decoyStrings.get(inserted));
                    inserted++;
                    callSites++;
                }
            }

            int layers = context.config().antiLlm().wrapperLayers();
            int maxWrapped = context.config().antiLlm().maxWrappedMethodsPerClass();
            if (layers > 0 && maxWrapped > 0) {
                int wrapped = 0;
                for (MethodNode method : originals) {
                    if (wrapped >= maxWrapped) {
                        break;
                    }
                    if (!wrapEligible(method) || added.contains(method.name)) {
                        continue;
                    }
                    wrap(node, method, layers);
                    wrapperLayers += layers;
                    wrapped++;
                    touched = true;
                }
            }
            if (touched) {
                classes++;
            }
        }

        context.stats().add("antiLlm.decoys", decoys);
        context.stats().add("antiLlm.callsites", callSites);
        context.stats().add("antiLlm.wrapperLayers", wrapperLayers);
        context.stats().add("antiLlm.seeds", seeds);
        context.stats().add("antiLlm.classes", classes);
        context.log().info("anti-llm: %d decoy methods, %d guarded call sites, %d wrapper layers across %d classes",
                decoys, callSites, wrapperLayers, classes);
    }

    private static boolean callSiteEligible(MethodNode method) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        return method.instructions != null && method.instructions.size() > 1;
    }

    private static boolean wrapEligible(MethodNode method) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE
                | Opcodes.ACC_BRIDGE | Opcodes.ACC_SYNTHETIC)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        if (method.instructions == null || method.instructions.size() < 2) {
            return false;
        }
        if (method.visibleAnnotations != null && !method.visibleAnnotations.isEmpty()) {
            return false;
        }
        if (method.invisibleAnnotations != null && !method.invisibleAnnotations.isEmpty()) {
            return false;
        }
        return method.attrs == null || method.attrs.isEmpty();
    }

    /**
     * Adds a private decoy that looks like a domain-specific parser/hash
     * helper. It uses only loops, arrays and String methods so later passes can
     * still virtualize it.
     */
    private static MethodNode createDecoy(String name, int category, Random random) {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                name, "(Ljava/lang/String;)I", null, null);
        InsnList code = method.instructions;
        int seed = random.nextInt();
        AsmUtil.pushInt(code, seed);
        code.add(new VarInsnNode(Opcodes.ISTORE, 1));
        AsmUtil.pushInt(code, 0);
        code.add(new VarInsnNode(Opcodes.ISTORE, 2));

        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        code.add(loop);
        code.add(new VarInsnNode(Opcodes.ILOAD, 2));
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "length", "()I", false));
        code.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        AsmUtil.pushInt(code, 31);
        code.add(new InsnNode(Opcodes.IMUL));
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 2));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "charAt", "(I)C", false));
        code.add(new InsnNode(Opcodes.IXOR));
        code.add(new VarInsnNode(Opcodes.ISTORE, 1));
        code.add(new IincInsnNode(2, 1));
        code.add(new JumpInsnNode(Opcodes.GOTO, loop));
        code.add(end);

        // A small table and a second mixing step mirror common codec shapes.
        AsmUtil.pushInt(code, 8);
        code.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        code.add(new VarInsnNode(Opcodes.ASTORE, 3));
        for (int i = 0; i < 8; i++) {
            code.add(new VarInsnNode(Opcodes.ALOAD, 3));
            AsmUtil.pushInt(code, i);
            AsmUtil.pushInt(code, random.nextInt());
            code.add(new InsnNode(Opcodes.IASTORE));
        }
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        code.add(new VarInsnNode(Opcodes.ALOAD, 3));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        AsmUtil.pushInt(code, 4);
        code.add(new InsnNode(Opcodes.IUSHR));
        AsmUtil.pushInt(code, 7);
        code.add(new InsnNode(Opcodes.IAND));
        code.add(new InsnNode(Opcodes.IALOAD));
        code.add(new InsnNode(Opcodes.IXOR));
        code.add(new VarInsnNode(Opcodes.ISTORE, 1));

        // Semantic cue for a decompiler / model.
        code.add(new LdcInsnNode(STRINGS[category][random.nextInt(STRINGS[category].length)]));
        code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "hashCode", "()I", false));
        code.add(new InsnNode(Opcodes.POP));

        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        code.add(new InsnNode(Opcodes.IRETURN));
        method.maxLocals = 4;
        method.maxStack = 4;
        return method;
    }

    /**
     * The opaque-predicate seed. It computes zero through a short chain of
     * arithmetic, and is itself eligible for virtualization and flow noise.
     */
    private static MethodNode createSeed(String name, Random random) {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                name, "()I", null, null);
        InsnList code = method.instructions;
        int value = random.nextInt();
        int mask = random.nextInt();
        AsmUtil.pushInt(code, value);
        code.add(new VarInsnNode(Opcodes.ISTORE, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        AsmUtil.pushInt(code, mask);
        code.add(new InsnNode(Opcodes.IXOR));
        code.add(new VarInsnNode(Opcodes.ISTORE, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        AsmUtil.pushInt(code, mask);
        code.add(new InsnNode(Opcodes.IXOR));
        code.add(new VarInsnNode(Opcodes.ISTORE, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        AsmUtil.pushInt(code, value);
        code.add(new InsnNode(Opcodes.IXOR));
        code.add(new VarInsnNode(Opcodes.ISTORE, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 0));
        code.add(new InsnNode(Opcodes.IRETURN));
        method.maxLocals = 1;
        method.maxStack = 2;
        return method;
    }

    private static void addSeedInit(ClassNode node, String fieldName, String seedMethod) {
        node.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                fieldName, "I", null, null));

        MethodNode clinit = null;
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                clinit = method;
                break;
            }
        }
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            clinit.maxLocals = 0;
            clinit.maxStack = 1;
            node.methods.add(clinit);
        }
        InsnList init = new InsnList();
        init.add(new MethodInsnNode(Opcodes.INVOKESTATIC, node.name, seedMethod, "()I", false));
        init.add(new org.objectweb.asm.tree.FieldInsnNode(
                Opcodes.PUTSTATIC, node.name, fieldName, "I"));
        clinit.instructions.insert(init);
        clinit.maxStack = Math.max(clinit.maxStack, 1);
    }

    private static void insertDecoyCall(ClassNode owner, MethodNode method, String seedField,
                                        String decoyName, String decoyString) {
        LabelNode real = new LabelNode();
        InsnList prelude = new InsnList();
        prelude.add(new org.objectweb.asm.tree.FieldInsnNode(
                Opcodes.GETSTATIC, owner.name, seedField, "I"));
        prelude.add(new JumpInsnNode(Opcodes.IFEQ, real));
        prelude.add(new LdcInsnNode(decoyString));
        prelude.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, decoyName,
                "(Ljava/lang/String;)I", false));
        prelude.add(new InsnNode(Opcodes.POP));
        prelude.add(real);
        method.instructions.insert(prelude);
    }

    /** Moves the body behind {@code layers} private forwarding methods. */
    private static void wrap(ClassNode node, MethodNode method, int layers) {
        MethodNode current = method;
        for (int i = 0; i < layers; i++) {
            String bodyName = uniqueMethodName(node, "a");
            MethodNode body = new MethodNode(movedAccess(current.access), bodyName,
                    current.desc, current.signature,
                    current.exceptions == null ? null : current.exceptions.toArray(new String[0]));
            body.instructions = current.instructions;
            body.tryCatchBlocks = current.tryCatchBlocks;
            body.localVariables = current.localVariables;
            body.visibleLocalVariableAnnotations = current.visibleLocalVariableAnnotations;
            body.invisibleLocalVariableAnnotations = current.invisibleLocalVariableAnnotations;
            body.maxLocals = Math.max(current.maxLocals, argumentSlots(current));
            body.maxStack = current.maxStack;
            node.methods.add(body);

            current.instructions = forwarder(node, current, bodyName);
            current.tryCatchBlocks = new ArrayList<org.objectweb.asm.tree.TryCatchBlockNode>();
            current.localVariables = null;
            current.visibleLocalVariableAnnotations = null;
            current.invisibleLocalVariableAnnotations = null;
            int forwarderSlots = argumentSlots(current);
            current.maxLocals = Math.max(current.maxLocals, forwarderSlots);
            // A forwarder pushes receiver + arguments before the call and may keep
            // a 2-slot return value afterwards; never leave maxStack at 0.
            current.maxStack = forwarderSlots + 2;
            current = body;
        }
    }

    private static int movedAccess(int access) {
        int keep = access & (Opcodes.ACC_STATIC | Opcodes.ACC_STRICT | Opcodes.ACC_FINAL);
        return keep | Opcodes.ACC_PRIVATE | Opcodes.ACC_SYNTHETIC;
    }

    private static InsnList forwarder(ClassNode owner, MethodNode method, String bodyName) {
        InsnList out = new InsnList();
        boolean isStatic = (method.access & Opcodes.ACC_STATIC) != 0;
        if (!isStatic) {
            out.add(new VarInsnNode(Opcodes.ALOAD, 0));
        }
        int slot = isStatic ? 0 : 1;
        for (Type argument : Type.getArgumentTypes(method.desc)) {
            out.add(new VarInsnNode(AsmUtil.loadOpcode(argument), slot));
            slot += argument.getSize();
        }
        out.add(new MethodInsnNode(isStatic ? Opcodes.INVOKESTATIC : Opcodes.INVOKESPECIAL,
                owner.name, bodyName, method.desc, false));
        out.add(new InsnNode(AsmUtil.returnOpcode(Type.getReturnType(method.desc))));
        return out;
    }

    private static int argumentSlots(MethodNode method) {
        int slots = (method.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type argument : Type.getArgumentTypes(method.desc)) {
            slots += argument.getSize();
        }
        return slots;
    }

    private static String uniqueMethodName(ClassNode node, String base) {
        String name = sanitize(base);
        Set<String> existing = new HashSet<String>();
        for (MethodNode method : node.methods) {
            existing.add(method.name);
        }
        String candidate = name;
        int counter = 0;
        while (existing.contains(candidate)) {
            candidate = name + Integer.toHexString(counter++);
        }
        return candidate;
    }

    private static String uniqueFieldName(ClassNode node) {
        Set<String> existing = new HashSet<String>();
        for (FieldNode field : node.fields) {
            existing.add(field.name);
        }
        int counter = 0;
        String candidate;
        do {
            candidate = "s$" + Integer.toHexString(counter++);
        } while (existing.contains(candidate));
        return candidate;
    }

    private static String sanitize(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isJavaIdentifierPart(c)) {
                out.append(c);
            }
        }
        if (out.length() == 0 || !Character.isJavaIdentifierStart(out.charAt(0))) {
            out.insert(0, 'x');
        }
        return out.toString();
    }
}
