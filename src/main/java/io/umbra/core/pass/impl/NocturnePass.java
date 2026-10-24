package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.nocturne.NocturneVerifier;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Nocturne - Umbra's independent method-body obfuscation engine.
 *
 * <p>Nocturne is deliberately <b>exclusive</b>: the engine disables the other
 * method-body rewrites (flow, flattening, exception, MBA, virtualization,
 * native, reference hiding, anti-LLM wrappers, parameter/junk mutations) when
 * {@code nocturne.enabled=true}, so it is not a layer on top of existing
 * techniques.</p>
 *
 * <p><b>Polymorphic Keyed-Argument Method Shadows.</b> For an eligible method
 * {@code M} the pass:</p>
 * <ol>
 *   <li>creates {@code N} private synthetic shadow clones {@code M$nX} whose
 *       descriptor is {@code M}'s descriptor plus a trailing {@code J key}; each
 *       clone contains a byte-for-byte deep copy of {@code M}'s body (fresh
 *       labels, copied exception table) preceded by a decode prefix that
 *       restores the original int/long arguments from their encoded form;</li>
 *   <li>replaces {@code M}'s body with a dispatcher that draws a fresh runtime
 *       key ({@code ThreadLocalRandom.current().nextLong() ^ classSecret}),
 *       derives a variant index from {@code (int)(key ^ salt)}, selects a clone
 *       through a {@code tableswitch}, pushes {@code this}/arguments with
 *       int/long arguments encoded (XOR with the key), passes the key itself,
 *       and returns the clone's result.</li>
 * </ol>
 *
 * <p>Every invocation therefore crosses a keyed argument boundary and executes
 * one of {@code N} equivalent bodies; the call graph no longer shows the real
 * body directly. Build output is seed-deterministic (only the emitted runtime
 * key is random). Only int/long parameters are encoded; float/double/reference
 * arguments cross unchanged, which keeps the verifier and the JVM happy for
 * every descriptor.</p>
 *
 * <p>Options: {@code nocturne.enabled} (default false),
 * {@code nocturne.variants} 2..4 (default 3),
 * {@code nocturne.maxInstructions} (default 4000),
 * {@code nocturne.maxMethods} per class, 0 = unlimited.</p>
 */
public final class NocturnePass implements Pass {

    private static final String TARGET = "java/lang/IllegalStateException";
    private static final long GOLDEN = 0x9E3779B97F4A7C15L;

    @Override
    public String name() {
        return "nocturne";
    }

    @Override
    public int order() {
        // Runs after the classic Java body passes (VM, reference hiding, string/
        // integer encryption, MBA, flow, flattening, exception obfuscation) so
        // that compatible mode can wrap their output instead of being wrapped.
        // In exclusive mode those passes are disabled, so the position only
        // affects logging.
        return 106;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool("nocturne.enabled", false);
    }

    @Override
    public void run(PassContext context) {
        int variants = Math.max(2, Math.min(4,
                context.config().optionInt("nocturne.variants", 3)));
        int maxInstructions = Math.max(16,
                context.config().optionInt("nocturne.maxInstructions", 4000));
        int maxMethods = Math.max(0, context.config().optionInt("nocturne.maxMethods", 0));
        long seed = context.config().seed();
        NocturneVerifier verifier = new NocturneVerifier(context);
        int methods = 0;
        int shadowVariants = 0;
        int instructions = 0;
        int skipped = 0;
        int classes = 0;
        for (ClassNode node : context.classes().classes().values()) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
            if (!context.rules().transformClass(node)) {
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0
                    || "module-info".equals(node.name)) {
                continue;
            }
            if (context.rules().skipBodyTransform(node.name)) {
                continue;
            }

            List<MethodNode> originals = new ArrayList<MethodNode>(node.methods);
            List<MethodNode> work = new ArrayList<MethodNode>(originals);
            Set<String> usedNames = new HashSet<String>();
            for (MethodNode method : originals) {
                usedNames.add(method.name);
            }
            int classMethods = 0;
            int classVariants = 0;
            int classInstructions = 0;
            long classSecret = classSecret(seed, node.name);
            for (int index = 0; index < originals.size(); index++) {
                if (maxMethods > 0 && classMethods >= maxMethods) {
                    break;
                }
                MethodNode method = originals.get(index);
                if (!hasBody(method)) {
                    continue;
                }
                if (method.name.startsWith("<")) {
                    // Constructors / class initialisers keep their exact shape.
                    continue;
                }
                if (!eligible(context, node, method, maxInstructions)) {
                    skipped++;
                    continue;
                }
                try {
                    ShadowPlan plan = plan(context, node, method, variants, classSecret, usedNames);
                    if (plan == null) {
                        skipped++;
                        continue;
                    }
                    work.set(index, plan.dispatcher);
                    work.addAll(plan.shadows);
                    classMethods++;
                    classVariants += plan.shadows.size();
                    classInstructions += plan.instructions;
                } catch (RuntimeException e) {
                    skipped++;
                    context.log().debug("nocturne: skipped %s.%s: %s",
                            node.name, method.name, e.toString());
                }
            }
            if (classMethods == 0) {
                continue;
            }
            node.methods = work;
            if (verifier.verifyClass(node)) {
                methods += classMethods;
                shadowVariants += classVariants;
                instructions += classInstructions;
                classes++;
            } else {
                node.methods = originals;
                skipped += classMethods;
                context.log().debug("nocturne: rolled back class %s after verification failure",
                        node.name);
            }
        }
        context.stats().add("nocturne.methods", methods);
        context.stats().add("nocturne.variants", shadowVariants);
        context.stats().add("nocturne.instructions", instructions);
        context.stats().add("nocturne.skipped", skipped);
        context.stats().add("nocturne.classes", classes);
        context.log().info("nocturne: shadowed %d methods with %d keyed variants (%d instructions) "
                        + "across %d classes; %d skipped",
                methods, shadowVariants, instructions, classes, skipped);
    }

    // ------------------------------------------------------------- eligibility

    private static boolean hasBody(MethodNode method) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        return method.instructions != null && method.instructions.size() > 0;
    }

    private static boolean eligible(PassContext context, ClassNode owner, MethodNode method,
                                    int maxInstructions) {
        if ((method.access & Opcodes.ACC_SYNCHRONIZED) != 0) {
            // Moving a synchronized body into a shadow would change the monitor
            // that is released when an exception leaves the body.
            return false;
        }
        if (method.instructions.size() > maxInstructions) {
            return false;
        }
        if (AsmUtil.containsJsrOrRet(method)) {
            return false;
        }
        if (context.rules().keepMethod(owner.name, method)) {
            return false;
        }
        return !context.rules().hasKeepAnnotation(method);
    }

    // ----------------------------------------------------------------- shadows

    private static ShadowPlan plan(PassContext context, ClassNode owner, MethodNode original,
                                   int variants, long classSecret, Set<String> usedNames) {
        int argumentSlots = argumentSlots(original);
        String shadowDescriptor = appendKey(original.desc);
        long salt = context.random().nextLong();
        Encoding encoding = Encoding.create(context, salt ^ classSecret);
        List<MethodNode> shadows = new ArrayList<MethodNode>(variants);
        for (int i = 0; i < variants; i++) {
            String shadowName = uniqueShadowName(original.name, usedNames, context);
            shadows.add(shadow(context, original, shadowName, shadowDescriptor, argumentSlots, encoding));
        }
        MethodNode dispatcher = dispatcher(original, owner, shadows, argumentSlots, salt,
                variants, classSecret, encoding);
        ShadowPlan plan = new ShadowPlan();
        plan.dispatcher = dispatcher;
        plan.shadows = shadows;
        int count = dispatcher.instructions.size();
        for (MethodNode shadow : shadows) {
            count += shadow.instructions.size();
        }
        plan.instructions = count;
        return plan;
    }

    /**
     * Argument transcoding used across the dispatcher/shadow boundary.
     *
     * <p>The old {@code arg ^ key} scheme was trivially invertible from a single
     * pair of values. The default encoding is a two-round ARX permutation:
     * add-key, xor-key, per-method rotation, add-constant, xor-key, rotation,
     * with the decode emitted as the exact reverse sequence. Every constant is
     * derived from the per-invocation key and a per-method build salt, so two
     * methods (or two invocations) never share the same transform. {@code xor}
     * is retained only as a compatibility option.</p>
     */
    static final class Encoding {
        final boolean arx;
        final int rot1;
        final int c1;
        final int rot2;
        final int longRot1;
        final long longC1;
        final int longRot2;

        private Encoding(boolean arx, int rot1, int c1, int rot2,
                         int longRot1, long longC1, int longRot2) {
            this.arx = arx;
            this.rot1 = rot1;
            this.c1 = c1;
            this.rot2 = rot2;
            this.longRot1 = longRot1;
            this.longC1 = longC1;
            this.longRot2 = longRot2;
        }

        static Encoding create(PassContext context, long seed) {
            String mode = context.config().option("nocturne.encoding", "arx")
                    .trim().toLowerCase(java.util.Locale.ROOT);
            java.util.Random random = new java.util.Random(seed ^ 0x9E3779B97F4A7C15L);
            return new Encoding(!"xor".equals(mode),
                    5 + random.nextInt(23), random.nextInt() | 1,
                    5 + random.nextInt(23),
                    7 + random.nextInt(57), random.nextLong() | 1L,
                    7 + random.nextInt(57));
        }

        void encodeInt(InsnList out, int slot, int keySlot) {
            out.add(new VarInsnNode(Opcodes.ILOAD, slot));
            if (!arx) {
                out.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
                out.add(new InsnNode(Opcodes.L2I));
                out.add(new InsnNode(Opcodes.IXOR));
                return;
            }
            out.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
            out.add(new InsnNode(Opcodes.L2I));
            out.add(new InsnNode(Opcodes.IADD));
            pushKeyInt(out, keySlot, 32);
            out.add(new InsnNode(Opcodes.IXOR));
            AsmUtil.pushInt(out, rot1);
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                    "rotateLeft", "(II)I", false));
            AsmUtil.pushInt(out, c1);
            out.add(new InsnNode(Opcodes.IADD));
            pushKeyInt(out, keySlot, 17);
            out.add(new InsnNode(Opcodes.IXOR));
            AsmUtil.pushInt(out, rot2);
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                    "rotateLeft", "(II)I", false));
        }

        void decodeInt(InsnList out, int slot, int keySlot) {
            out.add(new VarInsnNode(Opcodes.ILOAD, slot));
            if (!arx) {
                out.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
                out.add(new InsnNode(Opcodes.L2I));
                out.add(new InsnNode(Opcodes.IXOR));
                out.add(new VarInsnNode(Opcodes.ISTORE, slot));
                return;
            }
            AsmUtil.pushInt(out, rot2);
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                    "rotateRight", "(II)I", false));
            pushKeyInt(out, keySlot, 17);
            out.add(new InsnNode(Opcodes.IXOR));
            AsmUtil.pushInt(out, c1);
            out.add(new InsnNode(Opcodes.ISUB));
            AsmUtil.pushInt(out, rot1);
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                    "rotateRight", "(II)I", false));
            pushKeyInt(out, keySlot, 32);
            out.add(new InsnNode(Opcodes.IXOR));
            out.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
            out.add(new InsnNode(Opcodes.L2I));
            out.add(new InsnNode(Opcodes.ISUB));
            out.add(new VarInsnNode(Opcodes.ISTORE, slot));
        }

        void encodeLong(InsnList out, int slot, int keySlot) {
            out.add(new VarInsnNode(Opcodes.LLOAD, slot));
            if (!arx) {
                out.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
                out.add(new InsnNode(Opcodes.LXOR));
                return;
            }
            out.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
            out.add(new InsnNode(Opcodes.LADD));
            pushKeyLong(out, keySlot, 32);
            out.add(new InsnNode(Opcodes.LXOR));
            AsmUtil.pushInt(out, longRot1);
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long",
                    "rotateLeft", "(JI)J", false));
            out.add(new LdcInsnNode(Long.valueOf(longC1)));
            out.add(new InsnNode(Opcodes.LADD));
            pushKeyLong(out, keySlot, 17);
            out.add(new InsnNode(Opcodes.LXOR));
            AsmUtil.pushInt(out, longRot2);
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long",
                    "rotateLeft", "(JI)J", false));
        }

        void decodeLong(InsnList out, int slot, int keySlot) {
            out.add(new VarInsnNode(Opcodes.LLOAD, slot));
            if (!arx) {
                out.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
                out.add(new InsnNode(Opcodes.LXOR));
                out.add(new VarInsnNode(Opcodes.LSTORE, slot));
                return;
            }
            AsmUtil.pushInt(out, longRot2);
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long",
                    "rotateRight", "(JI)J", false));
            pushKeyLong(out, keySlot, 17);
            out.add(new InsnNode(Opcodes.LXOR));
            out.add(new LdcInsnNode(Long.valueOf(longC1)));
            out.add(new InsnNode(Opcodes.LSUB));
            AsmUtil.pushInt(out, longRot1);
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long",
                    "rotateRight", "(JI)J", false));
            pushKeyLong(out, keySlot, 32);
            out.add(new InsnNode(Opcodes.LXOR));
            out.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
            out.add(new InsnNode(Opcodes.LSUB));
            out.add(new VarInsnNode(Opcodes.LSTORE, slot));
        }

        private static void pushKeyInt(InsnList out, int keySlot, int shift) {
            out.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
            AsmUtil.pushInt(out, shift);
            out.add(new InsnNode(Opcodes.LUSHR));
            out.add(new InsnNode(Opcodes.L2I));
        }

        private static void pushKeyLong(InsnList out, int keySlot, int shift) {
            out.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
            AsmUtil.pushInt(out, shift);
            out.add(new InsnNode(Opcodes.LUSHR));
        }
    }

    /** Deep copy of the original body with a key decode prefix. */
    private static MethodNode shadow(PassContext context, MethodNode original, String name,
                                     String descriptor, int argumentSlots, Encoding encoding) {
        MethodNode shadow = copyMethod(original);
        shadow.name = name;
        shadow.desc = descriptor;
        shadow.access = Opcodes.ACC_PRIVATE | Opcodes.ACC_SYNTHETIC
                | (original.access & (Opcodes.ACC_STATIC | Opcodes.ACC_STRICT));
        shadow.signature = null;
        shadow.visibleAnnotations = null;
        shadow.invisibleAnnotations = null;
        shadow.visibleTypeAnnotations = null;
        shadow.invisibleTypeAnnotations = null;
        shadow.visibleParameterAnnotations = null;
        shadow.invisibleParameterAnnotations = null;
        shadow.annotationDefault = null;
        shadow.attrs = null;
        shadow.parameters = null;
        shadow.localVariables = null;
        shadow.visibleLocalVariableAnnotations = null;
        shadow.invisibleLocalVariableAnnotations = null;

        int keySlot = argumentSlots;
        // Randomized local-slot remap: free local slots (everything from the
        // first non-argument slot upwards) are shifted by 2..3 slots so the N
        // shadows do not share one local layout. The key occupies the argument
        // slots immediately after the real parameters, so a delta >= 2 keeps
        // the remapped locals clear of it.
        int delta = 2 + context.random().nextInt(2);
        remapLocals(shadow.instructions, argumentSlots, delta);
        InsnList decode = new InsnList();
        int slot = (original.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1;
        for (Type type : Type.getArgumentTypes(original.desc)) {
            switch (type.getSort()) {
                case Type.BOOLEAN:
                case Type.BYTE:
                case Type.CHAR:
                case Type.SHORT:
                case Type.INT:
                    encoding.decodeInt(decode, slot, keySlot);
                    slot += 1;
                    break;
                case Type.LONG:
                    encoding.decodeLong(decode, slot, keySlot);
                    slot += 2;
                    break;
                default:
                    slot += type.getSize();
                    break;
            }
        }
        shadow.instructions.insert(decode);
        int baseLocals = Math.max(Math.max(0, original.maxLocals) + delta, keySlot + 2);
        shadow.maxLocals = Math.max(baseLocals, nextFreeLocal(shadow));
        shadow.maxStack = Math.max(original.maxStack, 6);
        if (context.config().optionBool("nocturne.debug", false)) {
            context.log().debug("nocturne: shadow %s%s", name, descriptor);
        }
        return shadow;
    }

    /** The dispatcher that replaces the original method body. */
    private static MethodNode dispatcher(MethodNode original, ClassNode owner,
                                         List<MethodNode> shadows, int argumentSlots,
                                         long salt, int variants, long classSecret,
                                         Encoding encoding) {
        MethodNode dispatcher = copyMethod(original);
        dispatcher.instructions = new InsnList();
        dispatcher.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
        dispatcher.localVariables = null;
        dispatcher.visibleLocalVariableAnnotations = null;
        dispatcher.invisibleLocalVariableAnnotations = null;
        int keyLocal = argumentSlots;
        InsnList out = dispatcher.instructions;

        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/concurrent/ThreadLocalRandom",
                "current", "()Ljava/util/concurrent/ThreadLocalRandom;", false));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/concurrent/ThreadLocalRandom",
                "nextLong", "()J", false));
        out.add(new LdcInsnNode(Long.valueOf(classSecret)));
        out.add(new InsnNode(Opcodes.LXOR));
        out.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
        out.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        out.add(new LdcInsnNode(Long.valueOf(salt)));
        out.add(new InsnNode(Opcodes.LXOR));
        out.add(new InsnNode(Opcodes.L2I));
        AsmUtil.pushInt(out, Integer.MAX_VALUE);
        out.add(new InsnNode(Opcodes.IAND));
        AsmUtil.pushInt(out, variants);
        out.add(new InsnNode(Opcodes.IREM));

        LabelNode defaultLabel = new LabelNode();
        LabelNode[] cases = new LabelNode[variants];
        for (int i = 0; i < variants; i++) {
            cases[i] = new LabelNode();
        }
        out.add(new TableSwitchInsnNode(0, variants - 1, defaultLabel, cases));

        boolean isStatic = (original.access & Opcodes.ACC_STATIC) != 0;
        Type[] arguments = Type.getArgumentTypes(original.desc);
        for (int i = 0; i < variants; i++) {
            out.add(cases[i]);
            if (!isStatic) {
                out.add(new VarInsnNode(Opcodes.ALOAD, 0));
            }
            int slot = isStatic ? 0 : 1;
            for (Type type : arguments) {
                switch (type.getSort()) {
                    case Type.BOOLEAN:
                    case Type.BYTE:
                    case Type.CHAR:
                    case Type.SHORT:
                    case Type.INT:
                        encoding.encodeInt(out, slot, keyLocal);
                        slot += 1;
                        break;
                    case Type.LONG:
                        encoding.encodeLong(out, slot, keyLocal);
                        slot += 2;
                        break;
                    case Type.FLOAT:
                        out.add(new VarInsnNode(Opcodes.FLOAD, slot));
                        slot += 1;
                        break;
                    case Type.DOUBLE:
                        out.add(new VarInsnNode(Opcodes.DLOAD, slot));
                        slot += 2;
                        break;
                    default:
                        out.add(new VarInsnNode(Opcodes.ALOAD, slot));
                        slot += 1;
                        break;
                }
            }
            out.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            MethodNode shadow = shadows.get(i);
            out.add(new MethodInsnNode(isStatic ? Opcodes.INVOKESTATIC : Opcodes.INVOKESPECIAL,
                    owner.name, shadow.name, shadow.desc, false));
            out.add(new InsnNode(returnOpcode(Type.getReturnType(original.desc))));
        }
        out.add(defaultLabel);
        out.add(new TypeInsnNode(Opcodes.NEW, TARGET));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, TARGET, "<init>", "()V", false));
        out.add(new InsnNode(Opcodes.ATHROW));

        dispatcher.maxLocals = Math.max(argumentSlots, keyLocal + 2);
        dispatcher.maxStack = Math.max(6, argumentSlots + 4);
        return dispatcher;
    }

    // -------------------------------------------------------------- utilities

    private static MethodNode copyMethod(MethodNode original) {
        MethodNode copy = new MethodNode(original.access, original.name, original.desc,
                original.signature, original.exceptions == null
                        ? null : original.exceptions.toArray(new String[0]));
        Map<LabelNode, LabelNode> labels = new IdentityHashMap<LabelNode, LabelNode>();
        for (AbstractInsnNode insn = original.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode) {
                labels.put((LabelNode) insn, new LabelNode());
            }
        }
        for (AbstractInsnNode insn = original.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            AbstractInsnNode cloned = insn.clone(labels);
            if (cloned != null) {
                copy.instructions.add(cloned);
            }
        }
        if (original.tryCatchBlocks != null) {
            copy.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
            for (TryCatchBlockNode table : original.tryCatchBlocks) {
                copy.tryCatchBlocks.add(new TryCatchBlockNode(
                        labels.get(table.start), labels.get(table.end),
                        labels.get(table.handler), table.type));
            }
        }
        copy.maxStack = original.maxStack;
        copy.maxLocals = original.maxLocals;
        copy.visibleAnnotations = original.visibleAnnotations;
        copy.invisibleAnnotations = original.invisibleAnnotations;
        copy.visibleTypeAnnotations = original.visibleTypeAnnotations;
        copy.invisibleTypeAnnotations = original.invisibleTypeAnnotations;
        copy.visibleParameterAnnotations = original.visibleParameterAnnotations;
        copy.invisibleParameterAnnotations = original.invisibleParameterAnnotations;
        copy.annotationDefault = original.annotationDefault;
        copy.attrs = original.attrs;
        copy.parameters = original.parameters;
        return copy;
    }

    /** Shifts every non-argument local slot by {@code delta}. */
    private static void remapLocals(InsnList instructions, int argumentSlots, int delta) {
        if (delta == 0) {
            return;
        }
        for (AbstractInsnNode insn = instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof VarInsnNode) {
                VarInsnNode variable = (VarInsnNode) insn;
                if (variable.var >= argumentSlots) {
                    variable.var += delta;
                }
            } else if (insn instanceof IincInsnNode) {
                IincInsnNode increment = (IincInsnNode) insn;
                if (increment.var >= argumentSlots) {
                    increment.var += delta;
                }
            }
        }
    }

    private static String appendKey(String descriptor) {
        int close = descriptor.indexOf(')');
        return descriptor.substring(0, close) + "J" + descriptor.substring(close);
    }

    private static String uniqueShadowName(String original, Set<String> usedNames,
                                           PassContext context) {
        for (int attempt = 0; attempt < 4096; attempt++) {
            String candidate = original + "$" + Integer.toHexString(
                    context.random().nextInt() & 0xFFFF);
            if (usedNames.add(candidate)) {
                return candidate;
            }
        }
        int counter = 1;
        while (true) {
            String candidate = original + "$" + Integer.toHexString(counter++);
            if (usedNames.add(candidate)) {
                return candidate;
            }
        }
    }

    private static long classSecret(long seed, String className) {
        long hash = seed ^ GOLDEN;
        for (int i = 0; i < className.length(); i++) {
            hash = hash * GOLDEN + className.charAt(i);
            hash ^= hash >>> 29;
        }
        hash ^= hash >>> 33;
        hash *= 0xFF51AFD7ED558CCDL;
        hash ^= hash >>> 33;
        return hash;
    }

    private static int returnOpcode(Type returnType) {
        return AsmUtil.returnOpcode(returnType);
    }

    private static int argumentSlots(MethodNode method) {
        int slots = (method.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type type : Type.getArgumentTypes(method.desc)) {
            slots += type.getSize();
        }
        return slots;
    }

    private static int nextFreeLocal(MethodNode method) {
        int used = Math.max(0, method.maxLocals);
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof VarInsnNode) {
                int slot = ((VarInsnNode) insn).var;
                int size = (insn.getOpcode() == Opcodes.LLOAD || insn.getOpcode() == Opcodes.LSTORE
                        || insn.getOpcode() == Opcodes.DLOAD || insn.getOpcode() == Opcodes.DSTORE) ? 2 : 1;
                used = Math.max(used, slot + size);
            } else if (insn instanceof IincInsnNode) {
                used = Math.max(used, ((IincInsnNode) insn).var + 1);
            }
        }
        return used;
    }

    private static final class ShadowPlan {
        MethodNode dispatcher;
        List<MethodNode> shadows;
        int instructions;
    }
}
