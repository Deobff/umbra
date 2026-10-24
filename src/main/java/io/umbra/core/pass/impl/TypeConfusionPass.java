package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.rules.Glob;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Type-confusion pass (KBox {@code typeConfusion} parity).
 *
 * <p>Removes static type information from selected internal call and field
 * traffic by routing it through {@code Object}/{@code Object[]} carriers, so a
 * decompiler cannot reconstruct the true parameter and field types:</p>
 *
 * <ul>
 *   <li><b>Level 1 - call ABI.</b> Every selected {@code private static}
 *       method gets a synthetic static trampoline
 *       {@code ([Ljava/lang/Object;)Ljava/lang/Object;} (or {@code ...)V}) in
 *       the same class. Call sites inside the declaring class are rewritten to
 *       box their arguments into an {@code Object[]}, call the trampoline and
 *       unbox the result. The original method stays intact and is called by the
 *       trampoline, so recursion, method handles, lambdas and reflection keep
 *       working; only the call sites lose their static signature.</li>
 *   <li><b>Level 2 - static field carriers.</b> Eligible {@code private static}
 *       non-final fields are re-typed to {@code Object}, their implicit zero
 *       initialisation is replaced by a boxed default value at the start of
 *       {@code <clinit>}, and every read/write inside the declaring class is
 *       wrapped in box/unbox. The field's real type only survives as a cast in
 *       generated code.</li>
 * </ul>
 *
 * <p>Refusals are deliberate: constructors and {@code <clinit>} are never call
 * targets, methods/fields observed from outside the declaring class (nestmate
 * direct access, keep rules, reflection-derived keep rules,
 * {@code io.umbra.annotations.Keep}) are skipped, and every transformed method
 * is verified on a copy with the shared {@link MethodGate} before it is
 * committed. A class whose post-transform bytes do not serialize is rolled
 * back completely (methods and fields), so the pass can never break a valid
 * input. Verification failures are counted, not silently ignored.</p>
 *
 * <p>Deterministic for a seed and bounded per method and per class.</p>
 */
public final class TypeConfusionPass implements Pass {

    private static final String OBJECT = "Ljava/lang/Object;";
    private static final String OBJECT_ARRAY = "[Ljava/lang/Object;";

    /** Internal safety cap: trampolines created per class. */
    private static final int MAX_METHODS_PER_CLASS = 32;
    /** Internal safety cap: fields carried per class. */
    private static final int MAX_FIELDS_PER_CLASS = 16;

    @Override
    public String name() {
        return "type-confusion";
    }

    @Override
    public int order() {
        return 67;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool("typeConfusion.enabled", false);
    }

    @Override
    public void run(PassContext context) {
        Options options = Options.resolve(context);
        if (!options.enabled) {
            return;
        }
        Counters counters = new Counters();
        RefIndex index = RefIndex.build(context.classes().classes().values());
        for (ClassNode node : new ArrayList<ClassNode>(context.classes().classes().values())) {
            try {
                if (skip(context, node)) {
                    continue;
                }
                transformClass(context, node, options, counters, index);
            } catch (RuntimeException failure) {
                context.log().debug("type-confusion: failed on class %s: %s", node.name, failure);
            }
        }
        context.stats().add("typeConfusion.level", options.level);
        context.stats().add("typeConfusion.classes", counters.classes);
        context.stats().add("typeConfusion.methods", counters.methods);
        context.stats().add("typeConfusion.calls", counters.calls);
        context.stats().add("typeConfusion.fields", counters.fields);
        context.stats().add("typeConfusion.fieldSites", counters.fieldSites);
        context.stats().add("typeConfusion.refused.external", counters.refusedExternal);
        context.stats().add("typeConfusion.refused.kept", counters.refusedKept);
        context.stats().add("typeConfusion.refused.cap", counters.refusedCap);
        context.stats().add("typeConfusion.refused.verify", counters.refusedVerify);
        context.stats().add("typeConfusion.rollback.classes", counters.rolledBackClasses);
        context.log().info("type-confusion[%d]: %d methods, %d call sites, %d static fields "
                        + "(%d accesses) across %d classes; refused: %d external, %d kept, %d cap, "
                        + "%d verify; %d class rollbacks",
                options.level, counters.methods, counters.calls, counters.fields, counters.fieldSites,
                counters.classes, counters.refusedExternal, counters.refusedKept, counters.refusedCap,
                counters.refusedVerify, counters.rolledBackClasses);
    }

    private static boolean skip(PassContext context, ClassNode node) {
        if (node == null || node.name == null) {
            return true;
        }
        if ("module-info".equals(node.name) || node.name.endsWith("/module-info")) {
            return true;
        }
        if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
            return true;
        }
        if (context.rules().skipBodyTransform(node.name)) {
            return true;
        }
        if (!context.rules().transformClass(node)) {
            return true;
        }
        if (context.rules().hasKeepAnnotation(node)) {
            return true;
        }
        if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) {
            return true;
        }
        return AsmUtil.containsJsrOrRet(node);
    }

    // ------------------------------------------------------------------
    // One class
    // ------------------------------------------------------------------

    private void transformClass(PassContext context, ClassNode node, Options options,
                                Counters counters, RefIndex index) {
        List<MethodNode> originals = new ArrayList<MethodNode>(node.methods);
        List<MethodNode> backups = new ArrayList<MethodNode>(originals.size());
        for (MethodNode method : originals) {
            backups.add(MethodGate.copy(method));
        }
        List<FieldNode> originalFields = new ArrayList<FieldNode>(node.fields.size());
        for (FieldNode field : node.fields) {
            originalFields.add(copyField(field));
        }
        Map<MethodNode, MethodNode> work = new LinkedHashMap<MethodNode, MethodNode>();
        for (MethodNode method : originals) {
            work.put(method, MethodGate.copy(method));
        }
        Set<MethodNode> dirty = new LinkedHashSet<MethodNode>();
        MethodGate gate = new MethodGate(context);
        List<FieldDefault> defaults = new ArrayList<FieldDefault>();
        int classMethods = 0;
        int classCalls = 0;
        int classFields = 0;
        int classFieldSites = 0;
        try {
            // 1. Static field carriers (level 2).
            if (options.level >= 2) {
                for (FieldNode field : node.fields) {
                    if (classFields >= MAX_FIELDS_PER_CLASS) {
                        break;
                    }
                    if (!fieldEligible(context, node, field)) {
                        if (fieldPrivateStatic(field) && kept(context, node, field)) {
                            counters.refusedKept++;
                        }
                        continue;
                    }
                    if (index.hasExternalFieldAccess(node.name, field.name)) {
                        counters.refusedExternal++;
                        continue;
                    }
                    Type fieldType = Type.getType(field.desc);
                    int sites = rewriteFieldAccesses(work, node, field, dirty);
                    if (sites == 0) {
                        continue;
                    }
                    field.desc = OBJECT;
                    field.signature = null;
                    defaults.add(new FieldDefault(field.name, fieldType));
                    classFields++;
                    classFieldSites += sites;
                }
            }

            // 2. Pick eligible call targets and allocate their trampolines.
            Map<String, MethodNode> targets = new LinkedHashMap<String, MethodNode>();
            Map<String, String> trampolines = new LinkedHashMap<String, String>();
            Set<String> allocatedTrampolines = new HashSet<String>();
            for (MethodNode method : originals) {
                if (!staticMethod(method)) {
                    continue;
                }
                if (kept(context, node, method)) {
                    counters.refusedKept++;
                    continue;
                }
                if (!methodEligible(context, node, method, options)) {
                    continue;
                }
                // The original method is never modified, so calls from other
                // classes keep working with their typed ABI. A private method
                // reached from another class's bytecode is unusual (nestmate
                // direct access) and left alone.
                if (privateStaticMethod(method)
                        && index.hasExternalMethodCall(node.name, method.name, method.desc)) {
                    counters.refusedExternal++;
                    continue;
                }
                if (trampolines.size() >= MAX_METHODS_PER_CLASS) {
                    counters.refusedCap++;
                    continue;
                }
                String key = method.name + method.desc;
                targets.put(key, method);
                trampolines.put(key, allocateTrampolineName(node, context, allocatedTrampolines));
            }

            // 3. Rewrite call sites in every method of the class.
            Set<String> usedTargets = new HashSet<String>();
            for (Map.Entry<MethodNode, MethodNode> entry : work.entrySet()) {
                int rewritten = rewriteCalls(node, entry.getValue(), targets, trampolines,
                        options.maxPerMethod, usedTargets);
                classCalls += rewritten;
                if (rewritten > 0) {
                    dirty.add(entry.getKey());
                }
            }

            // 4. Boxed defaults for the re-typed static fields (before any <clinit> code).
            if (!defaults.isEmpty()) {
                applyFieldDefaults(node, work, defaults, dirty);
            }

            // 5. Install only the trampolines that actually gained a call site
            //    (targets without a rewritten site stay dead metadata otherwise).
            for (Map.Entry<String, String> entry : trampolines.entrySet()) {
                if (!usedTargets.contains(entry.getKey())) {
                    continue;
                }
                MethodNode target = targets.get(entry.getKey());
                node.methods.add(trampoline(entry.getValue(), target, node.name));
                classMethods++;
            }

            // 6. Verify every changed method on a copy; commit only verified ones.
            boolean verificationFailed = false;
            for (Map.Entry<MethodNode, MethodNode> entry : work.entrySet()) {
                MethodNode original = entry.getKey();
                MethodNode candidate = entry.getValue();
                if (!dirty.contains(original)) {
                    continue;
                }
                if (!gate.verify(node, candidate)) {
                    counters.refusedVerify++;
                    verificationFailed = true;
                    context.log().debug("type-confusion: verification rejected %s.%s",
                            node.name, original.name);
                    continue;
                }
                MethodGate.commit(original, candidate);
            }
            if (verificationFailed && classFields > 0) {
                // A re-typed field is observed by every committed accessor; if any
                // accessor could not be verified the class must not keep the new
                // descriptors at all.
                restore(node, backups, originalFields);
                counters.rolledBackClasses++;
                context.log().debug("type-confusion: class %s rolled back after a field-accessor "
                        + "verification failure", node.name);
                return;
            }

            // 7. Class-level check: if the new field descriptors or trampolines do
            //    not serialize, restore methods and fields completely.
            if (classMethods > 0 || classFields > 0) {
                if (!gate.writes(node)) {
                    restore(node, backups, originalFields);
                    counters.rolledBackClasses++;
                    context.log().debug("type-confusion: class %s does not serialize, rolled back",
                            node.name);
                    return;
                }
            }
            if (classMethods > 0 || classFields > 0) {
                counters.classes++;
                counters.methods += classMethods;
                counters.calls += classCalls;
                counters.fields += classFields;
                counters.fieldSites += classFieldSites;
            }
        } catch (RuntimeException failure) {
            restore(node, backups, originalFields);
            counters.rolledBackClasses++;
            throw failure;
        }
    }

    private static void restore(ClassNode node, List<MethodNode> backups, List<FieldNode> fields) {
        node.methods = new ArrayList<MethodNode>(backups);
        node.fields = new ArrayList<FieldNode>(fields);
    }

    private static FieldNode copyField(FieldNode field) {
        return new FieldNode(field.access, field.name, field.desc, field.signature, field.value);
    }

    // ------------------------------------------------------------------
    // Method eligibility and call-site rewriting
    // ------------------------------------------------------------------

    private static boolean privateStaticMethod(MethodNode method) {
        return (method.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC))
                == (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC);
    }

    private static boolean staticMethod(MethodNode method) {
        return (method.access & Opcodes.ACC_STATIC) != 0;
    }

    private static boolean methodEligible(PassContext context, ClassNode node, MethodNode method,
                                          Options options) {
        if (!staticMethod(method)) {
            return false;
        }
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            // Constructors and <clinit> are never call targets.
            return false;
        }
        if (method.instructions == null || method.instructions.size() == 0) {
            return false;
        }
        if (AsmUtil.containsJsrOrRet(method)) {
            return false;
        }
        return options.matches(context, node, method);
    }

    private static boolean kept(PassContext context, ClassNode node, MethodNode method) {
        return context.rules().hasKeepAnnotation(method) || context.rules().keepMethod(node.name, method);
    }

    private static boolean kept(PassContext context, ClassNode node, FieldNode field) {
        return context.rules().hasKeepAnnotation(field) || context.rules().keepField(node.name, field);
    }

    /**
     * Rewrites every direct {@code INVOKESTATIC} of a mapped target inside
     * {@code caller} and returns the number of rewritten sites.
     */
    private static int rewriteCalls(ClassNode node, MethodNode caller,
                                    Map<String, MethodNode> targets, Map<String, String> trampolines,
                                    int maxPerMethod, Set<String> usedTargets) {
        if (caller.instructions == null || caller.instructions.size() == 0) {
            return 0;
        }
        int rewritten = 0;
        for (AbstractInsnNode insn = caller.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;
                if (call.getOpcode() == Opcodes.INVOKESTATIC && node.name.equals(call.owner)) {
                    String key = call.name + call.desc;
                    MethodNode target = targets.get(key);
                    if (target != null && rewritten < maxPerMethod) {
                        caller.instructions.insertBefore(call,
                                callSite(caller, call, trampolines.get(key)));
                        caller.instructions.remove(call);
                        usedTargets.add(key);
                        rewritten++;
                    }
                }
            }
            insn = next;
        }
        return rewritten;
    }

    /**
     * Emits {@code Object[] args = new Object[n]; args[i] = box(arg_i);
     * Object r = trampoline(args); unbox(r)} replacing the original static call.
     */
    private static InsnList callSite(MethodNode caller, MethodInsnNode call, String trampoline) {
        Type[] arguments = Type.getArgumentTypes(call.desc);
        Type returnType = Type.getReturnType(call.desc);
        int base = nextFreeLocal(caller);
        int[] locals = new int[arguments.length];
        int slot = base;
        for (int i = 0; i < arguments.length; i++) {
            locals[i] = slot;
            slot += arguments[i].getSize();
        }
        caller.maxLocals = Math.max(caller.maxLocals, slot > 0 ? slot : base);

        InsnList out = new InsnList();
        for (int i = arguments.length - 1; i >= 0; i--) {
            out.add(new VarInsnNode(AsmUtil.storeOpcode(arguments[i]), locals[i]));
        }
        AsmUtil.pushInt(out, arguments.length);
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        for (int i = 0; i < arguments.length; i++) {
            out.add(new InsnNode(Opcodes.DUP));
            AsmUtil.pushInt(out, i);
            out.add(new VarInsnNode(AsmUtil.loadOpcode(arguments[i]), locals[i]));
            emitBox(out, arguments[i]);
            out.add(new InsnNode(Opcodes.AASTORE));
        }
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, call.owner, trampoline,
                trampolineDesc(returnType), false));
        if (returnType.getSort() != Type.VOID) {
            emitUnbox(out, returnType);
        }
        return out;
    }

    /** Builds the synthetic trampoline that unboxes the array and calls the original. */
    private static MethodNode trampoline(String name, MethodNode target, String owner) {
        Type[] arguments = Type.getArgumentTypes(target.desc);
        Type returnType = Type.getReturnType(target.desc);
        MethodNode method = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, trampolineDesc(returnType), null, null);
        InsnList code = method.instructions;
        for (int i = 0; i < arguments.length; i++) {
            code.add(new VarInsnNode(Opcodes.ALOAD, 0));
            AsmUtil.pushInt(code, i);
            code.add(new InsnNode(Opcodes.AALOAD));
            emitUnbox(code, arguments[i]);
        }
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner, target.name, target.desc, false));
        if (returnType.getSort() == Type.VOID) {
            code.add(new InsnNode(Opcodes.RETURN));
        } else {
            emitBox(code, returnType);
            code.add(new InsnNode(Opcodes.ARETURN));
        }
        method.maxLocals = 1;
        method.maxStack = 8 + arguments.length * 2;
        return method;
    }

    private static String trampolineDesc(Type returnType) {
        return "(" + OBJECT_ARRAY + ")"
                + (returnType.getSort() == Type.VOID ? "V" : OBJECT);
    }

    // ------------------------------------------------------------------
    // Boxing helpers
    // ------------------------------------------------------------------

    private static void emitBox(InsnList out, Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN:
                out.add(wrapper("java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;"));
                break;
            case Type.BYTE:
                out.add(wrapper("java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;"));
                break;
            case Type.CHAR:
                out.add(wrapper("java/lang/Character", "valueOf", "(C)Ljava/lang/Character;"));
                break;
            case Type.SHORT:
                out.add(wrapper("java/lang/Short", "valueOf", "(S)Ljava/lang/Short;"));
                break;
            case Type.INT:
                out.add(wrapper("java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;"));
                break;
            case Type.FLOAT:
                out.add(wrapper("java/lang/Float", "valueOf", "(F)Ljava/lang/Float;"));
                break;
            case Type.LONG:
                out.add(wrapper("java/lang/Long", "valueOf", "(J)Ljava/lang/Long;"));
                break;
            case Type.DOUBLE:
                out.add(wrapper("java/lang/Double", "valueOf", "(D)Ljava/lang/Double;"));
                break;
            default:
                // Reference and array types are already objects.
                break;
        }
    }

    private static MethodInsnNode wrapper(String owner, String name, String desc) {
        return new MethodInsnNode(Opcodes.INVOKESTATIC, owner, name, desc, false);
    }

    private static void emitUnbox(InsnList out, Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN:
                unbox(out, "java/lang/Boolean", "booleanValue", "()Z");
                break;
            case Type.BYTE:
                unbox(out, "java/lang/Byte", "byteValue", "()B");
                break;
            case Type.CHAR:
                unbox(out, "java/lang/Character", "charValue", "()C");
                break;
            case Type.SHORT:
                unbox(out, "java/lang/Short", "shortValue", "()S");
                break;
            case Type.INT:
                unbox(out, "java/lang/Integer", "intValue", "()I");
                break;
            case Type.FLOAT:
                unbox(out, "java/lang/Float", "floatValue", "()F");
                break;
            case Type.LONG:
                unbox(out, "java/lang/Long", "longValue", "()J");
                break;
            case Type.DOUBLE:
                unbox(out, "java/lang/Double", "doubleValue", "()D");
                break;
            case Type.ARRAY:
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, type.getDescriptor()));
                break;
            default:
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, type.getInternalName()));
                break;
        }
    }

    private static void unbox(InsnList out, String wrapper, String name, String desc) {
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, wrapper));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, wrapper, name, desc, false));
    }

    // ------------------------------------------------------------------
    // Static field carriers
    // ------------------------------------------------------------------

    private static boolean fieldPrivateStatic(FieldNode field) {
        return (field.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC))
                == (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC);
    }

    private static boolean fieldEligible(PassContext context, ClassNode node, FieldNode field) {
        if (!fieldPrivateStatic(field)) {
            return false;
        }
        if ((field.access & Opcodes.ACC_FINAL) != 0) {
            // A final static field can carry a ConstantValue attribute that must
            // match its descriptor; changing the type would corrupt the class.
            return false;
        }
        if (OBJECT.equals(field.desc)) {
            return false;
        }
        return field.value == null;
    }

    /** Rewrites GETSTATIC/PUTSTATIC of {@code field} in the given method copies. */
    private static int rewriteFieldAccesses(Map<MethodNode, MethodNode> work, ClassNode owner,
                                            FieldNode field, Set<MethodNode> dirty) {
        Type fieldType = Type.getType(field.desc);
        int sites = 0;
        for (Map.Entry<MethodNode, MethodNode> entry : work.entrySet()) {
            MethodNode method = entry.getValue();
            if (method.instructions == null) {
                continue;
            }
            boolean changed = false;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
                AbstractInsnNode next = insn.getNext();
                if (insn instanceof FieldInsnNode) {
                    FieldInsnNode access = (FieldInsnNode) insn;
                    if ((access.getOpcode() == Opcodes.GETSTATIC || access.getOpcode() == Opcodes.PUTSTATIC)
                            && owner.name.equals(access.owner) && field.name.equals(access.name)) {
                        if (access.getOpcode() == Opcodes.GETSTATIC) {
                            access.desc = OBJECT;
                            InsnList unbox = new InsnList();
                            emitUnbox(unbox, fieldType);
                            method.instructions.insert(access, unbox);
                        } else {
                            InsnList box = new InsnList();
                            emitBox(box, fieldType);
                            method.instructions.insertBefore(access, box);
                            access.desc = OBJECT;
                        }
                        sites++;
                        changed = true;
                    }
                }
                insn = next;
            }
            if (changed) {
                dirty.add(entry.getKey());
            }
        }
        return sites;
    }

    /** Boxed default values at the start of {@code <clinit>} preserve the zero-init contract. */
    private static void applyFieldDefaults(ClassNode node, Map<MethodNode, MethodNode> work,
                                           List<FieldDefault> defaults, Set<MethodNode> dirty) {
        MethodNode original = null;
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                original = method;
                break;
            }
        }
        MethodNode candidate;
        if (original == null) {
            original = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            original.instructions.add(new InsnNode(Opcodes.RETURN));
            candidate = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            candidate.instructions.add(new InsnNode(Opcodes.RETURN));
            node.methods.add(original);
            work.put(original, candidate);
        } else {
            candidate = work.get(original);
            if (candidate == null) {
                candidate = MethodGate.copy(original);
                work.put(original, candidate);
            }
        }
        InsnList prefix = new InsnList();
        for (int i = 0; i < defaults.size(); i++) {
            FieldDefault fieldDefault = defaults.get(i);
            AsmUtil.pushDefault(prefix, fieldDefault.type);
            emitBox(prefix, fieldDefault.type);
            prefix.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, fieldDefault.name, OBJECT));
        }
        candidate.instructions.insert(prefix);
        candidate.maxStack = Math.max(candidate.maxStack, 2);
        dirty.add(original);
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

    private static String allocateTrampolineName(ClassNode node, PassContext context,
                                                 Set<String> allocated) {
        Set<String> used = new HashSet<String>(allocated);
        for (MethodNode method : node.methods) {
            used.add(method.name + method.desc);
        }
        Random random = new Random(context.config().seed() ^ node.name.hashCode() * 0x9E3779B9L);
        NameGenerator names = new NameGenerator(random, "");
        for (int attempt = 0; attempt < 10000; attempt++) {
            String candidate = "u$t" + names.random(7);
            String withVoid = candidate + '(' + OBJECT_ARRAY + ")V";
            String withObject = candidate + '(' + OBJECT_ARRAY + ')' + OBJECT;
            if (!used.contains(withVoid) && !used.contains(withObject)) {
                allocated.add(withVoid);
                allocated.add(withObject);
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to allocate a trampoline name in " + node.name);
    }

    // ------------------------------------------------------------------
    // Cross-class reference index
    // ------------------------------------------------------------------

    /**
     * One-pass index of member references whose owner is a different class than
     * the referencing one. Such members are observed from outside and must not
     * be re-typed.
     */
    private static final class RefIndex {
        private final Set<String> methods = new HashSet<String>();
        private final Set<String> fields = new HashSet<String>();

        static RefIndex build(Iterable<ClassNode> classes) {
            RefIndex index = new RefIndex();
            for (ClassNode node : classes) {
                for (MethodNode method : node.methods) {
                    if (method.instructions == null) {
                        continue;
                    }
                    for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                         insn = insn.getNext()) {
                        if (insn instanceof MethodInsnNode) {
                            MethodInsnNode call = (MethodInsnNode) insn;
                            if (!node.name.equals(call.owner)) {
                                index.methods.add(call.owner + '#' + call.name + '#' + call.desc);
                            }
                        } else if (insn instanceof FieldInsnNode) {
                            FieldInsnNode access = (FieldInsnNode) insn;
                            if (!node.name.equals(access.owner)) {
                                index.fields.add(access.owner + '#' + access.name);
                            }
                        }
                    }
                }
            }
            return index;
        }

        boolean hasExternalMethodCall(String owner, String name, String desc) {
            return methods.contains(owner + '#' + name + '#' + desc);
        }

        boolean hasExternalFieldAccess(String owner, String name) {
            return fields.contains(owner + '#' + name);
        }
    }

    // ------------------------------------------------------------------
    // Options
    // ------------------------------------------------------------------

    /** Resolved pass configuration and method-glob matcher. */
    static final class Options {
        private boolean enabled;
        private int level = 1;
        private int maxPerMethod = 64;
        private List<Pattern> patterns = new ArrayList<Pattern>();

        static Options resolve(PassContext context) {
            Options options = new Options();
            options.enabled = context.config().optionBool("typeConfusion.enabled", false);
            options.level = context.config().optionInt("typeConfusion.level", 1);
            if (options.level < 1) {
                options.level = 1;
            } else if (options.level > 2) {
                options.level = 2;
            }
            options.maxPerMethod = Math.max(1,
                    context.config().optionInt("typeConfusion.maxPerMethod", 64));
            String raw = context.config().option("typeConfusion.methods", "**");
            if (raw != null) {
                String[] tokens = raw.split("[,;\\s]+");
                for (int i = 0; i < tokens.length; i++) {
                    if (!tokens[i].isEmpty()) {
                        options.patterns.add(Pattern.parse(tokens[i]));
                    }
                }
            }
            if (options.patterns.isEmpty()) {
                options.patterns.add(Pattern.parse("**"));
            }
            return options;
        }

        /** True when the method matches {@code typeConfusion.methods}. */
        boolean matches(PassContext context, ClassNode node, MethodNode method) {
            for (int i = 0; i < patterns.size(); i++) {
                if (patterns.get(i).matches(node.name, method.name)) {
                    return true;
                }
            }
            String originalClass = context.mappings().reverseClasses().get(node.name);
            if (originalClass == null) {
                return false;
            }
            String originalMethod = originalMethodName(context, node.name, originalClass,
                    method.name, method.desc);
            if (originalMethod == null) {
                return false;
            }
            for (int i = 0; i < patterns.size(); i++) {
                if (patterns.get(i).matches(originalClass, originalMethod)) {
                    return true;
                }
            }
            return false;
        }

        private static String originalMethodName(PassContext context, String currentOwner,
                                                 String originalOwner, String currentName,
                                                 String desc) {
            for (Map.Entry<String, String> entry : context.mappings().methods().entrySet()) {
                if (!entry.getValue().equals(currentName)) {
                    continue;
                }
                String key = entry.getKey();
                int first = key.indexOf('#');
                int last = key.lastIndexOf('#');
                if (first < 0 || last <= first) {
                    continue;
                }
                String owner = key.substring(0, first);
                String keyDesc = key.substring(last + 1);
                if (!desc.equals(keyDesc)) {
                    continue;
                }
                if (owner.equals(currentOwner) || owner.equals(originalOwner)) {
                    return key.substring(first + 1, last);
                }
            }
            return null;
        }
    }

    /** One {@code Class#method} glob (the method part may be {@code *}). */
    private static final class Pattern {
        private final Glob classGlob;
        private final String methodName;

        private Pattern(Glob classGlob, String methodName) {
            this.classGlob = classGlob;
            this.methodName = methodName;
        }

        static Pattern parse(String raw) {
            int hash = raw.indexOf('#');
            if (hash < 0) {
                return new Pattern(new Glob(raw), "*");
            }
            return new Pattern(new Glob(raw.substring(0, hash)), raw.substring(hash + 1));
        }

        boolean matches(String className, String method) {
            if (!classGlob.matches(className)) {
                return false;
            }
            return "*".equals(methodName) || methodName.equals(method);
        }
    }

    /** Field that was re-typed to Object and needs a boxed default in <clinit>. */
    private static final class FieldDefault {
        private final String name;
        private final Type type;

        private FieldDefault(String name, Type type) {
            this.name = name;
            this.type = type;
        }
    }

    /** Mutable statistics holder for one run. */
    private static final class Counters {
        private int classes;
        private int methods;
        private int calls;
        private int fields;
        private int fieldSites;
        private int refusedExternal;
        private int refusedKept;
        private int refusedCap;
        private int refusedVerify;
        private int rolledBackClasses;
    }
}
