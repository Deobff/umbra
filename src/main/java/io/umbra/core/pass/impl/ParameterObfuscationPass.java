package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.model.ClassInfo;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Method parameter obfuscation with a packed key carrier.
 *
 * <p>Eligible private methods get one extra trailing {@code long}. That value is
 * not a decorative constant: it carries three fields and the method head
 * unpacks them into new locals:</p>
 *
 * <pre>
 *   bits 63..56  site index   (per call site, so two calls never carry the same value)
 *   bits 55..48  method index (per protected method)
 *   bits 47..00  rolling key material
 * </pre>
 *
 * <p>The unpacked values guard a genuinely unreachable dead block through an
 * always-true comparison that no decompiler can fold without evaluating the
 * carrier, so the parameter is read on every execution path. Direct call sites
 * are rewritten to push their own carrier, which keeps the parameter alive and
 * makes each call site unique.</p>
 *
 * <p>Exemptions are strict: only private methods, never {@code <init>}/{@code main},
 * never a method referenced through a {@code MethodHandle}/{@code invokedynamic}
 * bootstrap, never a name that appears in a reflective lookup, and never a
 * method the rule set keeps.</p>
 */
public final class ParameterObfuscationPass implements Pass {

    /** Where the site index starts inside the carrier long. */
    private static final int SITE_SHIFT = 56;
    /** Where the method index starts inside the carrier long. */
    private static final int METHOD_SHIFT = 48;
    /** Low bits reserved for key material. */
    private static final long PAYLOAD_MASK = 0xFFFFFFFFFFFFL;

    private static final long INDEX_MASK = 0xFFL;

    @Override
    public String name() {
        return "parameter-obfuscation";
    }

    @Override
    public int order() {
        return 48;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().parameterObfuscation().enabled();
    }

    @Override
    public void run(PassContext context) {
        Set<String> handleKeys = scanHandles(context);
        Set<String> reflectiveNames = scanReflectiveNames(context);

        List<Change> changes = new ArrayList<Change>();
        int methodIndex = 0;
        for (ClassNode node : context.classes().classes().values()) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
            if (context.rules().skipBodyTransform(node.name)) {
                continue;
            }
            if ((node.access & Opcodes.ACC_INTERFACE) != 0) {
                continue;
            }
            if (!context.rules().transformClass(node)) {
                continue;
            }
            for (MethodNode method : node.methods) {
                if (!eligible(context, node, method)) {
                    continue;
                }
                String key = node.name + "#" + method.name + "#" + method.desc;
                if (handleKeys.contains(key)) {
                    continue;
                }
                if (reflectiveNames.contains(method.name)) {
                    continue;
                }
                changes.add(new Change(node.name, method, method.desc, appendLong(method.desc),
                        methodIndex++, context.random().nextLong() & PAYLOAD_MASK));
            }
        }

        if (changes.isEmpty()) {
            context.log().info("parameter-obfuscation: no eligible private methods");
            return;
        }

        Map<Change, List<CallSite>> callSites = collectCallSites(context, changes);
        List<Change> applied = new ArrayList<Change>();
        for (Change change : changes) {
            List<CallSite> sites = callSites.get(change);
            if (sites != null && !sites.isEmpty()) {
                applied.add(change);
            }
        }
        if (applied.isEmpty()) {
            context.log().info("parameter-obfuscation: no methods had direct call sites");
            return;
        }

        int rewritten = 0;
        for (Change change : applied) {
            applySignature(context, change);
            rewritten++;
        }

        int sites = 0;
        for (Change change : applied) {
            int site = 0;
            for (CallSite callSite : callSites.get(change)) {
                long carrier = pack(change.methodIndex, site++, change.payload);
                InsnList push = new InsnList();
                push.add(new LdcInsnNode(Long.valueOf(carrier)));
                callSite.method.instructions.insertBefore(callSite.insn, push);
                callSite.insn.desc = change.newDesc;
                sites++;
            }
        }

        for (ClassNode node : context.classes().classes().values()) {
            if (!context.classes().isGenerated(node.name)) {
                context.hierarchy().addInput(node);
            }
        }

        context.stats().add("parameters.changed", rewritten);
        context.stats().add("parameters.callsites", sites);
        context.log().info("parameter-obfuscation: packed a long carrier into %d private "
                + "method(s) across %d call site(s)", Integer.valueOf(rewritten), Integer.valueOf(sites));
    }

    private static boolean eligible(PassContext context, ClassNode node, MethodNode method) {
        if ((method.access & Opcodes.ACC_PRIVATE) == 0) {
            return false;
        }
        if ((method.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) {
            return false;
        }
        if (method.name.startsWith("<") || "main".equals(method.name)) {
            return false;
        }
        if (context.rules().keepMethod(node.name, method)) {
            return false;
        }
        if (method.visibleParameterAnnotations != null || method.invisibleParameterAnnotations != null) {
            return false;
        }
        if (method.visibleAnnotations != null || method.invisibleAnnotations != null) {
            return false;
        }
        if (isSerializationHook(method.name)) {
            return false;
        }
        return method.instructions != null && method.instructions.size() > 0;
    }

    private static boolean isSerializationHook(String name) {
        return "readObject".equals(name) || "writeObject".equals(name)
                || "readResolve".equals(name) || "writeReplace".equals(name)
                || "readObjectNoData".equals(name);
    }

    private static long pack(int methodIndex, int siteIndex, long payload) {
        return ((long) (siteIndex & INDEX_MASK) << SITE_SHIFT)
                | ((long) (methodIndex & INDEX_MASK) << METHOD_SHIFT)
                | (payload & PAYLOAD_MASK);
    }

    private static void applySignature(PassContext context, Change change) {
        MethodNode method = change.method;
        int oldSlots = argumentSlots(method);
        shiftLocalSlots(method, oldSlots, 2);
        method.desc = change.newDesc;
        method.signature = null;
        int slots = argumentSlots(method);
        method.maxLocals = Math.max(method.maxLocals, slots);

        int carrier = oldSlots;
        int keySlot = carrier + 2;
        int siteSlot = keySlot + 2;
        int methodSlot = siteSlot + 1;
        method.maxLocals = Math.max(method.maxLocals, methodSlot + 1);

        InsnList head = new InsnList();
        LabelNode live = new LabelNode();

        head.add(new VarInsnNode(Opcodes.LLOAD, carrier));
        head.add(new VarInsnNode(Opcodes.LSTORE, keySlot));

        head.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
        head.add(new LdcInsnNode(Integer.valueOf(SITE_SHIFT)));
        head.add(new InsnNode(Opcodes.LUSHR));
        head.add(new InsnNode(Opcodes.L2I));
        head.add(new VarInsnNode(Opcodes.ISTORE, siteSlot));

        head.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
        head.add(new LdcInsnNode(Integer.valueOf(METHOD_SHIFT)));
        head.add(new InsnNode(Opcodes.LUSHR));
        head.add(new InsnNode(Opcodes.L2I));
        head.add(new LdcInsnNode(Integer.valueOf(0xFF)));
        head.add(new InsnNode(Opcodes.IAND));
        head.add(new VarInsnNode(Opcodes.ISTORE, methodSlot));

        // Always-true guard: (key >>> 63 & 1) is 0 or 1, so it can never equal 2.
        // The parameter is therefore read on every path and the dead block below
        // is unreachable, but a decompiler cannot prove that without the carrier.
        head.add(new VarInsnNode(Opcodes.LLOAD, keySlot));
        head.add(new LdcInsnNode(Integer.valueOf(63)));
        head.add(new InsnNode(Opcodes.LUSHR));
        head.add(new LdcInsnNode(Integer.valueOf(1)));
        head.add(new InsnNode(Opcodes.LAND));
        head.add(new InsnNode(Opcodes.L2I));
        head.add(new LdcInsnNode(Integer.valueOf(2)));
        head.add(new JumpInsnNode(Opcodes.IF_ICMPNE, live));

        head.add(new InsnNode(Opcodes.ACONST_NULL));
        head.add(new InsnNode(Opcodes.ATHROW));

        head.add(live);

        method.instructions.insert(head);
    }

    private static Map<Change, List<CallSite>> collectCallSites(PassContext context, List<Change> changes) {
        Map<String, Change> byKey = new HashMap<String, Change>();
        for (Change change : changes) {
            byKey.put(change.owner + "#" + change.method.name + "#" + change.oldDesc, change);
        }
        Map<Change, List<CallSite>> result = new LinkedHashMap<Change, List<CallSite>>();
        for (ClassNode node : context.classes().classes().values()) {
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode)) {
                        continue;
                    }
                    MethodInsnNode call = (MethodInsnNode) insn;
                    Change change = resolve(context, byKey, call);
                    if (change == null) {
                        continue;
                    }
                    List<CallSite> sites = result.get(change);
                    if (sites == null) {
                        sites = new ArrayList<CallSite>();
                        result.put(change, sites);
                    }
                    sites.add(new CallSite(method, call));
                }
            }
        }
        return result;
    }

    private static Change resolve(PassContext context, Map<String, Change> byKey, MethodInsnNode call) {
        String direct = call.owner + "#" + call.name + "#" + call.desc;
        Change change = byKey.get(direct);
        if (change != null) {
            return change;
        }
        ClassInfo declaring = context.hierarchy().resolveMethod(call.owner, call.name, call.desc);
        if (declaring == null) {
            return null;
        }
        return byKey.get(declaring.name() + "#" + call.name + "#" + call.desc);
    }

    private static int argumentSlots(MethodNode method) {
        int slots = (method.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type type : Type.getArgumentTypes(method.desc)) {
            slots += type.getSize();
        }
        return slots;
    }

    private static String appendLong(String desc) {
        int close = desc.indexOf(')');
        return desc.substring(0, close) + "J" + desc.substring(close);
    }

    /**
     * Moves every local-variable slot at or above {@code from} by {@code delta}
     * so the appended long parameter has room, and keeps the local-variable
     * table in sync.
     */
    private static void shiftLocalSlots(MethodNode method, int from, int delta) {
        if (method.instructions != null) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof VarInsnNode) {
                    VarInsnNode variable = (VarInsnNode) insn;
                    if (variable.var >= from) {
                        variable.var += delta;
                    }
                } else if (insn instanceof IincInsnNode) {
                    IincInsnNode inc = (IincInsnNode) insn;
                    if (inc.var >= from) {
                        inc.var += delta;
                    }
                }
            }
        }
        if (method.localVariables != null) {
            for (LocalVariableNode local : method.localVariables) {
                if (local.index >= from) {
                    local.index += delta;
                }
            }
        }
        method.maxLocals += delta;
    }

    private static Set<String> scanHandles(PassContext context) {
        Set<String> keys = new LinkedHashSet<String>();
        for (ClassNode node : context.classes().classes().values()) {
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof InvokeDynamicInsnNode) {
                        InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) insn;
                        addHandle(indy.bsm, keys);
                        for (Object arg : indy.bsmArgs) {
                            if (arg instanceof Handle) {
                                addHandle((Handle) arg, keys);
                            }
                        }
                    } else if (insn instanceof LdcInsnNode) {
                        Object cst = ((LdcInsnNode) insn).cst;
                        if (cst instanceof Handle) {
                            addHandle((Handle) cst, keys);
                        } else if (cst instanceof ConstantDynamic) {
                            ConstantDynamic dynamic = (ConstantDynamic) cst;
                            addHandle(dynamic.getBootstrapMethod(), keys);
                            for (int i = 0; i < dynamic.getBootstrapMethodArgumentCount(); i++) {
                                Object arg = dynamic.getBootstrapMethodArgument(i);
                                if (arg instanceof Handle) {
                                    addHandle((Handle) arg, keys);
                                }
                            }
                        }
                    }
                }
            }
        }
        return keys;
    }

    private static void addHandle(Handle handle, Set<String> keys) {
        if (handle != null) {
            keys.add(handle.getOwner() + "#" + handle.getName() + "#" + handle.getDesc());
        }
    }

    /**
     * Member names handed to a reflective lookup near the call site. A method
     * whose name shows up there must keep its signature, because the lookup
     * resolves it by descriptor.
     */
    private static Set<String> scanReflectiveNames(PassContext context) {
        Set<String> names = new LinkedHashSet<String>();
        for (ClassNode node : context.classes().classes().values()) {
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                String last = null;
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof LdcInsnNode) {
                        Object cst = ((LdcInsnNode) insn).cst;
                        if (cst instanceof String) {
                            last = (String) cst;
                        }
                        continue;
                    }
                    if (!(insn instanceof MethodInsnNode)) {
                        continue;
                    }
                    MethodInsnNode call = (MethodInsnNode) insn;
                    if (last != null && isLookup(call)) {
                        names.add(last);
                    }
                    last = null;
                }
            }
        }
        return names;
    }

    private static boolean isLookup(MethodInsnNode call) {
        if ("java/lang/Class".equals(call.owner)) {
            return "getMethod".equals(call.name) || "getDeclaredMethod".equals(call.name)
                    || "getField".equals(call.name) || "getDeclaredField".equals(call.name);
        }
        return "java/lang/invoke/MethodHandles$Lookup".equals(call.owner);
    }

    private static final class CallSite {
        final MethodNode method;
        final MethodInsnNode insn;

        CallSite(MethodNode method, MethodInsnNode insn) {
            this.method = method;
            this.insn = insn;
        }
    }

    private static final class Change {
        final String owner;
        final MethodNode method;
        final String oldDesc;
        final String newDesc;
        final int methodIndex;
        final long payload;

        Change(String owner, MethodNode method, String oldDesc, String newDesc,
               int methodIndex, long payload) {
            this.owner = owner;
            this.method = method;
            this.oldDesc = oldDesc;
            this.newDesc = newDesc;
            this.methodIndex = methodIndex;
            this.payload = payload;
        }
    }
}
