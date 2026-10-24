package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.model.ClassInfo;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Adds one unused trailing {@code int} parameter to private methods and updates
 * every direct call site.
 *
 * <p>Only private methods with at least one direct call site are changed; methods
 * referenced through method handles are skipped so that lambdas and method
 * references stay valid. The pass is off by default.</p>
 */
public final class ParameterObfuscationPass implements Pass {

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
        Map<String, Change> candidates = new HashMap<String, Change>();

        for (ClassNode node : context.classes().classes().values()) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
                if (context.rules().skipBodyTransform(node.name)) {
                    continue;
                }
            if (!context.rules().transformClass(node)) {
                continue;
            }
            for (MethodNode method : node.methods) {
                if ((method.access & Opcodes.ACC_PRIVATE) == 0) {
                    continue;
                }
                if ((method.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) {
                    continue;
                }
                if (method.name.startsWith("<") || "main".equals(method.name)) {
                    continue;
                }
                if (context.rules().keepMethod(node.name, method)) {
                    continue;
                }
                if (method.visibleParameterAnnotations != null || method.invisibleParameterAnnotations != null) {
                    continue;
                }
                // The appended parameter occupies the first slot after the
                // existing arguments. Only methods whose locals already end
                // there can be changed safely without shifting local indices.
                if (method.maxLocals > argumentSlots(method)) {
                    continue;
                }
                String key = node.name + "#" + method.name + "#" + method.desc;
                if (handleKeys.contains(key)) {
                    continue;
                }
                candidates.put(key, new Change(node.name, method, method.desc, appendInt(method.desc)));
            }
        }
        if (candidates.isEmpty()) {
            context.log().info("parameter-obfuscation: no eligible private methods");
            return;
        }

        // Count direct call sites and remember which candidates are actually used.
        Map<Change, Integer> callCounts = new HashMap<Change, Integer>();
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
                    Change change = resolveCandidate(context, candidates, call);
                    if (change != null) {
                        Integer count = callCounts.get(change);
                        callCounts.put(change, Integer.valueOf(count == null ? 1 : count.intValue() + 1));
                    }
                }
            }
        }

        int changed = 0;
        int callsites = 0;
        for (Map.Entry<Change, Integer> entry : callCounts.entrySet()) {
            Change change = entry.getKey();
            if (entry.getValue().intValue() <= 0) {
                continue;
            }
            change.method.desc = change.newDesc;
            change.method.signature = null;
            int slots = argumentSlots(change.method);
            change.method.maxLocals = Math.max(change.method.maxLocals, slots);
            changed++;
        }
        if (changed == 0) {
            context.log().info("parameter-obfuscation: no methods had direct call sites");
            return;
        }

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
                    Change change = resolveCandidate(context, candidates, call);
                    if (change == null || !change.method.desc.equals(change.newDesc)) {
                        continue;
                    }
                    org.objectweb.asm.tree.InsnList push = new org.objectweb.asm.tree.InsnList();
                    AsmUtil.pushInt(push, 0);
                    method.instructions.insertBefore(call, push);
                    call.desc = change.newDesc;
                    callsites++;
                }
            }
        }

        // Parameter descriptors changed; refresh hierarchy members for later passes.
        for (ClassNode node : context.classes().classes().values()) {
            if (!context.classes().isGenerated(node.name)) {
                context.hierarchy().addInput(node);
            }
        }
        context.stats().add("parameters.changed", changed);
        context.stats().add("parameters.callsites", callsites);
        context.log().info("parameter-obfuscation: changed %d private methods (%d call sites)",
                changed, callsites);
    }

    private static Change resolveCandidate(PassContext context, Map<String, Change> candidates,
                                           MethodInsnNode call) {
        String direct = call.owner + "#" + call.name + "#" + call.desc;
        Change change = candidates.get(direct);
        if (change != null) {
            return change;
        }
        ClassInfo declaring = context.hierarchy().resolveMethod(call.owner, call.name, call.desc);
        if (declaring == null) {
            return null;
        }
        return candidates.get(declaring.name() + "#" + call.name + "#" + call.desc);
    }

    private static int argumentSlots(org.objectweb.asm.tree.MethodNode method) {
        int slots = (method.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (org.objectweb.asm.Type type : org.objectweb.asm.Type.getArgumentTypes(method.desc)) {
            slots += type.getSize();
        }
        return slots;
    }

    private static String appendInt(String desc) {
        int close = desc.indexOf(')');
        return desc.substring(0, close) + "I" + desc.substring(close);
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

    private static final class Change {
        final String owner;
        final MethodNode method;
        final String oldDesc;
        final String newDesc;

        Change(String owner, MethodNode method, String oldDesc, String newDesc) {
            this.owner = owner;
            this.method = method;
            this.oldDesc = oldDesc;
            this.newDesc = newDesc;
        }
    }
}
