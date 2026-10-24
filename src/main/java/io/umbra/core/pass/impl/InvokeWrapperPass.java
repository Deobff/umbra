package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.model.ClassInfo;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Wraps static calls to program methods in generated forwarding methods.
 *
 * <p>Only calls whose declaring method is accessible from the caller are
 * wrapped, and only input classes participate. The pass is off by default
 * because it increases method count noticeably.</p>
 */
public final class InvokeWrapperPass implements Pass {

    @Override
    public String name() {
        return "invoke-wrapper";
    }

    @Override
    public int order() {
        return 45;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().invokeWrapper().enabled();
    }

    @Override
    public void run(PassContext context) {
        int total = 0;
        int limit = context.config().invokeWrapper().maxPerClass();
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
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0
                    || "module-info".equals(node.name)) {
                continue;
            }

            Set<String> methodNames = new HashSet<String>();
            for (MethodNode method : node.methods) {
                methodNames.add(method.name);
            }
            List<Wrapper> wrappers = new ArrayList<Wrapper>();
            int created = 0;

            for (MethodNode method : node.methods) {
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (created >= limit) {
                        break;
                    }
                    if (!(insn instanceof MethodInsnNode)) {
                        continue;
                    }
                    MethodInsnNode call = (MethodInsnNode) insn;
                    if (call.getOpcode() != Opcodes.INVOKESTATIC) {
                        continue;
                    }
                    if (call.name.startsWith("<")) {
                        continue;
                    }
                    ClassInfo declaring = context.hierarchy().resolveMethod(call.owner, call.name, call.desc);
                    if (declaring == null || !declaring.isInput()) {
                        continue;
                    }
                    Integer access = declaring.methodAccess(call.name, call.desc);
                    if (access == null || (access & Opcodes.ACC_STATIC) == 0) {
                        continue;
                    }
                    if (!accessible(context.hierarchy(), node, declaring, access)) {
                        continue;
                    }
                    String wrapperName = unique(methodNames, "z$w");
                    wrappers.add(new Wrapper(method, call, wrapperName));
                    created++;
                }
            }

            for (Wrapper wrapper : wrappers) {
                node.methods.add(wrapperMethod(wrapper));
                wrapper.callSite.instructions.set(wrapper.call,
                        new MethodInsnNode(Opcodes.INVOKESTATIC, node.name, wrapper.name, wrapper.call.desc, false));
            }
            total += wrappers.size();
        }
        context.stats().add("wrapper.methods", total);
        context.log().info("invoke-wrapper: created %d forwarding methods", total);
    }

    private static boolean accessible(Hierarchy hierarchy, ClassNode caller, ClassInfo declaring, int access) {
        if ((access & Opcodes.ACC_PUBLIC) != 0) {
            return true;
        }
        if (caller.name.equals(declaring.name())) {
            return true;
        }
        if ((access & Opcodes.ACC_PROTECTED) != 0
                && hierarchy.isAssignableFrom(declaring.name(), caller.name)) {
            return true;
        }
        return packageOf(caller.name).equals(packageOf(declaring.name()));
    }

    private static MethodNode wrapperMethod(Wrapper wrapper) {
        MethodInsnNode call = wrapper.call;
        MethodNode method = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                wrapper.name, call.desc, null, null);
        Type[] args = Type.getArgumentTypes(call.desc);
        int slot = 0;
        for (Type arg : args) {
            method.instructions.add(new VarInsnNode(AsmUtil.loadOpcode(arg), slot));
            slot += arg.getSize();
        }
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, call.owner, call.name, call.desc, call.itf));
        Type returnType = Type.getReturnType(call.desc);
        method.instructions.add(new InsnNode(AsmUtil.returnOpcode(returnType)));
        method.maxLocals = slot;
        method.maxStack = slot + 1;
        return method;
    }

    private static String packageOf(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? "" : internalName.substring(0, slash);
    }

    private static String unique(Set<String> names, String prefix) {
        int counter = 0;
        String candidate;
        do {
            candidate = prefix + Integer.toHexString(counter++);
        } while (names.contains(candidate));
        names.add(candidate);
        return candidate;
    }

    private static final class Wrapper {
        final MethodNode callSite;
        final MethodInsnNode call;
        final String name;

        Wrapper(MethodNode callSite, MethodInsnNode call, String name) {
            this.callSite = callSite;
            this.call = call;
            this.name = name;
        }
    }
}
