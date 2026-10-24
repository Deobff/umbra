package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.rules.RuleSet;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Conservative reflection analysis.
 *
 * <p>Scans string constants near reflection calls and adds exact keep rules
 * before renaming. This is intentionally heuristic: a missed edge case is
 * covered by user keep rules, while a false positive only reduces obfuscation.</p>
 */
public final class ReflectionAnalysisPass implements Pass {

    private static final int LOOKBACK = 6;

    @Override
    public String name() {
        return "reflection-analysis";
    }

    @Override
    public int order() {
        return 12;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().reflection().enabled();
    }

    @Override
    public void run(PassContext context) {
        Set<String> classKeeps = new LinkedHashSet<String>();
        Set<String> memberKeeps = new LinkedHashSet<String>();

        for (ClassNode node : context.classes().classes().values()) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                String lastString = null;
                int age = LOOKBACK + 1;
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof String) {
                        lastString = (String) ((LdcInsnNode) insn).cst;
                        age = 0;
                        continue;
                    }
                    if (insn instanceof MethodInsnNode) {
                        MethodInsnNode call = (MethodInsnNode) insn;
                        if (lastString != null && age <= LOOKBACK) {
                            classify(call, lastString, classKeeps, memberKeeps);
                        }
                        lastString = null;
                        age = LOOKBACK + 1;
                        continue;
                    }
                    age++;
                    if (age > LOOKBACK) {
                        lastString = null;
                    }
                }
            }
        }

        RuleSet rules = context.rules();
        boolean rewriteClassStrings = context.config().reflection().rewriteClassStrings();
        if (rules instanceof DefaultRuleSet) {
            DefaultRuleSet defaults = (DefaultRuleSet) rules;
            if (!rewriteClassStrings) {
                for (String className : classKeeps) {
                    defaults.addKeepRule(className);
                }
            }
            for (String member : memberKeeps) {
                defaults.addKeepRule("**#" + member);
            }
        }
        context.stats().add("reflection.autoKeep.classes",
                rewriteClassStrings ? 0 : classKeeps.size());
        context.stats().add("reflection.autoKeep.members", memberKeeps.size());
        context.log().info("reflection-analysis: %s %d classes and kept %d member names from reflection call sites",
                rewriteClassStrings ? "rewriting strings for" : "kept",
                classKeeps.size(), memberKeeps.size());
    }

    private static void classify(MethodInsnNode call, String value,
                                 Set<String> classKeeps, Set<String> memberKeeps) {
        if ("java/lang/Class".equals(call.owner)
                && ("forName".equals(call.name) || "loadClass".equals(call.name))) {
            if (looksLikeClass(value)) {
                classKeeps.add(value.trim());
            }
            return;
        }
        if (("java/lang/ClassLoader".equals(call.owner) || call.owner.endsWith("ClassLoader"))
                && "loadClass".equals(call.name)) {
            if (looksLikeClass(value)) {
                classKeeps.add(value.trim());
            }
            return;
        }
        if ("java/lang/Class".equals(call.owner)
                && ("getDeclaredMethod".equals(call.name) || "getMethod".equals(call.name))) {
            if (looksLikeIdentifier(value)) {
                memberKeeps.add(value.trim());
            }
            return;
        }
        if ("java/lang/Class".equals(call.owner)
                && ("getDeclaredField".equals(call.name) || "getField".equals(call.name))) {
            if (looksLikeIdentifier(value)) {
                memberKeeps.add(value.trim());
            }
            return;
        }
        if ("java/lang/invoke/MethodHandles$Lookup".equals(call.owner)
                && ("findVirtual".equals(call.name)
                || "findStatic".equals(call.name)
                || "findSpecial".equals(call.name))) {
            if (looksLikeIdentifier(value)) {
                memberKeeps.add(value.trim());
            }
        }
    }

    private static boolean looksLikeClass(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty() || trimmed.indexOf(' ') >= 0) {
            return false;
        }
        return trimmed.indexOf('.') > 0 || trimmed.indexOf('/') > 0;
    }

    private static boolean looksLikeIdentifier(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return false;
        }
        char first = trimmed.charAt(0);
        if (!Character.isJavaIdentifierStart(first)) {
            return false;
        }
        for (int i = 1; i < trimmed.length(); i++) {
            if (!Character.isJavaIdentifierPart(trimmed.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
