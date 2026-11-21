package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.rules.RuleSet;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Reflection analysis with constant propagation.
 *
 * <p>Scans every method for reflection call sites and recovers the class and
 * member names reachable from it. Unlike a bare "string literal next to a
 * reflective call" heuristic this pass tracks values through the method:</p>
 *
 * <ul>
 *   <li>local variables: LDC -&gt; ASTORE n is remembered and resolved on the
 *       matching ALOAD n (flow-insensitive per slot);</li>
 *   <li>string building: StringBuilder/StringBuffer append/toString chains and
 *       String.concat are folded into one value;</li>
 *   <li>class handles: Class.forName(...) / loadClass(...) results are
 *       remembered as a class context so a following getDeclaredMethod("m")
 *       is attributed to that exact owner instead of a global **#m rule;</li>
 *   <li>lookup chains: the class context survives an ASTORE/ALOAD pair and
 *       expires after a bounded number of instructions.</li>
 * </ul>
 *
 * <p>The pass is deliberately conservative: a false positive only reduces
 * obfuscation, never correctness. A false negative is reported as a warning.
 * Every method is guarded independently.</p>
 */
public final class ReflectionAnalysisPass implements Pass {

    private static final int WINDOW = 64;
    private static final int MIN_SAFE_GUESS = 4;
    private static final int CLASS_CONTEXT_WINDOW = 32;

    private static final String CLASS = "java/lang/Class";
    private static final String CLASS_LOADER = "java/lang/ClassLoader";
    private static final String STRING = "java/lang/String";
    private static final String LOOKUP = "java/lang/invoke/MethodHandles$Lookup";
    private static final String STRING_BUILDER = "java/lang/StringBuilder";
    private static final String STRING_BUFFER = "java/lang/StringBuffer";

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
        Set<String> scopedMembers = new LinkedHashSet<String>();
        Set<String> weakNames = new LinkedHashSet<String>();
        int[] counters = new int[3];

        for (ClassNode node : context.classes().classes().values()) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
            // Kept classes are not renamed, but their reflection strings can
            // still point at classes that *are* renamed, so they must be
            // scanned as well.
            for (MethodNode method : node.methods) {
                try {
                    scanMethod(context, node, method, classKeeps, memberKeeps, scopedMembers,
                            weakNames, counters);
                } catch (RuntimeException failure) {
                    context.log().debug("reflection-analysis: skipped %s.%s%s (%s)",
                            node.name, method.name, method.desc, failure.toString());
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
            for (String scoped : scopedMembers) {
                defaults.addKeepRule(scoped);
            }
        }

        context.stats().add("reflection.callsites", counters[0]);
        context.stats().add("reflection.autoKeep.classes",
                rewriteClassStrings ? 0 : classKeeps.size());
        context.stats().add("reflection.autoKeep.members", memberKeeps.size());
        context.stats().add("reflection.autoKeep.scopedMembers", scopedMembers.size());
        context.stats().add("reflection.weakNames", weakNames.size());

        context.log().info("reflection-analysis: %d call site(s); %s %d class name(s), "
                        + "kept %d member name(s) globally and %d per owner",
                Integer.valueOf(counters[0]),
                rewriteClassStrings ? "rewriting" : "keeping",
                Integer.valueOf(classKeeps.size()),
                Integer.valueOf(memberKeeps.size()),
                Integer.valueOf(scopedMembers.size()));
        if (!weakNames.isEmpty()) {
            context.log().warn("reflection-analysis: %d short reflected name(s) are kept as-is "
                    + "and remain brute-forceable: %s", Integer.valueOf(weakNames.size()), weakNames);
        }
    }

    private static void scanMethod(PassContext context, ClassNode owner, MethodNode method,
                                   Set<String> classKeeps, Set<String> memberKeeps,
                                   Set<String> scopedMembers, Set<String> weakNames,
                                   int[] counters) {
        InsnList insns = method.instructions;
        if (insns == null || insns.size() == 0) {
            return;
        }

        Map<Integer, String> stringLocals = new HashMap<Integer, String>();
        Map<Integer, String> classLocals = new HashMap<Integer, String>();

        String lastString = null;
        String prevString = null;
        String classRef = null;
        int age = 0;

        StringBuilder concat = null;
        int classContextAge = CLASS_CONTEXT_WINDOW + 1;
        String classContext = null;

        for (AbstractInsnNode insn = insns.getFirst(); insn != null; insn = insn.getNext()) {
            int op = insn.getOpcode();
            classContextAge++;

            if (insn instanceof LdcInsnNode) {
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof String) {
                    String text = (String) constant;
                    if (concat != null) {
                        concat.append(text);
                    }
                    prevString = lastString;
                    lastString = text;
                    age = 0;
                }
                continue;
            }

            if (insn instanceof VarInsnNode) {
                VarInsnNode variable = (VarInsnNode) insn;
                if (op == Opcodes.ASTORE) {
                    if (classRef != null) {
                        classLocals.put(Integer.valueOf(variable.var), classRef);
                        stringLocals.remove(Integer.valueOf(variable.var));
                        classRef = null;
                    } else if (lastString != null) {
                        stringLocals.put(Integer.valueOf(variable.var), lastString);
                        classLocals.remove(Integer.valueOf(variable.var));
                        lastString = null;
                    } else {
                        stringLocals.remove(Integer.valueOf(variable.var));
                        classLocals.remove(Integer.valueOf(variable.var));
                    }
                    prevString = null;
                    age = 0;
                    continue;
                }
                if (op == Opcodes.ALOAD) {
                    String knownClass = classLocals.get(Integer.valueOf(variable.var));
                    String knownString = stringLocals.get(Integer.valueOf(variable.var));
                    if (knownClass != null) {
                        classRef = knownClass;
                        age = 0;
                    }
                    if (knownString != null) {
                        lastString = knownString;
                        age = 0;
                    }
                    continue;
                }
                continue;
            }

            if (insn instanceof TypeInsnNode) {
                TypeInsnNode type = (TypeInsnNode) insn;
                if (op == Opcodes.NEW && isConcatOwner(type.desc)) {
                    concat = new StringBuilder();
                    lastString = null;
                    prevString = null;
                    classRef = null;
                }
                continue;
            }

            if (insn instanceof FieldInsnNode) {
                age++;
                if (age > WINDOW) {
                    lastString = null;
                    prevString = null;
                    classRef = null;
                }
                continue;
            }

            if (insn instanceof InsnNode || insn instanceof IntInsnNode) {
                if (op == Opcodes.POP || op == Opcodes.POP2) {
                    lastString = null;
                    prevString = null;
                    classRef = null;
                }
                continue;
            }

            if (insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;

                if (isConcatOwner(call.owner)) {
                    if ("append".equals(call.name)) {
                        if (concat == null) {
                            concat = new StringBuilder();
                        }
                        if (lastString != null) {
                            concat.append(lastString);
                            lastString = null;
                        }
                        prevString = null;
                        age = 0;
                        continue;
                    }
                    if ("toString".equals(call.name)) {
                        if (concat != null) {
                            lastString = concat.toString();
                            concat = null;
                            prevString = null;
                            classRef = null;
                            age = 0;
                        }
                        continue;
                    }
                }

                if (STRING.equals(call.owner) && "concat".equals(call.name)) {
                    if (prevString != null && lastString != null) {
                        lastString = prevString + lastString;
                    }
                    prevString = null;
                    age = 0;
                    continue;
                }

                if (STRING.equals(call.owner) && isStringPassThrough(call.name)) {
                    continue;
                }

                if (isDescriptorApi(call)) {
                    String descriptor = looksLikeDescriptor(lastString) ? lastString
                            : (looksLikeDescriptor(prevString) ? prevString : null);
                    if (descriptor != null) {
                        counters[0]++;
                        for (String cls : descriptorClasses(descriptor)) {
                            classKeeps.add(cls);
                            addOuterClasses(classKeeps, cls);
                        }
                        lastString = null;
                        prevString = null;
                        classRef = null;
                        age = 0;
                        continue;
                    }
                }

                String receiver = classContext != null ? classContext : classRef;
                Hit hit = classify(call, lastString, receiver);
                if (hit != null) {
                    counters[0]++;
                    if (hit.isClass) {
                        String internal = toInternal(hit.name);
                        if (!internal.isEmpty()) {
                            classKeeps.add(internal);
                            addOuterClasses(classKeeps, internal);
                            classContext = internal;
                            classContextAge = 0;
                            classRef = internal;
                            if (hit.name.length() < MIN_SAFE_GUESS) {
                                weakNames.add(hit.name);
                            }
                        }
                        lastString = null;
                        prevString = null;
                        age = 0;
                        continue;
                    }
                    String memberName = hit.name.trim();
                    if (!memberName.isEmpty() && isIdentifier(memberName)) {
                        if (hit.owner != null && !hit.owner.isEmpty()) {
                            scopedMembers.add(hit.owner + "#" + memberName);
                        } else {
                            memberKeeps.add(memberName);
                        }
                        if (memberName.length() < MIN_SAFE_GUESS) {
                            weakNames.add(memberName);
                        }
                    }
                    classContext = null;
                    classContextAge = CLASS_CONTEXT_WINDOW + 1;
                    lastString = null;
                    prevString = null;
                    classRef = null;
                    age = 0;
                    continue;
                }
                if (returnsClass(call)) {
                    classContext = null;
                    classContextAge = CLASS_CONTEXT_WINDOW + 1;
                }

                if (call.desc != null && call.desc.startsWith("()")) {
                    age++;
                    if (age > WINDOW) {
                        lastString = null;
                        prevString = null;
                        classRef = null;
                    }
                    continue;
                }

                lastString = null;
                prevString = null;
                classRef = null;
                age = 0;
                continue;
            }

            if (insn instanceof InvokeDynamicInsnNode) {
                lastString = null;
                prevString = null;
                classRef = null;
                concat = null;
                age = 0;
                continue;
            }

            age++;
            if (age > WINDOW) {
                lastString = null;
                prevString = null;
                classRef = null;
            }
            if (classContextAge > CLASS_CONTEXT_WINDOW) {
                classContext = null;
            }
        }
    }

    private static Hit classify(MethodInsnNode call, String value, String classContext) {
        if (value == null) {
            return null;
        }
        String owner = call.owner;
        String name = call.name;

        if (CLASS.equals(owner) && "forName".equals(name)) {
            return value.indexOf('.') > 0 || value.indexOf('/') > 0
                    ? Hit.className(value) : null;
        }
        if ((CLASS_LOADER.equals(owner) || owner.endsWith("ClassLoader")) && "loadClass".equals(name)) {
            return value.indexOf('.') > 0 || value.indexOf('/') > 0
                    ? Hit.className(value) : null;
        }

        if (CLASS.equals(owner)) {
            if ("getMethod".equals(name) || "getDeclaredMethod".equals(name)
                    || "getField".equals(name) || "getDeclaredField".equals(name)) {
                return Hit.member(classContext, value);
            }
            return null;
        }

        if (LOOKUP.equals(owner)) {
            if ("findVirtual".equals(name) || "findStatic".equals(name) || "findSpecial".equals(name)
                    || "findGetter".equals(name) || "findSetter".equals(name)
                    || "findStaticGetter".equals(name) || "findStaticSetter".equals(name)
                    || "findField".equals(name)) {
                return Hit.member(classContext, value);
            }
            return null;
        }

        if (owner.endsWith("ClassLoader") && "loadClass".equals(name)) {
            return value.indexOf('.') > 0 || value.indexOf('/') > 0 ? Hit.className(value) : null;
        }

        return null;
    }

    private static boolean isDescriptorApi(MethodInsnNode call) {
        return "java/lang/invoke/MethodType".equals(call.owner)
                && "fromMethodDescriptorString".equals(call.name);
    }

    private static boolean looksLikeDescriptor(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        if (value.charAt(0) == '(') {
            return true;
        }
        return value.indexOf('L') >= 0 && value.indexOf(';') >= 0;
    }

    private static Set<String> descriptorClasses(String descriptor) {
        Set<String> out = new LinkedHashSet<String>();
        if (descriptor == null) {
            return out;
        }
        int index = 0;
        while (index < descriptor.length()) {
            if (descriptor.charAt(index) == 'L') {
                int end = descriptor.indexOf(';', index);
                if (end < 0) {
                    break;
                }
                String internal = descriptor.substring(index + 1, end).trim();
                if (!internal.isEmpty()) {
                    out.add(internal);
                }
                index = end + 1;
            } else {
                index++;
            }
        }
        return out;
    }

    private static boolean returnsClass(MethodInsnNode call) {
        return CLASS.equals(call.owner) || LOOKUP.equals(call.owner);
    }

    private static boolean isConcatOwner(String owner) {
        return STRING_BUILDER.equals(owner) || STRING_BUFFER.equals(owner)
                || (owner != null && (owner.endsWith("StringBuilder") || owner.endsWith("StringBuffer")));
    }

    private static boolean isStringPassThrough(String name) {
        return "intern".equals(name) || "trim".equals(name) || "strip".equals(name)
                || "toString".equals(name) || "valueOf".equals(name) || "substring".equals(name);
    }

    /**
     * Nested classes are named after their outer class. Keeping a nested name
     * while the outer class is renamed breaks the InnerClasses relationship
     * (and the reflective lookup that made us keep it in the first place), so
     * every enclosing class is pinned as well.
     */
    private static void addOuterClasses(Set<String> keeps, String internal) {
        int dollar = internal.lastIndexOf('$');
        while (dollar > 0) {
            String outer = internal.substring(0, dollar);
            if (!keeps.add(outer)) {
                return;
            }
            dollar = outer.lastIndexOf('$');
        }
    }

    static String toInternal(String name) {
        if (name == null) {
            return "";
        }
        String trimmed = name.trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        int descriptor = trimmed.indexOf(';');
        if (trimmed.charAt(0) == 'L' && descriptor > 0) {
            trimmed = trimmed.substring(1, descriptor);
        }
        return trimmed.replace('.', '/');
    }

    private static boolean isIdentifier(String value) {
        if (value.isEmpty() || value.indexOf(' ') >= 0) {
            return false;
        }
        char first = value.charAt(0);
        if (!Character.isJavaIdentifierStart(first)) {
            return false;
        }
        for (int i = 1; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!Character.isJavaIdentifierPart(c)) {
                return false;
            }
        }
        return true;
    }

    private static final class Hit {
        final boolean isClass;
        final String name;
        final String owner;

        private Hit(boolean isClass, String name, String owner) {
            this.isClass = isClass;
            this.name = name;
            this.owner = owner;
        }

        static Hit className(String name) {
            return new Hit(true, name, null);
        }

        static Hit member(String owner, String name) {
            return new Hit(false, name, owner);
        }
    }
}
