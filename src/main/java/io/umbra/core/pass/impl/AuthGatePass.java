package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.model.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Injects the server-backed authorization gate call at program entry points.
 *
 * <p>The gate class (see {@code io.umbra.core.runtime.UmbraAuthGate}) is obtained
 * from {@link io.umbra.core.api.RuntimeSupport#ensureAuthGate}; this pass then
 * prepends {@code INVOKESTATIC <gate>.guard ()V} to every concrete
 * {@code static void main(String[])} and to configured entry points
 * ({@code owner#method} or {@code owner#method#desc}). Entry-point owners/methods
 * may be written with their original names: they are resolved through the rename
 * mappings produced earlier in the pipeline.</p>
 *
 * <p>Only an {@code invokestatic} is added, so class file version / stack map
 * rules are not affected. Anti-debug (order 115) inserts its own call first; both
 * calls then run at startup.</p>
 */
public final class AuthGatePass implements Pass {

    private static final String MAIN_DESC = "([Ljava/lang/String;)V";

    @Override
    public String name() {
        return "auth-gate";
    }

    @Override
    public int order() {
        return 118;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().authGate().enabled();
    }

    @Override
    public void run(PassContext context) {
        UmbraConfig.AuthGateOptions options = context.config().authGate();
        String helper = context.runtime().ensureAuthGate(context.classes(), context.config().seed(), options);
        if (helper == null) {
            context.log().warn("auth-gate: runtime support did not provide an authorization gate; skipping");
            return;
        }
        List<EntryPoint> entries = parseEntryPoints(options.entryPoints());
        Set<Integer> matchedEntries = new HashSet<Integer>();
        ClassPool pool = context.classes();
        Map<String, String> classMap = context.mappings().classes();
        Map<String, String> methodMap = context.mappings().methods();

        int classes = 0;
        int methods = 0;
        int mainMethods = 0;
        int entryCalls = 0;
        for (ClassNode node : new ArrayList<ClassNode>(pool.classes().values())) {
            if (pool.isGenerated(node.name) || pool.isFrozen(node.name) || "module-info".equals(node.name)) {
                continue;
            }
            // Deliberately no keep-class filter: the main class is often kept
            // (--keep / @Keep) and must still receive the gate.
            boolean touched = false;
            for (MethodNode method : node.methods) {
                if (method.name.startsWith("<") || method.instructions == null) {
                    continue;
                }
                if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
                    continue;
                }
                boolean isMain = "main".equals(method.name) && MAIN_DESC.equals(method.desc)
                        && (method.access & Opcodes.ACC_STATIC) != 0;
                boolean isEntry = false;
                for (int i = 0; i < entries.size(); i++) {
                    if (matches(entries.get(i), node, method, classMap, methodMap)) {
                        isEntry = true;
                        matchedEntries.add(Integer.valueOf(i));
                    }
                }
                if (!isMain && !isEntry) {
                    continue;
                }
                method.instructions.insert(new MethodInsnNode(Opcodes.INVOKESTATIC,
                        helper, "guard", "()V", false));
                touched = true;
                methods++;
                if (isMain) {
                    mainMethods++;
                }
                if (isEntry) {
                    entryCalls++;
                }
            }
            if (touched) {
                classes++;
            }
        }

        for (int i = 0; i < entries.size(); i++) {
            if (!matchedEntries.contains(Integer.valueOf(i))) {
                context.log().warn("auth-gate: entry point not found: %s", entries.get(i).display);
            }
        }
        context.stats().add("authGate.entrypoints", entryCalls);
        context.stats().add("authGate.classes", classes);
        context.stats().add("authGate.methods", methods);
        context.stats().add("authGate.helper", 1);
        context.log().info("auth-gate: %s guards %d method(s) (%d main, %d configured) across %d class(es)",
                helper, methods, mainMethods, entryCalls, classes);
    }

    // ------------------------------------------------------------------
    // entry-point parsing and mapping-aware matching
    // ------------------------------------------------------------------

    private static List<EntryPoint> parseEntryPoints(List<String> configured) {
        List<EntryPoint> result = new ArrayList<EntryPoint>();
        for (String raw : configured) {
            if (raw == null) {
                continue;
            }
            for (String part : raw.split(",")) {
                String value = part.trim();
                if (value.isEmpty()) {
                    continue;
                }
                int hash = value.indexOf('#');
                if (hash <= 0 || hash + 1 >= value.length()) {
                    continue;
                }
                String owner = value.substring(0, hash).trim().replace('.', '/');
                String member = value.substring(hash + 1).trim();
                String name = member;
                String desc = null;
                int paren = member.indexOf('(');
                if (paren >= 0) {
                    name = member.substring(0, paren).trim();
                    desc = member.substring(paren).trim();
                    if (desc.isEmpty()) {
                        desc = null;
                    }
                }
                if (!owner.isEmpty() && !name.isEmpty()) {
                    result.add(new EntryPoint(owner, name, desc, value));
                }
            }
        }
        return result;
    }

    private static boolean matches(EntryPoint entry, ClassNode node, MethodNode method,
                                   Map<String, String> classMap, Map<String, String> methodMap) {
        if (!ownerMatches(entry, node, classMap)) {
            return false;
        }
        if (entry.desc != null) {
            if (!entry.desc.equals(method.desc)) {
                return false;
            }
            if (entry.name.equals(method.name)) {
                return true;
            }
            return mappedName(entry, methodMap).equals(method.name);
        }
        if (entry.name.equals(method.name)) {
            return true;
        }
        String mapped = mappedName(entry, methodMap);
        return !mapped.isEmpty() && mapped.equals(method.name);
    }

    private static boolean ownerMatches(EntryPoint entry, ClassNode node, Map<String, String> classMap) {
        if (node.name.equals(entry.owner)) {
            return true;
        }
        String mapped = classMap.get(entry.owner);
        if (mapped != null && node.name.equals(mapped)) {
            return true;
        }
        // The configured entry may already spell the current (renamed) owner.
        return false;
    }

    /** Resolves the renamed method name for an original {@code owner#name[#desc]} entry. */
    private static String mappedName(EntryPoint entry, Map<String, String> methodMap) {
        for (Map.Entry<String, String> candidate : methodMap.entrySet()) {
            String[] parts = candidate.getKey().split("#");
            if (parts.length != 3) {
                continue;
            }
            if (!parts[0].equals(entry.owner) || !parts[1].equals(entry.name)) {
                continue;
            }
            if (entry.desc != null && !parts[2].equals(entry.desc)) {
                continue;
            }
            return candidate.getValue();
        }
        return "";
    }

    /** One configured verification entry point. */
    private static final class EntryPoint {
        final String owner;
        final String name;
        final String desc;
        final String display;

        EntryPoint(String owner, String name, String desc, String display) {
            this.owner = owner;
            this.name = name;
            this.desc = desc;
            this.display = display;
        }
    }
}
