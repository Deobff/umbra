package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.model.ClassPool;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Renames {@code assets/<domain>} resource directories and rewrites matching
 * string constants in code.
 *
 * <p>This hides domain names such as {@code clickgui} or {@code keystrokesmod}
 * while keeping the resource payload and relative paths unchanged. Bare domain
 * strings (used by {@code ResourceLocation}) are rewritten only when the domain
 * is listed in {@code resources.rewriteDomains}; this avoids changing unrelated
 * strings such as commands.</p>
 */
public final class ResourcePathObfuscationPass implements Pass {

    private static final String ASSETS = "assets/";

    @Override
    public String name() {
        return "resource-path-obfuscation";
    }

    @Override
    public int order() {
        return 58;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().resources().obfuscatePaths();
    }

    @Override
    public void run(PassContext context) {
        ClassPool pool = context.classes();
        List<String> names = new ArrayList<String>(pool.resources().keySet());
        Set<String> usedDomains = new HashSet<String>();
        for (String name : names) {
            String domain = domainOf(name);
            if (domain != null) {
                usedDomains.add(domain);
            }
        }

        NameGenerator generator = new NameGenerator(context.random(), "",
                "abcdefghijklmnopqrstuvwxyz", 3);
        Map<String, String> domains = new LinkedHashMap<String, String>();
        int moved = 0;
        for (String name : names) {
            String domain = domainOf(name);
            if (domain == null) {
                continue;
            }
            String mapped = domains.get(domain);
            if (mapped == null) {
                do {
                    mapped = generator.next();
                } while (usedDomains.contains(mapped));
                usedDomains.add(mapped);
                domains.put(domain, mapped);
            }
            String rest = name.substring(ASSETS.length());
            int slash = rest.indexOf('/');
            String newName = ASSETS + mapped + rest.substring(slash);
            ClassPool.Resource resource = pool.resource(name);
            if (resource != null) {
                pool.removeResource(name);
                pool.putResource(newName, resource.bytes(), resource.time(), resource.method());
                moved++;
            }
        }

        Set<String> rewriteDomains = new HashSet<String>(context.config().resources().rewriteDomains());
        int rewrites = 0;
        for (ClassNode node : new ArrayList<ClassNode>(pool.classes().values())) {
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof LdcInsnNode) {
                        Object value = ((LdcInsnNode) insn).cst;
                        if (value instanceof String) {
                            String rewritten = rewrite((String) value, domains, rewriteDomains);
                            if (!rewritten.equals(value)) {
                                ((LdcInsnNode) insn).cst = rewritten;
                                rewrites++;
                            }
                        }
                    }
                }
            }
        }

        context.stats().add("resources.paths.renamed", moved);
        context.stats().add("resources.paths.rewrites", rewrites);
        context.log().info("resource-path-obfuscation: moved %d assets, rewrote %d strings (%d domains)",
                moved, rewrites, domains.size());
    }

    private static String domainOf(String name) {
        if (!name.startsWith(ASSETS)) {
            return null;
        }
        String rest = name.substring(ASSETS.length());
        int slash = rest.indexOf('/');
        return slash <= 0 ? null : rest.substring(0, slash);
    }

    private static String rewrite(String value, Map<String, String> domains, Set<String> bareDomains) {
        for (Map.Entry<String, String> entry : domains.entrySet()) {
            String old = entry.getKey();
            String mapped = entry.getValue();
            String absolute = "/" + ASSETS + old + "/";
            if (value.startsWith(absolute)) {
                return "/" + ASSETS + mapped + value.substring(absolute.length() - 1);
            }
            String relative = ASSETS + old + "/";
            if (value.startsWith(relative)) {
                return ASSETS + mapped + value.substring(relative.length() - 1);
            }
            if (bareDomains.contains(old) && value.equals(old)) {
                return mapped;
            }
        }
        return value;
    }
}
