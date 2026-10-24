package io.umbra.core.runtime;

import io.umbra.core.model.ClassPool;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

/**
 * Injects compiled runtime template classes into the protected program.
 *
 * <p>Umbra's runtime helpers (string decryptor, VM interpreter, native loader,
 * encrypted-class loader) are ordinary classes inside the obfuscator JAR. A pass
 * copies one into the output pool under a random, unpredictable name. The copy
 * is marked {@code generated} (and therefore never renamed or transformed
 * again) and self-references are remapped together with the class name.</p>
 *
 * <p>Template classes must be self-contained: no nested/anonymous classes
 * (their binary names would break), and no references to other Umbra classes
 * except through template classes injected separately (pass the mapped names in
 * the placeholder map, or resolve them in the pass and splice the strings).</p>
 */
public final class TemplateInjector {

    private TemplateInjector() {
    }

    /** Loads a template as a {@link ClassNode} without modifying it. */
    public static ClassNode read(Class<?> template) {
        try {
            byte[] bytes = readBytes(template);
            ClassNode node = new ClassNode();
            new ClassReader(bytes).accept(node, ClassReader.EXPAND_FRAMES);
            return node;
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read runtime template " + template.getName(), e);
        }
    }

    /** Injects a template under a fresh random name and returns its internal name. */
    public static String inject(ClassPool pool, Class<?> template, String prefix, long seed) {
        return inject(pool, template, prefix, seed, null);
    }

    /**
     * Injects a template under a fresh random name, substituting string
     * constants.
     *
     * @param pool         program pool
     * @param template     compiled runtime class
     * @param prefix       internal-name prefix, for example {@code "umbra/runtime/V"}
     * @param seed         deterministic seed
     * @param replacements map of exact string constants to replacements (may be
     *                     {@code null}); every occurrence is rewritten in LDC
     *                     instructions and ConstantValue attributes
     * @return internal name of the injected class
     */
    public static String inject(ClassPool pool, Class<?> template, String prefix, long seed,
                                Map<String, String> replacements) {
        ClassNode node = read(template);
        Random random = new Random(seed ^ template.getName().hashCode() ^ pool.classes().size());
        NameGenerator names = new NameGenerator(random, "");
        String candidate;
        int guard = 0;
        do {
            candidate = prefix + names.random(10);
            if (++guard > 10000) {
                throw new IllegalStateException("Unable to allocate a unique name for " + template.getName());
            }
        } while (pool.getClass(candidate) != null);

        ClassNode remapped = new ClassNode();
        node.accept(new ClassRemapper(remapped, new SimpleRemapper(node.name, candidate)));
        remapped.access |= Opcodes.ACC_SYNTHETIC;
        if (replacements != null && !replacements.isEmpty()) {
            replaceConstants(remapped, replacements);
        }
        // The injected helper must run on every supported JVM; keep it at the
        // class file version the obfuscator itself is compiled for.
        remapped.version = Math.min(remapped.version, Opcodes.V1_8);
        pool.addGenerated(remapped);
        return candidate;
    }

    private static void replaceConstants(ClassNode node, Map<String, String> replacements) {
        for (org.objectweb.asm.tree.MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (org.objectweb.asm.tree.AbstractInsnNode insn = method.instructions.getFirst();
                 insn != null; insn = insn.getNext()) {
                if (insn instanceof org.objectweb.asm.tree.LdcInsnNode) {
                    org.objectweb.asm.tree.LdcInsnNode ldc = (org.objectweb.asm.tree.LdcInsnNode) insn;
                    if (ldc.cst instanceof String) {
                        String value = replacements.get(ldc.cst);
                        if (value != null) {
                            ldc.cst = value;
                        }
                    }
                }
            }
        }
        for (org.objectweb.asm.tree.FieldNode field : node.fields) {
            if (field.value instanceof String) {
                String value = replacements.get(field.value);
                if (value != null) {
                    field.value = value;
                }
            }
        }
    }

    /** Builds a placeholder map from alternating key/value pairs. */
    public static Map<String, String> placeholders(String... pairs) {
        if (pairs == null || pairs.length == 0) {
            return new LinkedHashMap<String, String>();
        }
        if ((pairs.length & 1) != 0) {
            throw new IllegalArgumentException("placeholders expects key/value pairs");
        }
        Map<String, String> out = new LinkedHashMap<String, String>();
        for (int i = 0; i < pairs.length; i += 2) {
            out.put(pairs[i], pairs[i + 1]);
        }
        return out;
    }

    private static byte[] readBytes(Class<?> template) throws IOException {
        String resource = template.getSimpleName() + ".class";
        InputStream in = template.getResourceAsStream(resource);
        if (in == null) {
            throw new IOException(resource + " resource is missing");
        }
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }
}
