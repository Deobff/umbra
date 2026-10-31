package io.umbra.core.runtime.crypto;

import io.umbra.core.model.ClassPool;
import io.umbra.core.runtime.TemplateInjector;
import io.umbra.core.util.DomainTags;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import io.umbra.core.util.RuntimeNames;

/**
 * Pass-side helper that injects the shared crypto template and the templates
 * that link against it.
 *
 * <p>{@link UmbraCrypto} is injected once per output program under a name that
 * is derived deterministically from the run seed, so that independent passes
 * (string encryption, integrity, class encryption) can all refer to the same
 * copy. Templates that call it are remapped from their compile-time reference
 * ({@code io/umbra/core/runtime/crypto/UmbraCrypto}) to the injected name.</p>
 */
public final class CryptoSupport {

    /** Internal name of the compile-time crypto template. */
    private static final String CRYPTO_TEMPLATE = "io/umbra/core/runtime/crypto/UmbraCrypto";

    private CryptoSupport() {
    }

    /**
     * Ensures the shared {@link UmbraCrypto} template exists in the pool and
     * returns its injected internal name.
     */
    public static synchronized String ensureCrypto(ClassPool pool, long seed) {
        Random random = new Random(seed ^ 0x5EEDC0DEL);
        NameGenerator names = new NameGenerator(random, "u");
        for (int attempt = 0; attempt < 1000; attempt++) {
            String candidate = RuntimeNames.prefix() + names.random(12);
            if (pool.getClass(candidate) != null) {
                if (pool.isGenerated(candidate)) {
                    return candidate;
                }
                continue;
            }
            injectWithCrypto(pool, UmbraCrypto.class, candidate, null, null);
            return candidate;
        }
        throw new IllegalStateException("Unable to allocate a name for the crypto helper");
    }

    /**
     * Injects {@code template} under {@code targetName}, remapping its own
     * references and its calls to {@link UmbraCrypto}.
     *
     * @param pool          program pool
     * @param template      compiled template class
     * @param targetName    internal name of the injected class
     * @param cryptoName    injected internal name of the crypto helper
     * @param replacements  exact string-constant replacements (may be null)
     */
    public static void injectWithCrypto(ClassPool pool, Class<?> template, String targetName,
                                        String cryptoName, Map<String, String> replacements) {
        injectWithCrypto(pool, template, targetName, cryptoName, replacements, null);
    }

    /**
     * Same as {@link #injectWithCrypto(ClassPool, Class, String, String, Map)}
     * with additional type-reference remappings (for example wiring a guard to
     * a separately injected watchdog class).
     */
    public static void injectWithCrypto(ClassPool pool, Class<?> template, String targetName,
                                        String cryptoName, Map<String, String> replacements,
                                        Map<String, String> extraRemap) {
        ClassNode node = TemplateInjector.read(template);
        Map<String, String> remap = new LinkedHashMap<String, String>();
        remap.put(node.name, targetName);
        if (cryptoName != null) {
            remap.put(CRYPTO_TEMPLATE, cryptoName);
        }
        if (extraRemap != null) {
            remap.putAll(extraRemap);
        }
        ClassNode remapped = new ClassNode();
        node.accept(new ClassRemapper(remapped, new SimpleRemapper(remap)));
        remapped.name = targetName;
        remapped.access |= Opcodes.ACC_SYNTHETIC;
        remapped.version = Math.min(remapped.version, Opcodes.V1_8);
        // Per-build domain separators must reach every injected template, or the
        // runtime would derive keys from the literal labels while the build side uses
        // the randomized ones (see DomainTags).
        Map<String, String> constants = DomainTags.replacements();
        if (replacements != null) {
            constants.putAll(replacements);
        }
        if (!constants.isEmpty()) {
            replaceConstants(remapped, constants);
        }
        TemplateInjector.stripDebugInfo(remapped);
        pool.addGenerated(remapped);
    }

    /**
     * Deterministically chooses an unused internal name for an injected
     * template.
     *
     * @param pool     program pool
     * @param seed     run seed
     * @param salt     distinguishes templates
     * @param prefix   internal-name prefix, interpreted as a package path
     *                 relative to the root when it contains no {@code /}
     */
    public static String randomName(ClassPool pool, long seed, String salt, String prefix) {
        Random random = new Random(seed ^ salt.hashCode() * 0x9E3779B97F4A7C15L);
        NameGenerator names = new NameGenerator(random, "");
        for (int attempt = 0; attempt < 10000; attempt++) {
            String candidate = prefix + names.random(10);
            if (pool.getClass(candidate) == null) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to allocate an injected class name for " + salt);
    }

    /** Replaces exact string constants in LDC instructions and ConstantValue attributes. */
    public static int replaceConstants(ClassNode node, Map<String, String> replacements) {
        if (replacements == null || replacements.isEmpty()) {
            return 0;
        }
        int replaced = 0;
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) insn;
                    if (ldc.cst instanceof String) {
                        String value = replacements.get(ldc.cst);
                        if (value != null) {
                            ldc.cst = value;
                            replaced++;
                        }
                    }
                }
            }
        }
        for (FieldNode field : node.fields) {
            if (field.value instanceof String) {
                String value = replacements.get(field.value);
                if (value != null) {
                    field.value = value;
                    replaced++;
                }
            }
        }
        return replaced;
    }
}
