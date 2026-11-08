package io.umbra.core.runtime;

import io.umbra.core.api.RuntimeSupport;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.model.ClassPool;
import io.umbra.core.util.DomainTags;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import io.umbra.core.util.RuntimeNames;

/** Default runtime support: injected string decryptor, indy bootstrap and watermark. */
public final class DefaultRuntimeSupport implements RuntimeSupport {

    private String decryptorName;
    private String indyBootstrapName;
    private String virtualMachineName;
    private String otpName;
    private String keyRootMaskName;
    private String authGateName;
    private String authGateKey;

    private static final String[] AUTH_GATE_PLACEHOLDERS = {
            "@@SERVER@@", "@@SOFTWARE@@", "@@TITLE@@", "@@CACHE@@",
            "@@REGISTER@@", "@@TIMEOUT@@", "@@ENTRY@@"
    };

    @Override
    public synchronized String ensureStringDecryptor(ClassPool pool, long seed) {
        if (decryptorName == null) {
            decryptorName = injectTemplate(UmbraStringDecryptor.class, RuntimeNames.prefix(), seed, pool);
        }
        return decryptorName;
    }

    @Override
    public synchronized String ensureIndyBootstrap(ClassPool pool, long seed) {
        if (indyBootstrapName == null) {
            indyBootstrapName = injectTemplate(UmbraIndyBootstrap.class, RuntimeNames.path("I"), seed, pool);
        }
        return indyBootstrapName;
    }

    @Override
    public synchronized String ensureVirtualMachine(ClassPool pool, long seed) {
        if (virtualMachineName == null) {
            virtualMachineName = injectTemplate(UmbraVM.class, RuntimeNames.path("V"), seed, pool);
        }
        return virtualMachineName;
    }

    @Override
    public synchronized String ensureOtp(ClassPool pool, long seed) {
        if (otpName == null) {
            otpName = injectTemplate(UmbraOtp.class, RuntimeNames.path("O"), seed, pool);
        }
        return otpName;
    }

    @Override
    public synchronized String ensureKeyRootMask(ClassPool pool, long seed) {
        if (keyRootMaskName != null) {
            return keyRootMaskName;
        }
        try {
            byte[] bytes = readTemplate(UmbraKeyRootMask.class);
            ClassNode node = new ClassNode();
            new ClassReader(bytes).accept(node, 0);
            Random random = new Random(seed ^ UmbraKeyRootMask.class.getName().hashCode()
                    ^ 0x4D41534BL);
            NameGenerator names = new NameGenerator(random, "");
            String candidate;
            int guard = 0;
            do {
                candidate = RuntimeNames.path("K") + names.random(10);
                if (++guard > 10000) {
                    throw new IllegalStateException("Unable to allocate a name for the "
                            + "key-root mask helper");
                }
            } while (pool.getClass(candidate) != null);

            ClassNode remapped = new ClassNode();
            node.accept(new ClassRemapper(remapped, new SimpleRemapper(node.name, candidate)));
            remapped.access |= Opcodes.ACC_SYNTHETIC;
            remapped.version = Math.min(remapped.version, Opcodes.V1_8);
            Map<String, String> replacements = new LinkedHashMap<String, String>();
            replacements.put("@@PREFIX@@", RuntimeNames.prefix());
            int replaced = replacePlaceholders(remapped, replacements);
            replacePlaceholders(remapped, DomainTags.replacements());
            if (replaced < 1) {

                throw new IllegalStateException("Key-root mask template is incomplete: "
                        + replaced + " prefix placeholders replaced");
            }
            TemplateInjector.stripDebugInfo(remapped);
            pool.addGenerated(remapped);
            keyRootMaskName = candidate;
            return candidate;
        } catch (IOException e) {
            throw new IllegalStateException("Unable to load runtime template UmbraKeyRootMask", e);
        }
    }

    @Override
    public synchronized String ensureAuthGate(ClassPool pool, long seed, UmbraConfig.AuthGateOptions options) {
        if (options == null || !options.enabled()) {
            return null;
        }
        String key = options.server() + "|" + options.software() + "|" + options.title() + "|"
                + options.allowRegister() + "|" + options.cacheFile() + "|" + options.timeoutMs()
                + "|" + options.entryPoints();
        if (authGateName != null && key.equals(authGateKey)) {
            return authGateName;
        }
        authGateName = injectAuthGate(seed, pool, options);
        authGateKey = key;
        return authGateName;
    }

    @Override
    public String embedWatermark(ClassPool pool, String watermark) {
        List<String> names = new ArrayList<String>(pool.classes().keySet());
        Collections.sort(names);
        for (String name : names) {
            ClassNode node = pool.getClass(name);
            if (node == null || "module-info".equals(node.name)) {
                continue;
            }

            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) {
                continue;
            }

            String fieldName = "z$" + Integer.toHexString(watermark.hashCode() & 0xFFFFFF);
            boolean exists = false;
            for (FieldNode field : node.fields) {
                if (field.name.equals(fieldName)) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                FieldNode field = new FieldNode(
                        Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                        fieldName, "Ljava/lang/String;", null, watermark);
                node.fields.add(0, field);
            }
            return node.name + "." + fieldName;
        }
        return null;
    }

    private static String injectAuthGate(long seed, ClassPool pool, UmbraConfig.AuthGateOptions options) {
        try {
            byte[] bytes = readTemplate(UmbraAuthGate.class);
            ClassReader reader = new ClassReader(bytes);
            ClassNode node = new ClassNode();
            reader.accept(node, 0);

            Random random = new Random(seed ^ UmbraAuthGate.class.getName().hashCode());
            NameGenerator names = new NameGenerator(random, "");
            String candidate;
            do {
                candidate = RuntimeNames.path("A") + names.random(10);
            } while (pool.getClass(candidate) != null);

            ClassNode remapped = new ClassNode();
            node.accept(new ClassRemapper(remapped, new SimpleRemapper(node.name, candidate)));
            remapped.version = Opcodes.V1_8;
            remapped.access |= Opcodes.ACC_SYNTHETIC;

            StringBuilder entries = new StringBuilder();
            for (String entry : options.entryPoints()) {
                if (entries.length() > 0) {
                    entries.append(',');
                }
                entries.append(entry);
            }
            Map<String, String> replacements = new LinkedHashMap<String, String>();
            replacements.put("@@SERVER@@", options.server());
            replacements.put("@@SOFTWARE@@", options.software());
            replacements.put("@@TITLE@@", options.title());
            replacements.put("@@CACHE@@", options.cacheFile());
            replacements.put("@@REGISTER@@", String.valueOf(options.allowRegister()));
            replacements.put("@@TIMEOUT@@", String.valueOf(options.timeoutMs()));
            replacements.put("@@ENTRY@@", entries.toString());
            int replaced = replacePlaceholders(remapped, replacements);
            if (replaced < AUTH_GATE_PLACEHOLDERS.length) {
                throw new IllegalStateException("Authorization gate template is incomplete: replaced "
                        + replaced + " of " + AUTH_GATE_PLACEHOLDERS.length + " placeholders");
            }

            pool.addGenerated(remapped);
            return candidate;
        } catch (IOException e) {
            throw new IllegalStateException("Unable to load runtime template UmbraAuthGate", e);
        }
    }

    private static int replacePlaceholders(ClassNode node, Map<String, String> replacements) {
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

    private static String injectTemplate(Class<?> template, String prefix, long seed, ClassPool pool) {
        try {
            byte[] bytes = readTemplate(template);
            ClassReader reader = new ClassReader(bytes);
            ClassNode node = new ClassNode();
            reader.accept(node, 0);

            Random random = new Random(seed ^ template.getName().hashCode());
            NameGenerator names = new NameGenerator(random, "");
            String candidate;
            do {
                candidate = prefix + names.random(10);
            } while (pool.getClass(candidate) != null);

            String originalName = node.name;

            ClassNode remapped = new ClassNode();
            node.accept(new ClassRemapper(remapped, new SimpleRemapper(originalName, candidate)));
            remapped.access |= Opcodes.ACC_SYNTHETIC;

            replacePlaceholders(remapped, DomainTags.replacements());
            TemplateInjector.stripDebugInfo(remapped);
            pool.addGenerated(remapped);
            return candidate;
        } catch (IOException e) {
            throw new IllegalStateException("Unable to load runtime template " + template.getName(), e);
        }
    }

    private static byte[] readTemplate(Class<?> template) throws IOException {
        String resource = template.getSimpleName() + ".class";
        try (InputStream in = template.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException(resource + " resource is missing");
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }
}
