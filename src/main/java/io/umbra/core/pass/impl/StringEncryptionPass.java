package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.model.ClassPool;
import io.umbra.core.runtime.crypto.CryptoSupport;
import io.umbra.core.runtime.crypto.UmbraStringCipher;
import io.umbra.core.runtime.crypto.UmbraStringIndy;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.Cipher;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import io.umbra.core.util.RuntimeNames;

/**
 * Replaces string constants with encrypted payloads and a call to an injected
 * decryptor (or an {@code invokedynamic} call site).
 *
 * <p>Engine v2 adds per-site cipher selection. Each encrypted site carries an
 * engine code and is decrypted with the matching stream cipher:</p>
 *
 * <ul>
 *   <li>{@code string.engine=xor|rc4|chacha20|aes-ctr|speck} - one engine for
 *       every site (default: the {@code string.strength} preset, ChaCha20 for
 *       strengths 2/3);</li>
 *   <li>{@code string.engine=auto} - a deterministic per-site rotation over
 *       {@code string.engineOrder} (default {@code chacha20,aes-ctr,rc4,speck}),
 *       so one archive mixes several ciphers and no single cryptanalytic path
 *       covers all strings.</li>
 * </ul>
 *
 * <p>The remaining protection features are unchanged from v1 and stay
 * compatible:</p>
 * <ul>
 *   <li>256-bit keys derived per class ({@code string.perClassKey}) and stored
 *       in one synthetic {@code private static final String} field per class;
 *       call sites reference that field, so no key literal appears next to the
 *       payload.</li>
 *   <li>Payload splitting ({@code string.split}) across several Base64
 *       constants that are reassembled at runtime.</li>
 *   <li>Per-call-site memoization ({@code string.cache}).</li>
 *   <li>Optional {@code invokedynamic} mode ({@code string.indy}).</li>
 *   <li>{@code string.strength} 1..3 presets; explicit options override a
 *       preset.</li>
 *   <li>{@code string.encryptAll} lowers the minimum length to 1 so even
 *       one-character literals and constant fields are covered.</li>
 *   <li>{@code string.wipe} makes the injected decryptor zero every
 *       intermediate byte/char buffer.</li>
 *   <li>{@code string.stackTraceHide} replaces a decryption failure with a
 *       sanitized exception that has an empty stack trace.</li>
 *   <li>{@code string.otpEngines} (with {@code otp.enabled}) stores two
 *       ciphertexts of the same value under two different engines and lets the
 *       one-time state's alternating carrier bit pick the decryption path on
 *       every call; {@code string.otpMaxSites} caps how many sites per class get
 *       the doubled payload.</li>
 * </ul>
 *
 * <p>Strings that are bootstrap arguments of an existing {@code invokedynamic}
 * instruction (string-concat recipes, lambda recipes) and annotation values are
 * never touched: they are not {@code LDC} instructions in method code.</p>
 */
public final class StringEncryptionPass implements Pass {

    private static final String ANNOTATION = "Lio/umbra/annotations/StringEncryption;";

    /** Descriptor of the injected string bootstrap (payload, key spec, seed, site, engine). */
    private static final String STRING_BOOTSTRAP_DESC =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;"
                    + "Ljava/lang/String;Ljava/lang/String;JII)Ljava/lang/invoke/CallSite;";

    private static final String CLASS_KEY_FIELD_DESC = "Ljava/lang/String;";

    /** Default rotation used by {@code string.engine=auto}. */
    private static final String DEFAULT_ENGINE_ORDER = "chacha20,aes-ctr,rc4,speck";

    /**
     * Conservative per-method code budget: encryption replaces a 2-byte
     * {@code ldc} with an array construction plus a call (or a 5-byte
     * {@code invokedynamic}), so a method close to the 65535-byte JVM limit
     * would otherwise become unwritable ({@code MethodTooLargeException}).
     */
    private static final int MAX_METHOD_CODE_BYTES = 60000;
    /** Conservative growth charged per helper-call site while budgeting. */
    private static final int HELPER_SITE_GROWTH = 48;
    /** Conservative growth charged per invokedynamic site while budgeting. */
    private static final int INDY_SITE_GROWTH = 6;
    /**
     * Constant-pool budget guard: every encrypted site adds a handful of pool
     * entries, and a class file may not exceed 65535 entries.
     */
    private static final int CLASS_SITE_LIMIT = 4000;

    /** Template placeholder: bit 0 = wipe, bit 1 = stack-trace hiding, bit 2 = cache. */
    private static final String FLAGS_SPEC = "@@FLAGS@@";

    /** Template placeholder for the per-build artifact salt. */
    private static final String SALT_SPEC = "@@SALT@@";

    /** Payload/key-schedule version produced by this pass (see UmbraStringCipher). */
    static final int PAYLOAD_VERSION = 3;

    /** Descriptor of the dual-engine decryptor entry point (per-site convention). */
    public static final String DUAL_PER_SITE_DESC = "([Ljava/lang/String;JIIII)Ljava/lang/String;";

    /** Descriptor of the dual-engine decryptor entry point (per-class key convention). */
    public static final String DUAL_PER_CLASS_DESC =
            "([Ljava/lang/String;Ljava/lang/String;IIII)Ljava/lang/String;";

    /** Default per-class cap of dual-ciphertext sites ({@code string.otpMaxSites}). */
    static final int DEFAULT_OTP_MAX_SITES = 16;

    /**
     * Dual payloads below this length would double more bytes than they hide, so
     * short literals keep a single ciphertext even when the option is on.
     */
    private static final int MIN_DUAL_LENGTH = 8;

    /** Extra code charged per dual site while budgeting a method. */
    private static final int DUAL_SITE_GROWTH = 24;

    /**
     * Strong engines tried for the second half when the configuration pins a
     * single engine: a dual payload needs two different ciphers by definition.
     */
    private static final int[] STRONG_ENGINES = {
            UmbraStringCipher.CHACHA20, UmbraStringCipher.AES_CTR,
            UmbraStringCipher.RC4, UmbraStringCipher.SPECK
    };

    @Override
    public String name() {
        return "string-encryption";
    }

    @Override
    public int order() {
        return 70;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().stringEncryption().enabled();
    }

    @Override
    public void run(PassContext context) {
        Options options = Options.resolve(context);
        Run run = new Run(context, options);
        for (ClassNode node : new ArrayList<ClassNode>(context.classes().classes().values())) {
            ClassPool pool = context.classes();
            if (pool.isGenerated(node.name) || pool.isFrozen(node.name)) {
                continue;
            }
            if (context.rules().skipBodyTransform(node.name)) {
                continue;
            }
            if ("module-info".equals(node.name) || node.name.endsWith("/module-info")) {
                continue;
            }
            // Note: keep rules that protect reflection-visible classes from
            // *renaming* do not protect their string constants; encrypting a
            // literal never changes observable behaviour, so kept classes are
            // processed too (an explicit @StringEncryption(enabled=false)
            // annotation still opts out below).
            if (Boolean.FALSE.equals(annotationFlag(node.invisibleAnnotations, node.visibleAnnotations))) {
                continue;
            }
            boolean perClass = options.perClassKey
                    && (node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) == 0;
            String classKeyField = perClass ? allocateFieldName(node, context) : null;
            byte[] classKey = perClass
                    ? UmbraStringCipher.classKeyV2(run.artifactSalt, context.config().seed(), node.name)
                    : null;
            boolean indyAllowed = indyAllowed(node, options);
            int sitesInClass = 0;
            run.beginClass(node.name);
            try {
                for (MethodNode method : node.methods) {
                    if (method.instructions == null || method.instructions.size() == 0) {
                        continue;
                    }
                    if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
                        continue;
                    }
                    if (Boolean.FALSE.equals(annotationFlag(method.invisibleAnnotations,
                            method.visibleAnnotations))) {
                        continue;
                    }
                    if (run.classSites >= CLASS_SITE_LIMIT) {
                        run.classLimitSkips++;
                        break;
                    }
                    sitesInClass += transformMethod(run, node, method, classKey, classKeyField, indyAllowed);
                }
                if ((node.access & Opcodes.ACC_ANNOTATION) == 0 && run.classSites < CLASS_SITE_LIMIT) {
                    sitesInClass += encryptFieldConstants(run, node, classKey, classKeyField);
                }
            } finally {
                Cipher.wipe(classKey);
            }
            if (perClass && sitesInClass > 0 && classKeyField != null) {
                addClassKeyField(node, classKeyField, UmbraStringCipher.classKeyV2(
                        run.artifactSalt, context.config().seed(), node.name));
                run.perClassClasses++;
            }

        }

        context.stats().add("strings.encrypted", run.encrypted);
        if (run.fieldConstants > 0) {
            context.stats().add("strings.fieldConstants", run.fieldConstants);
        }
        if (run.splitSites > 0) {
            context.stats().add("strings.splitSites", run.splitSites);
        }
        if (options.cache && run.cacheSites > 0) {
            context.stats().add("strings.cacheSites", run.cacheSites);
        }
        if (options.indy && run.indySites > 0) {
            context.stats().add("strings.indySites", run.indySites);
        }
        if (run.perClassClasses > 0) {
            context.stats().add("strings.perClassKeys", run.perClassClasses);
        }
        if (run.methodSizeSkips > 0) {
            context.stats().add("strings.skipped.methodSize", run.methodSizeSkips);
        }
        if (run.classLimitSkips > 0) {
            context.stats().add("strings.skipped.classLimit", run.classLimitSkips);
        }
        for (int engine = 0; engine < run.engineCounts.length; engine++) {
            context.stats().add("strings.engine." + UmbraStringCipher.engineId(engine),
                    run.engineCounts[engine]);
        }
        context.stats().add("strings.engineKinds", run.engineKinds());
        context.stats().add("strings.wipe", options.wipe ? 1 : 0);
        context.stats().add("strings.stackTraceHide", options.stackTraceHide ? 1 : 0);
        context.stats().add("strings.cache", options.cache ? 1 : 0);
        context.stats().add("strings.encryptAll", options.encryptAll ? 1 : 0);
        context.stats().add("strings.payloadVersion", PAYLOAD_VERSION);
        // Dual-ciphertext slots (P0-2-c): sites carrying two engines and the number
        // of distinct engine pairs those sites use.
        context.stats().add("string.otp.sites", run.otpSites);
        context.stats().add("string.otp.engines", run.otpPairs.size());
        if (options.unsupportedOptions > 0) {
            context.stats().add("strings.unsupportedOptions", options.unsupportedOptions);
        }
        if (options.engineFallback) {
            context.stats().add("strings.engineFallback", 1);
        }
        if (options.engineOrderIgnored > 0) {
            context.stats().add("strings.engineOrderIgnored", options.engineOrderIgnored);
        }
        context.log().info("string-encryption: encrypted %d string constants (%s, split=%s, cache=%s, "
                        + "perClassKey=%d classes, indy=%d sites, minLength=%d, wipe=%s, "
                        + "stackTraceHide=%s, payload=v%d, size-skips=%d/%d, otp-slots=%d/%d)",
                run.encrypted, run.describeEngines(), Boolean.valueOf(options.split),
                Boolean.valueOf(options.cache), run.perClassClasses, run.indySites, options.minLength,
                Boolean.valueOf(options.wipe), Boolean.valueOf(options.stackTraceHide),
                Integer.valueOf(PAYLOAD_VERSION), run.methodSizeSkips, run.classLimitSkips,
                Integer.valueOf(run.otpSites), Integer.valueOf(options.otpMaxSites));
        if (run.dualLayoutFallbacks > 0) {
            context.log().debug("string-encryption: %d dual slot(s) kept single-engine because the "
                    + "two halves split into a different number of parts",
                    run.dualLayoutFallbacks);
        }
        if (run.methodSizeSkips > 0 || run.classLimitSkips > 0) {
            context.log().debug("string-encryption: left %d site(s) plaintext in methods close to the "
                    + "64KB code limit and %d site(s) in classes near the constant-pool limit",
                    run.methodSizeSkips, run.classLimitSkips);
        }
        run.logTemplates();
    }

    private int transformMethod(Run run, ClassNode node, MethodNode method, byte[] classKey,
                                String classKeyField, boolean indyAllowed) {
        boolean perClass = classKey != null && classKeyField != null;
        int count = 0;
        int projectedBytes = estimateCodeBytes(method);
        int perSiteGrowth = indyAllowed ? INDY_SITE_GROWTH : HELPER_SITE_GROWTH;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof LdcInsnNode) {
                LdcInsnNode ldc = (LdcInsnNode) insn;
                if (ldc.cst instanceof String) {
                    String value = (String) ldc.cst;
                    if (shouldEncrypt(value, run.options)) {
                        if (run.classSites >= CLASS_SITE_LIMIT) {
                            run.classLimitSkips++;
                            break;
                        }
                        // invokedynamic sites keep the packed single-engine
                        // payload: the bootstrap descriptor is fixed, so the
                        // selector overload is only emitted for helper calls.
                        boolean dual = !indyAllowed && run.dualEligible(value);
                        int growth = dual ? perSiteGrowth + DUAL_SITE_GROWTH : perSiteGrowth;
                        if (projectedBytes + growth > MAX_METHOD_CODE_BYTES) {
                            run.methodSizeSkips++;
                            break;
                        }
                        projectedBytes += growth;
                        int siteId = run.nextSiteId();
                        Site site = encryptSite(run, value, node, siteId, perClass, classKey, dual);
                        run.countEngine(site.engine);
                        run.countDual(site);
                        if (site.partCount > 1) {
                            run.splitSites++;
                        }
                        if (indyAllowed) {
                            String helper = run.indyHelper();
                            Handle handle = new Handle(Opcodes.H_INVOKESTATIC, helper, "bootstrapString",
                                    STRING_BOOTSTRAP_DESC, false);
                            InvokeDynamicInsnNode call = new InvokeDynamicInsnNode("s" + siteId,
                                    "()Ljava/lang/String;", handle,
                                    site.packedPayload, site.perClass ? classKeyField : "",
                                    Long.valueOf(site.siteSeed), Integer.valueOf(site.siteId),
                                    Integer.valueOf(site.engine));
                            method.instructions.set(insn, call);
                            run.indySites++;
                        } else {
                            run.decryptor();
                            InsnList replacement = new InsnList();
                            emitHelperCall(run, replacement, node, site, classKeyField);
                            if (run.options.cache) {
                                run.cacheSites++;
                            }
                            method.instructions.insertBefore(insn, replacement);
                            method.instructions.remove(insn);
                        }
                        if (site.temporaryKey) {
                            Cipher.wipe(site.key);
                        }
                        run.encrypted++;
                        run.classSites++;
                        count++;
                    }
                }
            }
            insn = next;
        }
        return count;
    }

    private static boolean shouldEncrypt(String value, Options options) {
        return value.length() >= options.minLength && value.length() > 0;
    }

    /** Code-attribute byte estimate used to keep rewritten methods under 64KB. */
    static int estimateCodeBytes(MethodNode method) {
        int total = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            total += instructionBytes(insn);
        }
        return total;
    }

    /** Approximate encoded size of one instruction (conservative where variable). */
    private static int instructionBytes(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode < 0) {
            return 0;
        }
        if (insn instanceof TableSwitchInsnNode) {
            return 1 + 3 + 12 + 4 * ((TableSwitchInsnNode) insn).labels.size();
        }
        if (insn instanceof LookupSwitchInsnNode) {
            return 1 + 3 + 8 + 8 * ((LookupSwitchInsnNode) insn).labels.size();
        }
        if (insn instanceof LdcInsnNode) {
            // Could be ldc (2) or ldc_w/ldc2_w (3); charging 3 is conservative.
            return 3;
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH || opcode == Opcodes.NEWARRAY
                || opcode == Opcodes.RET) {
            return 2;
        }
        if (opcode == Opcodes.IINC) {
            return 3;
        }
        if ((opcode >= Opcodes.IFEQ && opcode <= Opcodes.JSR)
                || (opcode >= Opcodes.GETSTATIC && opcode <= Opcodes.INVOKESTATIC)
                || (opcode >= Opcodes.NEW && opcode <= Opcodes.ANEWARRAY)
                || opcode == Opcodes.CHECKCAST || opcode == Opcodes.INSTANCEOF) {
            return 3;
        }
        if (opcode == Opcodes.INVOKEINTERFACE || opcode == Opcodes.INVOKEDYNAMIC) {
            return 5;
        }
        if (opcode == Opcodes.MULTIANEWARRAY) {
            return 4;
        }
        if (opcode == 196) {
            return 4;
        }
        return 1;
    }

    /** Emits a call to the injected decryptor that reassembles and decrypts one site. */
    private static void emitHelperCall(Run run, InsnList out, ClassNode node, Site site,
                                       String classKeyField) {
        emitParts(out, site.parts);
        String decryptor = run.decryptor();
        String entry = run.options.cache ? "e" : "d";
        if (site.dual) {
            // Dual payload: the selector is the one-time state's carrier, whose
            // low bit strictly alternates, so the next call at this very site
            // takes the other engine. The template never references the state
            // class itself; the call site supplies the value.
            if (site.perClass) {
                out.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, classKeyField,
                        CLASS_KEY_FIELD_DESC));
            } else {
                out.add(new LdcInsnNode(Long.valueOf(site.siteSeed)));
            }
            AsmUtil.pushInt(out, site.siteId);
            AsmUtil.pushInt(out, site.engine);
            AsmUtil.pushInt(out, site.engineB);
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, run.otpClass(), "carrier", "()I", false));
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, decryptor, entry,
                    site.perClass ? DUAL_PER_CLASS_DESC : DUAL_PER_SITE_DESC, false));
            return;
        }
        if (site.perClass) {
            out.add(new FieldInsnNode(Opcodes.GETSTATIC, node.name, classKeyField, CLASS_KEY_FIELD_DESC));
            AsmUtil.pushInt(out, site.siteId);
            AsmUtil.pushInt(out, site.engine);
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, decryptor, entry,
                    "([Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;", false));
        } else {
            out.add(new LdcInsnNode(Long.valueOf(site.siteSeed)));
            AsmUtil.pushInt(out, site.siteId);
            AsmUtil.pushInt(out, site.engine);
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, decryptor, entry,
                    "([Ljava/lang/String;JII)Ljava/lang/String;", false));
        }
    }

    /**
     * Encrypts {@code static final String} field constants.
     *
     * <p>A field still carrying a {@code ConstantValue} attribute would leak
     * its plaintext through the class file even after every {@code LDC} was
     * rewritten (javac duplicates compile-time constants into both places).
     * The attribute is removed and the field is initialized at the start of
     * {@code <clinit>} with a decryptor call; for compile-time constants this
     * cannot change observable initialisation order (they are prepared before
     * {@code <clinit>} runs anyway).</p>
     */
    private int encryptFieldConstants(Run run, ClassNode node, byte[] classKey, String classKeyField) {
        boolean perClass = classKey != null && classKeyField != null;
        int count = 0;
        MethodNode clinit = null;
        int projectedBytes = -1;
        for (FieldNode field : node.fields) {
            if (!(field.value instanceof String) || !CLASS_KEY_FIELD_DESC.equals(field.desc)) {
                continue;
            }
            if ((field.access & (Opcodes.ACC_STATIC | Opcodes.ACC_FINAL)) !=
                    (Opcodes.ACC_STATIC | Opcodes.ACC_FINAL)) {
                continue;
            }
            String value = (String) field.value;
            if (!shouldEncrypt(value, run.options)) {
                continue;
            }
            if (run.classSites >= CLASS_SITE_LIMIT) {
                run.classLimitSkips++;
                break;
            }
            if (clinit == null) {
                clinit = findClinit(node);
                projectedBytes = clinit == null ? 1 : estimateCodeBytes(clinit);
            }
            boolean dual = run.dualEligible(value);
            int growth = dual ? HELPER_SITE_GROWTH + DUAL_SITE_GROWTH : HELPER_SITE_GROWTH;
            if (projectedBytes + growth > MAX_METHOD_CODE_BYTES) {
                run.methodSizeSkips++;
                continue;
            }
            projectedBytes += growth;
            int siteId = run.nextSiteId();
            Site site = encryptSite(run, value, node, siteId, perClass, classKey, dual);
            run.countEngine(site.engine);
            run.countDual(site);
            if (site.partCount > 1) {
                run.splitSites++;
            }
            clinit = ensureClinit(node);
            InsnList code = new InsnList();
            emitHelperCall(run, code, node, site, classKeyField);
            code.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, field.name, CLASS_KEY_FIELD_DESC));
            clinit.instructions.insert(code);
            field.value = null;
            if (site.temporaryKey) {
                Cipher.wipe(site.key);
            }
            run.encrypted++;
            run.classSites++;
            run.fieldConstants++;
            count++;
        }
        return count;
    }

    private static MethodNode findClinit(ClassNode node) {
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method;
            }
        }
        return null;
    }

    private static MethodNode ensureClinit(ClassNode node) {
        MethodNode existing = findClinit(node);
        if (existing != null) {
            return existing;
        }
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 0;
        clinit.maxStack = 0;
        node.methods.add(clinit);
        return clinit;
    }

    /** True when this class can host invokedynamic call sites. */
    private static boolean indyAllowed(ClassNode node, Options options) {
        if (!options.indy) {
            return false;
        }
        if ((node.version & 0xFFFF) >= Opcodes.V1_7) {
            return true;
        }
        if (AsmUtil.containsJsrOrRet(node)) {
            return false;
        }
        node.version = Opcodes.V1_7;
        return true;
    }

    /**
     * Encrypts one call site and prepares its constant-pool payload.
     *
     * <p>With {@code dualRequested} the value is encrypted twice under two
     * different engines and the two part lists are concatenated (first half
     * {@code engine}, second half {@code engineB}). Both halves are keyed with
     * their own domain-separated site index ({@link UmbraStringCipher#dualSiteId}),
     * so the two ciphertexts never share a keystream.</p>
     */
    private static Site encryptSite(Run run, String value, ClassNode node, int siteId,
                                    boolean perClass, byte[] classKey, boolean dualRequested) {
        int engine = run.engineFor(node.name, siteId);
        int second = -1;
        if (dualRequested) {
            // The xor engine takes its keystream from the per-site seed alone and
            // cannot share the per-class calling convention, so a dual payload
            // always pairs two strong engines.
            if (engine == UmbraStringCipher.XOR) {
                engine = run.strongEngine(UmbraStringCipher.XOR);
            }
            if (engine >= 0) {
                second = run.strongEngine(engine);
            }
        }
        byte[] plain = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        long buildSeed = run.context.config().seed();
        long siteSeed = UmbraStringCipher.siteSeedV2(run.artifactSalt, buildSeed, node.name, siteId);
        byte[] ciphertext;
        byte[] secondCiphertext = null;
        byte[] key = null;
        boolean temporaryKey = false;
        // The xor engine's keystream is seeded from the per-site seed, which a
        // per-class call site does not carry; those sites always use the
        // per-site calling convention even when per-class keys are enabled.
        boolean usePerClass = perClass && engine != UmbraStringCipher.XOR;
        try {
            if (engine == UmbraStringCipher.XOR) {
                ciphertext = UmbraStringCipher.transform(engine, plain, null, null, siteSeed);
            } else if (usePerClass) {
                byte[] nonce = UmbraStringCipher.classNonceV2(run.artifactSalt, classKey, siteId);
                ciphertext = UmbraStringCipher.transform(engine, plain, classKey, nonce, siteSeed);
                Cipher.wipe(nonce);
            } else {
                key = UmbraStringCipher.siteKeyV2(run.artifactSalt, siteSeed, siteId);
                temporaryKey = true;
                byte[] nonce = UmbraStringCipher.siteNonceV2(run.artifactSalt, siteSeed, siteId);
                ciphertext = UmbraStringCipher.transform(engine, plain, key, nonce, siteSeed);
                Cipher.wipe(nonce);
            }
            if (second >= 0) {
                secondCiphertext = encryptSecondHalf(run, second, plain, usePerClass, classKey,
                        siteSeed, UmbraStringCipher.dualSiteId(siteId, 1));
            }
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
        int partCount = run.options.split ? run.options.splitParts : 1;
        String[] parts;
        if (secondCiphertext != null) {
            String[] first = splitParts(ciphertext, partCount);
            String[] other = splitParts(secondCiphertext, partCount);
            Arrays.fill(ciphertext, (byte) 0);
            Arrays.fill(secondCiphertext, (byte) 0);
            if (first.length == other.length) {
                parts = concat(first, other);
            } else {
                // Uneven halves would make the runtime boundary ambiguous; keep
                // the site single-engine instead of emitting a guessed layout.
                run.dualLayoutFallbacks++;
                parts = first;
                second = -1;
            }
        } else {
            parts = splitParts(ciphertext, partCount);
            Arrays.fill(ciphertext, (byte) 0);
        }
        StringBuilder packed = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                packed.append('|');
            }
            packed.append(parts[i]);
        }
        Site site = new Site();
        site.siteId = siteId;
        site.siteSeed = siteSeed;
        site.engine = engine;
        site.engineB = second;
        site.dual = second >= 0;
        site.perClass = usePerClass;
        site.parts = parts;
        site.partCount = parts.length;
        site.packedPayload = packed.toString();
        site.key = key;
        site.temporaryKey = temporaryKey;
        return site;
    }

    /** Encrypts the second half of a dual payload with its own site index. */
    private static byte[] encryptSecondHalf(Run run, int engine, byte[] plain, boolean usePerClass,
                                            byte[] classKey, long siteSeed, int halfSiteId) {
        if (usePerClass) {
            byte[] nonce = UmbraStringCipher.classNonceV2(run.artifactSalt, classKey, halfSiteId);
            byte[] out = UmbraStringCipher.transform(engine, plain, classKey, nonce, siteSeed);
            Cipher.wipe(nonce);
            return out;
        }
        byte[] key = UmbraStringCipher.siteKeyV2(run.artifactSalt, siteSeed, halfSiteId);
        byte[] nonce = UmbraStringCipher.siteNonceV2(run.artifactSalt, siteSeed, halfSiteId);
        byte[] out = UmbraStringCipher.transform(engine, plain, key, nonce, siteSeed);
        Cipher.wipe(nonce);
        Cipher.wipe(key);
        return out;
    }

    /** Concatenates two part lists; the dual layout is "all of A, then all of B". */
    private static String[] concat(String[] first, String[] second) {
        String[] all = new String[first.length + second.length];
        System.arraycopy(first, 0, all, 0, first.length);
        System.arraycopy(second, 0, all, first.length, second.length);
        return all;
    }

    /** Splits ciphertext into {@code count} Base64 parts. */
    static String[] splitParts(byte[] ciphertext, int count) {
        if (count <= 1 || ciphertext.length < count * 2) {
            return new String[] { Cipher.base64(ciphertext) };
        }
        int chunk = (ciphertext.length + count - 1) / count;
        List<String> parts = new ArrayList<String>();
        for (int offset = 0; offset < ciphertext.length; offset += chunk) {
            int length = Math.min(chunk, ciphertext.length - offset);
            byte[] part = new byte[length];
            System.arraycopy(ciphertext, offset, part, 0, length);
            parts.add(Cipher.base64(part));
        }
        return parts.toArray(new String[0]);
    }

    private static void emitParts(InsnList out, String[] parts) {
        AsmUtil.pushInt(out, parts.length);
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"));
        for (int i = 0; i < parts.length; i++) {
            out.add(new InsnNode(Opcodes.DUP));
            AsmUtil.pushInt(out, i);
            out.add(new LdcInsnNode(parts[i]));
            out.add(new InsnNode(Opcodes.AASTORE));
        }
    }

    private static Boolean annotationFlag(List<AnnotationNode> invisible, List<AnnotationNode> visible) {
        Boolean value = AsmUtil.annotationBoolean(invisible, ANNOTATION, "enabled");
        return value != null ? value : AsmUtil.annotationBoolean(visible, ANNOTATION, "enabled");
    }

    // ------------------------------------------------------------------
    // Per-class key field
    // ------------------------------------------------------------------

    private static String allocateFieldName(ClassNode node, PassContext context) {
        Random random = new Random(context.config().seed() ^ node.name.hashCode() * 31L);
        NameGenerator names = new NameGenerator(random, "");
        for (int attempt = 0; attempt < 10000; attempt++) {
            String candidate = "u" + names.random(9);
            boolean exists = false;
            for (FieldNode field : node.fields) {
                if (field.name.equals(candidate)) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to allocate a string key field in " + node.name);
    }

    private static void addClassKeyField(ClassNode node, String name, byte[] classKey) {
        FieldNode field = new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                name, CLASS_KEY_FIELD_DESC, null, Cipher.base64(classKey));
        node.fields.add(0, field);
    }

    // ------------------------------------------------------------------
    // State holders
    // ------------------------------------------------------------------

    /** Resolved string-protection configuration. */
    static final class Options {
        private boolean autoEngine;
        private int singleEngine = UmbraStringCipher.CHACHA20;
        private List<Integer> rotation = new ArrayList<Integer>();
        private boolean perClassKey;
        private boolean split;
        private boolean indy;
        private boolean cache;
        private boolean wipe;
        private boolean stackTraceHide;
        private boolean encryptAll;
        private boolean otpEngines;
        private int otpMaxSites;
        private boolean engineFallback;
        private int engineOrderIgnored;
        private int unsupportedOptions;
        private int minLength;
        private int splitParts;
        private int strength;

        static Options resolve(PassContext context) {
            Map<String, String> map = context.config().options();
            Options options = new Options();
            options.strength = context.config().optionInt("string.strength", 2);
            if (options.strength < 1) {
                options.strength = 1;
            } else if (options.strength > 3) {
                options.strength = 3;
            }
            int presetEngine;
            switch (options.strength) {
                case 1:
                    presetEngine = UmbraStringCipher.XOR;
                    options.perClassKey = false;
                    options.split = false;
                    options.cache = false;
                    options.splitParts = 1;
                    break;
                case 2:
                    presetEngine = UmbraStringCipher.CHACHA20;
                    options.perClassKey = true;
                    options.split = true;
                    options.cache = false;
                    options.splitParts = 2;
                    break;
                default:
                    presetEngine = UmbraStringCipher.CHACHA20;
                    options.perClassKey = true;
                    options.split = true;
                    options.cache = false;
                    options.splitParts = 3;
                    break;
            }
            options.indy = false;
            options.minLength = context.config().stringEncryption().minLength();
            if (options.strength >= 3 && options.minLength > 1) {
                options.minLength = 1;
            }
            String legacyAlgorithm = context.config().option("string.algorithm", null);
            Integer algorithm = parseEngineName(legacyAlgorithm);
            if (legacyAlgorithm != null && !legacyAlgorithm.trim().isEmpty() && algorithm == null) {
                context.log().warn("string-encryption: unsupported string.algorithm '%s' ignored",
                        legacyAlgorithm.trim());
                options.unsupportedOptions++;
            }
            options.singleEngine = algorithm == null ? presetEngine : algorithm.intValue();
            options.perClassKey = context.config().optionBool("string.perClassKey", options.perClassKey);
            options.split = context.config().optionBool("string.split", options.split);
            options.indy = context.config().optionBool("string.indy", options.indy);
            // Plaintext memoization is opt-in only (heap-dump hygiene).
            options.cache = context.config().optionBool("string.cache", false);
            options.wipe = context.config().optionBool("string.wipe", false);
            options.stackTraceHide = context.config().optionBool("string.stackTraceHide", false);
            options.encryptAll = context.config().optionBool("string.encryptAll", false);
            if (options.encryptAll) {
                options.minLength = 1;
            }
            // Dual-ciphertext slots (P0-2-c). The presets that enable the
            // one-time state set this option; the pass still needs the OTP class
            // to supply the selector, so the effective switch also requires
            // otp.enabled (see Run#dualEnabled).
            options.otpEngines = context.config().optionBool("string.otpEngines", false);
            options.otpMaxSites = Math.max(0, Math.min(4096,
                    context.config().optionInt("string.otpMaxSites", DEFAULT_OTP_MAX_SITES)));
            if (map.containsKey("string.splitParts")) {
                options.splitParts = Math.max(1, Math.min(4,
                        context.config().optionInt("string.splitParts", options.splitParts)));
            }
            if (!options.split) {
                options.splitParts = 1;
            }
            String engineSpec = context.config().option("string.engine", null);
            String orderSpec = context.config().option("string.engineOrder", DEFAULT_ENGINE_ORDER);
            if (engineSpec != null && "auto".equalsIgnoreCase(engineSpec.trim())) {
                options.autoEngine = true;
                int[] ignored = new int[1];
                options.rotation = parseEngineOrder(orderSpec, ignored);
                options.engineOrderIgnored = ignored[0];
            } else {
                Integer explicit = parseEngineName(engineSpec);
                if (engineSpec != null && !engineSpec.trim().isEmpty() && explicit == null) {
                    // Never accept an unsupported cipher as a silent
                    // single-engine build: fall back to the randomized whitelist.
                    context.log().warn("string-encryption: unsupported string.engine '%s'; "
                            + "falling back to the auto engine distribution", engineSpec.trim());
                    options.autoEngine = true;
                    options.engineFallback = true;
                    options.unsupportedOptions++;
                    int[] ignored = new int[1];
                    options.rotation = parseEngineOrder(orderSpec, ignored);
                    options.engineOrderIgnored = ignored[0];
                } else {
                    if (explicit != null) {
                        options.singleEngine = explicit.intValue();
                    }
                    options.rotation.add(Integer.valueOf(options.singleEngine));
                }
            }
            return options;
        }

        String describe() {
            if (!autoEngine) {
                return UmbraStringCipher.engineId(singleEngine);
            }
            StringBuilder builder = new StringBuilder("auto[");
            for (int i = 0; i < rotation.size(); i++) {
                if (i > 0) {
                    builder.append(',');
                }
                builder.append(UmbraStringCipher.engineId(rotation.get(i).intValue()));
            }
            return builder.append(']').toString();
        }
    }

    /** Parses one engine name, returning {@code null} for unknown/empty values. */
    static Integer parseEngineName(String raw) {
        if (raw == null) {
            return null;
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if (value.isEmpty()) {
            return null;
        }
        if ("xor".equals(value)) {
            return Integer.valueOf(UmbraStringCipher.XOR);
        }
        if ("rc4".equals(value) || "arc4".equals(value)) {
            return Integer.valueOf(UmbraStringCipher.RC4);
        }
        if ("chacha20".equals(value) || "chacha".equals(value) || "chacha20-poly1305".equals(value)) {
            return Integer.valueOf(UmbraStringCipher.CHACHA20);
        }
        if ("aes-ctr".equals(value) || "aes".equals(value) || "aes256-ctr".equals(value)) {
            return Integer.valueOf(UmbraStringCipher.AES_CTR);
        }
        if ("speck".equals(value) || "speck64".equals(value) || "speck64-128".equals(value)) {
            return Integer.valueOf(UmbraStringCipher.SPECK);
        }
        return null;
    }

    /** Parses a comma/space/semicolon separated engine rotation; never empty. */
    static List<Integer> parseEngineOrder(String raw) {
        return parseEngineOrder(raw, new int[1]);
    }

    /**
     * Parses an engine rotation and counts unsupported/ignored tokens in
     * {@code ignored[0]}. The result is never empty: unknown-only lists fall back
     * to {@link #DEFAULT_ENGINE_ORDER}.
     */
    static List<Integer> parseEngineOrder(String raw, int[] ignored) {
        List<Integer> rotation = new ArrayList<Integer>();
        Set<Integer> seen = new LinkedHashSet<Integer>();
        if (raw != null) {
            String[] tokens = raw.split("[,;\\s]+");
            for (int i = 0; i < tokens.length; i++) {
                if (tokens[i].trim().isEmpty()) {
                    continue;
                }
                Integer engine = parseEngineName(tokens[i]);
                if (engine == null) {
                    if (ignored != null && ignored.length > 0) {
                        ignored[0]++;
                    }
                    continue;
                }
                if (seen.add(engine)) {
                    rotation.add(engine);
                }
            }
        }
        if (rotation.isEmpty()) {
            String[] fallback = DEFAULT_ENGINE_ORDER.split(",");
            for (int i = 0; i < fallback.length; i++) {
                Integer engine = parseEngineName(fallback[i]);
                if (engine != null) {
                    rotation.add(engine);
                }
            }
        }
        return rotation;
    }

    /** Encrypted call-site data. */
    private static final class Site {
        private int siteId;
        private long siteSeed;
        private int engine;
        /** Second engine of a dual payload, {@code -1} for a single-engine site. */
        private int engineB = -1;
        private boolean dual;
        private boolean perClass;
        private String[] parts;
        private int partCount;
        private String packedPayload;
        private byte[] key;
        private boolean temporaryKey;
    }

    /** Per-run mutable state, template cache and statistics. */
    private static final class Run {
        private final PassContext context;
        private final Options options;
        private final int[] engineCounts = new int[5];
        private final long artifactSalt;
        private final Set<Integer> classSiteIds = new HashSet<Integer>();
        private Random classRandom;
        private int encrypted;
        private int fieldConstants;
        private int splitSites;
        private int cacheSites;
        private int indySites;
        private int perClassClasses;
        private int classSites;
        private int methodSizeSkips;
        private int classLimitSkips;
        private final boolean dualEnabled;
        private final Set<Long> otpPairs = new LinkedHashSet<Long>();
        private int otpSites;
        private int classDualSites;
        private int dualLayoutFallbacks;
        private String otpClass;
        private String crypto;
        private String decryptor;
        private String indyHelper;

        Run(PassContext context, Options options) {
            this.context = context;
            this.options = options;
            this.artifactSalt = resolveArtifactSalt(context);
            // Dual payloads need the one-time state for the selector; without it
            // the call sites keep the byte-compatible single-engine form.
            this.dualEnabled = options.otpEngines
                    && context.config().optionBool("otp.enabled", false);
            if (options.otpEngines && !dualEnabled) {
                context.log().debug("string-encryption: string.otpEngines needs otp.enabled; "
                        + "keeping single-engine call sites");
            }
        }

        /**
         * Resolves the per-build artifact salt: explicit {@code string.siteSalt}
         * (decimal/hex number, or hashed text) or a deterministic 64-bit value
         * derived from the build seed. It is embedded in the injected decryptor
         * and mixed into every key/nonce/seed derivation (payload v3).
         */
        private static long resolveArtifactSalt(PassContext context) {
            String raw = context.config().option("string.siteSalt", "");
            if (raw != null && !raw.trim().isEmpty()) {
                String text = raw.trim();
                try {
                    long parsed = Long.decode(text).longValue();
                    return parsed == 0L ? 0x5A17C0DEL : parsed;
                } catch (NumberFormatException notNumeric) {
                    long hashed = UmbraStringCipher.hashSaltText(text);
                    return hashed == 0L ? 0x5A17C0DEL : hashed;
                }
            }
            return UmbraStringCipher.deriveArtifactSalt(context.config().seed());
        }

        void beginClass(String className) {
            classSites = 0;
            classDualSites = 0;
            classSiteIds.clear();
            long seed = context.config().seed();
            long mixed = seed * 0x9E3779B97F4A7C15L
                    ^ artifactSalt * 0xD6E8FEB86659FD93L
                    ^ (className == null ? 0L : className.hashCode() * 0x100000001B3L);
            classRandom = new Random(mixed);
        }

        /**
         * Deterministic but non-sequential 31-bit call-site index, unique inside
         * the class. The index participates in key/nonce derivation, so
         * uniqueness is required to avoid keystream reuse, and random-looking
         * values stop "grep the next index" batch extraction.
         */
        int nextSiteId() {
            if (classRandom == null) {
                throw new IllegalStateException("site id requested before beginClass");
            }
            for (int attempt = 0; attempt < 10000; attempt++) {
                int candidate = classRandom.nextInt() & 0x7FFFFFFF;
                if (classSiteIds.add(Integer.valueOf(candidate))) {
                    return candidate;
                }
            }
            throw new IllegalStateException("Unable to allocate a unique string site id");
        }

        /**
         * Randomized per-site engine selection for {@code string.engine=auto}.
         * Only whitelisted engines can appear (the rotation was parsed from
         * {@link #parseEngineName}); selection is deterministic per seed.
         */
        int engineFor(String className, int siteId) {
            if (!options.autoEngine) {
                return options.singleEngine;
            }
            List<Integer> rotation = options.rotation;
            if (classRandom == null) {
                beginClass(className);
            }
            return rotation.get(classRandom.nextInt(rotation.size())).intValue();
        }

        void countEngine(int engine) {
            if (engine >= 0 && engine < engineCounts.length) {
                engineCounts[engine]++;
            }
        }

        /**
         * Whether this site gets the doubled payload: the feature must be on, the
         * one-time state must be injected, the literal must be long enough for
         * the doubling to pay off, and the per-class cap must not be exhausted.
         */
        boolean dualEligible(String value) {
            if (!dualEnabled || value.length() < Math.max(options.minLength, MIN_DUAL_LENGTH)) {
                return false;
            }
            return classDualSites < options.otpMaxSites;
        }

        /** Records a site that really carries two ciphertexts. */
        void countDual(Site site) {
            if (!site.dual) {
                return;
            }
            otpSites++;
            classDualSites++;
            otpPairs.add(Long.valueOf((((long) site.engine) << 8) | site.engineB));
        }

        /**
         * Deterministic second-engine choice for a dual payload. The configured
         * rotation is preferred; when it pins a single engine (or only engines
         * already excluded) the default strong order is used, because a dual
         * payload needs two different ciphers by definition. Never returns
         * {@link UmbraStringCipher#XOR} and never returns {@code exclude}.
         */
        int strongEngine(int exclude) {
            List<Integer> candidates = new ArrayList<Integer>();
            for (int i = 0; i < options.rotation.size(); i++) {
                int candidate = options.rotation.get(i).intValue();
                if (candidate != exclude && candidate != UmbraStringCipher.XOR) {
                    candidates.add(Integer.valueOf(candidate));
                }
            }
            if (candidates.isEmpty()) {
                for (int i = 0; i < STRONG_ENGINES.length; i++) {
                    if (STRONG_ENGINES[i] != exclude) {
                        candidates.add(Integer.valueOf(STRONG_ENGINES[i]));
                    }
                }
            }
            if (candidates.isEmpty()) {
                return -1;
            }
            if (classRandom == null) {
                throw new IllegalStateException("engine requested before beginClass");
            }
            return candidates.get(classRandom.nextInt(candidates.size())).intValue();
        }

        /** Injected one-time state class, injected on first use and then cached. */
        String otpClass() {
            if (otpClass == null) {
                otpClass = context.runtime().ensureOtp(context.classes(), context.config().seed());
            }
            return otpClass;
        }

        int engineKinds() {
            int kinds = 0;
            for (int i = 0; i < engineCounts.length; i++) {
                if (engineCounts[i] > 0) {
                    kinds++;
                }
            }
            return kinds;
        }

        String describeEngines() {
            StringBuilder builder = new StringBuilder();
            if (options.autoEngine) {
                builder.append("auto:");
            }
            boolean first = true;
            for (int engine = 0; engine < engineCounts.length; engine++) {
                if (engineCounts[engine] == 0) {
                    continue;
                }
                if (!first) {
                    builder.append(", ");
                }
                builder.append(UmbraStringCipher.engineId(engine)).append('=')
                        .append(engineCounts[engine]);
                first = false;
            }
            if (first) {
                builder.append(options.describe());
            }
            return builder.toString();
        }

        String decryptor() {
            if (decryptor == null) {
                crypto = CryptoSupport.ensureCrypto(context.classes(), context.config().seed());
                decryptor = CryptoSupport.randomName(context.classes(), context.config().seed(),
                        "string-decryptor-v3", RuntimeNames.path("S"));
                int flags = (options.wipe ? 1 : 0) | (options.stackTraceHide ? 2 : 0)
                        | (options.cache ? 4 : 0);
                Map<String, String> replacements = new LinkedHashMap<String, String>();
                replacements.put(FLAGS_SPEC, String.valueOf(flags));
                replacements.put(SALT_SPEC, Long.toString(artifactSalt));
                CryptoSupport.injectWithCrypto(context.classes(), UmbraStringCipher.class, decryptor,
                        crypto, replacements);
            }
            return decryptor;
        }

        String indyHelper() {
            if (indyHelper == null) {
                String target = decryptor();
                Map<String, String> extra = new LinkedHashMap<String, String>();
                extra.put("io/umbra/core/runtime/crypto/UmbraStringCipher", target);
                indyHelper = CryptoSupport.randomName(context.classes(), context.config().seed(),
                        "string-indy-bootstrap-v3", RuntimeNames.path("I"));
                CryptoSupport.injectWithCrypto(context.classes(), UmbraStringIndy.class, indyHelper,
                        crypto, null, extra);
            }
            return indyHelper;
        }

        void logTemplates() {
            if (decryptor != null) {
                context.log().debug("string-encryption: decryptor %s, crypto helper %s", decryptor, crypto);
            }
            if (indyHelper != null) {
                context.log().debug("string-encryption: indy bootstrap %s", indyHelper);
            }
        }
    }
}
