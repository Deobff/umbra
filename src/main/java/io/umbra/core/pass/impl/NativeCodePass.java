package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.model.ClassPool;
import io.umbra.core.jni.CGenerator;
import io.umbra.core.jni.NativeCompiler;
import io.umbra.core.jni.NativeMethodTranslator;
import io.umbra.core.jni.NativeSettings;
import io.umbra.core.jni.intrinsic.IntrinsicTable;
import io.umbra.core.jni.payload.Lzma2Writer;
import io.umbra.core.jni.payload.PayloadCodec;
import io.umbra.core.jni.payload.PayloadLayout;
import io.umbra.annotations.NativeExclude;
import io.umbra.annotations.NativeInclude;
import io.umbra.core.runtime.TemplateInjector;
import io.umbra.core.runtime.UmbraNativeLoader;
import io.umbra.core.runtime.crypto.GuardSupport;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.Log;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeAnnotationNode;

import java.io.IOException;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import io.umbra.core.util.RuntimeNames;

/**
 * Native (JNI) code generation.
 *
 * <p>Eligible method bodies are transpiled to C, compiled into a shared library
 * with the configured compiler and rebound as {@code native} methods. Binding
 * uses the JVM&#39;s JNI symbol lookup: every method gets short and long
 * {@code Java_<mangled>} exports (JNI name mangling rules, including unicode
 * escapes). {@code RegisterNatives} is intentionally not used because HotSpot
 * initializes the class as a side effect of that call, which would run class
 * initializers at library-load time. The compiled library is embedded in the
 * output JAR as a raw resource; an injected loader class extracts it at runtime
 * and loads it from a synthesized {@code <clinit>} hook before any native method
 * can run.</p>
 *
 * <p>The pass is deliberately conservative: anything the translator cannot
 * faithfully reproduce (constructors, class initializers, invalid bytecode,
 * monitors, {@code invokedynamic}, ...) keeps its Java implementation. When the
 * C toolchain is missing or compilation fails and {@code native.atomic=true}
 * (default) the pass logs a warning and leaves the whole program untouched.</p>
 */
public final class NativeCodePass implements Pass {

    private static final long ZIP_TIME = 315532800000L;

    /** Name the translated class initializer is published under. */
    private static final String CLINIT_NATIVE_NAME = "$umbraClinit";

    private static final String INCLUDE_DESC =
            "L" + NativeInclude.class.getName().replace('.', '/') + ";";

    private static final String EXCLUDE_DESC =
            "L" + NativeExclude.class.getName().replace('.', '/') + ";";
    private static final int MAX_LOGGED_COMPILER_OUTPUT = 8000;

    @Override
    public String name() {
        return "native-code";
    }

    @Override
    public int order() {
        return 106;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool("native.enabled", false);
    }

    @Override
    public void run(PassContext context) {
        NativeSettings settings = NativeSettings.from(context.config());
        context.log().debug("native-code: %s", settings);

        String compiler = NativeCompiler.resolve(settings.compiler(), context.log());
        if (compiler == null || !NativeCompiler.hasJniHeaders()) {
            if (compiler == null) {
                context.log().warn("native-code: no C compiler available (configured '%s'); keeping Java methods",
                        settings.compiler());
            } else {
                context.log().warn("native-code: JNI headers of the running JDK were not found; keeping Java methods");
            }
            context.stats().add("native.fallback", 1);
            context.stats().text("native.fallbackReason", "native toolchain unavailable");
            failIfNotAtomic(context, settings, "native toolchain unavailable");
            return;
        }

        List<ClassWork> classes = select(context, settings);
        if (classes.isEmpty()) {
            context.log().info("native-code: no eligible methods found");
            context.stats().add("native.methods", 0);
            return;
        }

        Path tempDirectory = null;
        boolean loaderInjected = false;
        String loaderName = null;
        List<ConstructorRewrite> rewrites = new ArrayList<ConstructorRewrite>();
        List<AddedMethod> addedMethods = new ArrayList<AddedMethod>();
        List<ClinitRewrite> clinits = new ArrayList<ClinitRewrite>();
        try {

            cleanupStaleNativeTemp(context.log());
            tempDirectory = Files.createTempDirectory(NativeCompiler.randomToken());
            CGenerator generator = new CGenerator();

            generator.configureLiteralKey(context.random().nextLong());
            boolean antiDump = settings.antiDump();
            boolean antiBackfill = settings.antiBackfill();
            String resourceName = resourceName(context, settings);
            long antiDumpKey = context.random().nextLong();
            long translatedInstructions = 0;
            int translatedMethods = 0;
            int skipped = 0;
            int indyBridges = 0;
            int constructorsExtracted = 0;
            Map<String, Integer> ownerIds = new LinkedHashMap<String, Integer>();
            if (settings.constructors()) {
                for (ClassWork work : classes) {
                    constructorsExtracted += extractConstructorBodies(context, work, rewrites);
                }
            }
            for (ClassWork work : classes) {
                int accepted = 0;
                for (MethodNode method : new ArrayList<MethodNode>(work.methods)) {
                    if (settings.maxMethodsPerClass() > 0 && accepted >= settings.maxMethodsPerClass()) {
                        break;
                    }
                    if (instructionCount(method) > settings.maxInstructions()) {
                        skipped++;
                        continue;
                    }
                    MethodNode input = method;
                    List<AddedMethod> methodBridges = new ArrayList<AddedMethod>();
                    if (settings.indy()) {
                        MethodNode copy = copyMethod(method);
                        if (hasInvokeDynamic(copy)) {
                            bridgeInvokeDynamic(work.node, copy, methodBridges);
                            addedMethods.addAll(methodBridges);
                            input = copy;
                        }
                    }
                    NativeMethodTranslator translator =
                            new NativeMethodTranslator(work.node.name, input, generator);
                    try {
                        CGenerator.MethodC generated = translator.translate();
                        generator.addMethod(generated);
                        work.translated.add(generated);
                        work.translatedNames.add(method.name + method.desc);

                        if (!ownerIds.containsKey(work.node.name)) {
                            ownerIds.put(work.node.name, Integer.valueOf(ownerIds.size()));
                        }
                        accepted++;
                        translatedInstructions += translator.instructionCount();
                        indyBridges += methodBridges.size();
                    } catch (NativeMethodTranslator.UnsupportedException e) {
                        skipped++;
                        discardBridges(work.node, methodBridges);
                        context.log().debug("native-code: skipping %s#%s%s: %s",
                                work.node.name, method.name, method.desc, e.getMessage());
                    } catch (RuntimeException e) {
                        skipped++;
                        discardBridges(work.node, methodBridges);
                        context.log().debug("native-code: skipping %s#%s%s: %s",
                                work.node.name, method.name, method.desc, String.valueOf(e));
                    }
                }
                if (settings.classInitializers()) {
                    MethodNode clinit = findClinit(work.node);
                    if (clinit != null && clinit.instructions != null
                            && instructionCount(clinit) <= settings.maxInstructions()) {
                        MethodNode copy = copyMethod(clinit);
                        copy.name = CLINIT_NATIVE_NAME;
                        try {
                            CGenerator.MethodC generated = new NativeMethodTranslator(
                                    work.node.name, copy, generator, true).translate();
                            generator.addMethod(generated);
                            work.translated.add(generated);
                            work.translatedNames.add(CLINIT_NATIVE_NAME + "()V");
                            clinits.add(new ClinitRewrite(work, clinit));
                            if (!ownerIds.containsKey(work.node.name)) {
                                ownerIds.put(work.node.name, Integer.valueOf(ownerIds.size()));
                            }
                            translatedInstructions += instructionCount(clinit);
                            context.log().debug("native-code: translated %s#<clinit> as %s",
                                    work.node.name, CLINIT_NATIVE_NAME);
                        } catch (Exception unsupported) {
                            context.log().debug("native-code: keeping %s#<clinit> in Java: %s",
                                    work.node.name, String.valueOf(unsupported));
                        }
                    }
                }
                translatedMethods += work.translated.size();
            }

            int constructorBodies = 0;
            for (ConstructorRewrite rewrite : rewrites) {
                if (rewrite.work.translatedNames.contains(rewrite.helper.name + rewrite.helper.desc)) {
                    constructorBodies++;
                } else {
                    revertConstructor(rewrite);
                }
            }
            context.stats().add("native.skipped", skipped);
            if (translatedMethods == 0) {
                context.log().info("native-code: no method could be translated");
                context.stats().add("native.methods", 0);
                rollbackCoverage(rewrites, addedMethods);
                return;
            }

            Map<String, String> replacements = new LinkedHashMap<String, String>();

            // The injected loader template declares its JAR entry as @@RESOURCE@@
            // (UmbraNativeLoader.RESOURCE). The old map only knew @@CODELIB@@ - the
            // key the class-encryption loader uses - so every single-pass native
            // build kept the literal placeholder and died at runtime with
            // UnsatisfiedLinkError. Keep both: @@RESOURCE@@ feeds the native loader,
            // @@CODELIB@@ stays for a bridge loader that declares it.
            replacements.put("@@RESOURCE@@", resourceName);
            replacements.put("@@CODELIB@@", resourceName);
            replacements.put("@@ANTIDUMP@@", String.valueOf(antiDump));
            replacements.put("@@ANTIBACKFILL@@", String.valueOf(antiBackfill));
            replacements.put("@@AKEY@@", hex16(antiDumpKey));
            // The fingerprint is not known before the library is compiled. Leave its
            // placeholders in the injected template and fill them below, so both the
            // constant-pool copies and the static fields end up with the same chunks.
            // (Substituting dummy zeros at injection time used to leave the fields on
            // the dummy value while only the folded string literal got the real one.)

            String sharedLoader = context.classes().getMeta("native.loader");
            if (sharedLoader != null && !sharedLoader.isEmpty()) {
                loaderName = sharedLoader;
                loaderInjected = false;
            } else {
                context.log().warn("native-code: native.loader missing; injecting a second loader");
                loaderName = TemplateInjector.inject(context.classes(), UmbraNativeLoader.class,
                        RuntimeNames.path("N"), context.config().seed(), replacements);
                loaderInjected = true;
            }
            if (antiDump || antiBackfill) {
                generator.configureAntiDump(loaderName, antiDumpKey, antiBackfill);
            }

            generator.configureRegistration(loaderName);

            String sourceText = generator.finish();

            if (!sourceText.contains("umbra_bind_loader(JNIEnv* env, jclass loader")
                    || !sourceText.contains("const char* registerName")) {
                throw new IllegalStateException("native-code: umbra_bind_loader lost its name parameters");
            }
            Path sourceFile = tempDirectory.resolve("umbra_native.c");
            Files.write(sourceFile, (NATIVE_SOURCE_MARKER + "\n" + sourceText)
                    .getBytes(StandardCharsets.UTF_8));
            Path nativeDirectory = tempDirectory.resolve("out");
            Files.createDirectories(nativeDirectory);

            List<String> targets = filterTargets(settings, compiler, context);
            List<byte[]> libraries = new ArrayList<byte[]>();
            StringBuilder layout = new StringBuilder();
            long offset = 0L;
            long compiledMillis = 0L;
            NativeCompiler.Result lastResult = null;
            for (String target : targets) {
                Path libraryFile = nativeDirectory.resolve(
                        "umbra_native_" + target.toLowerCase(java.util.Locale.ROOT) + librarySuffix(target));
                NativeCompiler.Result result = NativeCompiler.compile(compiler, sourceFile,
                        libraryFile, osFamily(target), settings.compilerFlags(), context.log());
                compiledMillis += result.millis();
                if (!result.success()) {
                    context.log().error("native-code: compilation failed for %s with %s; keeping Java methods",
                            target, displayCommand(result));
                    String output = result.output();
                    if (output != null && !output.trim().isEmpty()) {
                        context.log().error("native-code: compiler output: %s", abbreviate(output));
                    }
                    context.stats().add("native.fallback", 1);
                    context.stats().add("native.compileFailed", 1);
                    context.stats().text("native.fallbackReason", "native compilation failed");
                    rollbackCoverage(rewrites, addedMethods);
                    failIfNotAtomic(context, settings, "native compilation failed");
                    return;
                }
                byte[] library = Files.readAllBytes(result.library());
                layout.append(PayloadLayout.line(target, offset, offset + library.length));
                offset += library.length;
                libraries.add(library);
                lastResult = result;
                context.stats().add("native.compile", 1);
            }
            deleteSourceWithRetry(sourceFile, context.log());
            context.stats().add("native.compile.ms", compiledMillis);
            byte[] libraryBytes = PayloadCodec.concat(libraries);
            byte[] payload = settings.payload() ? Lzma2Writer.encode(libraryBytes) : libraryBytes;
            String layoutName = resourceName(context, settings, "lay");
            replacements.put("@@LAYOUT@@", layoutName);
            replacements.put("@@PAYLOAD@@", settings.payload() ? "1" : "0");
            context.stats().add("native.dll.bytes", libraryBytes.length);
            context.stats().add("native.payload.bytes", payload.length);
            context.stats().add("native.payload.targets", targets.size());
            context.stats().add("native.payload.enabled", settings.payload() ? 1 : 0);

            if (antiDump) {
                // The digest covers the *decompressed* payload: the loader rebuilds
                // exactly these bytes before System.load, so one digest serves every
                // platform folded into this build.
                String fingerprint = sha256Hex(libraryBytes);
                if (fingerprint == null || fingerprint.length() != 64) {
                    throw new IllegalStateException(
                            "native-code: cannot compute the library fingerprint");
                }
                replacements.put("@@FP0@@", fingerprint.substring(0, 24));
                replacements.put("@@FP1@@", fingerprint.substring(24, 44));
                replacements.put("@@FP2@@", fingerprint.substring(44, 64));
            } else {
                // antiDump is off: the constants are dead but must not survive as
                // placeholders, or the fail-closed loader assertion below rejects a
                // build that is perfectly fine.
                replacements.put("@@FP0@@", "000000000000000000000000");
                replacements.put("@@FP1@@", "00000000000000000000");
                replacements.put("@@FP2@@", "00000000000000000000");
            }
            patchLoaderConstants(context.classes(), loaderName, replacements);
            assertLoaderReady(context, context.classes(), loaderName);

            int convertedClasses = 0;
            int convertedMethods = 0;

            String hookDispatch = GuardSupport.ensureGuardDispatch(context.classes(), loaderName);
            for (ClinitRewrite clinit : clinits) {
                clinit.method.name = CLINIT_NATIVE_NAME;
                convertToNative(clinit.method);
                clinit.work.clinitNativized = true;
                convertedMethods++;
                context.stats().add("native.clinit", 1);
            }
            for (ClassWork work : classes) {
                if (work.translated.isEmpty()) {
                    continue;
                }
                for (MethodNode method : work.methods) {
                    if (!work.translatedNames.contains(method.name + method.desc)) {
                        continue;
                    }
                    convertToNative(method);
                    convertedMethods++;
                }
                addLoaderHook(work.node, loaderName, ownerIds.get(work.node.name).intValue(),
                        hookDispatch, work.clinitNativized ? CLINIT_NATIVE_NAME : null);
                convertedClasses++;
            }

            context.classes().putResource(resourceName, payload, ZIP_TIME, 8);
            context.classes().putResource(layoutName,
                    layout.toString().getBytes(StandardCharsets.UTF_8), ZIP_TIME, 8);

            context.classes().putMeta("native.codeLibrary", resourceName);
            context.classes().putMeta("native.codeLayout", layoutName);
            if (settings.keepDll()) {
                keepArtifacts(context, settings, sourceText, libraryBytes, lastResult);
            }

            context.stats().add("native.methods", convertedMethods);
            context.stats().add("native.classes", convertedClasses);
            context.stats().add("native.instructions", translatedInstructions);
            context.stats().add("native.constructors", constructorsExtracted);
            context.stats().add("native.constructorBodies", constructorBodies);
            context.stats().add("native.indyBridges", indyBridges);
            context.stats().add("native.idSites", generator.idSiteCount());
            context.stats().add("native.idDedup", generator.idSiteCount() - generator.uniqueIdCount());
            context.stats().add("native.intrinsics", generator.intrinsicCount());
            context.stats().add("native.antiDump", antiDump ? 1 : 0);
            context.stats().add("native.antiDump.fingerprint", antiDump ? 1 : 0);
            context.stats().add("native.antiBackfill", antiBackfill ? 1 : 0);
            context.stats().add("native.antiBackfill.entries", generator.bindingCount());
            context.log().info("native-code: translated %d methods in %d classes into a %d-byte native library"
                            + " (%s, %d translated JVM instructions, %d skipped, %d constructor "
                            + "bodies, %d indy bridges, antiDump=%s, antiBackfill=%s/%d entries)",
                    convertedMethods, convertedClasses, libraryBytes.length,
                    lastResult == null ? "no compiler output" : lastResult.command(),
                    translatedInstructions, skipped, constructorBodies,
                    indyBridges, antiDump ? "sha256" : "off",
                    antiBackfill ? "table+challenge" : "off",
                    Integer.valueOf(generator.bindingCount()));
        } catch (IOException e) {
            rollbackCoverage(rewrites, addedMethods);
            if (loaderInjected && loaderName != null) {
                context.classes().removeClass(loaderName);
            }
            context.log().warn("native-code: I/O failure while generating the native library: %s", e);
            context.stats().add("native.fallback", 1);
            context.stats().text("native.fallbackReason", "native generation failed");
            failIfNotAtomic(context, settings, "native generation failed");
        } catch (RuntimeException e) {
            rollbackCoverage(rewrites, addedMethods);
            if (loaderInjected && loaderName != null) {
                context.classes().removeClass(loaderName);
            }
            throw e;
        } finally {
            if (tempDirectory != null) {
                deleteRecursively(tempDirectory);
                if (Files.exists(tempDirectory)) {

                    deleteRecursively(tempDirectory);
                    context.log().warn("native-code: temp directory survived cleanup: %s",
                            tempDirectory);
                }
            }
        }
    }

    /**
     * A {@code <clinit>} whose body was translated. The rename and the body wipe
     * only happen after the whole library compiled, so a failed build leaves the
     * original initializer untouched.
     */
    private static final class ClinitRewrite {
        final ClassWork work;
        final MethodNode method;

        ClinitRewrite(ClassWork work, MethodNode method) {
            this.work = work;
            this.method = method;
        }
    }

    private static final class AddedMethod {
        final ClassNode owner;
        final MethodNode method;

        AddedMethod(ClassNode owner, MethodNode method) {
            this.owner = owner;
            this.method = method;
        }
    }

    private static final class ConstructorRewrite {
        final ClassWork work;
        final MethodNode constructor;
        final InsnList savedInstructions;
        final List<org.objectweb.asm.tree.TryCatchBlockNode> savedTrys;
        final MethodNode helper;

        ConstructorRewrite(ClassWork work, MethodNode constructor, InsnList savedInstructions,
                           List<org.objectweb.asm.tree.TryCatchBlockNode> savedTrys,
                           MethodNode helper) {
            this.work = work;
            this.constructor = constructor;
            this.savedInstructions = savedInstructions;
            this.savedTrys = savedTrys;
            this.helper = helper;
        }
    }

    private static int extractConstructorBodies(PassContext context, ClassWork work,
                                                List<ConstructorRewrite> rewrites) {
        ClassNode owner = work.node;
        if ((owner.access & Opcodes.ACC_INTERFACE) != 0) {
            return 0;
        }
        List<MethodNode> snapshot = new ArrayList<MethodNode>(owner.methods);
        int extracted = 0;
        for (MethodNode constructor : snapshot) {
            if (!"<init>".equals(constructor.name)) {
                continue;
            }
            ConstructorRewrite rewrite = extractConstructorBody(context, work, constructor);
            if (rewrite != null) {
                rewrites.add(rewrite);
                extracted++;
            }
        }
        return extracted;
    }

    private static ConstructorRewrite extractConstructorBody(PassContext context, ClassWork work,
                                                             MethodNode constructor) {
        ClassNode owner = work.node;
        if ((constructor.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE
                | Opcodes.ACC_SYNCHRONIZED)) != 0) {
            return null;
        }
        if (constructor.instructions == null || constructor.instructions.size() < 2) {
            return null;
        }
        List<AbstractInsnNode> nodes = new ArrayList<AbstractInsnNode>();
        Map<LabelNode, Integer> labelIndex = new java.util.IdentityHashMap<LabelNode, Integer>();
        for (AbstractInsnNode insn = constructor.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof LabelNode) {
                labelIndex.put((LabelNode) insn, Integer.valueOf(nodes.size()));
            }
            nodes.add(insn);
        }
        int initializerIndex = -1;
        for (int i = 0; i < nodes.size(); i++) {
            AbstractInsnNode insn = nodes.get(i);
            if (!(insn instanceof MethodInsnNode)) {
                continue;
            }
            MethodInsnNode call = (MethodInsnNode) insn;
            if (call.getOpcode() == Opcodes.INVOKESPECIAL && "<init>".equals(call.name)
                    && (call.owner.equals(owner.superName) || call.owner.equals(owner.name))) {
                if (initializerIndex >= 0) {
                    return null;
                }
                initializerIndex = i;
            }
        }
        if (initializerIndex < 0) {
            return null;
        }

        for (AbstractInsnNode insn : nodes) {
            int opcode = insn.getOpcode();
            if (opcode < 0) {
                continue;
            }
            if (insn instanceof JumpInsnNode || insn instanceof TableSwitchInsnNode
                    || insn instanceof LookupSwitchInsnNode
                    || opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT) {
                return null;
            }
        }

        if (constructor.tryCatchBlocks != null) {
            for (org.objectweb.asm.tree.TryCatchBlockNode block : constructor.tryCatchBlocks) {
                Integer start = labelIndex.get(block.start);
                Integer end = labelIndex.get(block.end);
                Integer handler = labelIndex.get(block.handler);
                if (start == null || end == null || handler == null
                        || start.intValue() <= initializerIndex
                        || end.intValue() <= initializerIndex
                        || handler.intValue() <= initializerIndex) {
                    return null;
                }
            }
        }

        for (int i = initializerIndex + 1; i < nodes.size(); i++) {
            AbstractInsnNode insn = nodes.get(i);
            if (!(insn instanceof FieldInsnNode) || insn.getOpcode() != Opcodes.PUTFIELD) {
                continue;
            }
            FieldInsnNode field = (FieldInsnNode) insn;
            for (FieldNode candidate : owner.fields) {
                if (candidate.name.equals(field.name)
                        && (candidate.access & Opcodes.ACC_FINAL) != 0) {
                    return null;
                }
            }
        }
        int bodySize = 0;
        for (int i = initializerIndex + 1; i < nodes.size(); i++) {
            AbstractInsnNode insn = nodes.get(i);
            if (!(insn instanceof LabelNode) && !(insn instanceof LineNumberNode)
                    && !(insn instanceof FrameNode)) {
                bodySize++;
            }
        }
        if (bodySize < 2) {
            return null;
        }
        String helperName = uniqueHelperName(owner);
        MethodNode helper = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_SYNTHETIC, helperName, constructor.desc,
                null, null);
        Map<LabelNode, LabelNode> labelMap = new java.util.IdentityHashMap<LabelNode, LabelNode>();
        for (int i = initializerIndex + 1; i < nodes.size(); i++) {
            if (nodes.get(i) instanceof LabelNode) {
                labelMap.put((LabelNode) nodes.get(i), new LabelNode());
            }
        }
        for (int i = initializerIndex + 1; i < nodes.size(); i++) {
            helper.instructions.add(nodes.get(i).clone(labelMap));
        }
        if (constructor.tryCatchBlocks != null) {
            helper.tryCatchBlocks = new ArrayList<org.objectweb.asm.tree.TryCatchBlockNode>();
            for (org.objectweb.asm.tree.TryCatchBlockNode block : constructor.tryCatchBlocks) {
                LabelNode start = labelMap.get(block.start);
                LabelNode end = labelMap.get(block.end);
                LabelNode handler = labelMap.get(block.handler);
                if (start == null || end == null || handler == null) {
                    return null;
                }
                helper.tryCatchBlocks.add(
                        new org.objectweb.asm.tree.TryCatchBlockNode(start, end, handler, block.type));
            }
        }
        helper.maxLocals = constructor.maxLocals;
        // The extracted tail may legitimately need at least as much stack as the
        // whole constructor; leave headroom so a verifier never rejects it.
        helper.maxStack = Math.max(constructor.maxStack, 8) + 4;

        // Deep snapshot: the rebuild below moves the original nodes into a new
        // InsnList, so a shallow reference cannot restore them on rollback.
        Map<LabelNode, LabelNode> snapshotLabels =
                new java.util.IdentityHashMap<LabelNode, LabelNode>();
        for (AbstractInsnNode insn = constructor.instructions.getFirst(); insn != null;
                insn = insn.getNext()) {
            if (insn instanceof LabelNode) {
                snapshotLabels.put((LabelNode) insn, new LabelNode());
            }
        }
        InsnList savedInstructions = new InsnList();
        for (AbstractInsnNode insn = constructor.instructions.getFirst(); insn != null;
                insn = insn.getNext()) {
            savedInstructions.add(insn.clone(snapshotLabels));
        }
        List<org.objectweb.asm.tree.TryCatchBlockNode> savedTrys =
                new ArrayList<org.objectweb.asm.tree.TryCatchBlockNode>();
        if (constructor.tryCatchBlocks != null) {
            for (org.objectweb.asm.tree.TryCatchBlockNode block : constructor.tryCatchBlocks) {
                LabelNode start = snapshotLabels.get(block.start);
                LabelNode end = snapshotLabels.get(block.end);
                LabelNode handler = snapshotLabels.get(block.handler);
                if (start != null && end != null && handler != null) {
                    savedTrys.add(new org.objectweb.asm.tree.TryCatchBlockNode(
                            start, end, handler, block.type));
                }
            }
        }

        InsnList rebuilt = new InsnList();
        for (int i = 0; i <= initializerIndex; i++) {
            rebuilt.add(nodes.get(i));
        }
        rebuilt.add(new VarInsnNode(Opcodes.ALOAD, 0));
        int slot = 1;
        int argumentSlots = 1;
        for (Type argument : Type.getArgumentTypes(constructor.desc)) {
            rebuilt.add(new VarInsnNode(AsmUtil.loadOpcode(argument), slot));
            slot += argument.getSize();
            argumentSlots += argument.getSize();
        }
        rebuilt.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, owner.name, helperName,
                constructor.desc, false));
        rebuilt.add(new InsnNode(Opcodes.RETURN));
        constructor.instructions = rebuilt;
        constructor.tryCatchBlocks = new ArrayList<org.objectweb.asm.tree.TryCatchBlockNode>();
        constructor.localVariables = null;
        constructor.visibleLocalVariableAnnotations = null;
        constructor.invisibleLocalVariableAnnotations = null;
        constructor.maxStack = Math.max(2, argumentSlots + 1);
        owner.methods.add(helper);
        work.methods.add(helper);
        context.log().debug("native-code: extracted constructor body %s#%s%s into %s",
                owner.name, constructor.name, constructor.desc, helperName);
        return new ConstructorRewrite(work, constructor, savedInstructions, savedTrys, helper);
    }

    private static String uniqueHelperName(ClassNode owner) {
        int counter = 0;
        while (true) {
            String candidate = "umbra$ctor$" + Integer.toHexString(counter);
            boolean taken = false;
            for (MethodNode method : owner.methods) {
                if (method.name.equals(candidate)) {
                    taken = true;
                    break;
                }
            }
            if (!taken) {
                return candidate;
            }
            counter++;
        }
    }

    private static void revertConstructor(ConstructorRewrite rewrite) {
        rewrite.constructor.instructions = rewrite.savedInstructions;
        rewrite.constructor.tryCatchBlocks = rewrite.savedTrys;
        rewrite.work.node.methods.remove(rewrite.helper);
    }

    private static void rollbackCoverage(List<ConstructorRewrite> rewrites,
                                         List<AddedMethod> addedMethods) {
        for (ConstructorRewrite rewrite : rewrites) {
            revertConstructor(rewrite);
        }
        for (AddedMethod added : addedMethods) {
            added.owner.methods.remove(added.method);
        }
    }

    private static MethodNode copyMethod(MethodNode source) {
        MethodNode copy = new MethodNode(source.access, source.name, source.desc,
                source.signature, source.exceptions == null ? null
                : source.exceptions.toArray(new String[0]));
        copy.maxLocals = source.maxLocals;
        copy.maxStack = source.maxStack;
        Map<LabelNode, LabelNode> labels = new java.util.IdentityHashMap<LabelNode, LabelNode>();
        for (AbstractInsnNode insn = source.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof LabelNode) {
                labels.put((LabelNode) insn, new LabelNode());
            }
        }
        for (AbstractInsnNode insn = source.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            copy.instructions.add(insn.clone(labels));
        }
        if (source.tryCatchBlocks != null) {
            copy.tryCatchBlocks = new ArrayList<org.objectweb.asm.tree.TryCatchBlockNode>();
            for (org.objectweb.asm.tree.TryCatchBlockNode block : source.tryCatchBlocks) {
                copy.tryCatchBlocks.add(new org.objectweb.asm.tree.TryCatchBlockNode(
                        labels.get(block.start), labels.get(block.end), labels.get(block.handler),
                        block.type));
            }
        }
        return copy;
    }

    private static boolean hasInvokeDynamic(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof InvokeDynamicInsnNode) {
                return true;
            }
        }
        return false;
    }

    private static int bridgeInvokeDynamic(ClassNode owner, MethodNode method,
                                           List<AddedMethod> addedMethods) {
        List<InvokeDynamicInsnNode> found = new ArrayList<InvokeDynamicInsnNode>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof InvokeDynamicInsnNode) {
                found.add((InvokeDynamicInsnNode) insn);
            }
        }
        for (int i = 0; i < found.size(); i++) {
            InvokeDynamicInsnNode indy = found.get(i);
            String bridgeName = uniqueBridgeName(owner);
            MethodNode bridge = new MethodNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    bridgeName, indy.desc, null, null);
            int slot = 0;
            for (Type argument : Type.getArgumentTypes(indy.desc)) {
                bridge.instructions.add(new VarInsnNode(AsmUtil.loadOpcode(argument), slot));
                slot += argument.getSize();
            }
            bridge.instructions.add(
                    new InvokeDynamicInsnNode(indy.name, indy.desc, indy.bsm, indy.bsmArgs));
            bridge.instructions.add(
                    new InsnNode(AsmUtil.returnOpcode(Type.getReturnType(indy.desc))));
            bridge.maxLocals = slot;
            bridge.maxStack = Math.max(2, slot + 2);
            owner.methods.add(bridge);
            addedMethods.add(new AddedMethod(owner, bridge));
            method.instructions.set(indy, new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name,
                    bridgeName, indy.desc, false));
        }
        return found.size();
    }

    private static String uniqueBridgeName(ClassNode owner) {
        int counter = 0;
        while (true) {
            String candidate = "umbra$indy$" + Integer.toHexString(counter);
            boolean taken = false;
            for (MethodNode method : owner.methods) {
                if (method.name.equals(candidate)) {
                    taken = true;
                    break;
                }
            }
            if (!taken) {
                return candidate;
            }
            counter++;
        }
    }

    private static void discardBridges(ClassNode owner, List<AddedMethod> bridges) {
        for (AddedMethod bridge : bridges) {
            bridge.owner.methods.remove(bridge.method);
        }
        bridges.clear();
    }

    private static MethodNode findClinit(ClassNode node) {
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method;
            }
        }
        return null;
    }

    private static boolean hasAnnotation(List<org.objectweb.asm.tree.AnnotationNode> visible,
                                         List<org.objectweb.asm.tree.AnnotationNode> invisible,
                                         String descriptor) {
        return containsAnnotation(visible, descriptor) || containsAnnotation(invisible, descriptor);
    }

    private static boolean containsAnnotation(List<org.objectweb.asm.tree.AnnotationNode> nodes,
                                              String descriptor) {
        if (nodes == null) {
            return false;
        }
        for (org.objectweb.asm.tree.AnnotationNode annotation : nodes) {
            if (annotation != null && descriptor.equals(annotation.desc)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Drops targets this compiler cannot actually produce.
     *
     * <p>A plain host gcc cannot cross-compile, yet the compiler invocation only
     * differs by OS family: asking for {@code WINDOWS_AARCH64} would silently emit
     * an x86-64 image and then label it AARCH64 in {@code layout.txt}, so the
     * protected program would load the wrong architecture on that machine. Only a
     * cross compiler (zig) may claim architectures other than the host's.</p>
     */
    private static List<String> filterTargets(NativeSettings settings, String compiler,
                                              PassContext context) {
        List<String> requested = settings.targets();
        String host = PayloadLayout.targetForHost(settings.target(), settings.arch());
        String hostArch = host.endsWith("AARCH64") ? "AARCH64" : "X86_64";
        boolean crossCompiler = compiler != null
                && compiler.toLowerCase(java.util.Locale.ROOT).indexOf("zig") >= 0;
        if (crossCompiler || requested.size() <= 1) {
            return requested;
        }
        List<String> kept = new ArrayList<String>();
        for (String target : requested) {
            String arch = target.endsWith("AARCH64") ? "AARCH64" : "X86_64";
            if (arch.equals(hostArch)) {
                kept.add(target);
            } else {
                context.log().warn("native-code: dropping target %s, %s cannot cross-compile; "
                        + "use zig for multi-architecture payloads", target, compiler);
            }
        }
        if (kept.isEmpty()) {
            kept.add(host);
        }
        return kept;
    }

    /** Maps {@code WINDOWS_X86_64} back to the compiler's OS family flag. */
    private static String osFamily(String target) {
        String normalized = target == null ? "" : target.toUpperCase(java.util.Locale.ROOT);
        if (normalized.startsWith("LINUX")) {
            return "linux";
        }
        if (normalized.startsWith("MACOS")) {
            return "macos";
        }
        return "windows";
    }

    private static int instructionCount(MethodNode method) {
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn.getOpcode() >= 0) {
                count++;
            }
        }
        return count;
    }

    private static final class ClassWork {
        final ClassNode node;
        final List<MethodNode> methods = new ArrayList<MethodNode>();
        final List<CGenerator.MethodC> translated = new ArrayList<CGenerator.MethodC>();
        final Set<String> translatedNames = new LinkedHashSet<String>();
        boolean clinitNativized;

        ClassWork(ClassNode node) {
            this.node = node;
        }
    }

    private List<ClassWork> select(PassContext context, NativeSettings settings) {
        ClassPool pool = context.classes();
        List<String> names = new ArrayList<String>(pool.classes().keySet());
        Collections.sort(names);
        List<ClassWork> result = new ArrayList<ClassWork>();
        for (String name : names) {
            ClassNode node = pool.getClass(name);
            if (node == null) {
                continue;
            }
            if (pool.isGenerated(name) || pool.isFrozen(name)) {
                continue;
            }

            if (RuntimeNames.isRuntime(name) || name.startsWith("umbra/")) {
                continue;
            }
            if (context.rules().skipBodyTransform(node.name)) {
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) {

                continue;
            }
            if ("module-info".equals(node.name) || node.version < Opcodes.V1_6) {
                continue;
            }
            if (!context.rules().transformClass(node)) {
                continue;
            }
            if (hasAnnotation(node.visibleAnnotations, node.invisibleAnnotations, EXCLUDE_DESC)) {
                context.stats().add("native.annotations.excluded", 1);
                context.log().debug("native-code: %s is excluded by @NativeExclude", name);
                continue;
            }
            boolean classIncluded = hasAnnotation(node.visibleAnnotations,
                    node.invisibleAnnotations, INCLUDE_DESC);
            String originalOwner = NativeSettings.originalOwner(context.mappings(), name);
            ClassWork work = new ClassWork(node);
            for (MethodNode method : node.methods) {
                if ((method.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) {
                    continue;
                }
                if (method.name.startsWith("<")) {
                    continue;
                }
                if (hasAnnotation(method.visibleAnnotations, method.invisibleAnnotations,
                        EXCLUDE_DESC)) {
                    context.stats().add("native.annotations.excluded", 1);
                    continue;
                }
                boolean annotated = classIncluded
                        || hasAnnotation(method.visibleAnnotations, method.invisibleAnnotations,
                        INCLUDE_DESC);
                if (!annotated && !settings.accepts(name, originalOwner, method.name, method.desc)) {
                    continue;
                }
                if (annotated) {
                    context.stats().add("native.annotations.included", 1);
                }
                if (context.rules().keepMethod(name, method)
                        || context.rules().hasKeepAnnotation(method)) {
                    context.log().debug("native-code: %s#%s%s is kept", name, method.name, method.desc);
                    continue;
                }
                if (method.instructions == null) {
                    continue;
                }
                int instructionCount = 0;
                for (AbstractInsnNode ignored = method.instructions.getFirst();
                     ignored != null; ignored = ignored.getNext()) {
                    instructionCount++;
                }
                if (instructionCount > settings.maxInstructions()) {
                    continue;
                }
                work.methods.add(method);
            }
            if (!work.methods.isEmpty()) {
                result.add(work);
            }
        }
        return result;
    }

    private static void convertToNative(MethodNode method) {
        method.instructions.clear();
        if (method.tryCatchBlocks != null) {
            method.tryCatchBlocks.clear();
        }
        if (method.localVariables != null) {
            method.localVariables.clear();
        }
        method.visibleLocalVariableAnnotations = null;
        method.invisibleLocalVariableAnnotations = null;

        method.visibleTypeAnnotations = dropCodeTypeAnnotations(method.visibleTypeAnnotations);
        method.invisibleTypeAnnotations = dropCodeTypeAnnotations(method.invisibleTypeAnnotations);
        method.maxStack = 0;
        method.maxLocals = 0;
        method.access = (method.access | Opcodes.ACC_NATIVE) & ~(Opcodes.ACC_ABSTRACT | Opcodes.ACC_STRICT);
    }

    private static List<TypeAnnotationNode> dropCodeTypeAnnotations(List<TypeAnnotationNode> annotations) {
        if (annotations == null || annotations.isEmpty()) {
            return annotations;
        }
        List<TypeAnnotationNode> kept = new ArrayList<TypeAnnotationNode>();
        for (TypeAnnotationNode annotation : annotations) {
            int targetType = annotation.typeRef >>> 24;
            boolean codeTarget = targetType == 0x40 || targetType == 0x41 || targetType == 0x42
                    || targetType == 0x43 || targetType == 0x44 || targetType == 0x45
                    || targetType == 0x46 || targetType == 0x47;
            if (!codeTarget) {
                kept.add(annotation);
            }
        }
        return kept.isEmpty() ? null : kept;
    }

    private static void addLoaderHook(ClassNode node, String loaderName, int classId,
                                      String dispatch, String clinitNative) {
        MethodNode clinit = null;
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                clinit = method;
                break;
            }
        }
        InsnList hook = new InsnList();
        // Fail closed. The loader checks the payload fingerprint before System.load and
        // the backfill challenge right after it, but the old ensureLoaded()/POP pair
        // discarded that verdict: a refused payload still reached the native
        // register() call and died as a bare UnsatisfiedLinkError that looks like a
        // JNI wiring bug. assertLoaded() throws the recorded refusal instead, so the
        // class fails to initialize and no unbound native method can run.
        hook.add(GuardSupport.indirectCall(dispatch, loaderName, "assertLoaded", "()V"));
        AsmUtil.pushInt(hook, classId);
        hook.add(new LdcInsnNode(org.objectweb.asm.Type.getObjectType(node.name)));
        hook.add(GuardSupport.indirectCall(dispatch, loaderName, "register",
                "(ILjava/lang/Class;)I"));
        hook.add(new InsnNode(Opcodes.POP));
        // The original <clinit> body now lives in a native method; it runs after
        // the library is loaded and the class is registered, and before anything
        // else observes this class, which preserves JLS 12.4.2 ordering.
        if (clinitNative != null) {
            hook.add(new MethodInsnNode(Opcodes.INVOKESTATIC, node.name, clinitNative, "()V",
                    false));
        }

        int hookStack = 2;
        if (clinit != null) {
            clinit.instructions.insert(hook);
            clinit.maxStack = Math.max(clinit.maxStack, hookStack);
        } else {
            MethodNode created = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            created.instructions.add(hook);
            created.instructions.add(new InsnNode(Opcodes.RETURN));
            created.maxStack = hookStack;
            created.maxLocals = 0;
            node.methods.add(created);
        }
    }

    /**
     * Fail-closed sanity check of the loader that will carry this build.
     *
     * <p>A missing {@code native.loader} used to be logged as a warning and papered
     * over with a second, silently injected loader; whether its placeholders were
     * actually substituted (the {@code @@RESOURCE@@}/{@code @@CODELIB@@} mismatch did
     * exactly this) or whether it even declared the two entry points the native
     * library registers was only discovered at run time, as an
     * {@code UnsatisfiedLinkError} inside {@code <clinit>}. The pass now verifies its
     * own product before it converts a single method: no placeholder may survive and
     * {@code register(I,Class)I}/{@code verifyChallenge(I)J} must be declared native.</p>
     */
    private static void assertLoaderReady(PassContext context, ClassPool pool, String loaderName) {
        ClassNode loader = pool.getClass(loaderName);
        if (loader == null) {
            throw new IllegalStateException("native-code: loader " + loaderName
                    + " is missing from the class pool");
        }
        List<String> placeholders = new ArrayList<String>();
        for (MethodNode method : loader.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof LdcInsnNode)) {
                    continue;
                }
                Object constant = ((LdcInsnNode) insn).cst;
                if (constant instanceof String && ((String) constant).indexOf("@@") >= 0) {
                    placeholders.add(method.name + ": " + constant);
                }
            }
        }
        for (FieldNode field : loader.fields) {
            if (field.value instanceof String && ((String) field.value).indexOf("@@") >= 0) {
                placeholders.add(field.name + "=" + field.value);
            }
        }
        boolean register = declaresNative(loader, "register", "(ILjava/lang/Class;)I");
        boolean challenge = declaresNative(loader, "verifyChallenge", "(I)J");
        boolean failClosed = declaresStatic(loader, "assertLoaded", "()V");
        context.stats().add("native.loader.checked", 1);
        if (!placeholders.isEmpty() || !register || !challenge || !failClosed) {
            context.stats().add("native.loader.ready", 0);
            throw new IllegalStateException("native-code: loader " + loaderName
                    + " is not usable (unreplaced placeholders=" + placeholders
                    + ", register=" + register + ", verifyChallenge=" + challenge
                    + ", assertLoaded=" + failClosed + ")");
        }
        context.stats().add("native.loader.ready", 1);
        context.log().debug("native-code: loader %s verified (constants replaced, "
                + "register/verifyChallenge native, assertLoaded present)", loaderName);
    }

    private static boolean declaresNative(ClassNode node, String name, String desc) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name) && method.desc.equals(desc)
                    && (method.access & Opcodes.ACC_NATIVE) != 0) {
                return true;
            }
        }
        return false;
    }

    private static boolean declaresStatic(ClassNode node, String name, String desc) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name) && method.desc.equals(desc)
                    && (method.access & Opcodes.ACC_STATIC) != 0
                    && (method.access & Opcodes.ACC_NATIVE) == 0) {
                return true;
            }
        }
        return false;
    }

    private static void patchLoaderConstants(ClassPool pool, String loaderInternalName,
                                             Map<String, String> replacements) {
        ClassNode loader = pool.getClass(loaderInternalName);
        if (loader == null) {
            throw new IllegalStateException("native-code: injected loader " + loaderInternalName
                    + " is missing from the class pool");
        }
        for (MethodNode method : loader.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof LdcInsnNode)) {
                    continue;
                }
                LdcInsnNode ldc = (LdcInsnNode) insn;
                if (!(ldc.cst instanceof String)) {
                    continue;
                }
                ldc.cst = substitute(String.valueOf(ldc.cst), replacements);
            }
        }
        for (FieldNode field : loader.fields) {
            if (!(field.value instanceof String)) {
                continue;
            }
            field.value = substitute(String.valueOf(field.value), replacements);
        }
    }

    private static String substitute(String value, Map<String, String> replacements) {
        String result = value;
        for (Map.Entry<String, String> entry : replacements.entrySet()) {
            if (result.indexOf(entry.getKey()) >= 0) {
                result = result.replace(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
            char[] hex = new char[hash.length * 2];
            char[] digits = "0123456789abcdef".toCharArray();
            for (int i = 0; i < hash.length; i++) {
                int value = hash[i] & 0xFF;
                hex[i * 2] = digits[value >>> 4];
                hex[i * 2 + 1] = digits[value & 0x0F];
            }
            return new String(hex);
        } catch (RuntimeException error) {
            return null;
        } catch (java.security.NoSuchAlgorithmException error) {
            return null;
        }
    }

    private static String hex16(long value) {
        String hex = Long.toHexString(value);
        StringBuilder out = new StringBuilder(16);
        for (int i = hex.length(); i < 16; i++) {
            out.append('0');
        }
        out.append(hex);
        return out.toString();
    }

    private static String resourceName(PassContext context, NativeSettings settings) {
        Random random = new Random(context.config().seed() ^ 0x4E41544956454CL);
        NameGenerator names = new NameGenerator(random, "");
        for (int attempt = 0; attempt < 1000; attempt++) {
            String candidate = "umbra/native/" + names.random(16) + ".dat";
            if (context.classes().resource(candidate) == null
                    && context.classes().getClass(candidate) == null) {
                return candidate;
            }
        }
        throw new IllegalStateException("unable to allocate a unique native resource name");
    }

    private static String librarySuffix(String target) {
        String normalized = target == null ? "" : target.trim().toLowerCase(java.util.Locale.ROOT);
        if ("linux".equals(normalized) || normalized.startsWith("linux")) {
            return ".so";
        }
        if ("macos".equals(normalized) || normalized.startsWith("macos")) {
            return ".dylib";
        }
        return ".dll";
    }

    private static String resourceName(PassContext context, NativeSettings settings,
                                       String extension) {
        Random random = new Random(context.config().seed() ^ 0x4C41594F55544CL);
        NameGenerator names = new NameGenerator(random, "");
        for (int attempt = 0; attempt < 1000; attempt++) {
            String candidate = "umbra/native/" + names.random(16) + "." + extension;
            if (context.classes().resource(candidate) == null
                    && context.classes().getClass(candidate) == null) {
                return candidate;
            }
        }
        throw new IllegalStateException("unable to allocate a unique native layout name");
    }

    private void keepArtifacts(PassContext context, NativeSettings settings, String sourceText,
                               byte[] libraryBytes, NativeCompiler.Result result) {
        Path output = context.config().output().toAbsolutePath();
        Path parent = output.getParent();
        if (parent == null) {
            parent = output.toAbsolutePath().getParent();
        }
        if (parent == null) {
            return;
        }
        String base = output.getFileName().toString();
        try {
            Files.createDirectories(parent);
            Path source = parent.resolve(base + ".native.c");
            Path library = parent.resolve(base + ".native" + librarySuffix(settings.target()));
            Files.write(source, sourceText.getBytes(StandardCharsets.UTF_8));
            Files.write(library, libraryBytes);
            context.log().info("native-code: kept %s and %s", source, library);
        } catch (IOException e) {
            context.log().warn("native-code: could not keep native artifacts: %s", e);
        }
    }

    private static void failIfNotAtomic(PassContext context, NativeSettings settings, String reason) {
        if (!settings.atomic()) {
            throw new IllegalStateException("native-code: " + reason + " and native.atomic=false");
        }
    }

    private static String displayCommand(NativeCompiler.Result result) {
        String command = result.command();
        return command == null ? "the C compiler" : command;
    }

    private static String abbreviate(String text) {
        String trimmed = text.trim();
        if (trimmed.length() <= MAX_LOGGED_COMPILER_OUTPUT) {
            return trimmed;
        }
        return trimmed.substring(0, MAX_LOGGED_COMPILER_OUTPUT) + "... (truncated)";
    }

    private static final String NATIVE_SOURCE_MARKER = "/* umbra-native generated source */";

    private static final java.util.concurrent.atomic.AtomicBoolean SWEPT =
            new java.util.concurrent.atomic.AtomicBoolean();

    private static final long STALE_NATIVE_AGE_MILLIS = 30L * 60L * 1000L;

    private static String readFirstLine(Path file) {
        try (java.io.BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line = reader.readLine();
            return line == null ? "" : line;
        } catch (IOException failure) {
            return "";
        }
    }
    private static void deleteSourceWithRetry(Path source, Log log) {
        if (source == null) {
            return;
        }
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                Files.deleteIfExists(source);
                if (!Files.exists(source)) {
                    return;
                }
            } catch (IOException failure) {
                log.warn("native-code: could not delete %s (attempt %d): %s", source,
                        Integer.valueOf(attempt + 1), failure);
            }
            try {
                Thread.sleep(50L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        log.warn("native-code: generated C source is still on disk: %s", source);
    }

    private static void cleanupStaleNativeTemp(Log log) {

        if (!SWEPT.compareAndSet(false, true)) {
            return;
        }
        String tempRoot = System.getProperty("java.io.tmpdir");
        if (tempRoot == null || tempRoot.isEmpty()) {
            return;
        }
        Path root = Paths.get(tempRoot);
        if (!Files.isDirectory(root)) {
            return;
        }
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(root)) {
            for (Path entry : entries) {
                if (Files.isRegularFile(entry) && entry.getFileName() != null
                        && "umbra_native.c".equals(entry.getFileName().toString())) {
                    try {
                        Files.deleteIfExists(entry);
                        log.info("native-code: removed stale native source %s", entry);
                    } catch (IOException failure) {
                        log.warn("native-code: could not remove %s: %s", entry, failure);
                    }
                    continue;
                }
                Path source = entry.resolve("umbra_native.c");
                if (!Files.isRegularFile(source)) {
                    continue;
                }
                try {
                    long age = System.currentTimeMillis()
                            - Files.getLastModifiedTime(source).toMillis();
                    if (age < STALE_NATIVE_AGE_MILLIS) {

                        continue;
                    }
                } catch (IOException failure) {
                    continue;
                }
                try {

                    deleteRecursively(entry);
                    log.info("native-code: removed stale native temp %s", entry);
                } catch (RuntimeException failure) {
                    log.warn("native-code: could not remove %s: %s", entry, failure);
                }
            }
        } catch (IOException failure) {
            log.warn("native-code: could not scan the temp directory: %s", failure);
        }
    }

    private static void deleteRecursively(Path path) {
        try {
            if (!Files.exists(path)) {
                return;
            }
            Files.walk(path)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (IOException ignored) {

                        }
                    });
        } catch (IOException ignored) {

        }
    }
}
