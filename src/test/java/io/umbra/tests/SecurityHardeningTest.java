package io.umbra.tests;

import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.runtime.crypto.UmbraCrypto;
import io.umbra.core.runtime.crypto.UmbraRuntimeGuard;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Security-hardening tests for class encryption / runtime guard (index v3).
 *
 * <p>Plain-main test (no JUnit). Covers the analysis findings P0-1 (sample-bound
 * master key: random {@code siteSeed} + ZIP comment + entry count, nonce in the
 * per-entry KDF), P0-2 (HMAC-keyed class/resource/loader digests), P1-4 (silent
 * failures, no SourceFile/line-number leaks), P1-6 (default integrity level 2,
 * sampled watchdog), P2-1..P2-4 (build assertions, bounded index parsing, no dead
 * XOR path) and P2-6 (heap-dump / self-attach guard signals).</p>
 */
public final class SecurityHardeningTest {

    private static int checks;
    private static Path work;

    private SecurityHardeningTest() {
    }

    public static void main(String[] args) throws Exception {
        long started = System.currentTimeMillis();
        work = Files.createTempDirectory("umbra-security");
        try {
            testGuardSignalUnits();
            testBuildShapeAndAssertions();
            testSampleBoundMaster();
            testAesCtrArchive();
            testEntryCountBinding();
            testCommentTamperIsFatal();
            testSeedBindingDiagnosticMode();
            testKeyedDigestsAndReplay();
            testMalformedIndexFailsSafely();
            testTamperedPayloadRejected();
            testIntegrityDefaultsAndWatchdog();
            testRuntimeDetectionSilent();
        } finally {
            deleteRecursively(work);
        }
        System.out.println("SecurityHardeningTest: " + checks + " checks passed in "
                + (System.currentTimeMillis() - started) + " ms");
    }

    // ------------------------------------------------------------------
    // P2-6: guard signal units
    // ------------------------------------------------------------------

    private static void testGuardSignalUnits() {
        check(UmbraRuntimeGuard.heapDumpSignal(Arrays.asList(
                "-XX:+HeapDumpOnOutOfMemoryError", "-Xmx1g")),
                "heap-dump-on-OOM flag detected");
        check(UmbraRuntimeGuard.heapDumpSignal(Arrays.asList(
                "-XX:+HeapDumpBeforeFullGC")), "heap-dump-before-full-GC flag detected");
        check(!UmbraRuntimeGuard.heapDumpSignal(Arrays.asList(
                "-Xmx1g", "-XX:HeapDumpPath=/tmp")), "heap dump path alone is not flag-enabled");
        check(!UmbraRuntimeGuard.heapDumpSignal(Arrays.asList("-Dfile.encoding=UTF-8")),
                "clean JVM options produce no heap-dump signal");
        check(!UmbraRuntimeGuard.heapDumpSignal(null), "null arguments produce no heap-dump signal");
        check(UmbraRuntimeGuard.attachSelfSignal("true"), "jdk.attach.allowAttachSelf=true detected");
        check(!UmbraRuntimeGuard.attachSelfSignal("false"), "allowAttachSelf=false is clean");
        check(!UmbraRuntimeGuard.attachSelfSignal(null), "absent allowAttachSelf is clean");
    }

    // ------------------------------------------------------------------
    // P2-1/P2-2/P1-4: built archive shape, build assertions, template stripping
    // ------------------------------------------------------------------

    private static void testBuildShapeAndAssertions() throws Exception {
        Path dir = work.resolve("shape");
        Path input = buildProgram(dir, "SHAPE-OK", true);
        Path encrypted = encrypt(dir, input, "shape-enc.jar", null);
        ArchiveView view = ArchiveView.read(encrypted);
        check(view.version == 3, "archive index is version 3");
        check(view.binding == 0, "default master binding is sample-bound");
        check(view.level >= 2, "default integrity level is at least 2");
        check(view.plaintextClasses.contains("module-info") == false,
                "module-info is only indexed when present in the input");
        check(view.classes.size() >= 1 && view.resources.size() >= 1,
                "class and resource maps are populated");

        Map<String, byte[]> entries = readZip(encrypted);
        for (String name : entries.keySet()) {
            check(name.indexOf("@@") < 0, "no unreplaced placeholder in entry name: " + name);
        }
        for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
            if (!entry.getKey().endsWith(".class")) {
                continue;
            }
            byte[] bytes = entry.getValue();
            String text = new String(bytes, StandardCharsets.ISO_8859_1);
            check(text.indexOf("@@") < 0, "no unreplaced placeholder in plaintext class "
                    + entry.getKey());
            check(text.indexOf("UmbraClassLoader") < 0 && text.indexOf("UmbraCrypto") < 0
                            && text.indexOf("UmbraRuntimeGuard") < 0
                            && text.indexOf("UmbraWatchdog") < 0,
                    "plaintext runtime class leaks no Umbra source class name: " + entry.getKey());
            ClassNode node = new ClassNode();
            new ClassReader(bytes).accept(node, ClassReader.EXPAND_FRAMES);
            check(node.sourceFile == null && node.sourceDebug == null,
                    "injected template has no SourceFile attribute: " + entry.getKey());
            boolean lineInfo = false;
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                     insn = insn.getNext()) {
                    if (insn instanceof LineNumberNode) {
                        lineInfo = true;
                    }
                }
            }
            check(!lineInfo, "injected template has no LineNumberTable: " + entry.getKey());
        }
        check(view.plaintextClasses.size() == 4,
                "plaintext class list is exactly the four injected infrastructure classes: "
                        + view.plaintextClasses);
    }

    // ------------------------------------------------------------------
    // P0-1: sample-bound master key
    // ------------------------------------------------------------------

    private static void testAesCtrArchive() throws Exception {
        Path dir = work.resolve("aes");
        Path input = buildProgram(dir, "AES-OK", false);
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("classEncryption.algorithm", "aes-ctr");
        Path encrypted = encrypt(dir, input, "aes-enc.jar", options);
        ArchiveView view = ArchiveView.read(encrypted);
        check(view.algorithm == 2, "AES-CTR archive advertises algorithm id 2");
        Child clean = runJar(java8(), encrypted, null);
        check(clean.exit == 0 && clean.output.contains("AES-OK"),
                "AES-CTR v3 archive runs clean (output: " + clean.output + ")");
        Map<String, byte[]> entries = readZip(encrypted);
        String payload = firstClassPayload(view);
        entries.get(payload)[entries.get(payload).length / 2] ^= 0x01;
        Path tampered = dir.resolve("aes-tampered.jar");
        writeZip(tampered, entries, view.comment);
        Child child = runJar(java8(), tampered, null);
        check(child.exit != 0, "AES-CTR tampered payload is rejected");
    }

    private static void testSampleBoundMaster() throws Exception {
        Path dir = work.resolve("master");
        Path input = buildProgram(dir, "MASTER-OK", false);
        Path first = encrypt(dir, input, "master-a.jar", null);
        Path second = encrypt(dir, input, "master-b.jar", null);
        ArchiveView a = ArchiveView.read(first);
        ArchiveView b = ArchiveView.read(second);
        check(a.comment != null && b.comment != null, "sample binding writes a ZIP comment");
        check(!a.comment.equals(b.comment),
                "two builds of the same input use different random ZIP comments");
        check(!Arrays.equals(a.master, b.master), "two builds of the same input use different "
                + "master keys");
        check(a.indexEntry.equals(b.indexEntry),
                "entry names stay deterministic for a seed (only the key changes)");
        byte[] indexA = readZip(first).get(a.indexEntry);
        byte[] indexB = readZip(second).get(b.indexEntry);
        check(!Arrays.equals(indexA, indexB),
                "sealed index differs across builds even with deterministic entry naming");
        String classA = firstClassPayload(a);
        String classB = firstClassPayload(b);
        check(!Arrays.equals(readZip(first).get(classA), readZip(second).get(classB)),
                "class payload ciphertext differs across builds (master + nonce binding)");

        Child clean = runJar(java8(), first, null);
        check(clean.exit == 0 && clean.output.contains("MASTER-OK"),
                "sample-bound archive runs clean (output: " + clean.output + ")");
    }

    private static void testEntryCountBinding() throws Exception {
        Path dir = work.resolve("entries");
        Path input = buildProgram(dir, "ENTRY-OK", false);
        Path encrypted = encrypt(dir, input, "entry-enc.jar", null);
        ArchiveView view = ArchiveView.read(encrypted);
        Map<String, byte[]> entries = readZip(encrypted);
        entries.put("extra-non-payload-entry.txt", "extra".getBytes(StandardCharsets.UTF_8));
        Path tampered = dir.resolve("entry-count-tampered.jar");
        writeZip(tampered, entries, view.comment);
        Child child = runJar(java8(), tampered, null);
        check(child.exit != 0, "adding an archive entry breaks the entry-count master binding");
        check(!child.output.contains("ENTRY-OK"),
                "entry-count tampered archive never runs the program");

        // Removing a plaintext entry must also break the binding (entry count).
        Map<String, byte[]> removed = readZip(encrypted);
        removed.remove("META-INF/MANIFEST.MF");
        Path removedPath = dir.resolve("entry-removed.jar");
        writeZip(removedPath, removed, view.comment);
        Child removedChild = runJar(java8(), removedPath, null);
        check(removedChild.exit != 0, "removing an entry breaks the entry-count master binding");
    }

    private static void testCommentTamperIsFatal() throws Exception {
        Path dir = work.resolve("comment");
        Path input = buildProgram(dir, "COMMENT-OK", false);
        Path encrypted = encrypt(dir, input, "comment-enc.jar", null);
        ArchiveView view = ArchiveView.read(encrypted);
        Map<String, byte[]> entries = readZip(encrypted);
        Path tampered = dir.resolve("comment-tampered.jar");
        writeZip(tampered, entries, "AAAAAAAAAAAAAAAAAAAAAAAA");
        Child child = runJar(java8(), tampered, null);
        check(child.exit != 0, "editing the ZIP comment breaks the sample-bound master key");
        check(!child.output.contains("COMMENT-OK"), "comment-tampered archive never runs");

        Path stripped = dir.resolve("comment-stripped.jar");
        writeZip(stripped, entries, null);
        Child strippedChild = runJar(java8(), stripped, null);
        check(strippedChild.exit != 0,
                "removing the ZIP comment (forcing seed binding) breaks the master key");
    }

    private static void testSeedBindingDiagnosticMode() throws Exception {
        Path dir = work.resolve("seedbinding");
        Path input = buildProgram(dir, "SEEDBIND-OK", false);
        Map<String, String> options = new LinkedHashMap<String, String>();
        options.put("classEncryption.masterBinding", "seed");
        Path encrypted = encrypt(dir, input, "seed-enc.jar", options);
        ArchiveView view = ArchiveView.read(encrypted);
        check(view.binding == 1, "diagnostic seed binding is recorded in the index");
        check(view.comment == null || view.comment.isEmpty(),
                "diagnostic seed binding writes no ZIP comment");
        Child clean = runJar(java8(), encrypted, null);
        check(clean.exit == 0 && clean.output.contains("SEEDBIND-OK"),
                "seed-binding diagnostic archive runs clean");
        Map<String, byte[]> entries = readZip(encrypted);
        Path withComment = dir.resolve("seed-with-comment.jar");
        writeZip(withComment, entries, "AAAAAAAAAAAAAAAAAAAAAAAA");
        Child child = runJar(java8(), withComment, null);
        check(child.exit != 0, "adding a comment to a seed-binding archive breaks the binding");
    }

    // ------------------------------------------------------------------
    // P0-2: keyed digests and nonce-bound payload keys
    // ------------------------------------------------------------------

    private static void testKeyedDigestsAndReplay() throws Exception {
        Path dir = work.resolve("digests");
        Path input = buildProgram(dir, "DIGEST-OK", false);
        Path encrypted = encrypt(dir, input, "digest-enc.jar", null);
        ArchiveView view = ArchiveView.read(encrypted);
        String className = view.classes.keySet().iterator().next();
        ArchiveView.ClassEntry classEntry = view.classes.get(className);
        Map<String, byte[]> entries = readZip(encrypted);
        byte[] sealed = entries.get(classEntry.payload);
        byte[] plain = decryptPayload(view.master, "c:" + className, sealed);
        byte[] plainSha = UmbraCrypto.sha256(plain);
        check(!Arrays.equals(plainSha, classEntry.digest),
                "index class digest is keyed (not a bare SHA-256 of the plaintext)");
        byte[] keyed = UmbraCrypto.keyedDigest(view.master, "d:c:" + className, plain);
        check(Arrays.equals(keyed, classEntry.digest),
                "keyed class digest recomputes from the master key");
        // Replay: re-seal a 1-byte-tampered plaintext with a valid HMAC but keep the
        // original keyed digest; HMAC passes, the keyed digest must refuse it.
        byte[] tamperedPlain = plain.clone();
        tamperedPlain[tamperedPlain.length / 2] ^= 0x01;
        byte[] nonce = UmbraCrypto.nonceOf(sealed);
        byte[] key = UmbraCrypto.entryKey(view.master, "c:" + className, nonce);
        byte[] resealed = UmbraCrypto.seal(tamperedPlain, key, nonce, view.algorithm);
        entries.put(classEntry.payload, resealed);
        Path tampered = dir.resolve("digest-tampered.jar");
        writeZip(tampered, entries, view.comment);
        Child child = runJar(java8(), tampered, null);
        check(child.exit != 0, "valid-HMAC/1-byte-plaintext tamper is rejected by keyed digest");
        check(!child.output.contains("DIGEST-OK"),
                "keyed-digest tampered archive never runs the program");
        check(child.output.indexOf("SecurityException") < 0
                        && child.output.indexOf("UmbraClassLoader.java") < 0,
                "keyed-digest refusal is silent (no stack/source leak)");
        // Nonce is part of the per-entry KDF: a different nonce yields a different key.
        byte[] otherNonce = nonce.clone();
        otherNonce[0] ^= 0x01;
        check(!Arrays.equals(UmbraCrypto.entryKey(view.master, "c:" + className, nonce),
                UmbraCrypto.entryKey(view.master, "c:" + className, otherNonce)),
                "per-entry nonce participates in the payload KDF");

        // Loader digest is keyed too: replacing the plaintext loader class bytes must
        // be detected (the stored loader digest is HMAC(master, "d:loader"||bytes)).
        String loaderName = view.mainClass.replace('.', '/') + ".class";
        byte[] loaderBytes = readZip(encrypted).get(loaderName);
        check(loaderBytes != null, "plaintext loader entry is present");
        check(Arrays.equals(UmbraCrypto.keyedDigest(view.master, "d:loader", loaderBytes),
                view.loaderDigest), "loader digest is keyed with the master key");
    }

    // ------------------------------------------------------------------
    // P2-3: malformed index parsing fails safely
    // ------------------------------------------------------------------

    private static void testMalformedIndexFailsSafely() throws Exception {
        Path dir = work.resolve("malformed");
        Path input = buildProgram(dir, "MALFORMED-OK", false);
        Path encrypted = encrypt(dir, input, "malformed-enc.jar", null);
        ArchiveView view = ArchiveView.read(encrypted);
        Map<String, byte[]> entries = readZip(encrypted);

        byte[] countHuge = view.indexPlain.clone();
        putInt(countHuge, 8, 0x7FFFFFFF);
        Path huge = dir.resolve("malformed-count.jar");
        entries.put(view.indexEntry, sealIndex(view.master, countHuge));
        writeZip(huge, entries, view.comment);
        Child hugeChild = runJar(java8(), huge, null);
        check(hugeChild.exit != 0, "huge plaintext-class count fails safely");
        check(!hugeChild.timedOut, "huge count does not hang the loader");

        byte[] lengthHuge = view.indexPlain.clone();
        putInt(lengthHuge, 8, 1);
        putInt(lengthHuge, 12, 0x7FFFFFFF);
        Path lengthPath = dir.resolve("malformed-length.jar");
        entries.put(view.indexEntry, sealIndex(view.master, lengthHuge));
        writeZip(lengthPath, entries, view.comment);
        Child lengthChild = runJar(java8(), lengthPath, null);
        check(lengthChild.exit != 0, "huge index string length fails safely");

        byte[] negative = view.indexPlain.clone();
        putInt(negative, 12, -1);
        Path negativePath = dir.resolve("malformed-negative.jar");
        entries.put(view.indexEntry, sealIndex(view.master, negative));
        writeZip(negativePath, entries, view.comment);
        Child negativeChild = runJar(java8(), negativePath, null);
        check(negativeChild.exit != 0, "negative index string length fails safely");

        // Unsupported payload algorithm: flags bits 3..4 = 3 (XOR/dead branch) must
        // be refused instead of silently falling back to ChaCha20.
        byte[] badAlg = view.indexPlain.clone();
        badAlg[5] = (byte) ((badAlg[5] & ~(3 << 3)) | (3 << 3));
        Path badAlgPath = dir.resolve("malformed-alg.jar");
        entries.put(view.indexEntry, sealIndex(view.master, badAlg));
        writeZip(badAlgPath, entries, view.comment);
        Child algChild = runJar(java8(), badAlgPath, null);
        check(algChild.exit != 0, "unsupported payload algorithm id is refused");
    }

    // ------------------------------------------------------------------
    // Tampered payload
    // ------------------------------------------------------------------

    private static void testTamperedPayloadRejected() throws Exception {
        Path dir = work.resolve("tamper");
        Path input = buildProgram(dir, "TAMPER-OK", false);
        Path encrypted = encrypt(dir, input, "tamper-enc.jar", null);
        ArchiveView view = ArchiveView.read(encrypted);
        Map<String, byte[]> entries = readZip(encrypted);
        String payload = firstClassPayload(view);
        entries.get(payload)[entries.get(payload).length / 2] ^= 0x01;
        Path tampered = dir.resolve("tampered-payload.jar");
        writeZip(tampered, entries, view.comment);
        Child child = runJar(java8(), tampered, null);
        check(child.exit != 0 && !child.output.contains("TAMPER-OK"),
                "tampered encrypted payload is rejected");
    }

    // ------------------------------------------------------------------
    // P1-6: integrity defaults + sampled watchdog
    // ------------------------------------------------------------------

    private static void testIntegrityDefaultsAndWatchdog() throws Exception {
        Path dir = work.resolve("integrity");
        Path program = buildSleepProgram(dir, "WATCHDOG-OK", 2500L);
        Path encrypted = encrypt(dir, program, "integrity-default.jar", null);
        ArchiveView defaults = ArchiveView.read(encrypted);
        check(defaults.level == 2, "class encryption defaults to integrity level 2 (actual "
                + defaults.level + ")");

        Map<String, String> explicitLow = new LinkedHashMap<String, String>();
        explicitLow.put("integrity.level", "1");
        Path low = encrypt(dir, program, "integrity-low.jar", explicitLow);
        ArchiveView lowView = ArchiveView.read(low);
        check(lowView.level == 2, "integrity.level=1 is clamped to 2 for encrypted archives");

        Map<String, String> high = new LinkedHashMap<String, String>();
        high.put("integrity.level", "3");
        high.put("classEncryption.watchdogMs", "1000");
        Path level3 = encrypt(dir, program, "integrity-l3.jar", high);
        ArchiveView l3 = ArchiveView.read(level3);
        check(l3.level == 3, "integrity.level=3 is preserved");
        Child clean = runJar(java8(), level3, null);
        check(clean.exit == 0 && clean.output.contains("WATCHDOG-OK"),
                "level-3 archive with sampled/full watchdog runs clean (output: "
                        + clean.output + ")");
        check(!clean.timedOut, "watchdog is a daemon and never keeps the JVM alive");
    }

    // ------------------------------------------------------------------
    // P1-4 runtime detection: silent rejection on real agent launches
    // ------------------------------------------------------------------

    private static void testRuntimeDetectionSilent() throws Exception {
        Path dir = work.resolve("runtime");
        Path input = buildProgram(dir, "RUNTIME-OK", false);
        Path encrypted = encrypt(dir, input, "runtime-enc.jar", null);
        Child clean = runJar(java8(), encrypted, null);
        check(clean.exit == 0 && clean.output.contains("RUNTIME-OK"),
                "clean archive launch prints OK (output: " + clean.output + ")");
        Child jdwp = runJar(java8(), encrypted, Arrays.asList(
                "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=0"));
        check(jdwp.exit != 0, "JDWP launch is rejected");
        check(jdwp.output.indexOf("SecurityException") < 0
                        && jdwp.output.indexOf("UmbraClassLoader.java") < 0
                        && jdwp.output.indexOf("[umbra-guard]") < 0,
                "JDWP rejection leaks no stack/source/fixed log prefix (output: "
                        + jdwp.output + ")");
        Path agent = buildAgent(dir);
        Child javaagent = runJar(java8(), encrypted,
                Arrays.asList("-javaagent:" + agent.toAbsolutePath()));
        check(javaagent.exit != 0, "javaagent launch is rejected");
        check(javaagent.output.indexOf("SecurityException") < 0,
                "javaagent rejection is silent (output: " + javaagent.output + ")");
        Child heapDump = runJar(java8(), encrypted,
                Arrays.asList("-XX:+HeapDumpOnOutOfMemoryError"));
        check(heapDump.exit != 0, "heap-dump-on-OOM flagged launch is rejected by the guard");
        check(heapDump.output.indexOf("SecurityException") < 0,
                "heap-dump rejection is silent (output: " + heapDump.output + ")");
    }

    // ------------------------------------------------------------------
    // Archive reader (test-side implementation of the v3 format + KDF)
    // ------------------------------------------------------------------

    private static final class ArchiveView {
        String comment;
        int entries;
        byte[] siteSeed;
        byte[] master;
        int version;
        int flags;
        int level;
        int binding;
        String indexEntry;
        byte[] indexPlain;
        String mainClass;
        byte[] loaderDigest;
        List<String> plaintextClasses = new ArrayList<String>();
        String entryClass;
        String entryMethod;
        Map<String, ClassEntry> classes = new LinkedHashMap<String, ClassEntry>();
        Map<String, ResourceEntry> resources = new LinkedHashMap<String, ResourceEntry>();
        int algorithm;

        static final class ClassEntry {
            String payload;
            byte[] digest;
        }

        static final class ResourceEntry {
            String payload;
            byte[] digest;
            int size;
        }

        static ArchiveView read(Path jar) throws Exception {
            ArchiveView view = new ArchiveView();
            Map<String, byte[]> entries = readZip(jar);
            try (JarFile file = new JarFile(jar.toFile())) {
                view.comment = file.getComment();
                view.entries = 0;
                java.util.Enumeration<JarEntry> enumeration = file.entries();
                while (enumeration.hasMoreElements()) {
                    JarEntry entry = enumeration.nextElement();
                    if (!entry.isDirectory()) {
                        view.entries++;
                    }
                }
                Manifest manifest = file.getManifest();
                view.mainClass = manifest.getMainAttributes().getValue("Main-Class");
            }
            String loaderEntry = view.mainClass.replace('.', '/') + ".class";
            byte[] loaderBytes = entries.get(loaderEntry);
            if (loaderBytes == null) {
                throw new IOException("loader entry missing");
            }
            view.siteSeed = findSiteSeed(loaderBytes);
            byte[] commentBytes = view.comment == null || view.comment.isEmpty()
                    ? null : UmbraCrypto.base64Decode(view.comment);
            view.master = commentBytes == null
                    ? UmbraCrypto.masterFromSeed(view.siteSeed)
                    : UmbraCrypto.masterFromSample(view.siteSeed, commentBytes, view.entries);

            // Locate the sealed index: the first non-class entry whose envelope
            // authenticates with the master key and carries the "UMB2" magic.
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                String name = entry.getKey();
                if (name.endsWith(".class") || name.startsWith("META-INF/")) {
                    continue;
                }
                try {
                    byte[] plain = UmbraCrypto.unseal(entry.getValue(), view.master,
                            UmbraCrypto.ALG_CHACHA20);
                    if (plain.length >= 4 && ((plain[0] & 0xFF) == 0x55) && ((plain[1] & 0xFF) == 0x4D)
                            && ((plain[2] & 0xFF) == 0x42) && ((plain[3] & 0xFF) == 0x32)) {
                        view.indexEntry = name;
                        view.indexPlain = plain;
                        break;
                    }
                } catch (Throwable notIndex) {
                    // payload entry
                }
            }
            if (view.indexPlain == null) {
                throw new IOException("sealed v3 index not found");
            }
            parse(view, entries);
            return view;
        }

        private static void parse(ArchiveView view, Map<String, byte[]> entries) throws Exception {
            ByteBuffer buffer = ByteBuffer.wrap(view.indexPlain);
            check(buffer.getInt() == 0x554D4232, "index magic is UMB2");
            view.version = buffer.get() & 0xFF;
            view.flags = buffer.get() & 0xFF;
            view.level = buffer.get() & 0xFF;
            view.binding = buffer.get() & 0xFF;
            view.algorithm = (view.flags >>> 3) & 3;
            int plaintextCount = buffer.getInt();
            for (int i = 0; i < plaintextCount; i++) {
                view.plaintextClasses.add(readString(buffer));
            }
            view.entryClass = readString(buffer);
            view.entryMethod = readString(buffer);
            view.loaderDigest = readBytes(buffer, 32);
            int classCount = buffer.getInt();
            for (int i = 0; i < classCount; i++) {
                String name = readString(buffer);
                ClassEntry entry = new ClassEntry();
                entry.payload = readString(buffer);
                entry.digest = readBytes(buffer, 32);
                view.classes.put(name, entry);
                if (!entries.containsKey(entry.payload)) {
                    throw new IOException("index names a missing class payload: " + entry.payload);
                }
            }
            int resourceCount = buffer.getInt();
            for (int i = 0; i < resourceCount; i++) {
                String name = readString(buffer);
                ResourceEntry entry = new ResourceEntry();
                entry.payload = readString(buffer);
                entry.digest = readBytes(buffer, 32);
                entry.size = buffer.getInt();
                view.resources.put(name, entry);
                if (!entries.containsKey(entry.payload)) {
                    throw new IOException("index names a missing resource payload: " + entry.payload);
                }
            }
        }

        private static String readString(ByteBuffer buffer) {
            int length = buffer.getInt();
            if (length < 0 || length > buffer.remaining()) {
                throw new IllegalStateException("malformed test index string");
            }
            byte[] bytes = new byte[length];
            buffer.get(bytes);
            return new String(bytes, StandardCharsets.UTF_8);
        }

        private static byte[] readBytes(ByteBuffer buffer, int length) {
            byte[] bytes = new byte[length];
            buffer.get(bytes);
            return bytes;
        }
    }

    private static byte[] findSiteSeed(byte[] loaderBytes) throws IOException {
        ClassNode node = new ClassNode();
        new ClassReader(loaderBytes).accept(node, 0);
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof LdcInsnNode)) {
                    continue;
                }
                Object constant = ((LdcInsnNode) insn).cst;
                if (!(constant instanceof String)) {
                    continue;
                }
                try {
                    byte[] decoded = UmbraCrypto.base64Decode((String) constant);
                    if (decoded.length == UmbraCrypto.KEY_BYTES) {
                        return decoded;
                    }
                } catch (Throwable notBase64) {
                    // normal string constant
                }
            }
        }
        throw new IOException("embedded siteSeed constant not found in the loader");
    }

    private static byte[] decryptPayload(byte[] master, String label, byte[] sealed) {
        byte[] nonce = UmbraCrypto.nonceOf(sealed);
        byte[] key = UmbraCrypto.entryKey(master, label, nonce);
        return UmbraCrypto.unseal(sealed, key, UmbraCrypto.ALG_CHACHA20);
    }

    private static byte[] sealIndex(byte[] master, byte[] indexPlain) {
        byte[] nonce = new byte[UmbraCrypto.NONCE_BYTES];
        new java.security.SecureRandom().nextBytes(nonce);
        return UmbraCrypto.seal(indexPlain, master, nonce, UmbraCrypto.ALG_CHACHA20);
    }

    private static String firstClassPayload(ArchiveView view) {
        return view.classes.values().iterator().next().payload;
    }

    private static void putInt(byte[] buffer, int offset, int value) {
        buffer[offset] = (byte) (value >>> 24);
        buffer[offset + 1] = (byte) (value >>> 16);
        buffer[offset + 2] = (byte) (value >>> 8);
        buffer[offset + 3] = (byte) value;
    }

    // ------------------------------------------------------------------
    // Build helpers
    // ------------------------------------------------------------------

    private static Path encrypt(Path dir, Path input, String name, Map<String, String> extra)
            throws Exception {
        Path output = dir.resolve(name);
        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(input)
                .output(output)
                .seed(424242L)
                .option("classEncryption.enabled", "true")
                .option("classEncryption.integrity", "true")
                .option("classEncryption.antiDump", "true")
                .option("antiDebug.level", "2")
                .option("antiDebug.nativeGuard", "false");
        if (extra != null) {
            for (Map.Entry<String, String> entry : extra.entrySet()) {
                builder.option(entry.getKey(), entry.getValue());
            }
        }
        Log log = new Log(null, false);
        EngineResult result = new UmbraEngine(log).run(builder.build(), ProgressListener.NONE);
        check(result.stats().snapshot().containsKey("classEncryption.classes"),
                "class encryption produced an archive: " + name);
        return output;
    }

    private static Path buildProgram(Path dir, String marker, boolean withResource) throws Exception {
        Path src = dir.resolve("src-" + marker);
        Path classes = dir.resolve("classes-" + marker);
        Files.createDirectories(src.resolve("tiny"));
        Files.createDirectories(classes);
        String code = "package tiny;\n"
                + "public final class Hello {\n"
                + "  public static void main(String[] args) throws Exception {\n"
                + "    System.out.println(\"" + marker + "\");\n"
                + (withResource
                ? "    java.io.InputStream in = Hello.class.getResourceAsStream(\"/tiny/config.txt\");\n"
                + "    System.out.println(\"RES=\" + (in == null ? \"none\" :\n"
                + "        new java.io.BufferedReader(new java.io.InputStreamReader(in, \"UTF-8\"))\n"
                + "            .readLine()));\n"
                : "")
                + "  }\n"
                + "}\n";
        Path source = src.resolve("tiny").resolve("Hello.java");
        Files.write(source, code.getBytes(StandardCharsets.UTF_8));
        compile(classes, source);
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", "tiny.Hello");
        Path jar = dir.resolve("program-" + marker + ".jar");
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            out.putNextEntry(new JarEntry("tiny/Hello.class"));
            out.write(Files.readAllBytes(classes.resolve("tiny/Hello.class")));
            out.closeEntry();
            if (withResource) {
                out.putNextEntry(new JarEntry("tiny/config.txt"));
                out.write("config-value".getBytes(StandardCharsets.UTF_8));
                out.closeEntry();
            }
        }
        return jar;
    }

    private static Path buildSleepProgram(Path dir, String marker, long millis) throws Exception {
        Path src = dir.resolve("sleep-src");
        Path classes = dir.resolve("sleep-classes");
        Files.createDirectories(src.resolve("tiny"));
        Files.createDirectories(classes);
        Path source = src.resolve("tiny").resolve("Sleepy.java");
        Files.write(source, ("package tiny;\n"
                + "public final class Sleepy {\n"
                + "  public static void main(String[] args) throws Exception {\n"
                + "    Thread.sleep(" + millis + "L);\n"
                + "    System.out.println(\"" + marker + "\");\n"
                + "  }\n"
                + "}\n").getBytes(StandardCharsets.UTF_8));
        compile(classes, source);
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", "tiny.Sleepy");
        Path jar = dir.resolve("program-sleep.jar");
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            out.putNextEntry(new JarEntry("tiny/Sleepy.class"));
            out.write(Files.readAllBytes(classes.resolve("tiny/Sleepy.class")));
            out.closeEntry();
        }
        return jar;
    }

    private static Path buildAgent(Path dir) throws Exception {
        Path src = dir.resolve("agent-src");
        Path classes = dir.resolve("agent-classes");
        Files.createDirectories(src.resolve("secagent"));
        Files.createDirectories(classes);
        Path source = src.resolve("secagent").resolve("Agent.java");
        Files.write(source, ("package secagent;\n"
                + "public final class Agent {\n"
                + "  public static void premain(String args, java.lang.instrument.Instrumentation i) {\n"
                + "    System.out.println(\"AGENT\");\n"
                + "  }\n"
                + "}\n").getBytes(StandardCharsets.UTF_8));
        compile(classes, source);
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Premain-Class", "secagent.Agent");
        Path jar = dir.resolve("agent.jar");
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            out.putNextEntry(new JarEntry("secagent/Agent.class"));
            out.write(Files.readAllBytes(classes.resolve("secagent/Agent.class")));
            out.closeEntry();
        }
        return jar;
    }

    private static void compile(Path destination, Path... sources) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new AssertionError("FAILED: no system Java compiler for a test fixture");
        }
        List<String> arguments = new ArrayList<String>();
        arguments.add("-encoding");
        arguments.add("UTF-8");
        arguments.add("-d");
        arguments.add(destination.toString());
        for (Path source : sources) {
            arguments.add(source.toString());
        }
        int exit = compiler.run(null, null, null, arguments.toArray(new String[0]));
        check(exit == 0, "test fixture compiles: " + sources[0]);
    }

    // ------------------------------------------------------------------
    // Process / zip helpers
    // ------------------------------------------------------------------

    private static final class Child {
        int exit;
        String output;
        boolean timedOut;
    }

    private static Child runJar(String java, Path jar, List<String> jvmArguments) throws Exception {
        List<String> command = new ArrayList<String>();
        command.add(java);
        if (jvmArguments != null) {
            command.addAll(jvmArguments);
        }
        command.add("-jar");
        command.add(jar.toAbsolutePath().toString());
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        builder.environment().remove("JAVA_TOOL_OPTIONS");
        builder.environment().remove("_JAVA_OPTIONS");
        builder.environment().remove("JDK_JAVA_OPTIONS");
        Process process = builder.start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        final InputStream in = process.getInputStream();
        Thread pump = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = in.read(buffer)) >= 0) {
                        synchronized (output) {
                            output.write(buffer, 0, read);
                        }
                    }
                } catch (IOException ignored) {
                    // closed
                }
            }
        }, "security-test-pump");
        pump.setDaemon(true);
        pump.start();
        Child child = new Child();
        if (!process.waitFor(60L, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            process.waitFor(5L, TimeUnit.SECONDS);
            child.timedOut = true;
            child.exit = -1;
        } else {
            child.exit = process.exitValue();
        }
        try {
            pump.join(2000L);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        synchronized (output) {
            child.output = new String(output.toByteArray(), StandardCharsets.UTF_8);
        }
        return child;
    }

    private static String java8() {
        return System.getProperty("java.home") + File.separator + "bin" + File.separator
                + (System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT)
                .indexOf("win") >= 0 ? "java.exe" : "java");
    }

    private static Map<String, byte[]> readZip(Path jar) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<String, byte[]>();
        try (ZipInputStream in = new ZipInputStream(new FileInputStream(jar.toFile()))) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) >= 0) {
                    out.write(buffer, 0, read);
                }
                entries.put(entry.getName(), out.toByteArray());
            }
        }
        return entries;
    }

    private static void writeZip(Path target, Map<String, byte[]> entries, String comment)
            throws IOException {
        try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(target.toFile()))) {
            if (comment != null) {
                out.setComment(comment);
            }
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                out.putNextEntry(new ZipEntry(entry.getKey()));
                out.write(entry.getValue());
                out.closeEntry();
            }
        }
    }

    private static void deleteRecursively(Path path) {
        try {
            if (path == null || !Files.exists(path)) {
                return;
            }
            Files.walk(path)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (IOException ignored) {
                            // best effort
                        }
                    });
        } catch (IOException ignored) {
            // best effort
        }
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}
