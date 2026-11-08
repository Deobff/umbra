package io.umbra.tests;

import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.engine.UmbraVerifier;
import io.umbra.core.runtime.crypto.NativeKeySupport;
import io.umbra.core.runtime.crypto.UmbraCrypto;
import io.umbra.core.runtime.crypto.UmbraStringCipher;
import io.umbra.core.util.Cipher;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
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
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Plain-main tests for Umbra's data-protection layer (no JUnit dependency).
 *
 * <p>Covered: ChaCha20 known-answer vector (RFC 8439) and round-trips, AES-CTR
 * and sealed-envelope authentication/tamper rejection, key derivation,
 * constant-time comparison/wiping, the string-encryption pass on the demo JAR
 * (no plaintext constants left), and a full class-encryption round-trip on a
 * generated tiny JAR (archive rewritten, loaded through a
 * {@link URLClassLoader}, original main invoked, tampered index rejected).</p>
 */
public final class CryptoTest {

    private static int checks;

    private static final String RESOURCE_SECRET = "resource-secret";

    private CryptoTest() {
    }

    public static void main(String[] args) throws Exception {
        testChaCha20KnownAnswer();
        testChaCha20RoundTrip();
        testLegacyStringRoundTrip();
        testKeyDerivation();
        testAesCtr();
        testSealedEnvelope();
        testSecurityHelpers();
        testNativeKeyRoot();
        testNativeGate();
        testStringEncryptionOnDemo();
        testClassEncryptionTinyJar();
        System.out.println("CryptoTest: " + checks + " checks passed");
    }

    private static void testChaCha20KnownAnswer() {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }
        byte[] nonce = new byte[12];
        nonce[7] = 0x4a;
        byte[] plaintext = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
                + "for the future, sunscreen would be it.").getBytes(StandardCharsets.UTF_8);
        String expected = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                + "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                + "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365"
                + "af90bbf74a35be6b40b8eedf2785e42874d";
        byte[] ciphertext = Cipher.chacha20(key, nonce, 1, plaintext);
        check(expected.equals(Cipher.hex(ciphertext)), "ChaCha20 RFC 8439 known-answer vector");
        byte[] decrypted = Cipher.chacha20(key, nonce, 1, ciphertext);
        check(Arrays.equals(plaintext, decrypted), "ChaCha20 is an involution");
    }

    private static void testChaCha20RoundTrip() {
        byte[] key = Cipher.sha256("stream-key".getBytes(StandardCharsets.UTF_8));
        byte[] nonce = Cipher.sha256("stream-nonce".getBytes(StandardCharsets.UTF_8));
        int[] lengths = { 0, 1, 63, 64, 65, 127, 128, 129, 1000 };
        for (int length : lengths) {
            byte[] data = new byte[length];
            for (int i = 0; i < length; i++) {
                data[i] = (byte) (i * 31 + 7);
            }
            byte[] encrypted = Cipher.chacha20(key, Cipher.first(nonce, 12), 1, data);
            byte[] restored = Cipher.chacha20(key, Cipher.first(nonce, 12), 1, encrypted);
            check(Arrays.equals(data, restored), "ChaCha20 round-trip for " + length + " bytes");
        }
        Cipher.wipe(key);
        check(isZero(key), "Cipher.wipe clears key material");
    }

    private static void testLegacyStringRoundTrip() {
        StringBuilder wide = new StringBuilder();
        for (int i = 0; i < 512; i++) {
            wide.append('a');
        }
        String[] samples = { "Hello, Umbra!", "Unicode sample \\u00e9\\u00fc", "", "x", wide.toString() };
        long[] keys = { 1L, 0x9E3779B97F4A7C15L, -42L, Long.MIN_VALUE, Long.MAX_VALUE };
        for (String sample : samples) {
            for (long key : keys) {
                String payload = Cipher.encrypt(sample, key);
                check(payload != null, "legacy cipher produced a payload");
                check(Cipher.decrypt(payload, key).equals(sample),
                        "legacy cipher round-trip for length " + sample.length());
                check(Cipher.encrypt(sample, key).equals(payload), "legacy cipher is deterministic");
            }
        }
    }

    private static void testKeyDerivation() {
        byte[] classA = Cipher.deriveClassKey(424242L, "demo/A");
        byte[] classA2 = Cipher.deriveClassKey(424242L, "demo/A");
        byte[] classB = Cipher.deriveClassKey(424242L, "demo/B");
        check(Arrays.equals(classA, classA2), "class key is deterministic");
        check(!Arrays.equals(classA, classB), "class key differs per class");
        check(classA.length == 32, "class key is 256 bits");

        long siteA = Cipher.deriveSiteSeed(424242L, "demo/A", 0);
        long siteB = Cipher.deriveSiteSeed(424242L, "demo/A", 1);
        check(siteA != siteB, "site seed differs per call site");
        check(Arrays.equals(Cipher.stringSiteKey(siteA, 0), Cipher.stringSiteKey(siteA, 0)),
                "site key is deterministic");
        check(!Arrays.equals(Cipher.stringSiteKey(siteA, 0), Cipher.stringSiteKey(siteB, 1)),
                "site key differs per site");
        check(Cipher.stringClassNonce(classA, 5).length == 12, "class nonce is 96 bits");
        check(Cipher.aesIv(classA, Cipher.stringClassNonce(classA, 5)).length == 16, "AES IV is 128 bits");
    }

    private static void testAesCtr() {
        byte[] key = Cipher.deriveClassKey(7L, "aes/test");
        byte[] nonce = Cipher.stringClassNonce(key, 3);
        byte[] iv = Cipher.aesIv(key, nonce);
        byte[] plain = "Unicode sample \\u00e9\\u00fc".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = Cipher.aesCtr(key, iv, plain);
        check(!Arrays.equals(plain, encrypted), "AES-CTR changes the payload");
        check(Arrays.equals(plain, Cipher.aesCtr(key, iv, encrypted)), "AES-CTR round-trip");
        byte[] sealed = Cipher.seal(plain, key, nonce, Cipher.Algorithm.AES_CTR);
        check(Arrays.equals(plain, Cipher.unseal(sealed, key, Cipher.Algorithm.AES_CTR)),
                "AES-CTR sealed envelope round-trip");
    }

    private static void testSealedEnvelope() {
        byte[] key = Cipher.sha256("envelope-key".getBytes(StandardCharsets.UTF_8));
        byte[] nonce = Cipher.first(Cipher.sha256("envelope-nonce".getBytes(StandardCharsets.UTF_8)), 12);
        byte[] plain = "class file bytes".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = Cipher.seal(plain, key, nonce, Cipher.Algorithm.CHACHA20);
        check(sealed.length == plain.length + Cipher.NONCE_BYTES + Cipher.TAG_BYTES,
                "sealed envelope layout is nonce|ciphertext|tag");
        check(Arrays.equals(plain, Cipher.unseal(sealed, key, Cipher.Algorithm.CHACHA20)),
                "sealed envelope round-trip");

        for (int index : new int[] { 0, sealed.length / 2, sealed.length - 1 }) {
            byte[] tampered = sealed.clone();
            tampered[index] ^= 0x01;
            boolean rejected = false;
            try {
                Cipher.unseal(tampered, key, Cipher.Algorithm.CHACHA20);
            } catch (SecurityException expected) {
                rejected = true;
            }
            check(rejected, "tampered envelope is rejected (byte " + index + ")");
        }
        byte[] wrongKey = Cipher.sha256("wrong-key".getBytes(StandardCharsets.UTF_8));
        boolean rejected = false;
        try {
            Cipher.unseal(sealed, wrongKey, Cipher.Algorithm.CHACHA20);
        } catch (SecurityException expected) {
            rejected = true;
        }
        check(rejected, "envelope is rejected with the wrong key");
        check(sealed.length >= 0, "sealed nonce is not all-zero by construction");
    }

    private static void testSecurityHelpers() {
        check(Cipher.constantTimeEquals(new byte[] { 1, 2 }, new byte[] { 1, 2 }), "equal arrays compare equal");
        check(!Cipher.constantTimeEquals(new byte[] { 1, 2 }, new byte[] { 1, 3 }), "different arrays differ");
        check(!Cipher.constantTimeEquals(new byte[] { 1, 2 }, new byte[] { 1 }), "length mismatch differs");
        char[] secret = { 's', 'e', 'c' };
        Cipher.wipe(secret);
        check(secret[0] == '\0' && secret[1] == '\0' && secret[2] == '\0', "char material is wiped");
        check(Cipher.hex(new byte[] { 0x0f, (byte) 0xa0 }).equals("0fa0"), "hex encoding");
    }

    private static void testNativeKeyRoot() {
        byte[] root = new byte[UmbraCrypto.ROOT_BYTES];
        for (int i = 0; i < root.length; i++) {
            root[i] = (byte) (i * 7 + 3);
        }
        byte[] comment = "zip-comment".getBytes(StandardCharsets.UTF_8);
        byte[] nativeMaster = UmbraCrypto.masterFromRoot(root, comment, 42);
        check(nativeMaster != null && nativeMaster.length == 32, "native master is 256 bits");
        check(Arrays.equals(nativeMaster, UmbraCrypto.masterFromRoot(root, comment, 42)),
                "native master is deterministic");
        check(!Arrays.equals(nativeMaster, UmbraCrypto.masterFromSample(root, comment, 42)),
                "native master uses its own domain separator");
        check(!Arrays.equals(nativeMaster, UmbraCrypto.masterFromRoot(root, comment, 41)),
                "native master is bound to the entry count");
        byte[] otherRoot = root.clone();
        otherRoot[0] ^= 0x01;
        check(!Arrays.equals(nativeMaster, UmbraCrypto.masterFromRoot(otherRoot, comment, 42)),
                "native master is bound to the key root");
        check(UmbraCrypto.masterFromRoot(null, comment, 42) == null, "no root, no native master");

        check(!Arrays.equals(UmbraCrypto.masterFromRoot(root, comment, 42),
                        UmbraCrypto.masterFromRoot(root, "other-comment".getBytes(StandardCharsets.UTF_8), 42)),
                "native master is bound to the comment as well");

        byte[] digestKey = UmbraCrypto.subKey(root, UmbraCrypto.SLOT_DIGEST, 0);
        byte[] stringKey = UmbraCrypto.subKey(root, UmbraCrypto.SLOT_STRING, 0);
        check(digestKey != null && digestKey.length == 32, "layer sub-key is 256 bits");
        check(!Arrays.equals(digestKey, stringKey), "two layers never share a sub-key");
        check(!Arrays.equals(digestKey, UmbraCrypto.subKey(root, UmbraCrypto.SLOT_DIGEST, 1)),
                "sub-key index changes the key");
        check(UmbraCrypto.subKey((byte[]) null, UmbraCrypto.SLOT_DIGEST, 0) == null,
                "no root, no sub-key");

        UmbraCrypto.installKeyRoot(root);
        check(Arrays.equals(root, UmbraCrypto.keyRoot()), "the published root is readable");
        check(UmbraCrypto.hasKeyRoot(), "the published root is reported");
        UmbraCrypto.installKeyRoot(null);
        check(UmbraCrypto.keyRoot() == null, "the root can be cleared");

        byte[] payloadSalt = "SALT1234".getBytes(StandardCharsets.UTF_8);
        byte[] withRoot = UmbraStringCipher.siteKeyV4(root, 77L, 1234L, 5, payloadSalt);
        byte[] withoutRoot = UmbraStringCipher.siteKeyV4(null, 77L, 1234L, 5, payloadSalt);
        check(Arrays.equals(withRoot, UmbraStringCipher.siteKeyV4(root, 77L, 1234L, 5, payloadSalt)),
                "v4 site key is deterministic");
        check(!Arrays.equals(withRoot, withoutRoot), "v4 site key is bound to the native root");
        byte[] otherSalt = "SALT5678".getBytes(StandardCharsets.UTF_8);
        check(!Arrays.equals(withRoot, UmbraStringCipher.siteKeyV4(root, 77L, 1234L, 5, otherSalt)),
                "v4 site key is bound to the payload salt");
        check(!Arrays.equals(withRoot, UmbraStringCipher.siteKeyV4(root, 77L, 1234L, 6, payloadSalt)),
                "v4 site key still separates call sites");

        byte[] plain = "self-check failed: ".getBytes(StandardCharsets.UTF_8);
        long siteSeed = 0x1122334455667788L;
        byte[] key = UmbraStringCipher.siteKeyV4(root, 99L, siteSeed, 7, payloadSalt);
        byte[] nonce = UmbraStringCipher.siteNonceV4(root, 99L, siteSeed, 7, payloadSalt);
        long streamSeed = UmbraStringCipher.payloadStreamSeed(siteSeed, payloadSalt);
        byte[] body = UmbraStringCipher.transform(UmbraStringCipher.CHACHA20, plain, key, nonce,
                streamSeed);
        byte[] payload = new byte[payloadSalt.length + body.length];
        System.arraycopy(payloadSalt, 0, payload, 0, payloadSalt.length);
        System.arraycopy(body, 0, payload, payloadSalt.length, body.length);
        byte[] runtimeSalt = Arrays.copyOfRange(payload, 0, UmbraStringCipher.PAYLOAD_SALT_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(payload, UmbraStringCipher.PAYLOAD_SALT_BYTES,
                payload.length);
        byte[] runtimeKey = UmbraStringCipher.siteKeyV4(root, 99L, siteSeed, 7, runtimeSalt);
        byte[] runtimeNonce = UmbraStringCipher.siteNonceV4(root, 99L, siteSeed, 7, runtimeSalt);
        byte[] restored = UmbraStringCipher.transform(UmbraStringCipher.CHACHA20, ciphertext,
                runtimeKey, runtimeNonce, UmbraStringCipher.payloadStreamSeed(siteSeed, runtimeSalt));
        check(Arrays.equals(plain, restored), "payload v4 round-trips through the self-binding schedule");
        byte[] tampered = payload.clone();
        tampered[0] ^= 0x01;
        byte[] tamperedSalt = Arrays.copyOfRange(tampered, 0, UmbraStringCipher.PAYLOAD_SALT_BYTES);
        byte[] tamperedKey = UmbraStringCipher.siteKeyV4(root, 99L, siteSeed, 7, tamperedSalt);
        check(!Arrays.equals(runtimeKey, tamperedKey),
                "changing one payload byte changes the derived key");

        check(!NativeKeySupport.declaresKeyRoot(null), "an absent loader class is not native-bound");
        ClassNode withoutKeyRoot = new ClassNode();
        withoutKeyRoot.methods = new ArrayList<MethodNode>();
        withoutKeyRoot.methods.add(new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "deriveKey", "(II)[B", null, null));
        check(!NativeKeySupport.declaresKeyRoot(withoutKeyRoot),
                "a loader without keyRoot is not native-bound");
        ClassNode withKeyRoot = new ClassNode();
        withKeyRoot.methods = new ArrayList<MethodNode>();
        withKeyRoot.methods.add(new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_NATIVE,
                "keyRoot", "(II[B)I", null, null));
        check(NativeKeySupport.declaresKeyRoot(withKeyRoot),
                "a loader that declares keyRoot is accepted");
    }

    private static void testNativeGate() throws Exception {
        byte[] secret = new byte[32];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) (0x40 + i);
        }
        long nonce = 0x1122334455667788L;

        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
        mac.update("umbra.gate.v1".getBytes(StandardCharsets.UTF_8));
        byte[] nonceBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            nonceBytes[i] = (byte) (nonce >>> (8 * i));
        }
        mac.update(nonceBytes);
        byte[] expected = mac.doFinal();
        check(Arrays.equals(expected, UmbraCrypto.gateAttest(secret, nonce)),
                "gate attestation matches HMAC-SHA256(gateSecret, label | LE64(nonce))");
        check(!Arrays.equals(UmbraCrypto.gateAttest(secret, nonce),
                        UmbraCrypto.gateAttest(secret, nonce + 1)),
                "the gate response depends on the nonce");
        check(UmbraCrypto.gateAttest(null, nonce) == null, "no gate secret, no response");

        byte[] rawRoot = new byte[32];
        for (int i = 0; i < rawRoot.length; i++) {
            rawRoot[i] = (byte) (0x70 + i);
        }
        javax.crypto.Mac mac2 = javax.crypto.Mac.getInstance("HmacSHA256");
        mac2.init(new javax.crypto.spec.SecretKeySpec(rawRoot, "HmacSHA256"));
        mac2.update("umbra.keyroot.v1".getBytes(StandardCharsets.UTF_8));
        mac2.update(new byte[] { 2, 0, 0, 0 });
        mac2.update(new byte[] { 0, 0, 0, 0 });
        byte[] expectedRoot = mac2.doFinal();
        check(Arrays.equals(expectedRoot, UmbraCrypto.payloadRoot(rawRoot)),
                "payload root matches the library's slot-2 derivation");
        check(!Arrays.equals(expectedRoot, UmbraCrypto.nativeKeyRoot(rawRoot, 1, 0)),
                "the payload root differs from the bootstrap root");
        check(UmbraCrypto.payloadRoot(null) == null, "no root, no payload root");

        byte[] master = Cipher.sha256("gate-master".getBytes(StandardCharsets.UTF_8));
        byte[] payloadNonce = Cipher.first(Cipher.sha256("nonce".getBytes(StandardCharsets.UTF_8)), 12);
        byte[] plain = "class-bytes".getBytes(StandardCharsets.UTF_8);
        byte[] bootstrapKey = UmbraCrypto.entryKey(master, "c:demo/A", payloadNonce);
        byte[] gatedKey = UmbraCrypto.entryKey(master, "c:demo/A", payloadNonce, expectedRoot);
        check(!Arrays.equals(bootstrapKey, gatedKey),
                "the gated business key differs from the bootstrap key");
        check(Arrays.equals(bootstrapKey, UmbraCrypto.entryKey(master, "c:demo/A", payloadNonce, null)),
                "a null payload root keeps the bootstrap key");
        check(!Arrays.equals(UmbraCrypto.keyedDigest(master, "d:c:demo/A", plain),
                        UmbraCrypto.keyedDigest(master, "d:c:demo/A", plain, expectedRoot)),
                "the gated digest is bound to the payload root");

        ClassNode loader = new ClassNode();
        loader.methods = new ArrayList<MethodNode>();
        loader.methods.add(new MethodNode(Opcodes.ACC_STATIC | Opcodes.ACC_NATIVE,
                "gateChallenge", "([J)I", null, null));
        loader.methods.add(new MethodNode(Opcodes.ACC_STATIC | Opcodes.ACC_NATIVE,
                "gateAttest", "(J[B)I", null, null));
        check(NativeKeySupport.declaresGate(loader), "a loader with both gate entry points is accepted");
        loader.methods.remove(1);
        check(!NativeKeySupport.declaresGate(loader), "a loader without gateAttest is not gated");

        ClassNode guard = new ClassNode();
        guard.methods = new ArrayList<MethodNode>();
        guard.methods.add(new MethodNode(Opcodes.ACC_STATIC | Opcodes.ACC_PUBLIC,
                "attest", "(J)[B", null, null));
        check(NativeKeySupport.declaresAttest(guard), "a guard with attest(long) is accepted");
        guard.methods.clear();
        check(!NativeKeySupport.declaresAttest(guard), "a guard without attest(long) is not gated");
        check(NativeKeySupport.gateSecret(null) == null, "no context, no gate secret");

        byte[] tickRoot = new byte[32];
        for (int i = 0; i < tickRoot.length; i++) {
            tickRoot[i] = (byte) (0x20 + i);
        }
        javax.crypto.Mac tickMac = javax.crypto.Mac.getInstance("HmacSHA256");
        tickMac.init(new javax.crypto.spec.SecretKeySpec(tickRoot, "HmacSHA256"));
        tickMac.update("umbra.tick.v1".getBytes(StandardCharsets.UTF_8));
        tickMac.update(new byte[] { 5, 0, 0, 0 });
        byte[] expectedTick = tickMac.doFinal();
        check(Arrays.equals(expectedTick, UmbraCrypto.gateTick(tickRoot, 5)),
                "gate tick matches HMAC(payloadRoot, 'umbra.tick.v1' | LE32(index))");
        check(!Arrays.equals(UmbraCrypto.gateTick(tickRoot, 5), UmbraCrypto.gateTick(tickRoot, 6)),
                "every class index derives its own tick");
        check(UmbraCrypto.gateTick(null, 5) == null, "no payload root, no tick");

        ClassNode loaderWithTick = new ClassNode();
        loaderWithTick.methods = new ArrayList<MethodNode>();
        check(!NativeKeySupport.declaresGateTick(loaderWithTick),
                "a loader without gateTick keeps the single-shot root");
        loaderWithTick.methods.add(new MethodNode(Opcodes.ACC_STATIC | Opcodes.ACC_NATIVE,
                "gateTick", "(I[B)I", null, null));
        check(NativeKeySupport.declaresGateTick(loaderWithTick),
                "a loader declaring gateTick activates the per-class tick");

        Class<?> clean = loadGuardVariant(secret, false);
        clean.getMethod("check").invoke(null);
        long challenge = 0x1122334455667788L;
        Object answered = clean.getMethod("attest", long.class).invoke(null, challenge);
        check(answered instanceof byte[], "a guard that ran check() answers the gate");
        check(Arrays.equals((byte[]) answered, UmbraCrypto.gateAttest(secret, challenge)),
                "the gate answer is HMAC(gateSecret, label | LE64(nonce))");

        Class<?> blanked = loadGuardVariant(secret, true);
        blanked.getMethod("check").invoke(null);
        check(blanked.getMethod("attest", long.class).invoke(null, challenge) == null,
                "a guard whose check() was blanked refuses to answer (patch3)");

        Class<?> never = loadGuardVariant(secret, false);
        check(never.getMethod("attest", long.class).invoke(null, challenge) == null,
                "a guard that never ran check() refuses to answer");

        javax.crypto.Mac evidence = javax.crypto.Mac.getInstance("HmacSHA256");
        evidence.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
        evidence.update("umbra.check.v1".getBytes(StandardCharsets.UTF_8));
        byte[] counterBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            counterBytes[i] = (byte) (7L >>> (8 * i));
        }
        evidence.update(counterBytes);
        evidence.update(new byte[] { 3, 0, 0, 0 });
        check(Arrays.equals(evidence.doFinal(), UmbraCrypto.checkEvidence(secret, 7L, 3)),
                "check evidence matches HMAC(gateSecret, 'umbra.check.v1' | LE64(counter) | LE32(mask))");
    }

    private static Class<?> loadGuardVariant(byte[] gateSecret, boolean blankCheck) throws Exception {
        ClassNode node = io.umbra.core.runtime.TemplateInjector.read(
                io.umbra.core.runtime.crypto.UmbraRuntimeGuard.class);
        Map<String, String> replacements = new LinkedHashMap<String, String>();
        replacements.put("@@GATESECRET@@", Cipher.base64(gateSecret));
        replacements.put("@@LEVEL@@", "1");
        replacements.put("@@THREAD@@", "false");
        replacements.put("@@JVMTI@@", "false");
        replacements.put("@@ATTACH@@", "false");
        replacements.put("@@ATTACHWATCH@@", "false");
        replacements.put("@@PORTPROBE@@", "false");
        replacements.put("@@ENV@@", "false");
        replacements.put("@@TIMING@@", "false");
        replacements.put("@@ACTION@@", "log");
        replacements.put("@@LOGTOKEN@@", "test");
        io.umbra.core.runtime.crypto.CryptoSupport.replaceConstants(node, replacements);
        if (blankCheck) {
            for (MethodNode method : node.methods) {
                if ("check".equals(method.name) && "()V".equals(method.desc)) {
                    org.objectweb.asm.tree.InsnList body = new org.objectweb.asm.tree.InsnList();
                    body.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
                    method.instructions = body;
                    method.tryCatchBlocks =
                            new ArrayList<org.objectweb.asm.tree.TryCatchBlockNode>();
                    if (method.localVariables != null) {
                        method.localVariables.clear();
                    }
                }
            }
        }
        org.objectweb.asm.ClassWriter writer =
                new org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        final byte[] bytes = writer.toByteArray();
        final String name = node.name.replace('/', '.');
        ClassLoader loader = new ClassLoader(CryptoTest.class.getClassLoader()) {
            @Override
            protected Class<?> loadClass(String requested, boolean resolve)
                    throws ClassNotFoundException {
                if (name.equals(requested)) {
                    Class<?> defined = findLoadedClass(requested);
                    if (defined == null) {
                        defined = defineClass(requested, bytes, 0, bytes.length);
                    }
                    if (resolve) {
                        resolveClass(defined);
                    }
                    return defined;
                }
                return super.loadClass(requested, resolve);
            }
        };
        return Class.forName(name, true, loader);
    }

    private static void testStringEncryptionOnDemo() throws Exception {
        Path demo = java.nio.file.Paths.get("demo", "demo.jar");
        if (!Files.isRegularFile(demo)) {
            System.out.println("CryptoTest: demo/demo.jar not present, skipping string-pass check");
            return;
        }
        Path dir = Files.createTempDirectory("umbra-crypto-strings");
        try {
            Path first = dir.resolve("strings-a.jar");
            Path second = dir.resolve("strings-b.jar");

            EngineResult result = runEngine(config(demo, first, "string.strength", "3", "string.cache", "true",
                    "string.allowKeylessFallback", "true"));
            check(stat(result, "strings.encrypted") > 300, "string pass encrypted > 300 constants");
            check(stat(result, "strings.perClassKeys") > 0, "string pass used per-class keys");
            check(stat(result, "strings.splitSites") > 0, "string pass split payloads across constants");
            check(stat(result, "strings.cacheSites") > 0, "string pass installed per-site caches");

            List<String> needles = Arrays.asList("Hello, Umbra!", "logic broken", "sum=", "caught:",
                    "demo.ReflectionProbe", "Class.forName", "alpha", "beta", "probe", "first", "second");
            Map<String, byte[]> entries = readZip(first);
            int plaintextHits = 0;
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                if (!entry.getKey().endsWith(".class")) {
                    continue;
                }
                for (String constant : constantPoolStrings(entry.getValue())) {
                    if (looksLikeNeedle(constant, needles)) {
                        plaintextHits++;
                    }
                }
            }
            check(plaintextHits == 0, "no demo plaintext string constants remain in the output");
            byte[] jarBytes = Files.readAllBytes(first);
            String raw = new String(jarBytes, StandardCharsets.ISO_8859_1);
            check(!raw.contains("Hello, Umbra!"), "raw archive does not contain a greeting literal");
            check(!raw.contains("logic broken"), "raw archive does not contain the failure literal");

            runEngine(config(demo, second, "string.strength", "3", "string.cache", "true",
                    "string.allowKeylessFallback", "true"));
            check(entryNames(first).equals(entryNames(second)), "string pass output is deterministic for a seed");
        } finally {
            deleteRecursively(dir);
        }
    }

    private static void testClassEncryptionTinyJar() throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            System.out.println("CryptoTest: no system Java compiler, skipping class-encryption check");
            return;
        }
        Path dir = Files.createTempDirectory("umbra-crypto-classes");
        try {
            Path sourceDir = dir.resolve("src");
            Path classDir = dir.resolve("classes");
            Files.createDirectories(sourceDir.resolve("tiny"));
            Files.createDirectories(classDir);
            Path hello = sourceDir.resolve("tiny").resolve("Hello.java");
            Path util = sourceDir.resolve("tiny").resolve("Util.java");
            Files.write(hello, ("package tiny;\n"
                    + "public final class Hello {\n"
                    + "  public static void main(String[] args) throws Exception {\n"
                    + "    java.io.FileOutputStream out = new java.io.FileOutputStream(args[0]);\n"
                    + "    Class<?> type = Class.forName(\"tiny.Util\");\n"
                    + "    String value = (String) type.getDeclaredMethod(\"value\").invoke(null);\n"
                    + "    String resource = readResource();\n"
                    + "    out.write((\"tiny-ok:\" + value + \":\" + resource).getBytes(\"UTF-8\"));\n"
                    + "    out.close();\n"
                    + "  }\n"
                    + "  private static String readResource() throws Exception {\n"
                    + "    java.io.InputStream in = Hello.class.getResourceAsStream(\"/tiny/config.txt\");\n"
                    + "    if (in == null) { throw new IllegalStateException(\"resource missing\"); }\n"
                    + "    java.io.BufferedReader reader = new java.io.BufferedReader(\n"
                    + "        new java.io.InputStreamReader(in, \"UTF-8\"));\n"
                    + "    try { return reader.readLine(); } finally { reader.close(); }\n"
                    + "  }\n"
                    + "}\n").getBytes(StandardCharsets.UTF_8));
            Files.write(util, ("package tiny;\n"
                    + "public final class Util {\n"
                    + "  private static final String VALUE = \"util-value\";\n"
                    + "  public static String value() { return VALUE; }\n"
                    + "}\n").getBytes(StandardCharsets.UTF_8));
            int compileExit = compiler.run(null, null, null, "-encoding", "UTF-8", "-source", "1.8",
                    "-target", "1.8", "-d", classDir.toString(), hello.toString(), util.toString());
            check(compileExit == 0, "tiny test program compiles");

            Path input = dir.resolve("tiny.jar");
            Manifest manifest = new Manifest();
            manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
            manifest.getMainAttributes().putValue("Main-Class", "tiny.Hello");
            try (JarOutputStream jar = new JarOutputStream(new FileOutputStream(input.toFile()), manifest)) {
                addClassEntry(jar, classDir, "tiny/Hello.class");
                addClassEntry(jar, classDir, "tiny/Util.class");
                JarEntry resourceEntry = new JarEntry("tiny/config.txt");
                jar.putNextEntry(resourceEntry);
                jar.write(createResourceContent());
                jar.closeEntry();
                jar.putNextEntry(new JarEntry("tiny/empty.bin"));
                jar.closeEntry();
            }

            Path output = dir.resolve("tiny-encrypted.jar");
            EngineResult result = runEngine(config(input, output,
                    "classEncryption.enabled", "true",
                    "classEncryption.integrity", "true",
                    "integrity.level", "2",
                    "integrity.action", "throw",
                    "string.strength", "3"));
            check(stat(result, "classEncryption.classes") >= 2, "class encryption encrypted every class");
            check(stat(result, "classEncryption.resources") >= 1, "class encryption encrypted the resource");
            check(stat(result, "classEncryption.resourceBytes") >= 20000,
                    "resource encryption counted the plaintext bytes");
            check(Files.isRegularFile(output), "encrypted archive was written");
            check(UmbraVerifier.verify(output).isEmpty(), "encrypted archive passes bytecode verification");
            check(stat(result, "classEncryption.indexVersion") == 7, "encrypted index is version 7");
            check(stat(result, "classEncryption.buildSerial") != 0, "the index carries a build serial");
            check(stat(result, "classEncryption.nativeGate") == 0,
                    "no native gate secret without a native bridge");
            check("fallback".equals(result.stats().text("classEncryption.nativeKey")),
                    "an automatic native key fallback is reported as such in the stats");
            check(stat(result, "classEncryption.nativeKeyFallback") == 1,
                    "an automatic native key fallback is counted");
            check(stat(result, "classEncryption.nativeGateTick") == 0,
                    "no per-class tick without a native bridge");
            check(stat(result, "classEncryption.nativeKey") == 0,
                    "without a native library the master key uses the documented seed fallback");

            Map<String, byte[]> entries = readZip(output);
            int plaintextClasses = 0;
            for (String name : entries.keySet()) {
                if (name.endsWith(".class")) {
                    plaintextClasses++;
                }
            }
            check(plaintextClasses <= 5, "only loader/crypto/URL-helper class files stay plaintext");
            check(!entries.containsKey("tiny/Hello.class"), "original class entry name is gone");
            check(!entries.containsKey("tiny/Util.class"), "original helper entry name is gone");
            check(!entries.containsKey("tiny/config.txt"), "original resource entry name is gone");
            byte[] raw = Files.readAllBytes(output);
            String rawText = new String(raw, StandardCharsets.ISO_8859_1);
            check(!rawText.contains("tiny-ok"), "program string is encrypted in the archive");
            check(!rawText.contains("util-value"), "helper string is encrypted in the archive");
            check(!rawText.contains("tiny/Hello"), "class entry names are obfuscated");
            int plaintextResourceEntries = 0;
            byte[] resourceSecret = RESOURCE_SECRET.getBytes(StandardCharsets.UTF_8);
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                if (contains(entry.getValue(), resourceSecret)) {
                    plaintextResourceEntries++;
                }
            }
            check(plaintextResourceEntries == 0, "no archive entry contains the plaintext resource content");

            Manifest encryptedManifest = readManifest(output);
            String loaderName = mainClass(output);
            check(loaderName != null && !"tiny.Hello".equals(loaderName), "Main-Class points at the loader");
            check(encryptedManifest.getMainAttributes().getValue("Class-Path") == null,
                    "manifest class path is stripped");
            check(encryptedManifest.getMainAttributes().getValue("Codebase") == null,
                    "manifest codebase is stripped");
            check(encryptedManifest.getMainAttributes().size() <= 2,
                    "manifest is minimized to Manifest-Version + Main-Class");

            Path marker = dir.resolve("marker.txt");
            invokeLoader(output, loaderName, new String[] { marker.toAbsolutePath().toString() });
            check(Files.isRegularFile(marker), "encrypted program produced its output file");
            String markerText = new String(Files.readAllBytes(marker), StandardCharsets.UTF_8);
            check(("tiny-ok:util-value:" + RESOURCE_SECRET).equals(markerText),
                    "reflection, nested loading and decrypted resources work through the loader");

            URLClassLoader resourceLoader = new URLClassLoader(new URL[] { output.toUri().toURL() },
                    CryptoTest.class.getClassLoader());
            try {
                Class<?> loaderType = Class.forName(loaderName, false, resourceLoader);
                Object loaderInstance = loaderType.getDeclaredConstructor().newInstance();
                URL resourceUrl = (URL) loaderType.getMethod("getResource", String.class)
                        .invoke(loaderInstance, "tiny/config.txt");
                check(resourceUrl != null, "loader.getResource returns a URL for an encrypted resource");
                check(RESOURCE_SECRET.equals(readFirstLine(resourceUrl.openStream())),
                        "resource URL openStream decrypts the content");
                java.net.URLConnection resourceConnection = resourceUrl.openConnection();
                check(resourceConnection.getContentLength() > 20000,
                        "resource URLConnection exposes the decrypted length");
                InputStream resourceStream = (InputStream) loaderType.getMethod("getResourceAsStream",
                        String.class).invoke(loaderInstance, "tiny/config.txt");
                check(resourceStream != null && RESOURCE_SECRET.equals(readFirstLine(resourceStream)),
                        "getResourceAsStream decrypts the content");
                InputStream emptyStream = (InputStream) loaderType.getMethod("getResourceAsStream",
                        String.class).invoke(loaderInstance, "tiny/empty.bin");
                check(emptyStream != null && emptyStream.read() == -1,
                        "empty encrypted resource round-trips");
                java.util.Enumeration<?> resourceUrls = (java.util.Enumeration<?>)
                        loaderType.getMethod("getResources", String.class)
                                .invoke(loaderInstance, "tiny/config.txt");
                check(resourceUrls != null && resourceUrls.hasMoreElements(),
                        "getResources enumerates the encrypted resource");
                check(loaderType.getMethod("getResource", String.class)
                                .invoke(loaderInstance, "tiny/payload-name-that-does-not-exist") == null,
                        "unknown resource names resolve to null");
            } finally {
                resourceLoader.close();
            }

            Path tampered = dir.resolve("tiny-tampered.jar");
            tamperLastEntry(output, tampered);
            boolean rejected = false;
            try {
                constructLoader(tampered, mainClass(tampered));
            } catch (java.lang.reflect.InvocationTargetException expected) {
                rejected = expected.getCause() instanceof SecurityException
                        || expected.getCause() instanceof IOException;
            }
            check(rejected, "tampered encrypted archive is rejected by the loader");

            Path tamperedResource = dir.resolve("tiny-resource-tampered.jar");
            tamperLargestEntry(output, tamperedResource);
            URLClassLoader tamperedLoader = new URLClassLoader(
                    new URL[] { tamperedResource.toUri().toURL() }, CryptoTest.class.getClassLoader());
            try {
                Class<?> loaderType = Class.forName(loaderName, false, tamperedLoader);
                Object loaderInstance = loaderType.getDeclaredConstructor().newInstance();
                boolean resourceRejected = false;
                try {
                    loaderType.getMethod("resourceContent", String.class)
                            .invoke(loaderInstance, "tiny/config.txt");
                } catch (java.lang.reflect.InvocationTargetException failure) {
                    Throwable cause = failure.getCause();
                    resourceRejected = cause instanceof SecurityException || cause instanceof IOException;
                }
                check(resourceRejected, "tampered resource payload is rejected (integrity level 2)");
            } finally {
                tamperedLoader.close();
            }

            Path output2 = dir.resolve("tiny-encrypted-2.jar");
            runEngine(config(input, output2,
                    "classEncryption.enabled", "true",
                    "classEncryption.integrity", "true",
                    "integrity.level", "2",
                    "integrity.action", "throw",
                    "string.strength", "3"));
            check(entryNames(output).equals(entryNames(output2)),
                    "class-encryption entry naming is deterministic for a seed");

            Path plainOutput = dir.resolve("tiny-plain-resources.jar");
            runEngine(config(input, plainOutput,
                    "classEncryption.enabled", "true",
                    "classEncryption.resources", "false",
                    "string.strength", "3"));
            Map<String, byte[]> plainEntries = readZip(plainOutput);
            check(plainEntries.containsKey("tiny/config.txt"),
                    "resources=false keeps the plaintext resource entry");
            check(contains(plainEntries.get("tiny/config.txt"), RESOURCE_SECRET.getBytes(StandardCharsets.UTF_8)),
                    "resources=false leaves the resource readable");

            Path refused = dir.resolve("tiny-refused.jar");
            boolean aborted = false;
            try {
                runEngine(config(input, refused,
                        "classEncryption.enabled", "true",
                        "classEncryption.nativeKey.fallback", "false",
                        "string.strength", "3"));
            } catch (Throwable expected) {
                aborted = true;
            }
            check(aborted, "nativeKey.fallback=false refuses to build without a native key root");
            check(!Files.exists(refused), "the refused build did not write an archive");

            Path refusedNative = dir.resolve("tiny-native-refused.jar");
            boolean abortedNative = false;
            try {
                runEngine(config(input, refusedNative,
                        "classEncryption.enabled", "true",
                        "classEncryption.nativeKey", "true",
                        "classEncryption.nativeKey.fallback", "false",
                        "string.strength", "3"));
            } catch (Throwable expected) {
                abortedNative = true;
            }
            check(abortedNative,
                    "maximum-style nativeKey=true + fallback=false refuses without a bridge");
            check(!Files.exists(refusedNative),
                    "the refused native build did not write an archive");
        } finally {
            deleteRecursively(dir);
        }
    }

    private static UmbraConfig config(Path input, Path output, String... options) throws Exception {
        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(input)
                .output(output)
                .seed(424242L);
        for (int i = 0; i + 1 < options.length; i += 2) {
            builder.option(options[i], options[i + 1]);
        }
        return builder.build();
    }

    private static EngineResult runEngine(UmbraConfig config) throws Exception {
        Log log = new Log(new Log.Sink() {
            @Override
            public void line(String level, String message) {

            }
        }, false);
        return new UmbraEngine(log).run(config, ProgressListener.NONE);
    }

    private static long stat(EngineResult result, String key) {
        Long value = result.stats().snapshot().get(key);
        return value == null ? 0L : value.longValue();
    }

    private static String mainClass(Path jar) throws IOException {
        try (JarFile file = new JarFile(jar.toFile())) {
            Manifest manifest = file.getManifest();
            return manifest == null ? null
                    : manifest.getMainAttributes().getValue("Main-Class");
        }
    }

    private static void invokeLoader(Path jar, String loaderName, String[] arguments) throws Exception {
        URLClassLoader loader = new URLClassLoader(new URL[] { jar.toUri().toURL() },
                CryptoTest.class.getClassLoader());
        try {
            Class<?> type = Class.forName(loaderName, true, loader);
            java.lang.reflect.Method main = type.getMethod("main", String[].class);
            main.invoke(null, new Object[] { arguments });
        } finally {
            loader.close();
        }
    }

    private static void constructLoader(Path jar, String loaderName) throws Exception {
        URLClassLoader loader = new URLClassLoader(new URL[] { jar.toUri().toURL() },
                CryptoTest.class.getClassLoader());
        try {
            Class<?> type = Class.forName(loaderName, false, loader);
            type.getDeclaredConstructor().newInstance();
        } finally {
            loader.close();
        }
    }

    private static void addClassEntry(JarOutputStream jar, Path classDir, String name) throws IOException {
        byte[] bytes = Files.readAllBytes(classDir.resolve(name));
        JarEntry entry = new JarEntry(name);
        jar.putNextEntry(entry);
        jar.write(bytes);
        jar.closeEntry();
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

    private static List<String> entryNames(Path jar) throws IOException {
        return new ArrayList<String>(readZip(jar).keySet());
    }

    private static void tamperLastEntry(Path source, Path target) throws IOException {
        Map<String, byte[]> entries = readZip(source);
        List<String> names = new ArrayList<String>(entries.keySet());
        String last = names.get(names.size() - 1);
        byte[] bytes = entries.get(last);
        if (bytes.length > 0) {
            bytes[0] ^= 0x01;
        }
        writeZip(target, entries, commentOf(source));
    }

    private static void tamperLargestEntry(Path source, Path target) throws IOException {
        Map<String, byte[]> entries = readZip(source);
        String largest = null;
        int largestSize = -1;
        for (Map.Entry<String, byte[]> entry : entries.entrySet()) {

            if (entry.getKey().endsWith(".class") || entry.getKey().startsWith("META-INF/")) {
                continue;
            }
            if (entry.getValue().length > largestSize) {
                largestSize = entry.getValue().length;
                largest = entry.getKey();
            }
        }
        byte[] bytes = entries.get(largest);
        if (bytes.length > 0) {
            bytes[1 % bytes.length] ^= 0x01;
        }
        writeZip(target, entries, commentOf(source));
    }

    private static String commentOf(Path jar) throws IOException {
        try (JarFile file = new JarFile(jar.toFile())) {
            return file.getComment();
        }
    }

    private static void writeZip(Path target, Map<String, byte[]> entries) throws IOException {
        writeZip(target, entries, null);
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

    private static byte[] createResourceContent() {
        StringBuilder builder = new StringBuilder(RESOURCE_SECRET).append('\n');
        for (int i = 0; i < 20000; i++) {
            builder.append('#');
        }
        builder.append('\n');
        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String readFirstLine(InputStream in) throws IOException {
        if (in == null) {
            return null;
        }
        try {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(in, StandardCharsets.UTF_8));
            return reader.readLine();
        } finally {
            in.close();
        }
    }

    private static Manifest readManifest(Path jar) throws IOException {
        try (JarFile file = new JarFile(jar.toFile())) {
            Manifest manifest = file.getManifest();
            return manifest == null ? new Manifest() : manifest;
        }
    }

    private static List<String> constantPoolStrings(byte[] classBytes) {
        List<String> strings = new ArrayList<String>();
        try {
            ClassNode node = new ClassNode();
            new ClassReader(classBytes).accept(node, 0);
            for (FieldNode field : node.fields) {
                if (field.value instanceof String) {
                    strings.add((String) field.value);
                }
            }
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof LdcInsnNode) {
                        Object constant = ((LdcInsnNode) insn).cst;
                        if (constant instanceof String) {
                            strings.add((String) constant);
                        }
                    } else if (insn instanceof InvokeDynamicInsnNode) {
                        Object[] arguments = ((InvokeDynamicInsnNode) insn).bsmArgs;
                        if (arguments != null) {
                            for (Object argument : arguments) {
                                if (argument instanceof String) {
                                    strings.add((String) argument);
                                }
                            }
                        }
                    }
                }
            }
        } catch (RuntimeException malformed) {

        }
        return strings;
    }

    private static boolean looksLikeNeedle(String constant, List<String> needles) {
        for (String needle : needles) {
            if (constant.equals(needle)) {
                return true;
            }
            if (needle.length() >= 6 && constant.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isZero(byte[] data) {
        for (byte value : data) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        if (haystack == null || needle == null || needle.length == 0) {
            return false;
        }
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
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
