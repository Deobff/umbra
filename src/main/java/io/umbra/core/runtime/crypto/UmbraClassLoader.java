package io.umbra.core.runtime.crypto;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Plaintext bootstrap loader for a fully encrypted archive (index format v3).
 *
 * <p>Runtime template: no nested/anonymous classes and no direct references to
 * other Umbra classes except {@link UmbraCrypto} (dependencies are plaintext
 * infrastructure classes whose names are remapped at injection time). This class
 * plus the crypto/URL-connection helpers are the only plaintext class files in
 * the protected JAR; the loader becomes {@code Main-Class}.</p>
 *
 * <p>At startup it opens its own archive, rebuilds the sample-bound master key
 * from the embedded random {@code siteSeed}, the ZIP comment and the archive
 * entry count, decrypts and authenticates the sealed index, verifies its own
 * bytes with a keyed digest, then decrypts class payloads on demand (per-entry
 * nonce mixed into the KDF) with keyed-digest verification. Failures are silent:
 * exceptions carry no message/stack unless {@code -Dumbra.debug=true}.</p>
 *
 * <p>Index v3 layout: magic, version, flags, integrity level, master-binding
 * byte, plaintext-class names, entry class/method, keyed loader digest, class
 * entries (name, payload entry, keyed digest) and resource entries (name, payload
 * entry, keyed digest, plaintext size). Integrity levels: 2 = per-class/resource
 * keyed digest on access + sampled watchdog, 3 = eager full verification plus
 * periodic full re-verification.</p>
 */
public final class UmbraClassLoader extends ClassLoader {

    private static final String INDEX_ENTRY = "@@INDEX@@";
    private static final String SITE_SEED = "@@SEED@@";

    private static final String CODELIB = "@@CODELIB@@";

    private static final String NATIVE_LOADER = "@@NATIVE@@";

    private static final boolean STRICT_NATIVE_VERIFY =
            Boolean.parseBoolean("@@STRICTVERIFY@@");
    private static final String ACTION = "@@ACTION@@";

    private static final String GUARD_LOG = "@@GUARDLOG@@";
    private static final String LOG_TOKEN = "@@LOGTOKEN@@";
    private static final String WATCHDOG = "@@WATCHDOG@@";
    private static final String RUNTIME_GUARD = "@@GUARD@@";

    private static final String NATIVE_GUARD = "@@NATIVEGUARD@@";
    private static final String WATCH_MS_TEXT = "@@WATCHMS@@";

    private static final int MAGIC = 0x554D4232;

    private static final int VERSION_LEGACY = 3;

    private static final int VERSION_CP = 4;

    private static final int VERSION_V5 = 5;

    private static final int VERSION_V6 = 6;

    private static final int VERSION = 7;
    private static final int FLAG_INTEGRITY = 1;
    private static final int FLAG_ANTIDUMP = 2;
    private static final int FLAG_RESOURCE_INTEGRITY = 4;

    private static final int FLAG_CONSTANT_POOL = 32;

    private static final int FLAG_NATIVE_ROOT = 64;

    private static final int FLAG_NATIVE_GATE = 128;
    private static final int ALG_SHIFT = 3;
    private static final int ALG_MASK = 3;

    private static final int BINDING_SAMPLE = 0;
    private static final int BINDING_SEED = 1;

    private static final int BINDING_NATIVE = 2;

    private static final int BINDING_HOST = 3;

    private static final int MAX_STRING_BYTES = 1024 * 1024;

    private static final int MAX_ENTRIES = 1_000_000;

    private static final int MIN_CLASS_ENTRY_BYTES = 8 + 32;

    private static final String RESOURCE_PROTOCOL = "umbra";

    private final URL location;
    private final JarFile jar;
    private final ProtectionDomain protectionDomain;

    private byte[] masterKey;

    private byte[] digestKey;

    private int indexVersion = VERSION_LEGACY;

    private boolean nativeBound;

    private int buildSerial;

    private boolean gateBound;

    private boolean gateOpen;

    private static volatile byte[] rootNonce;

    private static final java.util.concurrent.atomic.AtomicBoolean ROOT_CLAIM =
            new java.util.concurrent.atomic.AtomicBoolean();

    private static final java.util.concurrent.atomic.AtomicBoolean PAYLOAD_CLAIM =
            new java.util.concurrent.atomic.AtomicBoolean();

    static {
        try {
            byte[] fresh = new byte[UmbraCrypto.ROOT_BYTES];
            new java.security.SecureRandom().nextBytes(fresh);
            rootNonce = fresh;
            if (NATIVE_LOADER == null || NATIVE_LOADER.isEmpty()
                    || NATIVE_LOADER.charAt(0) == '@') {
                java.util.Arrays.fill(fresh, (byte) 0);
                rootNonce = null;
            } else {
                Class<?> type = Class.forName(NATIVE_LOADER, true,
                        UmbraClassLoader.class.getClassLoader());

                bindNativeNames(type);

                java.lang.reflect.Method setHandshake =
                        type.getMethod("setHandshake", byte[].class);
                setHandshake.invoke(null, (Object) fresh);
                try {
                    java.lang.reflect.Method derive = type.getMethod("keyRoot2", int.class,
                            int.class, byte[].class, byte[].class);
                    if (derive == null) {
                        java.util.Arrays.fill(fresh, (byte) 0);
                        rootNonce = null;
                    }
                } catch (NoSuchMethodException olderBridge) {

                    java.util.Arrays.fill(fresh, (byte) 0);
                    rootNonce = null;
                }
            }
        } catch (Throwable unavailable) {

            rootNonce = null;
        }
    }

    private static volatile byte[] hostRoot;

    private byte[] payloadRoot;

    private final Set<String> gateFreeClasses = new LinkedHashSet<String>();

    private final Set<String> tickClasses = new LinkedHashSet<String>();

    private final Map<String, Integer> classIndex = new LinkedHashMap<String, Integer>();
    private final Map<String, String> classEntries = new LinkedHashMap<String, String>();
    private final Map<String, byte[]> classDigests = new LinkedHashMap<String, byte[]>();
    private final Map<String, String> resourceEntries = new LinkedHashMap<String, String>();
    private final Map<String, byte[]> resourceDigests = new LinkedHashMap<String, byte[]>();
    private final Map<String, Integer> resourceSizes = new LinkedHashMap<String, Integer>();
    private final Set<String> plaintextClasses = new LinkedHashSet<String>();
    private final Set<String> payloadEntries = new LinkedHashSet<String>();
    private final String entryClass;
    private final String entryMethod;
    private final byte[] loaderDigest;
    private final int payloadAlgorithm;
    private final int integrityLevel;
    private final boolean integrityEnabled;
    private final boolean resourceIntegrityEnabled;
    private final boolean antiDump;
    private final boolean constantPoolEncrypted;
    private int bindingUsed;
    private int[] classOrder;
    private int[] resourceOrder;
    private int classCursor;
    private int resourceCursor;

    public UmbraClassLoader() throws Exception {
        super(UmbraClassLoader.class.getClassLoader());
        this.location = locateOwnArchive();
        File file = new File(location.toURI());
        if (!file.isFile()) {
            throw new IllegalStateException("Encrypted archive is missing");
        }
        this.jar = new JarFile(file);

        verifyOwnClassBytes();
        this.protectionDomain = new ProtectionDomain(
                new CodeSource(location, (Certificate[]) null), null, this, null);
        byte[] sealedIndex = readEntry(INDEX_ENTRY);
        byte[] index = openIndex(sealedIndex);
        say(logToken() + " openIndex ok");
        UmbraCrypto.wipe(sealedIndex);

        ByteBuffer buffer = ByteBuffer.wrap(index);
        if (readInt(buffer) != MAGIC) {
            throw silent("Encrypted archive index is not valid");
        }
        int version = buffer.get() & 0xFF;
        if (version != VERSION && version != VERSION_V6 && version != VERSION_CP
                && version != VERSION_LEGACY && version != VERSION_V5) {
            throw silent("Unsupported encrypted archive version");
        }
        this.indexVersion = version;
        byte flags = buffer.get();
        int level = buffer.get() & 0xFF;
        int binding = buffer.get() & 0xFF;
        if (binding != bindingUsed) {
            throw silent("Encrypted archive binding mismatch");
        }
        if (version >= VERSION_V5) {
            boolean flagged = (flags & FLAG_NATIVE_ROOT) != 0;

            boolean rootBound = binding == BINDING_NATIVE || binding == BINDING_HOST;
            if (flagged != rootBound) {
                throw silent("Encrypted archive binding flags disagree");
            }
            this.nativeBound = flagged;
        }
        if (version >= VERSION) {
            this.gateBound = (flags & FLAG_NATIVE_GATE) != 0;
            if (gateBound && !nativeBound) {
                throw silent("Encrypted archive gate flag without the native binding");
            }
        }
        this.integrityEnabled = (flags & FLAG_INTEGRITY) != 0;
        this.antiDump = (flags & FLAG_ANTIDUMP) != 0;
        this.resourceIntegrityEnabled = (flags & FLAG_RESOURCE_INTEGRITY) != 0;
        this.constantPoolEncrypted = (flags & FLAG_CONSTANT_POOL) != 0;
        this.payloadAlgorithm = (flags >>> ALG_SHIFT) & ALG_MASK;
        if (payloadAlgorithm != UmbraCrypto.ALG_CHACHA20
                && payloadAlgorithm != UmbraCrypto.ALG_AES_CTR) {
            throw silent("Unsupported payload algorithm");
        }
        if (integrityEnabled && level < 2) {
            throw silent("Encrypted archive integrity level is too weak");
        }
        this.integrityLevel = level;

        int plaintextCount = readCount(buffer, 10_000);
        for (int i = 0; i < plaintextCount; i++) {
            plaintextClasses.add(readString(buffer));
        }
        this.entryClass = readString(buffer);
        this.entryMethod = readString(buffer);
        this.loaderDigest = readBytes(buffer, 32);

        int classCount = readCount(buffer, MAX_ENTRIES);
        if (classCount > buffer.remaining() / MIN_CLASS_ENTRY_BYTES) {
            throw silent("Encrypted archive index class map is truncated");
        }
        for (int i = 0; i < classCount; i++) {
            String name = readString(buffer);
            String entry = readString(buffer);
            byte[] digest = readBytes(buffer, 32);
            if (version >= VERSION_V6) {

                int gateFlag = buffer.get() & 0xFF;
                if (gateFlag == 1) {
                    gateFreeClasses.add(name);
                } else if (gateFlag == 2 && version >= VERSION) {
                    tickClasses.add(name);
                }
            }
            if (name.isEmpty() || entry.isEmpty() || classEntries.put(name, entry) != null) {
                throw silent("Encrypted archive index class map is invalid");
            }

            classIndex.put(name, Integer.valueOf(i));
            classDigests.put(name, digest);
            payloadEntries.add(entry);
        }
        int resourceCount = readCount(buffer, MAX_ENTRIES);
        if (resourceCount > buffer.remaining() / (8 + 32 + 4)) {
            throw silent("Encrypted archive index resource map is truncated");
        }
        for (int i = 0; i < resourceCount; i++) {
            String name = readString(buffer);
            String entry = readString(buffer);
            byte[] digest = readBytes(buffer, 32);
            int size = readInt(buffer);
            if (name.isEmpty() || entry.isEmpty() || size < 0
                    || resourceEntries.put(name, entry) != null) {
                throw silent("Encrypted archive index resource map is invalid");
            }
            resourceDigests.put(name, digest);
            resourceSizes.put(name, Integer.valueOf(size));
            payloadEntries.add(entry);
        }
        if (version >= VERSION_V5) {

            if (buffer.remaining() < 4 + 32) {
                throw silent("Encrypted archive index is truncated");
            }
            this.buildSerial = readInt(buffer);
            byte[] serialTag = readBytes(buffer, 32);
            byte[] expectedTag = UmbraCrypto.keyedDigest(digestKey, "d:serial",
                    UmbraCrypto.le32(buildSerial));
            boolean serialValid = buildSerial != 0
                    && UmbraCrypto.constantTimeEquals(serialTag, expectedTag);
            UmbraCrypto.wipe(expectedTag);
            UmbraCrypto.wipe(serialTag);
            if (!serialValid) {
                throw silent("Encrypted archive serial is invalid");
            }
        }
        UmbraCrypto.wipe(index);

        runGuardCheck();

        if (gateBound) {
            openGate();
        }

        installCodeLibrary();

        if (integrityEnabled) {
            verifySelfBytes();
        }
        if (antiDump) {
            checkAntiDump();
        }
        if (integrityEnabled && integrityLevel >= 3) {
            verifyAllPayloads();
        }
        if (integrityEnabled && integrityLevel >= 2) {
            classOrder = shuffledIndices(classEntries.size());
            resourceOrder = shuffledIndices(resourceEntries.size());
            ACTIVE = this;
            startWatchdog();
        }
    }

    private void openGate() {

        try {
            if (guardCheckMethod != null) {
                guardCheckMethod.invoke(null);
            }
        } catch (Throwable unavailable) {

        }

        int nativeMask = nativeGuardMask();
        if (nativeMask != 0) {
            if (DEBUG) {
                say(logToken() + " the native guard reports a detection mask: 0x"
                        + Integer.toHexString(nativeMask));
            }
            fail("Native gate detection signal");
            return;
        }
        long nonce = nativeChallenge();
        if (nonce == 0L) {
            if (DEBUG) {
                say(logToken() + " native gate challenge is unavailable");
            }
            fail("Native gate challenge failed");
            return;
        }
        byte[] response = guardAttest(nonce);
        if (response == null) {
            if (DEBUG) {
                say(logToken() + " the runtime guard returned no gate "
                        + "attestation response");
            }
            fail("Native gate attestation failed");
            return;
        }
        if (!nativeAttest(nonce, response)) {
            if (DEBUG) {
                say(logToken() + " the native library refused the gate "
                        + "attestation");
            }
            fail("Native gate attestation failed");
            return;
        }
        byte[] root = claimPayloadRoot();
        if (root == null) {
            if (DEBUG) {
                say(logToken() + " native gate did not release the payload root");
            }
            fail("Native gate payload root is unavailable");
            return;
        }
        this.payloadRoot = root;
        this.gateOpen = true;
    }

    private int nativeGuardMask() {
        String guard = NATIVE_GUARD;
        if (guard == null || guard.isEmpty() || guard.charAt(0) == '@') {
            if (DEBUG) {
                say(logToken() + " no injected native guard is configured");
            }
            return -1;
        }
        try {

            Class<?> type = Class.forName(guard, true, this);
            try {
                java.lang.reflect.Method check = type.getDeclaredMethod("check");
                check.setAccessible(true);
                check.invoke(null);
            } catch (Throwable ignored) {

            }
            java.lang.reflect.Method nativeCheck = type.getDeclaredMethod("nativeCheck");
            nativeCheck.setAccessible(true);
            Object value = nativeCheck.invoke(null);
            return value instanceof Integer ? ((Integer) value).intValue() : -1;
        } catch (Throwable unavailable) {
            if (DEBUG) {
                say(logToken() + " native guard unavailable: " + unavailable);
            }
            return -1;
        }
    }

    private static long nativeChallenge() {
        Object value = invokeNative("challenge");
        return value instanceof Long ? ((Long) value).longValue() : 0L;
    }

    private static boolean nativeAttest(long nonce, byte[] response) {
        try {
            Class<?> type = nativeLoaderClass();
            if (type == null) {
                return false;
            }
            java.lang.reflect.Method attest =
                    type.getMethod("attest", long.class, byte[].class);
            Object result = attest.invoke(null, Long.valueOf(nonce), response);
            return Boolean.TRUE.equals(result);
        } catch (Throwable unavailable) {
            return false;
        }
    }

    private static byte[] nonceRoot(int slot, int sub) {
        try {
            Class<?> type = nativeLoaderClass();
            if (type == null) {
                return null;
            }
            java.lang.reflect.Method derive = type.getMethod("keyRoot2", int.class, int.class,
                    byte[].class, byte[].class);
            byte[] nonce = rootNonce;
            if (nonce == null) {
                return null;
            }
            byte[] out = new byte[UmbraCrypto.ROOT_BYTES];
            Object rc = derive.invoke(null, Integer.valueOf(slot), Integer.valueOf(sub),
                    nonce, out);
            if (rc instanceof Integer && ((Integer) rc).intValue() == 0) {
                return out;
            }
        } catch (Throwable unavailable) {

            Throwable cause = unavailable.getCause();
            say(logToken() + " nonce key root unavailable: " + unavailable
                    + (cause == null ? "" : " cause=" + cause)
                    + " handshakeInstalled=" + String.valueOf(rootNonce != null));
        }
        return null;
    }

    private static byte[] claimPayloadRoot() {
        if (!PAYLOAD_CLAIM.compareAndSet(false, true)) {
            if (DEBUG) {
                say(logToken() + " payload root already consumed");
            }
            return null;
        }
        byte[] nonced = nonceRoot(UmbraCrypto.SLOT_PAYLOAD, 0);
        if (nonced != null) {
            return nonced;
        }
        try {
            Class<?> type = nativeLoaderClass();
            if (type == null) {
                return null;
            }
            java.lang.reflect.Method derive =
                    type.getMethod("deriveKey", int.class, int.class);
            Object value = derive.invoke(null, Integer.valueOf(UmbraCrypto.SLOT_PAYLOAD),
                    Integer.valueOf(0));
            if (value instanceof byte[]) {
                byte[] root = (byte[]) value;
                if (root.length == UmbraCrypto.ROOT_BYTES) {
                    return root;
                }
            }
        } catch (Throwable unavailable) {

        }
        return null;
    }

    private byte[] guardAttest(long nonce) {
        String guard = RUNTIME_GUARD;
        if (guard == null || guard.isEmpty() || guard.charAt(0) == '@') {
            return null;
        }
        try {
            Class<?> type = Class.forName(guard, true, this);
            java.lang.reflect.Method attest = type.getDeclaredMethod("attest", long.class);
            attest.setAccessible(true);
            Object value = attest.invoke(null, Long.valueOf(nonce));
            if (value instanceof byte[]) {
                return (byte[]) value;
            }
            if (DEBUG) {
                say(logToken() + " the runtime guard attested with no payload");
            }
            return null;
        } catch (Throwable unavailable) {
            if (DEBUG) {
                say(logToken() + " guard attest failed: " + unavailable);
            }
            return null;
        }
    }

    private static Object invokeNative(String method) {
        try {
            Class<?> type = nativeLoaderClass();
            return type == null ? null : type.getMethod(method).invoke(null);
        } catch (Throwable unavailable) {
            return null;
        }
    }

    private static Class<?> nativeLoaderClass() {
        if (NATIVE_LOADER == null || NATIVE_LOADER.isEmpty() || NATIVE_LOADER.charAt(0) == '@') {
            return null;
        }
        try {
            return Class.forName(NATIVE_LOADER, true, UmbraClassLoader.class.getClassLoader());
        } catch (Throwable unavailable) {
            return null;
        }
    }

    public static void main(String[] args) {
        try {
            run(args);
        } catch (Throwable failure) {
            if (DEBUG) {
                failure.printStackTrace();
            }
            Runtime.getRuntime().halt(1);
        }
    }

    private static void run(String[] args) throws Throwable {
        UmbraClassLoader loader = new UmbraClassLoader();
        Thread.currentThread().setContextClassLoader(loader);
        Class<?> type = loader.loadClass(loader.entryClass);
        java.lang.reflect.Method entry;
        try {
            entry = type.getMethod(loader.entryMethod, String[].class);
        } catch (NoSuchMethodException e) {
            entry = type.getDeclaredMethod(loader.entryMethod, String[].class);
            entry.setAccessible(true);
        }
        try {
            entry.invoke(null, new Object[] { args });
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw e;
        }
    }

    public static void watch() {
        UmbraClassLoader loader = ACTIVE;
        if (loader == null) {
            return;
        }
        WATCHDOG_HEARTBEAT++;
        LAST_WATCHDOG_NANOS = System.nanoTime();
        try {
            loader.verifyWatchSample();
        } catch (Throwable failure) {
            loader.verifyFailure();
        }
    }

    private static volatile UmbraClassLoader ACTIVE;
    private static final boolean DEBUG = Boolean.getBoolean("umbra.debug");

    private static void say(String line) {
        if (DEBUG) {
            System.err.println(line);
        }
    }
    private static volatile boolean watchdogStarted;
    private static volatile long WATCHDOG_HEARTBEAT;
    private static volatile long LAST_WATCHDOG_NANOS;

    private void startWatchdog() {
        try {
            Class<?> watchdogType = Class.forName(WATCHDOG, true, this);
            Object watchdog = watchdogType.getConstructor(String.class, String.class, long.class, int.class)
                    .newInstance(getClass().getName(), "watch", Long.valueOf(watchIntervalMs()),
                            Integer.valueOf(0));
            LAST_WATCHDOG_NANOS = System.nanoTime();
            watchdogStarted = true;
            ((Thread) watchdog).start();
        } catch (Throwable ignored) {

        }
    }

    private static long watchIntervalMs() {
        try {
            long value = Long.parseLong(WATCH_MS_TEXT.trim());
            if (value < 1000L) {
                return 1000L;
            }
            return value > 60000L ? 60000L : value;
        } catch (Throwable unsubstituted) {
            return 4000L;
        }
    }

    private void checkWatchdogHeartbeat() {
        if (!watchdogStarted || !integrityEnabled || integrityLevel < 2) {
            return;
        }
        long last = LAST_WATCHDOG_NANOS;
        if (last == 0L) {
            return;
        }
        long gapMs = (System.nanoTime() - last) / 1000000L;
        long intervalMs = watchIntervalMs();
        if (gapMs > intervalMs * 4L + 10000L) {
            fail("Payload watchdog heartbeat lost");
        }
    }

    private volatile boolean guardResolved;
    private volatile boolean guardResolving;
    private volatile java.lang.reflect.Method guardCheckMethod;
    private volatile java.lang.reflect.Method guardDetectedMethod;

    private static boolean guardConfigured() {
        return RUNTIME_GUARD != null && RUNTIME_GUARD.length() > 1
                && RUNTIME_GUARD.charAt(0) != '@';
    }

    private void installCodeLibrary() {

        say(logToken() + " installCodeLibrary enter");
        String name = CODELIB;
        if (name == null || name.isEmpty() || name.charAt(0) == '@') {

            name = findSealedCodeLibrary();
        }
        if (DEBUG) {
            say(logToken() + " code library entry = \"" + name + "\"");
        }
        if (name == null || name.isEmpty() || name.charAt(0) == '@') {
            if (DEBUG) {
                say(logToken() + " no code library in this archive; skipping");
            }
            return;
        }
        if (NATIVE_LOADER == null || NATIVE_LOADER.isEmpty()
                || NATIVE_LOADER.charAt(0) == '@') {
            return;
        }
        java.io.InputStream stream = null;
        try {
            stream = getResourceAsStream(name);
            if (DEBUG) {
                say(logToken() + " code library resource " + name + " -> "
                        + (stream == null ? "null" : "stream"));
            }
            if (stream == null) {
                return;
            }
            byte[] library = readAll(stream);
            if (DEBUG) {
                say(logToken() + " code library bytes = " + library.length);
            }
            java.io.File temp = java.io.File.createTempFile("ums", ".tmp");
            temp.deleteOnExit();
            java.nio.file.Files.write(temp.toPath(), library);
            java.util.Arrays.fill(library, (byte) 0);
            Class<?> type = Class.forName(NATIVE_LOADER, true,
                    UmbraClassLoader.class.getClassLoader());

            try {
                java.lang.reflect.Method ensure = type.getMethod("ensureLoaded");
                Object loaded = ensure.invoke(null);
                if (DEBUG) {
                    say(logToken() + " bridge ensureLoaded() -> "
                            + String.valueOf(loaded));
                }
            } catch (NoSuchMethodException noEnsure) {

            }

            java.lang.reflect.Method install = type.getMethod("installCodeLibrary",
                    String.class, Class.class);
            Object installed = install.invoke(null, temp.getAbsolutePath(),
                    UmbraClassLoader.this.getClass());
            int rc = installed instanceof Integer ? ((Integer) installed).intValue() : -1;
            if (DEBUG) {
                say(logToken() + " installCodeLibrary(" + temp + ") -> " + rc);
            }
            if (rc != 0) {
                throw silent("Native code library could not be bound");
            }
        } catch (Throwable unavailable) {

            say(logToken() + " install exception: " + unavailable);
            Throwable cause = unavailable.getCause();
            if (cause != null) {
                say(logToken() + " install cause: " + cause);
            }
            unavailable.printStackTrace();

            throw silent("Native code library could not be installed");
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (Throwable ignored) {

                }
            }
        }
    }

    private static byte[] readAll(java.io.InputStream stream) throws java.io.IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = stream.read(buffer)) > 0) {
            out.write(buffer, 0, read);
        }
        java.util.Arrays.fill(buffer, (byte) 0);
        return out.toByteArray();
    }

    private void runGuardCheck() {
        if (!guardConfigured()) {
            return;
        }
        try {
            resolveGuard();
            if (guardCheckMethod == null) {
                return;
            }
            guardCheckMethod.invoke(null);
        } catch (java.lang.reflect.InvocationTargetException failure) {
            rethrowGuardCause(failure);
        } catch (Throwable unavailable) {

        }
    }

    private boolean guardSignal() {
        if (!guardConfigured()) {
            return false;
        }
        try {
            resolveGuard();
            if (guardDetectedMethod == null) {
                return false;
            }
            Object result = guardDetectedMethod.invoke(null);
            return Boolean.TRUE.equals(result);
        } catch (java.lang.reflect.InvocationTargetException failure) {
            rethrowGuardCause(failure);
            return false;
        } catch (Throwable unavailable) {
            return false;
        }
    }

    private void resolveGuard() {
        if (guardResolved) {
            return;
        }
        synchronized (this) {
            if (guardResolved || guardResolving) {
                return;
            }
            guardResolving = true;
            try {
                Class<?> type = Class.forName(RUNTIME_GUARD, true, this);
                java.lang.reflect.Method check = type.getDeclaredMethod("check");
                check.setAccessible(true);
                java.lang.reflect.Method detected = type.getDeclaredMethod("detected");
                detected.setAccessible(true);
                guardCheckMethod = check;
                guardDetectedMethod = detected;
            } catch (Throwable unavailable) {

            } finally {
                guardResolving = false;
                guardResolved = true;
            }
        }
    }

    private static void rethrowGuardCause(java.lang.reflect.InvocationTargetException failure) {
        Throwable cause = failure.getCause();
        if (cause instanceof SecurityException) {
            throw (SecurityException) cause;
        }
        if (cause instanceof Error) {
            throw (Error) cause;
        }
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        }
    }

    private static void guardRefuse(String what) {
        if (DEBUG) {
            say(logToken() + " guard: " + what);
        }
        if ("true".equals(GUARD_LOG)) {

            return;
        }
        throw silent("Runtime guard signal active");
    }

    public static void installHostRoot(byte[] root) {
        hostRoot = root == null ? null : root.clone();
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        String entry = classEntries.get(name);
        if (entry == null) {
            throw new ClassNotFoundException(name);
        }
        byte[] bytes = loadClassPayload(name, entry);
        try {
            definePackageFor(name);
            byte[] key = null;
            try {
                if (constantPoolEncrypted) {

                    byte[] sealed = readEntry(entry);
                    try {
                        key = payloadKey("c:" + name, sealed, classRoot(name));
                    } finally {
                        UmbraCrypto.wipe(sealed);
                    }
                    if (!cryptConstantPool(bytes, key)) {
                        fail("Class payload constant pool is invalid");
                    }
                }

                if (integrityEnabled && integrityLevel >= 2 && !verifyClassDigest(name, bytes)) {
                    fail("Class payload integrity check failed");
                }
                String declared = classNameOf(bytes);
                if (declared == null || !name.equals(declared)) {
                    fail("Class payload name mismatch");
                }
            } catch (SecurityException e) {
                throw e;
            } catch (Exception e) {
                throw new ClassNotFoundException(name);
            } finally {
                UmbraCrypto.wipe(key);
            }
            return defineClass(name, bytes, 0, bytes.length, protectionDomain);
        } finally {
            UmbraCrypto.wipe(bytes);
        }
    }

    private void definePackageFor(String className) {
        int dot = className.lastIndexOf('.');
        if (dot <= 0) {
            return;
        }
        String packageName = className.substring(0, dot);
        if (getPackage(packageName) != null) {
            return;
        }
        try {
            definePackage(packageName, null, null, null, null, null, null, null);
        } catch (IllegalArgumentException alreadyDefined) {

        }
    }

    private byte[] loadClassPayload(String className, String entryName) throws ClassNotFoundException {
        if (guardSignal()) {
            guardRefuse("class decryption");
        }
        checkWatchdogHeartbeat();
        try {
            byte[] sealed = readEntry(entryName);
            byte[] key = payloadKey("c:" + className, sealed, classRoot(className));
            try {
                byte[] plain = UmbraCrypto.unseal(sealed, key, payloadAlgorithm);

                if (guardSignal()) {
                    UmbraCrypto.wipe(plain);
                    guardRefuse("class define");
                }

                return plain;
            } finally {
                UmbraCrypto.wipe(key);
                UmbraCrypto.wipe(sealed);
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable t) {
            throw new ClassNotFoundException(className);
        }
    }

    private byte[] payloadKey(String label, byte[] sealed, byte[] root) {
        byte[] nonce = UmbraCrypto.nonceOf(sealed);
        try {
            return UmbraCrypto.entryKey(masterKey, label, nonce, root);
        } finally {
            UmbraCrypto.wipe(nonce);
        }
    }

    private byte[] classRoot(String name) {
        if (!gateBound || gateFreeClasses.contains(name)) {
            return null;
        }
        if (!tickClasses.contains(name)) {
            return payloadRoot;
        }
        if (!gateOpen) {

            if (DEBUG) {
                say(logToken() + " tick class requested before the gate opened: "
                        + name);
            }
            return payloadRoot;
        }
        Integer index = classIndex.get(name);
        byte[] tick = index == null ? null : nativeGateTick(index.intValue());
        if (tick == null) {
            if (DEBUG) {
                say(logToken() + " native gate tick was refused for " + name
                        + " (index " + index + ", gateOpen=" + gateOpen + ")");
            }
            fail("Native gate tick failed");
            return null;
        }
        return tick;
    }

    private static byte[] nativeGateTick(int index) {
        try {
            Class<?> type = nativeLoaderClass();
            if (type == null) {
                return null;
            }
            java.lang.reflect.Method tick = type.getMethod("gateTick", int.class, byte[].class);
            byte[] out = new byte[UmbraCrypto.ROOT_BYTES];
            Object rc = tick.invoke(null, Integer.valueOf(index), out);
            if (rc instanceof Integer && ((Integer) rc).intValue() == 0) {
                return out;
            }
            if (DEBUG) {
                say(logToken() + " native gate tick returned "
                        + String.valueOf(rc) + " for class index " + index);
            }
        } catch (Throwable unavailable) {
            if (DEBUG) {
                say(logToken() + " native gate tick unavailable: " + unavailable);
            }
        }
        return null;
    }

    public static boolean cryptConstantPool(byte[] cls, byte[] key) {
        if (cls == null || key == null || key.length < 8 || cls.length < 10) {
            return false;
        }
        if ((cls[0] & 0xFF) != 0xCA || (cls[1] & 0xFF) != 0xFE
                || (cls[2] & 0xFF) != 0xBA || (cls[3] & 0xFF) != 0xBE) {
            return false;
        }
        int count = ((cls[8] & 0xFF) << 8) | (cls[9] & 0xFF);
        if (count <= 0) {
            return false;
        }
        long state = 0L;
        for (int i = 0; i < 8; i++) {
            state = (state << 8) | (key[i] & 0xFFL);
        }
        state ^= 0x9E3779B97F4A7C15L;
        int pos = 10;
        for (int index = 1; index < count; index++) {
            if (pos >= cls.length) {
                return false;
            }
            int tag = cls[pos++] & 0xFF;
            switch (tag) {
                case 1: {
                    if (pos + 2 > cls.length) {
                        return false;
                    }
                    int length = ((cls[pos] & 0xFF) << 8) | (cls[pos + 1] & 0xFF);
                    pos += 2;
                    if (pos + length > cls.length) {
                        return false;
                    }
                    long entry = state ^ (((long) index) * 0x2545F4914F6CDD1DL);
                    for (int i = 0; i < length; i++) {
                        entry = entry * 6364136223846793005L + 1442695040888963407L;
                        cls[pos + i] ^= (byte) (entry >>> 33);
                    }
                    pos += length;
                    break;
                }
                case 3:
                case 4:
                    pos += 4;
                    break;
                case 5:
                case 6:

                    pos += 8;
                    index++;
                    break;
                case 7:
                case 8:
                case 16:
                case 19:
                case 20:
                    pos += 2;
                    break;
                case 9:
                case 10:
                case 11:
                case 12:
                case 17:
                case 18:
                    pos += 4;
                    break;
                case 15:
                    pos += 3;
                    break;
                case 21:
                case 22:
                    pos += 2;
                    break;
                default:
                    return false;
            }
            if (pos > cls.length) {
                return false;
            }
        }
        return true;
    }

    public byte[] resourceContent(String encodedName) throws IOException {
        String name = decodeResourceName(encodedName);
        String entry = resourceEntries.get(name);
        if (entry == null) {
            throw new IOException("Resource not found");
        }
        return loadResourcePayload(name, entry);
    }

    private byte[] loadResourcePayload(String name, String entryName) throws IOException {
        if (guardSignal()) {
            guardRefuse("resource decryption");
        }
        checkWatchdogHeartbeat();
        try {
            byte[] sealed = readEntry(entryName);
            byte[] key = payloadKey("r:" + name, sealed, (byte[]) null);
            try {
                byte[] plain = UmbraCrypto.unseal(sealed, key, payloadAlgorithm);
                if (guardSignal()) {
                    UmbraCrypto.wipe(plain);
                    guardRefuse("resource define");
                }
                if (integrityEnabled && resourceIntegrityEnabled && integrityLevel >= 2) {
                    byte[] expected = resourceDigests.get(name);
                    Integer size = resourceSizes.get(name);
                    byte[] actual = UmbraCrypto.keyedDigest(digestKey, "d:r:" + name, plain);
                    boolean valid = expected != null && UmbraCrypto.constantTimeEquals(expected, actual)
                            && (size == null || size.intValue() == plain.length);
                    UmbraCrypto.wipe(actual);
                    if (!valid) {
                        UmbraCrypto.wipe(plain);
                        fail("Resource payload integrity check failed");
                    }
                }
                return plain;
            } finally {
                UmbraCrypto.wipe(key);
                UmbraCrypto.wipe(sealed);
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("Encrypted resource is unreadable");
        }
    }

    @Override
    protected URL findResource(String name) {
        if (name == null || payloadEntries.contains(name)) {
            return null;
        }
        String entry = resourceEntries.get(name);
        if (entry != null) {
            try {
                return new URL(RESOURCE_PROTOCOL, "r", -1, encodeResourceName(name),
                        new UmbraResourceHandler(this));
            } catch (Throwable notUrlSafe) {
                return null;
            }
        }
        return plaintextResourceUrl(name);
    }

    @Override
    protected Enumeration<URL> findResources(String name) throws IOException {
        URL url = findResource(name);
        if (url == null) {
            return Collections.enumeration(Collections.<URL>emptyList());
        }
        return Collections.enumeration(Collections.singletonList(url));
    }

    private URL plaintextResourceUrl(String name) {
        try {
            synchronized (jar) {
                if (jar.getJarEntry(name) == null) {
                    return null;
                }
            }
            return new URL("jar:" + location.toExternalForm() + "!/" + name);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String encodeResourceName(String name) {
        byte[] bytes = name.getBytes(StandardCharsets.UTF_8);
        StringBuilder out = new StringBuilder(bytes.length + 16);
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xFF;
            if ((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
                    || (value >= '0' && value <= '9') || value == '/' || value == '-' || value == '_'
                    || value == '.' || value == '~') {
                out.append((char) value);
            } else {
                out.append('%');
                out.append(Character.toUpperCase(Character.forDigit((value >>> 4) & 0xF, 16)));
                out.append(Character.toUpperCase(Character.forDigit(value & 0xF, 16)));
            }
        }
        return out.toString();
    }

    private static String decodeResourceName(String encoded) {
        if (encoded == null) {
            return "";
        }
        if (encoded.indexOf('%') < 0) {
            return encoded;
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(encoded.length());
        int index = 0;
        while (index < encoded.length()) {
            char current = encoded.charAt(index);
            if (current == '%' && index + 2 < encoded.length()) {
                int high = Character.digit(encoded.charAt(index + 1), 16);
                int low = Character.digit(encoded.charAt(index + 2), 16);
                if (high >= 0 && low >= 0) {
                    bytes.write((high << 4) | low);
                    index += 3;
                    continue;
                }
            }
            bytes.write(current);
            index++;
        }
        return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
    }

    private void verifySelfBytes() {
        try {
            String selfEntry = UmbraClassLoader.class.getName().replace('.', '/') + ".class";
            byte[] self = readEntry(selfEntry);
            byte[] digest = UmbraCrypto.keyedDigest(digestKey, "d:loader", self);
            UmbraCrypto.wipe(self);
            boolean valid = UmbraCrypto.constantTimeEquals(digest, loaderDigest);
            UmbraCrypto.wipe(digest);

            UmbraCrypto.wipe(loaderDigest);
            if (!valid) {
                fail("Loader integrity check failed");
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable t) {
            fail("Loader integrity check could not run");
        }
    }

    private void verifyAllPayloads() {
        List<String> classNames = new ArrayList<String>(classEntries.keySet());
        for (int i = 0; i < classNames.size(); i++) {
            verifyClassPayload(classNames.get(i));
        }
        List<String> resourceNames = new ArrayList<String>(resourceEntries.keySet());
        for (int i = 0; i < resourceNames.size(); i++) {
            String name = resourceNames.get(i);
            try {
                byte[] plain = loadResourcePayload(name, resourceEntries.get(name));
                UmbraCrypto.wipe(plain);
            } catch (SecurityException e) {
                throw e;
            } catch (Throwable t) {
                fail("Resource payload could not be verified");
            }
        }
    }

    private void verifyWatchSample() {
        if (integrityLevel >= 3 && (WATCHDOG_HEARTBEAT % 20L) == 0L) {
            verifyAllPayloads();
            return;
        }
        if (guardSignal()) {
            guardRefuse("integrity re-check");
        }
        List<String> classNames = new ArrayList<String>(classEntries.keySet());
        int classSlice = Math.max(1, (classNames.size() + 19) / 20);
        for (int i = 0; i < classSlice && !classNames.isEmpty(); i++) {
            int index = classOrder == null
                    ? (classCursor + i) % classNames.size()
                    : classOrder[(classCursor + i) % classOrder.length];
            verifyClassPayload(classNames.get(index));
        }
        classCursor = classNames.isEmpty() ? 0 : (classCursor + classSlice) % classNames.size();
        List<String> resourceNames = new ArrayList<String>(resourceEntries.keySet());
        if (!resourceNames.isEmpty()) {
            int resourceSlice = Math.max(1, (resourceNames.size() + 19) / 20);
            for (int i = 0; i < resourceSlice; i++) {
                int index = resourceOrder == null
                        ? (resourceCursor + i) % resourceNames.size()
                        : resourceOrder[(resourceCursor + i) % resourceOrder.length];
                String name = resourceNames.get(index);
                try {
                    byte[] plain = loadResourcePayload(name, resourceEntries.get(name));
                    UmbraCrypto.wipe(plain);
                } catch (SecurityException e) {
                    throw e;
                } catch (Throwable t) {
                    fail("Resource payload could not be verified");
                }
            }
            resourceCursor = (resourceCursor + resourceSlice) % resourceNames.size();
        }
    }

    private boolean verifyClassDigest(String name, byte[] restored) {
        byte[] expected = classDigests.get(name);
        if (expected == null || restored == null) {
            return false;
        }
        byte[] actual = UmbraCrypto.keyedDigest(digestKey, "d:c:" + name, restored,
                classRoot(name));
        boolean valid = UmbraCrypto.constantTimeEquals(expected, actual);
        UmbraCrypto.wipe(actual);
        return valid;
    }

    private void verifyClassPayload(String name) {
        String entry = classEntries.get(name);
        if (entry == null) {
            return;
        }
        if (guardSignal()) {
            guardRefuse("integrity re-check");
        }
        try {
            byte[] sealed = readEntry(entry);
            byte[] key = payloadKey("c:" + name, sealed, classRoot(name));
            byte[] plain = null;
            try {
                plain = UmbraCrypto.unseal(sealed, key, payloadAlgorithm);

                if (constantPoolEncrypted && !cryptConstantPool(plain, key)) {
                    fail("Class payload constant pool is invalid");
                }
                if (integrityEnabled && integrityLevel >= 2
                        && !verifyClassDigest(name, plain)) {
                    fail("Class payload integrity check failed");
                }
                String declared = classNameOf(plain);
                if (declared == null || !name.equals(declared)) {
                    fail("Class payload name mismatch");
                }
            } finally {
                UmbraCrypto.wipe(key);
                UmbraCrypto.wipe(sealed);
                UmbraCrypto.wipe(plain);
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable t) {
            fail("Class payload could not be verified");
        }
    }

    private void checkAgentArguments() {
        try {
            java.lang.management.RuntimeMXBean bean =
                    java.lang.management.ManagementFactory.getRuntimeMXBean();
            List<String> arguments = bean.getInputArguments();
            for (int i = 0; i < arguments.size(); i++) {
                String argument = arguments.get(i);
                String lower = argument.toLowerCase(Locale.ROOT);
                if (lower.contains("jdwp") || lower.contains("javaagent") || lower.contains("agentlib")
                        || lower.contains("agentpath") || lower.contains("-xdebug")) {
                    if ("log".equals(ACTION)) {
                        if (DEBUG) {
                            say(logToken() + " dump/debug agent is attached "
                                    + "(log-only action)");
                        }
                        return;
                    }
                    fail("A dump/debug agent is attached");
                }
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable ignored) {

        }
    }

    private void checkAntiDump() {
        checkAgentArguments();
        try {
            Set<String> seen = new LinkedHashSet<String>();
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory()) {
                    continue;
                }
                if (!seen.add(name)) {
                    fail("Duplicate archive entry");
                }
                if (name.endsWith(".class")) {
                    byte[] bytes = readEntry(name);
                    try {
                        String binary = bytes == null ? null : classNameOf(bytes);
                        if (binary == null || !plaintextClasses.contains(binary)) {
                            fail("Unexpected plaintext class in encrypted archive");
                        }
                    } finally {

                        UmbraCrypto.wipe(bytes);
                    }
                }
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable t) {
            fail("Encrypted archive structure is invalid");
        }
    }

    private static void fail(String message) {
        if (DEBUG) {
            say(logToken() + " " + message);
        }
        if ("log".equals(ACTION)) {

            return;
        }
        if ("exit".equals(ACTION)) {
            Runtime.getRuntime().halt(1);
        }
        if ("corrupt".equals(ACTION)) {
            Runtime.getRuntime().halt(0);
        }
        throw silent(message);
    }

    private void verifyFailure() {
        if (DEBUG) {
            say(logToken() + " watchdog failure");
        }
        if ("corrupt".equals(ACTION)) {
            Runtime.getRuntime().halt(0);
        }
        Runtime.getRuntime().halt(1);
    }

    private static SecurityException silent(String message) {
        SecurityException failure = DEBUG ? new SecurityException(logToken() + " " + message)
                : new SecurityException();
        failure.setStackTrace(new StackTraceElement[0]);
        return failure;
    }

    private static String logToken() {
        return LOG_TOKEN == null || LOG_TOKEN.isEmpty() || LOG_TOKEN.charAt(0) == '@'
                ? "umbra" : LOG_TOKEN;
    }

    private byte[] openIndex(byte[] sealedIndex) throws Exception {

        say(logToken() + " openIndex start");
        byte[] commentBytes = null;
        String comment = jar.getComment();
        if (comment != null && !comment.trim().isEmpty()) {
            try {
                commentBytes = UmbraCrypto.base64Decode(comment.trim());
            } catch (Throwable unreadable) {
                throw silent("Archive comment is unreadable");
            }
        }
        try {
            byte[] host = hostRoot;

            hostRoot = null;
            if (host != null) {

                byte[] derived = UmbraCrypto.nativeKeyRoot(host,
                        UmbraCrypto.ROOT_SLOT, UmbraCrypto.ROOT_SUB);
                if (derived != null) {
                    byte[] hostMaster = UmbraCrypto.masterFromRoot(derived, commentBytes,
                            countEntries());
                    UmbraCrypto.wipe(derived);
                    if (hostMaster != null) {
                        try {
                            byte[] plain = UmbraCrypto.unseal(sealedIndex, hostMaster,
                                    UmbraCrypto.ALG_CHACHA20);
                            this.masterKey = hostMaster;
                            byte[] digestRoot = UmbraCrypto.nativeKeyRoot(host,
                                    UmbraCrypto.ROOT_SLOT, UmbraCrypto.ROOT_SUB);
                            this.digestKey = UmbraCrypto.subKey(digestRoot,
                                    UmbraCrypto.SLOT_DIGEST, 0);

                            UmbraCrypto.installKeyRoot(digestRoot);
                            UmbraCrypto.wipe(digestRoot);
                            this.bindingUsed = BINDING_HOST;
                            return plain;
                        } catch (SecurityException wrongHostRoot) {
                            UmbraCrypto.wipe(hostMaster);
                        }
                    }
                }
            }
            byte[] root = nativeKeyRoot();
            if (root == null && DEBUG) {
                say(logToken() + " native key root is unavailable");
            }
            if (root != null) {
                int entryCount = countEntries();
                byte[] nativeMaster = UmbraCrypto.masterFromRoot(root, commentBytes, entryCount);
                if (nativeMaster != null) {
                    try {
                        byte[] plain = UmbraCrypto.unseal(sealedIndex, nativeMaster,
                                UmbraCrypto.ALG_CHACHA20);
                        this.masterKey = nativeMaster;
                        this.digestKey = UmbraCrypto.subKey(root,
                                UmbraCrypto.SLOT_DIGEST, 0);

                        UmbraCrypto.installKeyRoot(root);
                        UmbraCrypto.wipe(root);
                        if (this.digestKey == null) {
                            throw silent("Archive digest key derivation failed");
                        }
                        this.bindingUsed = BINDING_NATIVE;
                        return plain;
                    } catch (SecurityException notNativeBound) {
                        if (DEBUG) {
                            say(logToken() + " native master key did not open the "
                                    + "sealed index (root, comment or entry count differs from the "
                                    + "build - compare the [diag] lines)");
                        }
                        UmbraCrypto.wipe(nativeMaster);
                    }
                }
                UmbraCrypto.wipe(root);
            }
            return legacyIndex(sealedIndex, commentBytes);
        } finally {
            UmbraCrypto.wipe(commentBytes);
        }
    }

    private byte[] legacyIndex(byte[] sealedIndex, byte[] commentBytes) throws Exception {
        byte[] siteSeed = siteSeedConstant();
        if (siteSeed == null) {
            if (DEBUG) {
                say(logToken() + " no embedded site seed in the loader "
                        + "(the archive is native-bound and the native root failed)");
            }
            throw silent("Archive master key derivation failed");
        }
        try {
            int entryCount = countEntries();
            int binding = commentBytes == null ? BINDING_SEED : BINDING_SAMPLE;
            byte[] master = commentBytes == null
                    ? UmbraCrypto.masterFromSeed(siteSeed)
                    : UmbraCrypto.masterFromSample(siteSeed, commentBytes, entryCount);
            try {
                byte[] plain = UmbraCrypto.unseal(sealedIndex, master, UmbraCrypto.ALG_CHACHA20);
                this.masterKey = master;
                this.digestKey = master;
                this.bindingUsed = binding;
                return plain;
            } catch (SecurityException wrongKey) {
                if (DEBUG) {
                    say(logToken() + " seed-bound master key did not open the "
                            + "sealed index");
                }
                UmbraCrypto.wipe(master);
                throw silent("Archive master key derivation failed");
            }
        } finally {
            UmbraCrypto.wipe(siteSeed);
        }
    }

    private static byte[] siteSeedConstant() {
        String value = SITE_SEED == null ? "" : SITE_SEED.trim();
        if (value.isEmpty() || value.charAt(0) == '@') {
            return null;
        }
        try {
            byte[] seed = UmbraCrypto.base64Decode(value);
            return seed.length == UmbraCrypto.KEY_BYTES ? seed : null;
        } catch (Throwable unreadable) {
            return null;
        }
    }

    private static byte[] nativeKeyRoot() {
        if (NATIVE_LOADER == null || NATIVE_LOADER.isEmpty() || NATIVE_LOADER.charAt(0) == '@') {
            return null;
        }

        if (!ROOT_CLAIM.compareAndSet(false, true)) {
            if (DEBUG) {
                say(logToken() + " native key root already consumed");
            }
            return null;
        }
        byte[] nonced = nonceRoot(UmbraCrypto.SLOT_CLASS_MASTER, 0);
        if (nonced != null) {
            return nonced;
        }
        try {
            Class<?> type = Class.forName(NATIVE_LOADER, true,
                    UmbraClassLoader.class.getClassLoader());
            java.lang.reflect.Method derive =
                    type.getMethod("deriveKey", int.class, int.class);
            Object value = derive.invoke(null, Integer.valueOf(UmbraCrypto.SLOT_CLASS_MASTER),
                    Integer.valueOf(0));
            if (value instanceof byte[]) {
                byte[] root = (byte[]) value;
                if (root.length == UmbraCrypto.ROOT_BYTES) {
                    return root;
                }
            }
        } catch (Throwable unavailable) {
            if (DEBUG) {
                say(logToken() + " native key root unavailable: "
                        + unavailable.getClass().getName());
            }
        }
        return null;
    }

    private String findSealedCodeLibrary() {
        for (String logical : resourceEntries.keySet()) {
            if (logical.endsWith(".dat")) {
                return logical;
            }
        }
        return null;
    }

    private void verifyOwnClassBytes() {
        if (NATIVE_LOADER == null || NATIVE_LOADER.isEmpty()
                || NATIVE_LOADER.charAt(0) == '@') {
            say(logToken() + " WARN no native bridge: loader self-verification "
                    + "skipped (seed binding, integrity is the class-digest layer)");
            return;
        }
        byte[] loaderBytes = null;
        byte[] bridgeBytes = null;
        try {
            Class<?> nativeType = Class.forName(NATIVE_LOADER, true,
                    UmbraClassLoader.class.getClassLoader());

            String loaderName = UmbraClassLoader.class.getName().replace('.', '/') + ".class";
            String bridgeName = NATIVE_LOADER.replace('.', '/') + ".class";
            loaderBytes = readEntryBytes(loaderName);
            bridgeBytes = readEntryBytes(bridgeName);
            if (loaderBytes == null || bridgeBytes == null) {
                say(logToken() + " loader self-verification could not read "
                        + (loaderBytes == null ? loaderName : bridgeName));
                System.exit(1);
                return;
            }

            say(logToken() + " verifyLoader loader=" + loaderName
                    + " len=" + loaderBytes.length + " sha=" + UmbraCrypto.sha256Hex(loaderBytes));
            say(logToken() + " verifyLoader bridge=" + bridgeName
                    + " len=" + bridgeBytes.length + " sha=" + UmbraCrypto.sha256Hex(bridgeBytes));

            String loaderSha = UmbraCrypto.sha256Hex(loaderBytes);
            String bridgeSha = UmbraCrypto.sha256Hex(bridgeBytes);
            java.lang.reflect.Method bySha;
            try {
                bySha = nativeType.getMethod("verifyLoader", String.class, String.class);
            } catch (NoSuchMethodException noShaForm) {
                bySha = null;
            }
            java.lang.reflect.Method byBytes;
            try {
                byBytes = nativeType.getMethod("verifyLoader", byte[].class, byte[].class);
            } catch (NoSuchMethodException noByteForm) {
                byBytes = null;
            }
            int rc;

            boolean maskSemantics = false;
            boolean strictAnchors = false;
            if (bySha != null) {

                try {
                    Object probe = bySha.invoke(null, "", "");
                    int probeRc = probe instanceof Integer ? ((Integer) probe).intValue() : -1;
                    maskSemantics = probeRc == 3;
                } catch (Throwable probeFailed) {
                    maskSemantics = false;
                }
                if (DEBUG) {
                    say(logToken() + " verifyLoader semantics="
                            + (maskSemantics ? "mask(1=loader,2=bridge)" : "legacy(single value)"));
                }

                String bogus = "0000000000000000000000000000000000000000000000000000000000000000";
                boolean loaderSlotEnforced = false;
                boolean bridgeSlotEnforced = false;
                try {
                    Object wrongLoader = bySha.invoke(null, bogus, bridgeSha);
                    int wrongLoaderRc = wrongLoader instanceof Integer
                            ? ((Integer) wrongLoader).intValue() : -1;
                    loaderSlotEnforced = maskSemantics ? (wrongLoaderRc & 1) != 0 : wrongLoaderRc != 0;
                    Object wrongBridge = bySha.invoke(null, loaderSha, bogus);
                    int wrongBridgeRc = wrongBridge instanceof Integer
                            ? ((Integer) wrongBridge).intValue() : -1;
                    bridgeSlotEnforced = maskSemantics ? (wrongBridgeRc & 2) != 0 : wrongBridgeRc != 0;
                } catch (Throwable probeFailed) {
                    loaderSlotEnforced = false;
                    bridgeSlotEnforced = false;
                }

                strictAnchors = loaderSlotEnforced && bridgeSlotEnforced;
                say(logToken() + " verifyLoader anchor-health loader="
                        + loaderSlotEnforced + " bridge=" + bridgeSlotEnforced
                        + (strictAnchors ? " (anchors enforced: mismatches are fatal)"
                                : " (anchor not enforced: mismatches are reported only)"));
                if (!strictAnchors) {

                    say(logToken() + " umbra-anchor-unhealthy=1 loader="
                            + loaderSlotEnforced + " bridge=" + bridgeSlotEnforced);
                }
                Object answer = bySha.invoke(null, loaderSha, bridgeSha);
                rc = answer instanceof Integer ? ((Integer) answer).intValue() : -1;
            } else if (byBytes != null) {

                say(logToken() + " WARN bridge has no verifyLoader(String,String): "
                        + "falling back to the byte form");
                Object answer = byBytes.invoke(null, loaderBytes, bridgeBytes);
                rc = answer instanceof Integer ? ((Integer) answer).intValue() : -1;
            } else {

                say(logToken() + " WARN bridge has no two-argument verifyLoader: "
                        + "falling back to the single-argument form, so the LOADER class is not "
                        + "natively verified in this build");
                java.lang.reflect.Method oneArg = nativeType.getMethod("verifyLoader", byte[].class);
                Object answer = oneArg.invoke(null, bridgeBytes);
                rc = answer instanceof Integer ? ((Integer) answer).intValue() : -1;
            }
            if (rc != 0) {
                boolean loaderMismatch = maskSemantics && (rc & 1) != 0;
                boolean bridgeMismatch = maskSemantics ? (rc & 2) != 0 : true;
                if (loaderMismatch) {

                    say(logToken() + " loader self-verification failed: the "
                            + "loader class was modified (rc=" + rc + ")");
                    System.exit(1);
                }

                if (bridgeMismatch && (STRICT_NATIVE_VERIFY || strictAnchors)) {
                    say(logToken() + " loader self-verification failed (" + rc + ")");
                    System.exit(1);
                }

                if (bridgeMismatch) {
                    say(logToken() + " ERROR native self-check mismatch (rc=" + rc
                            + "): the bridge anchor did not prove it enforces this slot, so the "
                            + "mismatch is reported instead of aborting; the index digest still "
                            + "covers the loader");
                } else {
                    say(logToken() + " WARN native self-check returned rc=" + rc
                            + " with neither mismatch bit set");
                }
            }
        } catch (Throwable failure) {

            say(logToken() + " loader self-verification error: " + failure);
            Throwable cause = failure.getCause();
            if (cause != null) {
                say(logToken() + " loader self-verification cause: " + cause);
                cause.printStackTrace();
            }
            System.exit(1);
        } finally {
            if (loaderBytes != null) {
                java.util.Arrays.fill(loaderBytes, (byte) 0);
            }
            if (bridgeBytes != null) {
                java.util.Arrays.fill(bridgeBytes, (byte) 0);
            }
        }
    }

    private byte[] readEntryBytes(String entryName) {
        java.util.zip.ZipEntry entry = jar.getJarEntry(entryName);
        java.io.InputStream stream = null;
        try {
            if (entry != null) {
                stream = jar.getInputStream(entry);
            } else {
                ClassLoader defining = UmbraClassLoader.class.getClassLoader();
                if (defining != null) {
                    stream = defining.getResourceAsStream(entryName);
                }
            }
            return stream == null ? null : readAll(stream);
        } catch (Throwable unreadable) {
            return null;
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (Throwable ignored) {

                }
            }
        }
    }

    private static void bindNativeNames(Class<?> type) {
        try {

            java.lang.reflect.Method bind;
            Object bound;
            try {
                bind = type.getMethod("bindOwnNames", Class.class);
                bound = bind.invoke(null, type);
            } catch (NoSuchMethodException noOwnerArg) {
                bind = type.getMethod("bindOwnNames");
                bound = bind.invoke(null);
            }
            boolean ok = Boolean.TRUE.equals(bound);
            if (!ok) {
                say(logToken() + " bindOwnNames returned " + String.valueOf(bound)
                        + "; native entry points stay unbound (keyRoot2 will report the cause)");
            } else if (DEBUG) {
                say(logToken() + " bindOwnNames -> true");
            }
        } catch (NoSuchMethodException olderBridge) {

        } catch (Throwable unavailable) {
            say(logToken() + " bindOwnNames failed: " + unavailable
                    + (unavailable.getCause() == null ? "" : " cause=" + unavailable.getCause()));
        }
    }

    private int countEntries() {
        int count = 0;
        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            if (!entry.isDirectory()) {
                count++;
            }
        }
        return count;
    }

    private URL locateOwnArchive() throws Exception {
        ProtectionDomain domain = UmbraClassLoader.class.getProtectionDomain();
        if (domain == null) {
            throw new IllegalStateException("Loader class has no protection domain");
        }
        CodeSource source = domain.getCodeSource();
        if (source == null || source.getLocation() == null) {
            throw new IllegalStateException("Loader class has no code source");
        }
        return source.getLocation();
    }

    private byte[] readEntry(String name) throws IOException {
        synchronized (jar) {
            JarEntry entry = jar.getJarEntry(name);
            if (entry == null) {
                throw new IOException("Missing archive entry");
            }
            InputStream in = jar.getInputStream(entry);
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

    private static int readInt(ByteBuffer buffer) {
        if (buffer.remaining() < 4) {
            throw silent("Encrypted archive index is truncated");
        }
        return buffer.getInt();
    }

    private static byte[] readBytes(ByteBuffer buffer, int length) {
        if (length < 0 || buffer.remaining() < length) {
            throw silent("Encrypted archive index is truncated");
        }
        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    private static int readCount(ByteBuffer buffer, int maximum) {
        int value = readInt(buffer);
        if (value < 0 || value > maximum) {
            throw silent("Encrypted archive index count is invalid");
        }
        return value;
    }

    private static String readString(ByteBuffer buffer) {
        int length = readInt(buffer);
        if (length < 0 || length > MAX_STRING_BYTES || length > buffer.remaining()) {
            throw silent("Encrypted archive index string is invalid");
        }
        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static int[] shuffledIndices(int size) {
        if (size <= 0) {
            return new int[0];
        }
        int[] order = new int[size];
        for (int i = 0; i < size; i++) {
            order[i] = i;
        }
        java.util.Random random = new java.util.Random(System.nanoTime() ^ (long) size);
        for (int i = size - 1; i > 0; i--) {
            int swap = random.nextInt(i + 1);
            int value = order[i];
            order[i] = order[swap];
            order[swap] = value;
        }
        return order;
    }

    private static String classNameOf(byte[] bytes) {
        try {
            int offset = 8;
            int poolCount = readU2(bytes, offset);
            offset += 2;
            String[] utf8 = new String[poolCount];
            int[] tagOffsets = new int[poolCount];
            for (int index = 1; index < poolCount; index++) {
                int tag = readU1(bytes, offset);
                offset++;
                tagOffsets[index] = offset - 1;
                switch (tag) {
                    case 1: {
                        int length = readU2(bytes, offset);
                        offset += 2;
                        utf8[index] = new String(bytes, offset, length, StandardCharsets.UTF_8);
                        offset += length;
                        break;
                    }
                    case 7:
                    case 8:
                    case 16:
                    case 19:
                    case 20:
                        offset += 2;
                        break;
                    case 15:
                        offset += 3;
                        break;
                    case 3:
                    case 4:
                    case 9:
                    case 10:
                    case 11:
                    case 12:
                    case 17:
                    case 18:
                        offset += 4;
                        break;
                    case 5:
                    case 6:
                        offset += 8;
                        index++;
                        break;
                    default:
                        return null;
                }
            }
            offset += 2;
            int thisClass = readU2(bytes, offset);
            if (thisClass <= 0 || thisClass >= poolCount) {
                return null;
            }
            int nameOffset = tagOffsets[thisClass];
            if (nameOffset < 0 || readU1(bytes, nameOffset) != 7) {
                return null;
            }
            int utf8Index = readU2(bytes, nameOffset + 1);
            if (utf8Index <= 0 || utf8Index >= poolCount) {
                return null;
            }
            String internal = utf8[utf8Index];
            return internal == null ? null : internal.replace('/', '.');
        } catch (Throwable invalid) {
            return null;
        }
    }

    private static int readU1(byte[] bytes, int offset) {
        return bytes[offset] & 0xFF;
    }

    private static int readU2(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF);
    }
}
