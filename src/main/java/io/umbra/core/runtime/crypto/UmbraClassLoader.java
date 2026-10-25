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

    // Substituted at injection time.
    private static final String INDEX_ENTRY = "@@INDEX@@";
    private static final String SITE_SEED = "@@SEED@@";
    private static final String ACTION = "@@ACTION@@";
    private static final String LOG_TOKEN = "@@LOGTOKEN@@";
    private static final String WATCHDOG = "@@WATCHDOG@@";
    private static final String RUNTIME_GUARD = "@@GUARD@@";
    private static final String WATCH_MS_TEXT = "@@WATCHMS@@";

    private static final int MAGIC = 0x554D4232;
    private static final int VERSION = 3;
    private static final int FLAG_INTEGRITY = 1;
    private static final int FLAG_ANTIDUMP = 2;
    private static final int FLAG_RESOURCE_INTEGRITY = 4;
    private static final int ALG_SHIFT = 3;
    private static final int ALG_MASK = 3;

    private static final int BINDING_SAMPLE = 0;
    private static final int BINDING_SEED = 1;

    /** Maximum accepted UTF-8 string length in the sealed index (1 MiB). */
    private static final int MAX_STRING_BYTES = 1024 * 1024;
    /** Maximum accepted class/resource index entries (sanity cap). */
    private static final int MAX_ENTRIES = 1_000_000;
    /** Minimum bytes per index entry (two length-prefixed names + 32-byte digest). */
    private static final int MIN_CLASS_ENTRY_BYTES = 8 + 32;

    /** Scheme of the decrypted-resource URLs served by the custom handler. */
    private static final String RESOURCE_PROTOCOL = "umbra";

    private final URL location;
    private final JarFile jar;
    private final ProtectionDomain protectionDomain;
    private final byte[] masterKey;
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
        this.protectionDomain = new ProtectionDomain(
                new CodeSource(location, (Certificate[]) null), null, this, null);
        this.masterKey = deriveMasterKey();

        byte[] sealedIndex = readEntry(INDEX_ENTRY);
        byte[] index = UmbraCrypto.unseal(sealedIndex, masterKey, UmbraCrypto.ALG_CHACHA20);
        UmbraCrypto.wipe(sealedIndex);

        ByteBuffer buffer = ByteBuffer.wrap(index);
        if (readInt(buffer) != MAGIC) {
            throw silent("Encrypted archive index is not valid");
        }
        int version = buffer.get() & 0xFF;
        if (version != VERSION) {
            throw silent("Unsupported encrypted archive version");
        }
        byte flags = buffer.get();
        int level = buffer.get() & 0xFF;
        int binding = buffer.get() & 0xFF;
        if (binding != bindingUsed) {
            throw silent("Encrypted archive binding mismatch");
        }
        this.integrityEnabled = (flags & FLAG_INTEGRITY) != 0;
        this.antiDump = (flags & FLAG_ANTIDUMP) != 0;
        this.resourceIntegrityEnabled = (flags & FLAG_RESOURCE_INTEGRITY) != 0;
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
            if (name.isEmpty() || entry.isEmpty() || classEntries.put(name, entry) != null) {
                throw silent("Encrypted archive index class map is invalid");
            }
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
        UmbraCrypto.wipe(index);

        // The class map is ready now, so the unified runtime guard (itself an
        // encrypted payload) can be loaded and consulted before the first program
        // class is decrypted/defined; if an instrumentation signal is active the
        // loader refuses to start even with action=log.
        runGuardCheck();

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

    /** JVM entry point: load and run the original main class. */
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

    /**
     * Watchdog tick: samples a random slice of the payload index (full pass every
     * 20th tick at level 3) and refreshes the heartbeat that the decrypt path
     * checks, so a suspended watchdog thread is detectable. A failure halts
     * silently from this background thread (a thrown exception would print a
     * stack trace); it never returns a diagnostic to the program.
     */
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
            // A missing watchdog must not break the program.
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

    /**
     * Detects a watchdog thread that stopped ticking (for example suspended with a
     * debugger): the next decrypt/define fails closed.
     */
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

    // ------------------------------------------------------------------
    // Unified runtime guard (anti-dump / anti-decrypt gate)
    // ------------------------------------------------------------------

    // Per-instance: a JVM may construct several loaders (tests, containers) and
    // each archive has its own seed-derived guard class name.
    // Volatile publication for the double-checked resolution below: without it a
    // second thread could observe guardResolved==true before the Method fields
    // (an unsafe-publication window that would silently skip the guard check).
    private volatile boolean guardResolved;
    private volatile boolean guardResolving;
    private volatile java.lang.reflect.Method guardCheckMethod;
    private volatile java.lang.reflect.Method guardDetectedMethod;

    /** True when the pass injected and named the unified runtime guard. */
    private static boolean guardConfigured() {
        return RUNTIME_GUARD != null && RUNTIME_GUARD.length() > 1
                && RUNTIME_GUARD.charAt(0) != '@';
    }

    /**
     * Runs the full guard check once, before any class payload is decrypted or
     * defined. The guard class is itself an encrypted payload, so it is loaded
     * through this loader; a reentrant resolution (the guard class decryption
     * asking whether a guard is present) is skipped instead of recursing.
     */
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
            // Guard infrastructure is best effort; digest checks still run.
        }
    }

    /**
     * Cheap fail-closed signal query used before every decrypt/define. When the
     * guard reports a signal the loader refuses to produce plaintext class bytes.
     */
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
                // Leave the methods null; the loader stays functional.
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

    /**
     * Refuses decryption/define after a guard signal. The exception carries no
     * message and an empty stack trace; diagnostics are only printed when
     * {@code -Dumbra.debug=true}.
     */
    private static void guardRefuse(String what) {
        if (DEBUG) {
            System.err.println(logToken() + " guard: " + what);
        }
        throw silent("Runtime guard signal active");
    }

    // ------------------------------------------------------------------
    // Class loading
    // ------------------------------------------------------------------

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        String entry = classEntries.get(name);
        if (entry == null) {
            throw new ClassNotFoundException(name);
        }
        byte[] bytes = loadClassPayload(name, entry);
        try {
            definePackageFor(name);
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
            // Another class of the same package won the race.
        }
    }

    private byte[] loadClassPayload(String className, String entryName) throws ClassNotFoundException {
        if (guardSignal()) {
            guardRefuse("class decryption");
        }
        checkWatchdogHeartbeat();
        try {
            byte[] sealed = readEntry(entryName);
            byte[] key = payloadKey("c:" + className, sealed);
            try {
                byte[] plain = UmbraCrypto.unseal(sealed, key, payloadAlgorithm);
                // Re-check between decryption and define: an attach that happened
                // while this payload was being processed still refuses the define.
                if (guardSignal()) {
                    UmbraCrypto.wipe(plain);
                    guardRefuse("class define");
                }
                if (integrityEnabled && integrityLevel >= 2) {
                    byte[] expected = classDigests.get(className);
                    byte[] actual = UmbraCrypto.keyedDigest(masterKey, "d:c:" + className, plain);
                    boolean valid = expected != null && UmbraCrypto.constantTimeEquals(expected, actual);
                    UmbraCrypto.wipe(actual);
                    if (!valid) {
                        UmbraCrypto.wipe(plain);
                        fail("Class payload integrity check failed");
                    }
                }
                String actualName = classNameOf(plain);
                if (!className.equals(actualName)) {
                    UmbraCrypto.wipe(plain);
                    fail("Class payload name mismatch");
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

    private byte[] payloadKey(String label, byte[] sealed) {
        byte[] nonce = UmbraCrypto.nonceOf(sealed);
        try {
            return UmbraCrypto.entryKey(masterKey, label, nonce);
        } finally {
            UmbraCrypto.wipe(nonce);
        }
    }

    // ------------------------------------------------------------------
    // Resources (decrypted through the custom URLStreamHandler)
    // ------------------------------------------------------------------

    /**
     * Decrypts one resource payload. Called by the injected
     * {@code UmbraResourceConnection} through the URL handler.
     *
     * @param encodedName URL path segment as produced by {@link #findResource}
     * @return decrypted resource bytes (caller owns the array)
     */
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
            byte[] key = payloadKey("r:" + name, sealed);
            try {
                byte[] plain = UmbraCrypto.unseal(sealed, key, payloadAlgorithm);
                if (guardSignal()) {
                    UmbraCrypto.wipe(plain);
                    guardRefuse("resource define");
                }
                if (integrityEnabled && resourceIntegrityEnabled && integrityLevel >= 2) {
                    byte[] expected = resourceDigests.get(name);
                    Integer size = resourceSizes.get(name);
                    byte[] actual = UmbraCrypto.keyedDigest(masterKey, "d:r:" + name, plain);
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

    /**
     * Percent-encodes a logical resource name for the URL path, keeping
     * {@code '/'} so path-based framework checks still work. Decoding is the
     * inverse of {@link #decodeResourceName(String)}.
     */
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

    // ------------------------------------------------------------------
    // Integrity / anti-dump
    // ------------------------------------------------------------------

    private void verifySelfBytes() {
        try {
            String selfEntry = UmbraClassLoader.class.getName().replace('.', '/') + ".class";
            byte[] self = readEntry(selfEntry);
            byte[] digest = UmbraCrypto.keyedDigest(masterKey, "d:loader", self);
            UmbraCrypto.wipe(self);
            boolean valid = UmbraCrypto.constantTimeEquals(digest, loaderDigest);
            UmbraCrypto.wipe(digest);
            // The expected loader digest is not needed after the comparison; a
            // memory dump cannot recover it to forge a rewritten loader.
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

    /** Sampled watchdog verification: ~1/20 of the classes/resources per tick. */
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
            byte[] key = payloadKey("c:" + name, sealed);
            byte[] plain = null;
            try {
                plain = UmbraCrypto.unseal(sealed, key, payloadAlgorithm);
                if (integrityEnabled && integrityLevel >= 2) {
                    byte[] expected = classDigests.get(name);
                    byte[] actual = UmbraCrypto.keyedDigest(masterKey, "d:c:" + name, plain);
                    boolean valid = expected != null && UmbraCrypto.constantTimeEquals(expected, actual);
                    UmbraCrypto.wipe(actual);
                    if (!valid) {
                        fail("Class payload integrity check failed");
                    }
                }
                if (!name.equals(classNameOf(plain))) {
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

    private void checkAntiDump() {
        // When the unified runtime guard is present it already covers agent/JDWP
        // command-line detection (with the full multi-signal policy); running the
        // old argument heuristic here would duplicate it and mask the guard's
        // configured action/logging. Keep the heuristic only for archives built
        // without the guard (antiDebug.level=0).
        if (!guardConfigured()) {
            try {
                java.lang.management.RuntimeMXBean bean =
                        java.lang.management.ManagementFactory.getRuntimeMXBean();
                List<String> arguments = bean.getInputArguments();
                for (int i = 0; i < arguments.size(); i++) {
                    String argument = arguments.get(i);
                    String lower = argument.toLowerCase(Locale.ROOT);
                    if (lower.contains("jdwp") || lower.contains("javaagent") || lower.contains("agentlib")
                            || lower.contains("agentpath") || lower.contains("-xdebug")) {
                        fail("A dump/debug agent is attached");
                    }
                }
            } catch (SecurityException e) {
                throw e;
            } catch (Throwable ignored) {
                // Management API not available: ignore this heuristic.
            }
        }
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
                    String binary = bytes == null ? null : classNameOf(bytes);
                    if (binary == null || !plaintextClasses.contains(binary)) {
                        fail("Unexpected plaintext class in encrypted archive");
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
            System.err.println(logToken() + " " + message);
        }
        if ("exit".equals(ACTION)) {
            Runtime.getRuntime().halt(1);
        }
        if ("corrupt".equals(ACTION)) {
            Runtime.getRuntime().halt(0);
        }
        throw silent(message);
    }

    /** Background-thread failure: cannot throw into the program, so halt silently. */
    private void verifyFailure() {
        if (DEBUG) {
            System.err.println(logToken() + " watchdog failure");
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

    // ------------------------------------------------------------------
    // Archive helpers
    // ------------------------------------------------------------------

    /**
     * Rebuilds the sample-bound master key (index v3). The binding mode is
     * signalled by the ZIP comment: a base64 comment means the sample-bound mode
     * (comment + entry count), an absent comment means the diagnostic seed mode.
     * Editing the comment or adding/removing entries changes the master key, so
     * decryption fails by design.
     */
    private byte[] deriveMasterKey() throws Exception {
        byte[] siteSeed;
        try {
            siteSeed = UmbraCrypto.base64Decode(SITE_SEED.trim());
        } catch (Throwable unreadable) {
            throw silent("Archive seed is unreadable");
        }
        if (siteSeed.length != UmbraCrypto.KEY_BYTES) {
            throw silent("Archive seed is invalid");
        }
        try {
            String comment = jar.getComment();
            byte[] master;
            if (comment == null || comment.trim().isEmpty()) {
                bindingUsed = BINDING_SEED;
                master = UmbraCrypto.masterFromSeed(siteSeed);
            } else {
                byte[] commentBytes;
                try {
                    commentBytes = UmbraCrypto.base64Decode(comment.trim());
                } catch (Throwable unreadable) {
                    throw silent("Archive comment is unreadable");
                }
                try {
                    bindingUsed = BINDING_SAMPLE;
                    master = UmbraCrypto.masterFromSample(siteSeed, commentBytes, countEntries());
                } finally {
                    UmbraCrypto.wipe(commentBytes);
                }
            }
            UmbraCrypto.wipe(siteSeed);
            return master;
        } catch (SecurityException failure) {
            UmbraCrypto.wipe(siteSeed);
            throw failure;
        } catch (Throwable unreadable) {
            UmbraCrypto.wipe(siteSeed);
            throw silent("Archive master key derivation failed");
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

    // ------------------------------------------------------------------
    // Bounded index parsing
    // ------------------------------------------------------------------

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

    /** Reads the internal class name out of a class file without loading it. */
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
            offset += 2; // access flags
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
