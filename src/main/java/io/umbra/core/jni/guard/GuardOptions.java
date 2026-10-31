package io.umbra.core.jni.guard;

import java.util.List;
import java.util.Locale;

/**
 * Shared, testable helpers for the native anti-debug / anti-Frida guard.
 *
 * <p>Everything here is pure Java so the guard policy (JDWP/agent detection,
 * Frida environment markers, token mixing) can be unit-tested without loading
 * native code. The injected runtime template re-implements the same small
 * helpers because runtime templates must stay self-contained and JDK-only.</p>
 */
public final class GuardOptions {

    /** Detection action codes shared with the injected template. */
    public static final int ACTION_THROW = 1;
    public static final int ACTION_EXIT = 2;
    public static final int ACTION_CORRUPT = 3;
    public static final int ACTION_LOG = 4;

    /** Detection bitmask values (kept in sync with the generated C guard). */
    public static final int DETECT_DEBUGGER = 1;
    public static final int DETECT_REMOTE_DEBUGGER = 1 << 1;
    public static final int DETECT_PEB = 1 << 2;
    public static final int DETECT_DEBUG_PORT = 1 << 3;
    public static final int DETECT_DEBUG_FLAGS = 1 << 4;
    public static final int DETECT_DEBUG_OBJECT = 1 << 5;
    public static final int DETECT_BREAKPOINTS = 1 << 6;
    public static final int DETECT_FRIDA_MODULE = 1 << 7;
    public static final int DETECT_FRIDA_PIPE = 1 << 8;
    public static final int DETECT_FRIDA_THREAD = 1 << 9;
    public static final int DETECT_FRIDA_ENV = 1 << 10;
    public static final int DETECT_JDWP = 1 << 11;
    public static final int DETECT_HASH = 1 << 12;
    public static final int DETECT_HOOK = 1 << 13;
    public static final int DETECT_TOKEN = 1 << 14;
    public static final int DETECT_BACKFILL = 1 << 15;
    public static final int DETECT_AGENT = 1 << 16;
    // Umbra 3.1 dynamic-protection signals (native guard).
    public static final int DETECT_REMOTE_THREAD = 1 << 17;
    public static final int DETECT_EXEC_MEMORY = 1 << 18;
    public static final int DETECT_IMAGE_BP = 1 << 19;
    public static final int DETECT_MODULE = 1 << 20;
    public static final int DETECT_TIMING = 1 << 21;
    public static final int DETECT_HANDLE_DUMP = 1 << 22;
    public static final int DETECT_CODE_SAMPLE = 1 << 23;
    public static final int DETECT_LINUX = 1 << 24;
    // Umbra 3.3 native memory protection (PhantomShield port).
    /** Guard code-section CRC readback mismatch (inline patch after startup). */
    public static final int DETECT_CODE_CRC = 1 << 25;
    /** Guard data-page protection tampering (PAGE_NOACCESS/PAGE_GUARD rotation). */
    public static final int DETECT_PAGE_GUARD = 1 << 26;

    /**
     * Default {@code antiDebug.execWhitelist}: JVM/AWT modules whose executable
     * mappings are not evidence of manual mapping. {@code javafx*} covers the
     * per-platform JavaFX native libraries.
     */
    public static final String DEFAULT_EXEC_WHITELIST = "jvm.dll,java.dll,javafx*,awt.dll";

    private static final String[] DEBUG_OPTION_MARKERS = {
            "jdwp", "xrunjdwp", "dt_socket", "dt_shmem", "agentlib:jdwp"
    };

    private GuardOptions() {
    }

    /** Maps {@code antiDebug.action} to the numeric action code (default throw). */
    public static int actionCode(String action) {
        String value = action == null ? "" : action.trim().toLowerCase(Locale.ROOT);
        if ("exit".equals(value)) {
            return ACTION_EXIT;
        }
        if ("corrupt".equals(value)) {
            return ACTION_CORRUPT;
        }
        if ("log".equals(value)) {
            return ACTION_LOG;
        }
        return ACTION_THROW;
    }

    /** Canonical action name ({@code throw}, {@code exit}, {@code corrupt} or {@code log}). */
    public static String actionName(int code) {
        switch (code) {
            case ACTION_EXIT:
                return "exit";
            case ACTION_CORRUPT:
                return "corrupt";
            case ACTION_LOG:
                return "log";
            default:
                return "throw";
        }
    }

    /**
     * Detects a JDWP / debug-agent JVM option.
     *
     * @param vmArguments JVM input arguments ({@code RuntimeMXBean.getInputArguments()})
     */
    public static boolean hasDebugOption(List<String> vmArguments) {
        if (vmArguments == null) {
            return false;
        }
        for (String argument : vmArguments) {
            if (isDebugOption(argument)) {
                return true;
            }
        }
        return false;
    }

    /** True for JDWP / debug transport options; case-insensitive. */
    public static boolean isDebugOption(String argument) {
        if (argument == null) {
            return false;
        }
        String value = argument.trim().toLowerCase(Locale.ROOT);
        for (String marker : DEBUG_OPTION_MARKERS) {
            if (value.indexOf(marker) >= 0) {
                return true;
            }
        }
        return false;
    }

    /** True for {@code -javaagent:}/{@code -agentpath:} style instrumentation agents. */
    public static boolean isInstrumentationOption(String argument) {
        if (argument == null) {
            return false;
        }
        String value = argument.trim().toLowerCase(Locale.ROOT);
        return value.startsWith("-javaagent:")
                || value.startsWith("-agentpath:")
                || value.startsWith("-agentlib:jdwp");
    }

    /**
     * Detects JDWP/debug or instrumentation markers inside agent-style
     * environment variables ({@code JAVA_TOOL_OPTIONS}, {@code _JAVA_OPTIONS},
     * {@code JDK_JAVA_OPTIONS}).
     */
    public static boolean hasDebugEnvironment(String name, String value) {
        if (value == null || name == null) {
            return false;
        }
        String upper = name.toUpperCase(Locale.ROOT);
        if (!"JAVA_TOOL_OPTIONS".equals(upper) && !"_JAVA_OPTIONS".equals(upper)
                && !"JDK_JAVA_OPTIONS".equals(upper)) {
            return false;
        }
        return isDebugOption(value) || isInstrumentationOption(value);
    }

    /** Detects a Frida / instrumentation marker in the process environment. */
    public static boolean isFridaEnvironment(String name, String value) {
        if (name == null) {
            return false;
        }
        String upperName = name.toUpperCase(Locale.ROOT);
        if (upperName.startsWith("FRIDA") || "GADGET".equals(upperName)) {
            return true;
        }
        if (value == null) {
            return false;
        }
        String lowerValue = value.toLowerCase(Locale.ROOT);
        if ("LD_PRELOAD".equals(upperName) || "DYLD_INSERT_LIBRARIES".equals(upperName)) {
            return lowerValue.indexOf("frida") >= 0;
        }
        if ("JAVA_TOOL_OPTIONS".equals(upperName) || "_JAVA_OPTIONS".equals(upperName)) {
            return lowerValue.indexOf("frida") >= 0;
        }
        return false;
    }

    /** Deterministic keyed token transform shared with the native guard. */
    public static long mixToken(long secret, int challenge, long fileHash) {
        long hash = 0xcbf29ce484222325L ^ secret ^ fileHash;
        hash ^= ((long) challenge) & 0xFFFFFFFFL;
        hash *= 0x100000001b3L;
        hash ^= hash >>> 33;
        hash *= 0xff51afd7ed558ccdL;
        hash ^= hash >>> 33;
        return hash;
    }

    /** FNV-1a 64-bit digest, used for the guard DLL self-integrity value. */
    public static long fnv1a64(byte[] data, int offset, int length) {
        long hash = 0xcbf29ce484222325L;
        for (int i = offset; i < offset + length; i++) {
            hash ^= data[i] & 0xFFL;
            hash *= 0x100000001b3L;
        }
        return hash;
    }

    public static long fnv1a64(byte[] data) {
        return fnv1a64(data, 0, data == null ? 0 : data.length);
    }

    /**
     * FNV-1a 32-bit digest of an ASCII name, shared with the generated native
     * resolver: the guard decrypts an API name into a stack buffer and only calls
     * {@code GetProcAddress} when its hash matches this build-time constant, so a
     * patched literal cannot be redirected to another export.
     */
    public static int fnv1a32(String text) {
        int hash = 0x811C9DC5;
        for (int i = 0; i < text.length(); i++) {
            hash ^= text.charAt(i) & 0xFF;
            hash *= 0x01000193;
        }
        return hash;
    }

    /** {@link #fnv1a32(String)} formatted as the C constant emitted into the guard. */
    public static String fnv1a32Hex(String text) {
        return "0x" + hex(fnv1a32(text) & 0xFFFFFFFFL, 8) + "UL";
    }

    /**
     * Canonical {@code antiDebug.execWhitelist} value: the configured list or the
     * conservative JVM/AWT default when it is blank.
     */
    public static String execWhitelist(String configured) {
        String value = configured == null ? "" : configured.trim();
        return value.isEmpty() ? DEFAULT_EXEC_WHITELIST : value;
    }

    /**
     * Case-insensitive match of a module name or path against a comma-separated
     * whitelist. A token ending in {@code *} matches on its prefix, every other
     * token on a substring; blank tokens are ignored.
     */
    public static boolean execWhitelistMatches(String whitelist, String moduleName) {
        if (whitelist == null || moduleName == null) {
            return false;
        }
        String name = moduleName.toLowerCase(Locale.ROOT);
        for (String token : whitelist.split(",")) {
            String value = token.trim().toLowerCase(Locale.ROOT);
            if (value.endsWith("*")) {
                value = value.substring(0, value.length() - 1);
            }
            if (!value.isEmpty() && name.indexOf(value) >= 0) {
                return true;
            }
        }
        return false;
    }

    public static String hex(long value, int digits) {
        StringBuilder out = new StringBuilder(digits);
        for (int i = digits - 1; i >= 0; i--) {
            out.append(Character.forDigit((int) ((value >>> (i * 4)) & 0xF), 16));
        }
        return out.toString();
    }

    public static String bytesToHex(byte[] data) {
        if (data == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(data.length * 2);
        for (byte b : data) {
            out.append(Character.forDigit((b >>> 4) & 0xF, 16));
            out.append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }

    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }
        String text = hex.trim();
        if ((text.length() & 1) != 0) {
            throw new IllegalArgumentException("odd-length hex string");
        }
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Formats a detection mask for logs ({@code 0x00000004}). */
    public static String describeMask(int mask) {
        return "0x" + hex(mask & 0xFFFFFFFFL, 8);
    }
}
