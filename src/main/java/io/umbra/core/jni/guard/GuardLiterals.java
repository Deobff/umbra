package io.umbra.core.jni.guard;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Build-time sealed string literals for the generated guard (P1-5.2).
 *
 * <p>Every detection marker (instrumentation names, {@code /proc} paths, module
 * names, API names) is stored in the compiled guard as a per-literal XOR byte
 * array and decoded on first use into a static buffer, so {@code strings} /
 * {@code objdump -s} on the shipped DLL shows no plaintext marker and no
 * plaintext import name.</p>
 *
 * <p>Only literals that the generated body actually references are emitted: the
 * body is rendered first, then {@link #emit} writes the arrays and accessors, so
 * a Linux-only marker costs nothing in a Windows build and GCC never warns about
 * an unused static function.</p>
 */
final class GuardLiterals {

    /**
     * Every literal the generated guard may reference. Order defines the emitted
     * accessor numbering, so the generated C stays byte-identical for a given
     * secret (build reproducibility).
     */
    private static final String[] VALUES = {
            // Windows instrumentation markers.
            "frida",
            "frida-",
            "gum-",
            "gum-js-loop",
            "gmain",
            "gdbus",
            "gadget",
            "\\\\.\\pipe\\*",
            // JDWP / agent modules.
            "jdwp",
            "dt_socket",
            "dt_shmem",
            "attach.dll",
            "instrument.dll",
            // Module names used by the hash-resolved import resolver.
            "kernel32.dll",
            "ntdll.dll",
            // Environment markers.
            "ld_preload",
            "dyld_insert_libraries",
            "java_tool_options",
            "_java_options",
            "jdk_java_options",
            // Linux /proc markers (compiled out on Windows).
            "/proc/self/status",
            "/proc/self/maps",
            "TracerPid:",
            "gum-js",
            // Sensitive imports resolved by FNV hash at runtime.
            "CheckRemoteDebuggerPresent",
            "CreateToolhelp32Snapshot",
            "GetFileAttributesA",
            "GetTickCount64",
            "GetThreadDescription",
            "NtQueryInformationProcess",
            "NtQueryInformationThread",
            "NtQuerySystemInformation"
    };

    /** Plaintext length of every registered literal. */
    private final Map<String, Integer> index = new LinkedHashMap<String, Integer>();
    private final List<String> values = new ArrayList<String>();
    private final int[] keys;

    /**
     * @param secret build secret (same value embedded in the Java guard)
     * @param extra  additional literals (for example the configured
     *               {@code antiDebug.execWhitelist} list)
     */
    GuardLiterals(long secret, String... extra) {
        for (String value : VALUES) {
            register(value);
        }
        if (extra != null) {
            for (String value : extra) {
                if (value != null && !value.isEmpty()) {
                    register(value);
                }
            }
        }
        keys = new int[values.size()];
        for (int i = 0; i < keys.length; i++) {
            keys[i] = key(secret, i);
        }
    }

    private void register(String value) {
        if (index.containsKey(value)) {
            return;
        }
        index.put(value, values.size());
        values.add(value);
    }

    /** Per-literal XOR key: derived from the build secret and the slot index. */
    private static int key(long secret, int slot) {
        int fromSecret = (int) ((secret >>> ((slot % 8) * 8)) & 0xFFL);
        return (fromSecret ^ ((slot * 31 + 0x5A) & 0xFF)) & 0xFF;
    }

    private int slotOf(String value) {
        Integer slot = index.get(value);
        if (slot == null) {
            throw new IllegalStateException("guard literal is not registered: " + value);
        }
        return slot.intValue();
    }

    /** C expression yielding the decoded literal ({@code umbra_lit_7()}). */
    String ref(String value) {
        return "umbra_lit_" + slotOf(value) + "()";
    }

    /** C symbol of the sealed byte array ({@code umbra_sealed_7}). */
    String sealed(String value) {
        return "umbra_sealed_" + slotOf(value);
    }

    /** Build-time XOR key of the literal, as emitted into the guard C. */
    int key(String value) {
        return keys[slotOf(value)];
    }

    /** Plaintext byte length of the literal. */
    int length(String value) {
        return value.length();
    }

    /**
     * Emits the decoder, the sealed arrays and the first-use accessors. Must be
     * called after the body was rendered (so only referenced literals appear) and
     * before the body is appended to the translation unit.
     */
    void emit(StringBuilder out) {
        if (values.isEmpty()) {
            return;
        }
        out.append("/* ---- P1-5.2: sealed literals (decoded on first use, no plaintext\n");
        out.append("   detection marker in .rdata) ---- */\n");
        out.append("static void umbra_unseal(const unsigned char* sealed, int length,\n");
        out.append("        char* out, unsigned char key) {\n");
        out.append("    int i;\n");
        out.append("    for (i = 0; i < length; i++) {\n");
        out.append("        out[i] = (char)(sealed[i] ^ (unsigned char)(key + i * 7));\n");
        out.append("    }\n");
        out.append("    out[length] = 0;\n");
        out.append("}\n\n");
        for (int i = 0; i < values.size(); i++) {
            String value = values.get(i);
            emitArray(out, i, value);
            emitAccessor(out, i, value);
        }
    }

    private void emitArray(StringBuilder out, int slot, String value) {
        out.append("static const unsigned char umbra_sealed_").append(slot).append("[] = {");
        for (int i = 0; i < value.length(); i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append("0x").append(Integer.toHexString(seal(value.charAt(i), keys[slot], i)));
        }
        out.append("};\n");
    }

    private void emitAccessor(StringBuilder out, int slot, String value) {
        out.append("static const char* umbra_lit_").append(slot).append("(void) {\n");
        out.append("    static char buffer[").append(value.length() + 1).append("];\n");
        out.append("    static volatile int ready;\n");
        out.append("    if (!ready) {\n");
        out.append("        umbra_unseal(umbra_sealed_").append(slot).append(", ")
                .append(value.length()).append(", buffer, 0x")
                .append(Integer.toHexString(keys[slot])).append(");\n");
        out.append("        ready = 1;\n");
        out.append("    }\n");
        out.append("    return buffer;\n");
        out.append("}\n");
    }

    /** One sealed byte: {@code plain ^ (key + position * 7)} (mirrors the C decoder). */
    private static int seal(char plain, int key, int position) {
        return (plain ^ ((key + position * 7) & 0xFF)) & 0xFF;
    }
}
