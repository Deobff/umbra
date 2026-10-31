package io.umbra.core.jni.guard;

/**
 * Build-time table of the guard's <em>synthetic import table</em> (P1-5.1).
 *
 * <p>The sensitive APIs the guard needs are no longer imported through the PE
 * import directory. Each one is stored as a sealed name literal (see
 * {@link GuardLiterals}), decoded into a stack buffer on first use, validated
 * against its build-time FNV-1a 32 hash and only then handed to
 * {@code GetProcAddress} on a module obtained through {@code LoadLibraryA}. The
 * shipped DLL therefore has no {@code CheckRemoteDebuggerPresent},
 * {@code CreateToolhelp32Snapshot}, {@code GetFileAttributesA} or
 * {@code NtQuery*} import entry and no plaintext API name in {@code .rdata}.</p>
 *
 * <p>The hash comparison is not decoration: it pins the decoded name to the name
 * this build was generated for, so patching the sealed array cannot redirect the
 * call to a different export.</p>
 */
final class GuardImports {

    private static final String KERNEL32 = "kernel32.dll";
    private static final String NTDLL = "ntdll.dll";

    /** {@code api name}, {@code module}, {@code accessor suffix}. */
    private static final String[][] APIS = {
            {"CheckRemoteDebuggerPresent", KERNEL32, "check_remote_debugger_present"},
            {"CreateToolhelp32Snapshot", KERNEL32, "create_toolhelp32_snapshot"},
            {"GetFileAttributesA", KERNEL32, "get_file_attributes_a"},
            {"GetTickCount64", KERNEL32, "get_tick_count64"},
            {"GetThreadDescription", KERNEL32, "get_thread_description"},
            {"NtQueryInformationProcess", NTDLL, "nt_query_information_process"},
            {"NtQueryInformationThread", NTDLL, "nt_query_information_thread"},
            {"NtQuerySystemInformation", NTDLL, "nt_query_system_information"}
    };

    private final GuardLiterals literals;

    GuardImports(GuardLiterals literals) {
        this.literals = literals;
    }

    /** C accessor returning the resolved function pointer ({@code umbra_api_<suffix>()}). */
    String ref(String apiName) {
        return "umbra_api_" + suffixOf(apiName) + "()";
    }

    private static String suffixOf(String apiName) {
        for (String[] api : APIS) {
            if (api[0].equals(apiName)) {
                return api[2];
            }
        }
        throw new IllegalStateException("API is not in the guard import table: " + apiName);
    }

    /** Emits the FNV-1a helper and one lazy hash-validated resolver per API. */
    void emit(StringBuilder out) {
        out.append("/* ---- P1-5.1: hash-resolved sensitive imports (LoadLibraryA +\n");
        out.append("   GetProcAddress on a decoded name; no plaintext API name in the PE) ---- */\n");
        out.append("static unsigned long umbra_fnv1a32(const char* text) {\n");
        out.append("    unsigned long hash = 2166136261UL;\n");
        out.append("    while (text[0] != 0) {\n");
        out.append("        hash ^= (unsigned long)(unsigned char)text[0];\n");
        out.append("        hash *= 16777619UL;\n");
        out.append("        text++;\n");
        out.append("    }\n");
        out.append("    return hash & 0xFFFFFFFFUL;\n");
        out.append("}\n\n");
        for (String[] api : APIS) {
            emitResolver(out, api[0], api[1], api[2]);
        }
    }

    private void emitResolver(StringBuilder out, String apiName, String module, String suffix) {
        int length = literals.length(apiName);
        out.append("static void* umbra_api_").append(suffix).append("(void) {\n");
        out.append("    static void* cached;\n");
        out.append("    char name[").append(length + 1).append("];\n");
        out.append("    if (cached == NULL) {\n");
        out.append("        umbra_unseal(").append(literals.sealed(apiName)).append(", ")
                .append(length).append(", name, 0x")
                .append(Integer.toHexString(literals.key(apiName))).append(");\n");
        out.append("        if (umbra_fnv1a32(name) == ")
                .append(GuardOptions.fnv1a32Hex(apiName)).append(") {\n");
        out.append("            HMODULE module = LoadLibraryA(").append(literals.ref(module))
                .append(");\n");
        out.append("            if (module != NULL) cached = (void*)GetProcAddress(module, name);\n");
        out.append("        }\n");
        out.append("        memset(name, 0, sizeof(name));\n");
        out.append("    }\n");
        out.append("    return cached;\n");
        out.append("}\n\n");
    }
}
