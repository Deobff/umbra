package io.umbra.core.jni.guard;

import io.umbra.core.jni.JniNames;

/**
 * Emits the platform-specific part of the Umbra 3.1 dynamic native guard.
 *
 * <p>Windows (primary):</p>
 * <ul>
 *   <li>quick checks (safe for the per-native-method tick): debugger/PEB via the
 *       classic block, timing-drift of the watchdog check calls, randomized
 *       guard-page/no-access scan of a few sampled pages of the guard image,
 *       randomized code-section byte sampling (offsets/bytes produced at
 *       protection time by {@link PeImage#codeSamples});</li>
 *   <li>deep checks (startup + every few watchdog passes only): remote-thread
 *       start addresses outside every loaded module, {@code MEM_PRIVATE}
 *       read+execute memory outside the image, unbacked/manually mapped module
 *       anomalies, opt-in external process-handle scan (level 3).</li>
 * </ul>
 *
 * <p>Linux (best effort): {@code /proc/self/status} {@code TracerPid},
 * {@code /proc/self/maps} Frida/gum markers, Frida environment markers are
 * covered by the Java template; a one-shot {@code ptrace(PTRACE_TRACEME)}
 * self-check is used at startup. Code-section byte sampling is PE-only because
 * the sampling offsets are RVAs; the file digest still covers the loaded
 * library. Other platforms keep the loadable portable stub.</p>
 */
final class GuardDynamicCode {

    private GuardDynamicCode() {
    }

    /** Emits feature defines, globals and the final quick/deep aggregators. */
    static void emitCommon(StringBuilder out, GuardFeatures features) {
        out.append("/* ---- Umbra 3.1 dynamic protection ---- */\n");
        define(out, "UMBRA_F_FRIDA", features.frida);
        define(out, "UMBRA_F_REMOTE_THREAD", features.remoteThread);
        define(out, "UMBRA_F_EXEC_MEMORY", features.execMemoryScan);
        define(out, "UMBRA_F_IMAGE_BP", features.imageBreakpoints);
        define(out, "UMBRA_F_CODE_SAMPLING", features.codeSampling);
        define(out, "UMBRA_F_MODULE", features.moduleIntegrity);
        define(out, "UMBRA_F_TIMING", features.timing);
        define(out, "UMBRA_F_HANDLE_DUMP", features.handleDump);
        define(out, "UMBRA_F_LINUX", features.linuxChecks);
        define(out, "UMBRA_F_TEST_HOOKS", features.testHooks);
        out.append("#define UMBRA_WATCHDOG_MS ").append(Math.max(0L, features.watchdogMs))
                .append("L\n");
        out.append("static volatile unsigned long g_check_counter;\n");
        out.append("static volatile long g_last_check_ms;\n");
        out.append("static volatile int g_sample_mismatch = -1;\n");
        out.append("static long g_interval_ms = UMBRA_WATCHDOG_MS;\n\n");
    }

    private static void define(StringBuilder out, String name, boolean value) {
        out.append("#define ").append(name).append(' ').append(value ? 1 : 0).append('\n');
    }

    /**
     * Emits the randomized code-section sample table.
     *
     * <p>The table is an <b>exported data symbol</b>
     * ({@code umbra_sample_table}) so the protection pass can fill in the
     * random RVAs/bytes after the single guard compilation by patching the
     * library file ({@link PeImage#withCodeSamples}). The compiled placeholder has
     * {@code count = 0}; until the table is patched the runtime check is a no-op,
     * so a failed patch can never produce a false positive.</p>
     */
    static void emitCodeSamples(StringBuilder out, int count, int window, long magic) {
        int size = Math.max(1, Math.min(64, window));
        int slots = Math.max(1, Math.min(64, count));
        out.append("#define UMBRA_SAMPLE_SLOTS ").append(slots).append('\n');
        out.append("#define UMBRA_SAMPLE_WINDOW ").append(size).append("\n");
        out.append("#define UMBRA_SAMPLE_MAGIC 0x").append(java.lang.Long.toHexString(magic))
                .append("ULL\n");
        out.append("typedef struct {\n");
        out.append("    unsigned long long magic;\n");
        out.append("    int count;\n");
        out.append("    int window;\n");
        out.append("    unsigned int rva[UMBRA_SAMPLE_SLOTS];\n");
        out.append("    unsigned char bytes[UMBRA_SAMPLE_SLOTS * UMBRA_SAMPLE_WINDOW];\n");
        out.append("} umbra_sample_table_t;\n");
        out.append("/* Located by its magic value and patched post-link; not exported. */\n");
        out.append("static volatile umbra_sample_table_t umbra_sample_table = {\n");
        out.append("    UMBRA_SAMPLE_MAGIC, 0, UMBRA_SAMPLE_WINDOW, {0}, {0}\n");
        out.append("};\n\n");
    }
    // ------------------------------------------------------------------
    // Windows
    // ------------------------------------------------------------------

    static void windows(StringBuilder out, GuardFeatures features) {
        out.append("static unsigned long umbra_lcg(unsigned long seed) {\n");
        out.append("    return seed * 1103515245UL + 12345UL;\n");
        out.append("}\n\n");
        out.append("static int umbra_self_image(unsigned char** base, unsigned long long* size) {\n");
        out.append("    HMODULE module = NULL;\n");
        out.append("    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS\n");
        out.append("            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,\n");
        out.append("            (LPCSTR)&umbra_frida_module, &module) == 0 || module == NULL) return 0;\n");
        out.append("    if (base != NULL) *base = (unsigned char*)module;\n");
        out.append("    if (size != NULL) {\n");
        out.append("        HANDLE snapshot = CreateToolhelp32Snapshot(\n");
        out.append("                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());\n");
        out.append("        MODULEENTRY32 entry;\n");
        out.append("        unsigned long long found = 0;\n");
        out.append("        if (snapshot != INVALID_HANDLE_VALUE) {\n");
        out.append("            memset(&entry, 0, sizeof(entry));\n");
        out.append("            entry.dwSize = sizeof(entry);\n");
        out.append("            if (Module32First(snapshot, &entry)) {\n");
        out.append("                do {\n");
        out.append("                    if ((HMODULE)entry.modBaseAddr == module) {\n");
        out.append("                        found = (unsigned long long)entry.modBaseSize;\n");
        out.append("                        break;\n");
        out.append("                    }\n");
        out.append("                } while (Module32Next(snapshot, &entry));\n");
        out.append("            }\n");
        out.append("            CloseHandle(snapshot);\n");
        out.append("        }\n");
        out.append("        *size = found;\n");
        out.append("    }\n");
        out.append("    return 1;\n");
        out.append("}\n\n");
        out.append("static unsigned long long umbra_read_u64(const void* address) {\n");
        out.append("    unsigned long long value = 0;\n");
        out.append("    memcpy(&value, address, sizeof(value));\n");
        out.append("    return value;\n");
        out.append("}\n\n");
        out.append("static unsigned int umbra_read_u32(const void* address) {\n");
        out.append("    unsigned int value = 0;\n");
        out.append("    memcpy(&value, address, sizeof(value));\n");
        out.append("    return value;\n");
        out.append("}\n\n");
        out.append("static unsigned short umbra_read_u16(const void* address) {\n");
        out.append("    unsigned short value = 0;\n");
        out.append("    memcpy(&value, address, sizeof(value));\n");
        out.append("    return value;\n");
        out.append("}\n\n");
        out.append("typedef unsigned long long (__stdcall *umbra_get_tick64)(void);\n");
        out.append("static unsigned long long umbra_now_ms(void) {\n");
        out.append("    static umbra_get_tick64 tick;\n");
        out.append("    if (tick == NULL) {\n");
        out.append("        tick = (umbra_get_tick64)GetProcAddress(GetModuleHandleA(\"kernel32.dll\"),\n");
        out.append("                \"GetTickCount64\");\n");
        out.append("    }\n");
        out.append("    if (tick != NULL) return tick();\n");
        out.append("    return (unsigned long long)GetTickCount();\n");
        out.append("}\n\n");
        out.append("static int umbra_timing_drift(void) {\n");
        out.append("    unsigned long long now;\n");
        out.append("    unsigned long long delta;\n");
        out.append("    unsigned long long threshold;\n");
        out.append("    if (!UMBRA_F_TIMING) return 0;\n");
        out.append("    now = umbra_now_ms();\n");
        out.append("    if (g_last_check_ms == 0) {\n");
        out.append("        g_last_check_ms = (long)now;\n");
        out.append("        return 0;\n");
        out.append("    }\n");
        out.append("    if (now < (unsigned long long)g_last_check_ms) {\n");
        out.append("        g_last_check_ms = (long)now;\n");
        out.append("        return 0;\n");
        out.append("    }\n");
        out.append("    delta = now - (unsigned long long)g_last_check_ms;\n");
        out.append("    g_last_check_ms = (long)now;\n");
        out.append("    threshold = (unsigned long long)g_interval_ms * 10ULL + 2000ULL;\n");
        out.append("    return delta > threshold ? 1 : 0;\n");
        out.append("}\n\n");
        out.append("static int umbra_code_samples_ok(void) {\n");
        out.append("    unsigned char* base = NULL;\n");
        out.append("    int i;\n");
        out.append("    int j;\n");
        out.append("    if (!UMBRA_F_CODE_SAMPLING || umbra_sample_table.count <= 0) return 1;\n");
        out.append("    if (!umbra_self_image(&base, NULL) || base == NULL) return 1;\n");
        out.append("    for (i = 0; i < umbra_sample_table.count; i++) {\n");
        out.append("        const unsigned char* actual;\n");
        out.append("        unsigned int rva = umbra_sample_table.rva[i];\n");
        out.append("        actual = base + rva;\n");
        out.append("        for (j = 0; j < umbra_sample_table.window; j++) {\n");
        out.append("            unsigned char expected = umbra_sample_table.bytes[i * umbra_sample_table.window + j];\n");
        out.append("            if (actual[j] != expected) {\n");
        out.append("                g_sample_mismatch = i;\n");
        out.append("                return 0;\n");
        out.append("            }\n");
        out.append("        }\n");
        out.append("    }\n");
        out.append("    return 1;\n");
        out.append("}\n\n");
        out.append("static int umbra_image_protection_ok(void) {\n");
        out.append("    unsigned char* base = NULL;\n");
        out.append("    unsigned long long size = 0;\n");
        out.append("    unsigned long state;\n");
        out.append("    int i;\n");
        out.append("    if (!UMBRA_F_IMAGE_BP) return 1;\n");
        out.append("    if (!umbra_self_image(&base, &size) || base == NULL || size < 0x2000ULL) return 1;\n");
        out.append("    state = (unsigned long)(g_check_counter * 2654435761UL + 1UL);\n");
        out.append("    for (i = 0; i < 8; i++) {\n");
        out.append("        unsigned long long pages = size / 4096ULL;\n");
        out.append("        unsigned long long offset;\n");
        out.append("        MEMORY_BASIC_INFORMATION info;\n");
        out.append("        state = umbra_lcg(state);\n");
        out.append("        if (pages <= 1ULL) break;\n");
        out.append("        offset = (unsigned long long)(state % (unsigned long)(pages - 1ULL)) * 4096ULL;\n");
        out.append("        if (VirtualQuery(base + offset, &info, sizeof(info)) == 0) continue;\n");
        out.append("        if (info.State == MEM_COMMIT && (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {\n");
        out.append("            return 0;\n");
        out.append("        }\n");
        out.append("    }\n");
        out.append("    return 1;\n");
        out.append("}\n\n");
        out.append("typedef long (__stdcall *umbra_nt_query_thread)(void*, int, void*, unsigned long, unsigned long*);\n");
        out.append("static umbra_nt_query_thread umbra_nt_query_thread_get(void) {\n");
        out.append("    static umbra_nt_query_thread query;\n");
        out.append("    if (query == NULL) {\n");
        out.append("        HMODULE ntdll = GetModuleHandleA(\"ntdll.dll\");\n");
        out.append("        if (ntdll != NULL) {\n");
        out.append("            query = (umbra_nt_query_thread)GetProcAddress(ntdll, \"NtQueryInformationThread\");\n");
        out.append("        }\n");
        out.append("    }\n");
        out.append("    return query;\n");
        out.append("}\n\n");
        out.append("static int umbra_addr_in_modules(unsigned long long address) {\n");
        out.append("    HANDLE snapshot = CreateToolhelp32Snapshot(\n");
        out.append("            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());\n");
        out.append("    MODULEENTRY32 entry;\n");
        out.append("    int found = 0;\n");
        out.append("    if (snapshot == INVALID_HANDLE_VALUE) return 1; /* cannot verify: never flag */\n");
        out.append("    memset(&entry, 0, sizeof(entry));\n");
        out.append("    entry.dwSize = sizeof(entry);\n");
        out.append("    if (Module32First(snapshot, &entry)) {\n");
        out.append("        do {\n");
        out.append("            unsigned long long start = (unsigned long long)entry.modBaseAddr;\n");
        out.append("            if (address >= start && address < start + (unsigned long long)entry.modBaseSize) {\n");
        out.append("                found = 1;\n");
        out.append("                break;\n");
        out.append("            }\n");
        out.append("        } while (Module32Next(snapshot, &entry));\n");
        out.append("    }\n");
        out.append("    CloseHandle(snapshot);\n");
        out.append("    return found;\n");
        out.append("}\n\n");
        out.append("static int umbra_remote_threads(void) {\n");
        out.append("    umbra_nt_query_thread query = umbra_nt_query_thread_get();\n");
        out.append("    HANDLE snapshot;\n");
        out.append("    THREADENTRY32 entry;\n");
        out.append("    int checked = 0;\n");
        out.append("    if (!UMBRA_F_REMOTE_THREAD || query == NULL) return 0;\n");
        out.append("    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);\n");
        out.append("    if (snapshot == INVALID_HANDLE_VALUE) return 0;\n");
        out.append("    memset(&entry, 0, sizeof(entry));\n");
        out.append("    entry.dwSize = sizeof(entry);\n");
        out.append("    if (Thread32First(snapshot, &entry)) {\n");
        out.append("        do {\n");
        out.append("            HANDLE thread;\n");
        out.append("            void* start = NULL;\n");
        out.append("            unsigned long returned = 0;\n");
        out.append("            if (entry.th32OwnerProcessID != GetCurrentProcessId()) continue;\n");
        out.append("            if (entry.th32ThreadID == GetCurrentThreadId()) continue;\n");
        out.append("            if (++checked > 512) break;\n");
        out.append("            thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION\n");
        out.append("                    | THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);\n");
        out.append("            if (thread == NULL) {\n");
        out.append("                thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE,\n");
        out.append("                        entry.th32ThreadID);\n");
        out.append("            }\n");
        out.append("            if (thread == NULL) continue;\n");
        out.append("            if (query((void*)thread, 9 /*ThreadQuerySetWin32StartAddress*/,\n");
        out.append("                    &start, sizeof(start), &returned) >= 0 && start != NULL\n");
        out.append("                    && !umbra_addr_in_modules((unsigned long long)start)) {\n");
        out.append("                CloseHandle(thread);\n");
        out.append("                CloseHandle(snapshot);\n");
        out.append("                return 1;\n");
        out.append("            }\n");
        out.append("            CloseHandle(thread);\n");
        out.append("        } while (Thread32Next(snapshot, &entry));\n");
        out.append("    }\n");
        out.append("    CloseHandle(snapshot);\n");
        out.append("    return 0;\n");
        out.append("}\n\n");
        out.append("static int umbra_exec_private(void) {\n");
        out.append("    unsigned char* address = (unsigned char*)0x10000;\n");
        out.append("#if defined(_M_X64) || defined(__x86_64__)\n");
        out.append("    unsigned char* limit = (unsigned char*)0x7FFFFFFF0000ULL;\n");
        out.append("#else\n");
        out.append("    unsigned char* limit = (unsigned char*)0x7FFF0000;\n");
        out.append("#endif\n");
        out.append("    long scanned = 0;\n");
        out.append("    if (!UMBRA_F_EXEC_MEMORY) return 0;\n");
        out.append("    while (address < limit && scanned < 500000) {\n");
        out.append("        MEMORY_BASIC_INFORMATION info;\n");
        out.append("        unsigned long long regionSize;\n");
        out.append("        if (VirtualQuery(address, &info, sizeof(info)) == 0) break;\n");
        out.append("        regionSize = (unsigned long long)info.RegionSize;\n");
        out.append("        if (regionSize == 0ULL) break;\n");
        out.append("        if (info.State == MEM_COMMIT && info.Type == MEM_PRIVATE) {\n");
        out.append("            unsigned long protect = (unsigned long)info.Protect;\n");
        out.append("            int executable = (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ\n");
        out.append("                    | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;\n");
        out.append("            int writable = (protect & (PAGE_EXECUTE_READWRITE\n");
        out.append("                    | PAGE_EXECUTE_WRITECOPY)) != 0;\n");
        out.append("            /* Read+execute private pages typically mean manually mapped code.\n");
        out.append("               RWX private pages are deliberately ignored: the JVM's JIT code\n");
        out.append("               cache is committed RWX, so flagging it would false-positive on\n");
        out.append("               every normal run. */\n");
        out.append("            if (executable && !writable && (protect & PAGE_GUARD) == 0) return 1;\n");
        out.append("        }\n");
        out.append("        address = (unsigned char*)info.BaseAddress + regionSize;\n");
        out.append("        scanned++;\n");
        out.append("    }\n");
        out.append("    return 0;\n");
        out.append("}\n\n");
        out.append("static int umbra_module_anomaly(void) {\n");
        out.append("    HANDLE snapshot = CreateToolhelp32Snapshot(\n");
        out.append("            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());\n");
        out.append("    MODULEENTRY32 entry;\n");
        out.append("    if (!UMBRA_F_MODULE || snapshot == INVALID_HANDLE_VALUE) return 0;\n");
        out.append("    memset(&entry, 0, sizeof(entry));\n");
        out.append("    entry.dwSize = sizeof(entry);\n");
        out.append("    if (Module32First(snapshot, &entry)) {\n");
        out.append("        do {\n");
        out.append("            unsigned char* base = (unsigned char*)entry.modBaseAddr;\n");
        out.append("            MEMORY_BASIC_INFORMATION info;\n");
        out.append("            if (base == NULL || entry.modBaseSize < 0x1000) continue;\n");
        out.append("            if (GetFileAttributesA(entry.szExePath) == INVALID_FILE_ATTRIBUTES) {\n");
        out.append("                CloseHandle(snapshot);\n");
        out.append("                return 1; /* unbacked module: no file behind the mapping */\n");
        out.append("            }\n");
        out.append("            if (VirtualQuery(base, &info, sizeof(info)) != 0 && info.Type == MEM_PRIVATE) {\n");
        out.append("                CloseHandle(snapshot);\n");
        out.append("                return 1; /* manually mapped module */\n");
        out.append("            }\n");
        out.append("            if (base[0] != 'M' || base[1] != 'Z') {\n");
        out.append("                CloseHandle(snapshot);\n");
        out.append("                return 1; /* executable mapping without a PE header */\n");
        out.append("            }\n");
        out.append("        } while (Module32Next(snapshot, &entry));\n");
        out.append("    }\n");
        out.append("    CloseHandle(snapshot);\n");
        out.append("    return 0;\n");
        out.append("}\n\n");
        out.append("typedef long (__stdcall *umbra_nt_query_system)(int, void*, unsigned long, unsigned long*);\n");
        out.append("static umbra_nt_query_system umbra_nt_query_system_get(void) {\n");
        out.append("    static umbra_nt_query_system query;\n");
        out.append("    if (query == NULL) {\n");
        out.append("        HMODULE ntdll = GetModuleHandleA(\"ntdll.dll\");\n");
        out.append("        if (ntdll != NULL) {\n");
        out.append("            query = (umbra_nt_query_system)GetProcAddress(ntdll,\n");
        out.append("                    \"NtQuerySystemInformation\");\n");
        out.append("        }\n");
        out.append("    }\n");
        out.append("    return query;\n");
        out.append("}\n\n");
        out.append("typedef long (__stdcall *umbra_nt_query_system)(int, void*, unsigned long, unsigned long*);\n");
        out.append("static int umbra_handle_dump(void) {\n");
        out.append("    umbra_nt_query_system system_query = umbra_nt_query_system_get();\n");
        out.append("    umbra_nt_query_process process_query = umbra_nt_query_process_get();\n");
        out.append("    void* buffer = NULL;\n");
        out.append("    unsigned long size = 1UL << 20;\n");
        out.append("    unsigned long needed = 0;\n");
        out.append("    int attempt;\n");
        out.append("    int detected = 0;\n");
        out.append("    unsigned long count = 0;\n");
        out.append("    unsigned char* entries;\n");
        out.append("    unsigned long index;\n");
        out.append("    int duplicates = 0;\n");
        out.append("    if (!UMBRA_F_HANDLE_DUMP || system_query == NULL || process_query == NULL) return 0;\n");
        out.append("    for (attempt = 0; attempt < 8; attempt++) {\n");
        out.append("        buffer = malloc(size);\n");
        out.append("        if (buffer == NULL) return 0;\n");
        out.append("        needed = 0;\n");
        out.append("        if (system_query(16 /*SystemHandleInformation*/, buffer, size, &needed) >= 0) break;\n");
        out.append("        free(buffer);\n");
        out.append("        buffer = NULL;\n");
        out.append("        size *= 2UL;\n");
        out.append("    }\n");
        out.append("    if (buffer == NULL) return 0;\n");
        out.append("    count = umbra_read_u32(buffer);\n");
        out.append("#if defined(_M_X64) || defined(__x86_64__)\n");
        out.append("    entries = (unsigned char*)buffer + 8;\n");
        out.append("#else\n");
        out.append("    entries = (unsigned char*)buffer + 4;\n");
        out.append("#endif\n");
        out.append("    for (index = 0; index < count && index < 200000UL; index++) {\n");
        out.append("#if defined(_M_X64) || defined(__x86_64__)\n");
        out.append("        unsigned char* item = entries + (unsigned long long)index * 24ULL;\n");
        out.append("        unsigned short ownerPid = umbra_read_u16(item + 0);\n");
        out.append("        unsigned char typeIndex = *(unsigned char*)(item + 4);\n");
        out.append("        unsigned short handleValue = umbra_read_u16(item + 6);\n");
        out.append("        unsigned long access = umbra_read_u32(item + 16);\n");
        out.append("        unsigned long targetPid;\n");
        out.append("#else\n");
        out.append("        unsigned char* item = entries + index * 16UL;\n");
        out.append("        unsigned short ownerPid = umbra_read_u16(item + 0);\n");
        out.append("        unsigned char typeIndex = *(unsigned char*)(item + 4);\n");
        out.append("        unsigned short handleValue = umbra_read_u16(item + 6);\n");
        out.append("        unsigned long access = umbra_read_u32(item + 12);\n");
        out.append("        unsigned long targetPid;\n");
        out.append("#endif\n");
        out.append("        HANDLE owner;\n");
        out.append("        HANDLE duplicate = NULL;\n");
        out.append("        unsigned long returned = 0;\n");
        out.append("        unsigned char processInfo[64];\n");
        out.append("        if (ownerPid == 0) continue;\n");
        out.append("        if ((unsigned long)ownerPid == (unsigned long)GetCurrentProcessId()) continue;\n");
        out.append("        if (typeIndex != 7) continue; /* Process object type index */\n");
        out.append("        if ((access & 0x0010UL /*PROCESS_VM_READ*/) == 0) continue;\n");
        out.append("        if (++duplicates > 32) break;\n");
        out.append("        owner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)ownerPid);\n");
        out.append("        if (owner == NULL) continue;\n");
        out.append("        if (DuplicateHandle(owner, (HANDLE)(ULONG_PTR)handleValue, GetCurrentProcess(),\n");
        out.append("                &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {\n");
        out.append("            memset(processInfo, 0, sizeof(processInfo));\n");
        out.append("            if (process_query(duplicate, 0 /*ProcessBasicInformation*/,\n");
        out.append("                    processInfo, sizeof(processInfo), &returned) >= 0) {\n");
        out.append("#if defined(_M_X64) || defined(__x86_64__)\n");
        out.append("                targetPid = (unsigned long)umbra_read_u64(processInfo + 32);\n");
        out.append("#else\n");
        out.append("                targetPid = umbra_read_u32(processInfo + 16);\n");
        out.append("#endif\n");
        out.append("                if (targetPid == (unsigned long)GetCurrentProcessId()) detected = 1;\n");
        out.append("            }\n");
        out.append("            CloseHandle(duplicate);\n");
        out.append("        }\n");
        out.append("        CloseHandle(owner);\n");
        out.append("        if (detected) break;\n");
        out.append("    }\n");
        out.append("    free(buffer);\n");
        out.append("    return detected;\n");
        out.append("}\n\n");
        out.append("static int umbra_detect_deep(void) {\n");
        out.append("    int mask = umbra_classic_marker();\n");
        out.append("    if (UMBRA_F_REMOTE_THREAD && umbra_remote_threads()) mask |= UMBRA_DETECT_REMOTE_THREAD;\n");
        out.append("    if (UMBRA_F_EXEC_MEMORY && umbra_exec_private()) mask |= UMBRA_DETECT_EXEC_MEMORY;\n");
        out.append("    if (UMBRA_F_MODULE && umbra_module_anomaly()) mask |= UMBRA_DETECT_MODULE;\n");
        out.append("    if (UMBRA_F_HANDLE_DUMP && umbra_handle_dump()) mask |= UMBRA_DETECT_HANDLE_DUMP;\n");
        out.append("    return mask;\n");
        out.append("}\n\n");
        out.append("static int umbra_detect_quick(void) {\n");
        out.append("    int mask = umbra_classic_quick();\n");
        out.append("    if (UMBRA_F_TIMING && umbra_timing_drift()) mask |= UMBRA_DETECT_TIMING;\n");
        out.append("    if (!umbra_code_samples_ok()) mask |= UMBRA_DETECT_CODE_SAMPLE;\n");
        out.append("    if (!umbra_image_protection_ok()) mask |= UMBRA_DETECT_IMAGE_BP;\n");
        out.append("    return mask;\n");
        out.append("}\n\n");
        out.append("static int umbra_detect_all(void) {\n");
        out.append("    return umbra_detect_quick() | umbra_detect_deep();\n");
        out.append("}\n\n");
        out.append("static void umbra_capture_handle_baseline(void) {\n");
        out.append("    g_last_check_ms = (long)umbra_now_ms();\n");
        out.append("    g_check_counter = 0;\n");
        out.append("}\n\n");
        if (features.testHooks && features.testHookClass != null) {
            appendWindowsTestHooks(out, features);
        }
    }

    private static void appendWindowsTestHooks(StringBuilder out, GuardFeatures features) {
        String prefix = JniNames.shortName(features.testHookClass, "");
        out.append("static jlong JNICALL umbra_hook_testAllocExec").append("(JNIEnv* env, jclass cls) {\n");
        out.append("    (void)env; (void)cls;\n");
        out.append("    return (jlong)(ULONG_PTR)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,\n");
        out.append("            PAGE_EXECUTE_READ);\n");
        out.append("}\n\n");
        out.append("static jint JNICALL umbra_hook_testRemoteThread").append("(JNIEnv* env, jclass cls) {\n");
        out.append("    unsigned char* code;\n");
        out.append("    HANDLE thread;\n");
        out.append("    (void)env; (void)cls;\n");
        out.append("    code = (unsigned char*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,\n");
        out.append("            PAGE_EXECUTE_READWRITE);\n");
        out.append("    if (code == NULL) return 0;\n");
        out.append("    /* Infinite-loop stub so the thread is still alive when the deep\n");
        out.append("       thread scan runs (a plain `ret` thread would exit immediately). */\n");
        out.append("    code[0] = 0x31; code[1] = 0xC0;   /* xor eax, eax */\n");
        out.append("    code[2] = 0xFF; code[3] = 0xC8;   /* dec eax */\n");
        out.append("    code[4] = 0x75; code[5] = 0xFD;   /* jnz -3 */\n");
        out.append("    code[6] = 0xC3;                   /* ret */\n");
        out.append("    thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)code, NULL, 0, NULL);\n");
        out.append("    if (thread == NULL) return 0;\n");
        out.append("    Sleep(50);\n");
        out.append("    CloseHandle(thread);\n");
        out.append("    return 1;\n");
        out.append("}\n\n");
        out.append("static jint JNICALL umbra_hook_testPatchSample").append("(JNIEnv* env, jclass cls) {\n");
        out.append("    (void)env; (void)cls;\n");
        out.append("    /* Flips one expected byte of the verified sample table: from the\n");
        out.append("       verifier's point of view this is exactly a patched code byte, without\n");
        out.append("       corrupting code that is executed later in a test process. */\n");
        out.append("    if (umbra_sample_table.count > 0) umbra_sample_table.bytes[0] ^= 0xFF;\n");
        out.append("    return 1;\n");
        out.append("}\n\n");
        out.append("static jint JNICALL umbra_hook_testAgeTiming").append("(JNIEnv* env, jclass cls, jlong milliseconds) {\n");
        out.append("    (void)env; (void)cls;\n");
        out.append("    g_last_check_ms -= (long)milliseconds;\n");
        out.append("    return 1;\n");
        out.append("}\n\n");
        out.append("static jint JNICALL umbra_hook_testSampleMismatch").append("(JNIEnv* env, jclass cls) {\n");
        out.append("    (void)env; (void)cls;\n");
        out.append("    return (jint)g_sample_mismatch;\n");
        out.append("}\n\n");
        out.append("static jint JNICALL umbra_hook_testSampleCount").append("(JNIEnv* env, jclass cls) {\n");
        out.append("    (void)env; (void)cls;\n");
        out.append("    return (jint)umbra_sample_table.count;\n");
        out.append("}\n\n");
        out.append("static jint JNICALL umbra_hook_testReadByte").append("(JNIEnv* env, jclass cls, jint rva) {\n");
        out.append("    unsigned char* base = NULL;\n");
        out.append("    (void)env; (void)cls;\n");
        out.append("    if (!umbra_self_image(&base, NULL) || base == NULL) return -1;\n");
        out.append("    return (jint)base[(unsigned int)rva];\n");
        out.append("}\n\n");
        out.append("static jint JNICALL umbra_hook_testQuick").append("(JNIEnv* env, jclass cls) {\n");
        out.append("    (void)env; (void)cls;\n");
        out.append("    return (jint)umbra_detect_quick();\n");
        out.append("}\n\n");
        out.append("static jint JNICALL umbra_hook_testDeep").append("(JNIEnv* env, jclass cls) {\n");
        out.append("    (void)env; (void)cls;\n");
        out.append("    return (jint)umbra_detect_deep();\n");
        out.append("}\n\n");
        out.append("static jint JNICALL umbra_hook_testExecScan").append("(JNIEnv* env, jclass cls) {\n");
        out.append("    (void)env; (void)cls;\n");
        out.append("    return (jint)(umbra_exec_private() ? 1 : 0);\n");
        out.append("}\n\n");
        out.append("static jint JNICALL umbra_hook_testRemoteScan").append("(JNIEnv* env, jclass cls) {\n");
        out.append("    (void)env; (void)cls;\n");
        out.append("    return (jint)(umbra_remote_threads() ? 1 : 0);\n");
        out.append("}\n\n");
        out.append("/* test hook prefix: ").append(prefix).append(" */\n");
    }

    // ------------------------------------------------------------------
    // Linux (best effort; never compiled on Windows)
    // ------------------------------------------------------------------

    static void linux(StringBuilder out, GuardFeatures features) {
        out.append("static int umbra_read_text_file(const char* path, char* buffer, int capacity) {\n");
        out.append("    FILE* file;\n");
        out.append("    int length = 0;\n");
        out.append("    int read;\n");
        out.append("    if (path == NULL || buffer == NULL || capacity <= 1) return 0;\n");
        out.append("    file = fopen(path, \"rb\");\n");
        out.append("    if (file == NULL) return 0;\n");
        out.append("    read = (int)fread(buffer, 1, (size_t)(capacity - 1), file);\n");
        out.append("    fclose(file);\n");
        out.append("    length = read < 0 ? 0 : read;\n");
        out.append("    buffer[length] = 0;\n");
        out.append("    return length > 0;\n");
        out.append("}\n\n");
        out.append("static int umbra_linux_tracer(void) {\n");
        out.append("    char buffer[8192];\n");
        out.append("    char* marker;\n");
        out.append("    if (!umbra_read_text_file(\"/proc/self/status\", buffer, (int)sizeof(buffer))) return 0;\n");
        out.append("    marker = strstr(buffer, \"TracerPid:\");\n");
        out.append("    if (marker == NULL) return 0;\n");
        out.append("    marker += 10;\n");
        out.append("    while (*marker == ' ' || *marker == '\\t') marker++;\n");
        out.append("    return *marker != '0' ? 1 : 0;\n");
        out.append("}\n\n");
        out.append("static int umbra_linux_maps(void) {\n");
        out.append("    FILE* file = fopen(\"/proc/self/maps\", \"r\");\n");
        out.append("    char line[1024];\n");
        out.append("    if (file == NULL) return 0;\n");
        out.append("    while (fgets(line, (int)sizeof(line), file) != NULL) {\n");
        out.append("        size_t i;\n");
        out.append("        for (i = 0; line[i] != 0; i++) {\n");
        out.append("            if (line[i] >= 'A' && line[i] <= 'Z') line[i] = (char)(line[i] - 'A' + 'a');\n");
        out.append("        }\n");
        out.append("        if (strstr(line, \"frida\") != NULL || strstr(line, \"gum-js\") != NULL\n");
        out.append("                || strstr(line, \"gum-\") != NULL) {\n");
        out.append("            fclose(file);\n");
        out.append("            return 1;\n");
        out.append("        }\n");
        out.append("    }\n");
        out.append("    fclose(file);\n");
        out.append("    return 0;\n");
        out.append("}\n\n");
        out.append("static int umbra_linux_ptrace(void) {\n");
        out.append("    if (!UMBRA_F_LINUX) return 0;\n");
        out.append("    /* One-shot self-check: fails with EPERM when another process is already\n");
        out.append("       tracing us. Debuggers that attach later are caught by TracerPid. */\n");
        out.append("    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {\n");
        out.append("        return errno == EPERM ? 1 : 0;\n");
        out.append("    }\n");
        out.append("    return 0;\n");
        out.append("}\n\n");
        out.append("static int umbra_classic_marker(void) {\n");
        out.append("    int mask = 0;\n");
        out.append("    if (umbra_linux_tracer()) mask |= UMBRA_DETECT_JDWP;\n");
        out.append("    if (UMBRA_F_FRIDA && umbra_linux_maps()) mask |= UMBRA_DETECT_FRIDA_MODULE;\n");
        out.append("    if (umbra_linux_ptrace()) mask |= UMBRA_DETECT_LINUX;\n");
        out.append("    return mask;\n");
        out.append("}\n\n");
        out.append("static int umbra_classic_quick(void) {\n");
        out.append("    return UMBRA_F_LINUX ? umbra_linux_tracer() : 0;\n");
        out.append("}\n\n");
        out.append("static int umbra_detect_quick(void) {\n");
        out.append("    return umbra_classic_quick();\n");
        out.append("}\n\n");
        out.append("static int umbra_detect_deep(void) {\n");
        out.append("    return umbra_classic_marker();\n");
        out.append("}\n\n");
        out.append("static int umbra_detect_all(void) {\n");
        out.append("    return umbra_classic_marker();\n");
        out.append("}\n\n");
        out.append("static unsigned long long umbra_now_ms(void) {\n");
        out.append("    struct timespec now;\n");
        out.append("    clock_gettime(CLOCK_MONOTONIC, &now);\n");
        out.append("    return (unsigned long long)now.tv_sec * 1000ULL\n");
        out.append("            + (unsigned long long)(now.tv_nsec / 1000000L);\n");
        out.append("}\n\n");
        out.append("static void umbra_capture_handle_baseline(void) {\n");
        out.append("    g_last_check_ms = (long)umbra_now_ms();\n");
        out.append("    g_check_counter = 0;\n");
        out.append("}\n\n");
        out.append("static int umbra_self_module_path(char* buffer, unsigned long capacity) {\n");
        out.append("    Dl_info info;\n");
        out.append("    if (buffer == NULL || capacity == 0) return 0;\n");
        out.append("    memset(&info, 0, sizeof(info));\n");
        out.append("    if (dladdr((void*)&umbra_self_module_path, &info) == 0 || info.dli_fname == NULL) {\n");
        out.append("        return 0;\n");
        out.append("    }\n");
        out.append("    strncpy(buffer, info.dli_fname, (size_t)(capacity - 1));\n");
        out.append("    buffer[capacity - 1] = 0;\n");
        out.append("    return 1;\n");
        out.append("}\n\n");
        if (features.testHooks && features.testHookClass != null) {
            out.append("/* Linux test hooks are not emitted: dynamic simulations require Windows. */\n");
        }
    }

    // ------------------------------------------------------------------
    // Other platforms: keep the library loadable, no dynamic checks
    // ------------------------------------------------------------------

    static void portable(StringBuilder out) {
        out.append("static int umbra_classic_marker(void) { return 0; }\n");
        out.append("static int umbra_classic_quick(void) { return 0; }\n");
        out.append("static int umbra_detect_all(void) { return 0; }\n");
        out.append("static int umbra_detect_quick(void) { return 0; }\n");
        out.append("static int umbra_detect_deep(void) { return 0; }\n");
        out.append("static unsigned long long umbra_now_ms(void) { return 0; }\n");
        out.append("static void umbra_capture_handle_baseline(void) { g_last_check_ms = 0; g_check_counter = 0; }\n");
        out.append("static int umbra_self_module_path(char* buffer, unsigned long capacity) {\n");
        out.append("    if (capacity > 0) buffer[0] = 0;\n");
        out.append("    return 0;\n");
        out.append("}\n");
    }
}
