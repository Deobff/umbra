package io.umbra.core.jni;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Emits the C source for one native library.
 *
 * <p>The generated translation unit contains:</p>
 * <ul>
 *   <li>a small runtime: lazily resolved {@code jclass} table, lazily resolved
 *       {@code jmethodID}/{@code jfieldID} slot table, Java-compatible
 *       arithmetic/compare helpers and array/reflection helpers,</li>
 *   <li>one C function per transpiled Java method. Every method is a stack
 *       machine over {@code jvalue} slots that mirror JVM operand-stack slots
 *       (long/double take two slots),</li>
 *   <li>{@code Java_<mangled>} exports for every method (short and long form;
 *       the JVM binds native methods through these symbols, so no
 *       {@code RegisterNatives} call is needed), and</li>
 *   <li>a minimal {@code JNI_OnLoad} that only reports the supported JNI
 *       version.</li>
 * </ul>
 */
public final class CGenerator {

    /** Runtime classes that generated code and helpers need; indices are stable. */
    static final String[] RUNTIME_CLASSES = {
            "java/lang/NullPointerException",   // 0
            "java/lang/ClassCastException",     // 1
            "java/lang/ArithmeticException",    // 2
            "java/lang/reflect/Array",          // 3
            "java/lang/Integer",                // 4
            "java/lang/Long",                   // 5
            "java/lang/Float",                  // 6
            "java/lang/Double",                 // 7
            "java/lang/Byte",                   // 8
            "java/lang/Character",              // 9
            "java/lang/Short",                  // 10
            "java/lang/Boolean"                 // 11
    };

    /** Macro suffix used by the runtime C code for every runtime class index. */
    private static final String[] RUNTIME_MACROS = {
            "NPE", "CLASSCASTEXCEPTION", "ARITHMETICEXCEPTION", "ARRAY",
            "INTEGER", "LONG", "FLOAT", "DOUBLE", "BYTE", "CHARACTER", "SHORT", "BOOLEAN"
    };

    /** One translated method (C statements only; the wrapper is emitted by {@link #finish}). */
    public static final class MethodC {
        public String functionName;
        public String owner;
        public String name;
        public String descriptor;
        public boolean staticMethod;
        public String cReturn;
        public List<String> cArguments = new ArrayList<String>();
        public String body;
        public int stackSlots;
        public int localSlots;
    }

    private final Map<String, Integer> classIndex = new LinkedHashMap<String, Integer>();
    private final List<String> classNames = new ArrayList<String>();
    private final Map<String, Integer> stringIndex = new LinkedHashMap<String, Integer>();
    private final List<String> strings = new ArrayList<String>();
    private final Map<String, Integer> literalIndex = new LinkedHashMap<String, Integer>();
    private final List<String> literals = new ArrayList<String>();
    private final List<MethodC> methods = new ArrayList<MethodC>();
    private int nextIdSite;

    /**
     * Key of the encrypted name/descriptor pool. The generated translation unit
     * carries the same constant, so the pool is always self-consistent; the pass
     * randomizes it per build so two builds of the same source do not share it.
     */
    private long literalKey = 0x6A09E667F3BCC908L;

    /** Length budget of one decoded name/descriptor literal (names and descriptors are short). */
    private static final int LITERAL_MAX = 256;

    // ---- anti-dump configuration (set by NativeCodePass before finish()) ----
    private String antiDumpLoader;
    private long antiDumpKey;
    private boolean antiBackfill;
    private int bindingCount;

    /** Internal name of the injected loader that owns the registration entry point. */
    private String registerLoader;

    /** Name of the JNI method the injected loader calls after {@code System.load}. */
    public static final String CHALLENGE_METHOD = "verifyChallenge";
    /** Descriptor of the challenge method (int nonce -> long response). */
    public static final String CHALLENGE_DESCRIPTOR = "(I)J";
    /** Name of the registration entry point the loader declares as a native method. */
    public static final String REGISTER_METHOD = "register";
    /** Descriptor of the registration entry point (class id + owning Class). */
    public static final String REGISTER_DESCRIPTOR = "(ILjava/lang/Class;)I";

    /**
     * Enables the anti-dump layer of the generated library.
     *
     * @param loaderInternalName internal name of the injected loader class
     * @param key                per-program secret shared with the Java loader
     * @param backfill           emit and verify the native registration-table check
     */
    public void configureAntiDump(String loaderInternalName, long key, boolean backfill) {
        this.antiDumpLoader = loaderInternalName;
        this.antiDumpKey = key;
        this.antiBackfill = backfill;
    }

    /**
     * Sets the loader that receives the {@code register} and {@code verifyChallenge}
     * natives from {@code JNI_OnLoad}.
     *
     * <p>Business classes are not registered from {@code JNI_OnLoad}: doing so
     * {@code FindClass}es them and therefore runs their static initializers before
     * the program asks for them. Instead every owning class calls back into the
     * loader from its own {@code <clinit>}, which is the moment the class would
     * have initialized anyway.</p>
     *
     * @param loaderInternalName internal name of the injected loader class
     */
    public void configureRegistration(String loaderInternalName) {
        this.registerLoader = loaderInternalName;
    }

    /** Number of method bindings the native registration table covers (0 when off). */
    public int bindingCount() {
        return bindingCount;
    }

    public CGenerator() {
        for (int i = 0; i < RUNTIME_CLASSES.length; i++) {
            classIndex.put(RUNTIME_CLASSES[i], Integer.valueOf(i));
            classNames.add(RUNTIME_CLASSES[i]);
        }
    }

    /** Interns a {@code FindClass} argument (internal name or array descriptor). */
    int classRef(String name) {
        Integer existing = classIndex.get(name);
        if (existing != null) {
            return existing.intValue();
        }
        int index = classNames.size();
        classIndex.put(name, Integer.valueOf(index));
        classNames.add(name);
        return index;
    }

    /** Interns a string constant; returns the index of its {@code umbra_str_N} array. */
    int stringRef(String value) {
        Integer existing = stringIndex.get(value);
        if (existing != null) {
            return existing.intValue();
        }
        int index = strings.size();
        stringIndex.put(value, Integer.valueOf(index));
        strings.add(value);
        return index;
    }

    /**
     * Interns a name or descriptor into the encrypted literal pool.
     *
     * <p>Class names, member names and descriptors are the only plaintext in a
     * native image that still maps the Java side onto the C functions; keeping
     * them as readable C string literals let {@code strings} rebuild that map
     * without touching the class files. They are therefore stored XOR-encrypted
     * and decoded on use by {@code umbra_l}.</p>
     *
     * @param value name or descriptor
     * @return index passed to {@code umbra_l}
     */
    int literalRef(String value) {
        Integer existing = literalIndex.get(value);
        if (existing != null) {
            return existing.intValue();
        }
        int index = literals.size();
        literalIndex.put(value, Integer.valueOf(index));
        literals.add(value);
        return index;
    }

    /** Sets the per-build key of the encrypted literal pool. */
    public void configureLiteralKey(long key) {
        this.literalKey = key;
    }

    /** Allocates one lazily resolved method/field id slot. */
    int newIdSite() {
        return nextIdSite++;
    }

    public void addMethod(MethodC method) {
        methods.add(method);
    }

    int methodCount() {
        return methods.size();
    }

    /** Assembles the complete translation unit. */
    public String finish() {
        StringBuilder out = new StringBuilder(1 << 16);
        out.append("#include <jni.h>\n");
        out.append("#include <string.h>\n");
        out.append("#include <stdlib.h>\n");
        out.append("#include <stdio.h>\n");
        out.append("#ifdef _WIN32\n");
        out.append("#include <windows.h>\n");
        out.append("#endif\n\n");
        // Java-compatible unsigned arithmetic helpers (JNI headers do not define
        // fixed-width unsigned types on every platform).
        out.append("typedef unsigned int umbra_u32;\n");
        out.append("typedef unsigned long long umbra_u64;\n\n");
        // A failed JNI_OnLoad only surfaces as "unsupported JNI version" from the
        // VM, so each refusal point reports itself when UMBRA_NATIVE_DEBUG is set.
        out.append("static int umbra_trace(const char* what, int value) {\n");
        out.append("    if (getenv(\"UMBRA_NATIVE_DEBUG\") != NULL) {\n");
        out.append("        fprintf(stderr, \"[umbra-native] %s=%d\\n\", what, value);\n");
        out.append("    }\n");
        out.append("    return value;\n");
        out.append("}\n\n");
        for (int i = 0; i < RUNTIME_CLASSES.length; i++) {
            out.append("#define UMBRA_C_").append(RUNTIME_MACROS[i])
                    .append(' ').append(i).append('\n');
        }
        out.append("#define UMBRA_CLASS_COUNT ").append(classNames.size()).append('\n');
        out.append("#define UMBRA_ID_COUNT ").append(Math.max(1, nextIdSite)).append("\n\n");
        out.append(RUNTIME_C);
        out.append('\n');
        int[] classNameLiterals = new int[classNames.size()];
        for (int i = 0; i < classNames.size(); i++) {
            classNameLiterals[i] = literalRef(classNames.get(i));
        }
        // The pool is emitted with a fixed count, so every literal used by the
        // registration and JNI_OnLoad emitters has to be interned first.
        for (MethodC method : methods) {
            literalRef(method.name);
            literalRef(method.descriptor);
        }
        if (registerLoader != null) {
            literalRef(registerLoader);
            literalRef(REGISTER_METHOD);
            literalRef(REGISTER_DESCRIPTOR);
            if (antiBackfill) {
                literalRef(CHALLENGE_METHOD);
                literalRef(CHALLENGE_DESCRIPTOR);
            }
        }
        appendLiteralPool(out);
        appendClassTable(out, classNameLiterals);
        appendIdTable(out);
        appendRuntimeDefinitions(out);
        out.append(GUARD_TICK_C);
        appendStringConstants(out);
        for (MethodC method : methods) {
            appendMethod(out, method);
        }
        List<String> bindings = appendNativeBindings(out);
        appendAntiDump(out, bindings);
        appendOnLoad(out);
        return out.toString();
    }

    private void appendClassTable(StringBuilder out, int[] classNameLiterals) {
        out.append("static jclass umbra_classes[UMBRA_CLASS_COUNT];\n");
        out.append("static const int umbra_class_lit[UMBRA_CLASS_COUNT] = {\n");
        for (int i = 0; i < classNameLiterals.length; i++) {
            out.append("    ").append(classNameLiterals[i]).append(",\n");
        }
        out.append("};\n\n");
    }

    private void appendIdTable(StringBuilder out) {
        out.append("static UMBRA_ID umbra_ids[UMBRA_ID_COUNT];\n\n");
    }

    /**
     * Emits the encrypted name/descriptor pool and its decoder.
     *
     * <p>Every class name, member name and descriptor the generated code needs is
     * stored XOR-encrypted with a per-build key and decoded on use by
     * {@code umbra_l}. This is what keeps {@code strings} from rebuilding the
     * Java-to-native map out of a dumped library.</p>
     */
    private void appendLiteralPool(StringBuilder out) {
        ByteArrayOutputStream pool = new ByteArrayOutputStream();
        StringBuilder offsets = new StringBuilder();
        StringBuilder lengths = new StringBuilder();
        for (int i = 0; i < literals.size(); i++) {
            byte[] plain = modifiedUtf8(literals.get(i));
            if (plain.length >= LITERAL_MAX) {
                throw new IllegalStateException("native literal " + i + " is " + plain.length
                        + " bytes, above the " + LITERAL_MAX + "-byte pool limit");
            }
            if (i > 0) {
                offsets.append(", ");
                lengths.append(", ");
            }
            offsets.append(pool.size());
            lengths.append(plain.length);
            byte[] cipher = encryptLiteral(literalKey, i, plain);
            pool.write(cipher, 0, cipher.length);
        }
        byte[] bytes = pool.toByteArray();
        out.append("#define UMBRA_LIT_KEY ").append(hex64(literalKey)).append("ULL\n");
        out.append("#define UMBRA_LIT_MAX ").append(LITERAL_MAX).append('\n');
        out.append("#define UMBRA_LIT_COUNT ").append(literals.size()).append("\n\n");
        out.append("static const unsigned char umbra_lit_bytes[] = {\n");
        for (int i = 0; i < bytes.length; i++) {
            if (i % 16 == 0) {
                out.append("   ");
            }
            out.append(' ').append("0x")
                    .append(String.format(java.util.Locale.ROOT, "%02x",
                            Integer.valueOf(bytes[i] & 0xFF)))
                    .append(',');
            if (i % 16 == 15) {
                out.append('\n');
            }
        }
        if (bytes.length % 16 != 0) {
            out.append('\n');
        }
        out.append("};\n");
        out.append("static const int umbra_lit_off[UMBRA_LIT_COUNT] = { ")
                .append(offsets).append(" };\n");
        out.append("static const int umbra_lit_len[UMBRA_LIT_COUNT] = { ")
                .append(lengths).append(" };\n\n");
        out.append("static char umbra_boot_name[UMBRA_LIT_MAX];\n");
        out.append("static char umbra_boot_reg[UMBRA_LIT_MAX];\n");
        out.append("static char umbra_boot_reg_sig[UMBRA_LIT_MAX];\n");
        out.append("static char umbra_boot_ch[UMBRA_LIT_MAX];\n");
        out.append("static char umbra_boot_ch_sig[UMBRA_LIT_MAX];\n\n");
        // Decodes into a caller-provided buffer. There is deliberately no shared
        // decode buffer: the translated methods run on application threads, and a
        // shared scratch area would let one thread overwrite a name another thread
        // is still passing to a JNI lookup (which showed up as NoSuchFieldError and
        // as JVM crashes on a NULL method id).
        out.append("static void umbra_lit_copy(int index, char* out) {\n");
        out.append("    umbra_u64 state;\n");
        out.append("    int len;\n");
        out.append("    int i;\n");
        out.append("    if (index < 0 || index >= UMBRA_LIT_COUNT) {\n");
        out.append("        out[0] = 0;\n");
        out.append("        return;\n");
        out.append("    }\n");
        out.append("    len = umbra_lit_len[index];\n");
        out.append("    if (len > UMBRA_LIT_MAX - 1) {\n");
        out.append("        len = UMBRA_LIT_MAX - 1;\n");
        out.append("    }\n");
        out.append("    state = UMBRA_LIT_KEY ^ (umbra_u64)(unsigned int)index;\n");
        out.append("    for (i = 0; i < len; i++) {\n");
        out.append("        state = state * 6364136223846793005ULL + 1442695040888963407ULL;\n");
        out.append("        out[i] = (char)(umbra_lit_bytes[umbra_lit_off[index] + i]");
        out.append(" ^ (unsigned char)(state >> 33));\n");
        out.append("    }\n");
        out.append("    out[len] = 0;\n");
        out.append("}\n\n");
    }

    /** Mirror of the {@code umbra_lit_copy} keystream: XOR of the modified UTF-8 bytes. */
    static byte[] encryptLiteral(long key, int index, byte[] plain) {
        byte[] out = new byte[plain.length];
        long state = key ^ (long) index;
        for (int i = 0; i < plain.length; i++) {
            state = state * 6364136223846793005L + 1442695040888963407L;
            out[i] = (byte) (plain[i] ^ (byte) (state >>> 33));
        }
        return out;
    }

    private void appendRuntimeDefinitions(StringBuilder out) {
        out.append("static jclass umbra_class(JNIEnv* env, jint index) {\n");
        out.append("    jclass cached;\n");
        out.append("    char _name[UMBRA_LIT_MAX];\n");
        out.append("    if (index < 0 || index >= UMBRA_CLASS_COUNT) {\n");
        out.append("        return NULL;\n");
        out.append("    }\n");
        out.append("    cached = umbra_classes[index];\n");
        out.append("    if (cached == NULL) {\n");
        out.append("        jclass found;\n");
        out.append("        umbra_lit_copy(umbra_class_lit[index], _name);\n");
        out.append("        found = (*env)->FindClass(env, _name);\n");
        out.append("        if (found == NULL) {\n");
        out.append("            return NULL;\n");
        out.append("        }\n");
        out.append("        cached = (jclass)(*env)->NewGlobalRef(env, found);\n");
        out.append("        (*env)->DeleteLocalRef(env, found);\n");
        out.append("        if (cached == NULL) {\n");
        out.append("            return NULL;\n");
        out.append("        }\n");
        out.append("        umbra_classes[index] = cached;\n");
        out.append("    }\n");
        out.append("    return cached;\n");
        out.append("}\n\n");
        out.append(PRIMITIVE_CLASS_C);
        out.append('\n');
    }

    private void appendStringConstants(StringBuilder out) {
        for (int i = 0; i < strings.size(); i++) {
            out.append("static const char umbra_str_").append(i).append("[] = ")
                    .append(cString(strings.get(i))).append(";\n");
        }
        if (!strings.isEmpty()) {
            out.append('\n');
        }
    }

    private void appendMethod(StringBuilder out, MethodC method) {
        out.append("/* ").append(method.owner).append('#').append(method.name)
                .append(method.descriptor).append(" */\n");
        out.append("static ").append(method.cReturn).append(" JNICALL ").append(method.functionName)
                .append("(JNIEnv* env, ").append(method.staticMethod ? "jclass _cls" : "jobject _self");
        for (int i = 0; i < method.cArguments.size(); i++) {
            out.append(", ").append(method.cArguments.get(i)).append(" _a").append(i);
        }
        out.append(") {\n");
        out.append("    jvalue st[").append(Math.max(8, method.stackSlots + 8)).append("];\n");
        out.append("    jvalue lc[").append(Math.max(4, method.localSlots + 2)).append("];\n");
        out.append("    int sp = 0;\n");
        out.append("    jthrowable umbra_ex = NULL;\n");
        out.append("    (void)st; (void)lc; (void)sp; (void)umbra_ex; (void)env;\n");
        if (method.staticMethod) {
            out.append("    (void)_cls;\n");
        } else {
            out.append("    (void)_self;\n");
            out.append("    lc[0].l = (jobject)_self;\n");
        }
        out.append("    (void)lc;\n");
        // Optional guard tick: the anti-debug guard library (when present) is
        // discovered through the "umbra.guard.path" system property that the
        // guard template sets before the native library is loaded. Without a
        // guard this is a single NULL check per native call.
        out.append("    if (umbra_guard_tick_fn != NULL) {\n");
        out.append("        if (umbra_guard_tick_fn() != 0) {\n");
        out.append("            ").append(defaultReturn(method.cReturn)).append("\n");
        out.append("        }\n");
        out.append("    }\n");
        out.append(method.body);
        out.append("    ").append(defaultReturn(method.cReturn)).append('\n');
        out.append("}\n\n");
    }

    /**
     * Emits the JNI wrappers, the per-owning-class registration functions and the
     * dispatcher behind {@code loader.register(classId, Class)}.
     *
     * <p>Nothing here is exported. The wrappers are {@code static} functions whose
     * addresses are registered with {@code RegisterNatives}, so the PE export
     * table exposes no {@code Java_*} symbol and a dumped library no longer
     * carries a ready-made Java-to-native map. Because registration is keyed by
     * (name, descriptor) pairs instead of mangled symbol lookup, overloads are
     * unambiguous and the old short/long export rules disappear.</p>
     *
     * @return {@code name + descriptor} of every binding, in registration order
     */
    private List<String> appendNativeBindings(StringBuilder out) {
        Map<String, List<Integer>> byOwner = new LinkedHashMap<String, List<Integer>>();
        for (int i = 0; i < methods.size(); i++) {
            MethodC method = methods.get(i);
            List<Integer> indexes = byOwner.get(method.owner);
            if (indexes == null) {
                indexes = new ArrayList<Integer>();
                byOwner.put(method.owner, indexes);
            }
            indexes.add(Integer.valueOf(i));
        }
        List<String> bindings = new ArrayList<String>();
        for (int i = 0; i < methods.size(); i++) {
            appendWrapper(out, "umbra_native_" + i, methods.get(i));
            bindings.add(methods.get(i).name + methods.get(i).descriptor);
        }
        if (!methods.isEmpty()) {
            out.append('\n');
        }
        out.append("/* ---- Umbra native registration ---- */\n");
        out.append("#define UMBRA_OWNER_COUNT ").append(byOwner.size()).append("\n\n");
        int ownerCount = 0;
        for (Map.Entry<String, List<Integer>> entry : byOwner.entrySet()) {
            List<Integer> indexes = entry.getValue();
            out.append("static char umbra_r").append(ownerCount).append("_names[")
                    .append(indexes.size()).append("][UMBRA_LIT_MAX];\n");
            out.append("static char umbra_r").append(ownerCount).append("_sigs[")
                    .append(indexes.size()).append("][UMBRA_LIT_MAX];\n");
            out.append("static int umbra_bind_").append(ownerCount)
                    .append("(JNIEnv* env, jclass cls) {\n");
            out.append("    JNINativeMethod m[").append(indexes.size()).append("];\n");
            for (int k = 0; k < indexes.size(); k++) {
                int index = indexes.get(k).intValue();
                MethodC method = methods.get(index);
                out.append("    umbra_lit_copy(").append(literalRef(method.name))
                        .append(", umbra_r").append(ownerCount).append("_names[").append(k)
                        .append("]);\n");
                out.append("    umbra_lit_copy(").append(literalRef(method.descriptor))
                        .append(", umbra_r").append(ownerCount).append("_sigs[").append(k)
                        .append("]);\n");
                out.append("    m[").append(k).append("].name = umbra_r").append(ownerCount)
                        .append("_names[").append(k).append("];\n");
                out.append("    m[").append(k).append("].signature = umbra_r").append(ownerCount)
                        .append("_sigs[").append(k).append("];\n");
                out.append("    m[").append(k).append("].fnPtr = (void*)(&umbra_native_")
                        .append(index).append(");\n");
            }
            out.append("    return (*env)->RegisterNatives(env, cls, m, ")
                    .append(indexes.size()).append(");\n");
            out.append("}\n\n");
            ownerCount++;
        }
        out.append("static int (*umbra_registrars[UMBRA_OWNER_COUNT])(JNIEnv*, jclass) = {\n");
        for (int i = 0; i < ownerCount; i++) {
            out.append("    umbra_bind_").append(i).append(",\n");
        }
        out.append("};\n");
        out.append("static const int umbra_owner_counts[UMBRA_OWNER_COUNT] = {\n");
        for (int i = 0; i < ownerCount; i++) {
            out.append("    ").append(byOwner.get(ownerName(byOwner, i)).size()).append(",\n");
        }
        out.append("};\n\n");
        out.append("static jint JNICALL umbra_register(JNIEnv* env, jclass self, jint classId,");
        out.append(" jclass owner) {\n");
        out.append("    (void)self;\n");
        out.append("    switch (classId) {\n");
        for (int i = 0; i < ownerCount; i++) {
            out.append("        case ").append(i).append(": return umbra_bind_").append(i)
                    .append("(env, owner);\n");
        }
        out.append("        default: return -1;\n");
        out.append("    }\n");
        out.append("}\n\n");
        return bindings;
    }

    /** Owner internal name at position {@code index} of the insertion-ordered map. */
    private static String ownerName(Map<String, List<Integer>> byOwner, int index) {
        int i = 0;
        for (String name : byOwner.keySet()) {
            if (i == index) {
                return name;
            }
            i++;
        }
        throw new IllegalStateException("owner index out of range: " + index);
    }

    private void appendWrapper(StringBuilder out, String functionName, MethodC method) {
        out.append("static ").append(method.cReturn).append(" JNICALL ").append(functionName)
                .append("(JNIEnv* env, ").append(method.staticMethod ? "jclass _cls" : "jobject _self");
        for (int i = 0; i < method.cArguments.size(); i++) {
            out.append(", ").append(method.cArguments.get(i)).append(" _a").append(i);
        }
        out.append(") {\n");
        if ("void".equals(method.cReturn)) {
            out.append("    ").append(method.functionName).append("(env, ")
                    .append(method.staticMethod ? "_cls" : "_self");
            for (int i = 0; i < method.cArguments.size(); i++) {
                out.append(", _a").append(i);
            }
            out.append(");\n}\n");
        } else {
            out.append("    return ").append(method.functionName).append("(env, ")
                    .append(method.staticMethod ? "_cls" : "_self");
            for (int i = 0; i < method.cArguments.size(); i++) {
                out.append(", _a").append(i);
            }
            out.append(");\n}\n");
        }
    }

    /**
     * Emits the anti-dump layer requested by {@link #configureAntiDump}:
     *
     * <ul>
     *   <li>a <b>backfill table</b> listing every exported native method
     *       (XOR-encrypted symbol name + this image's function address),</li>
     *   <li>a <b>table self-check</b> that resolves each entry through the
     *       module export table and compares it with the table pointer, so a
     *       patched export table / forwarded proxy library is detected,</li>
     *   <li>a <b>keyed challenge</b> ({@code verifyChallenge(int)}) the Java
     *       loader calls after {@code System.load}; the response mixes the
     *       per-program key with the caller nonce, so a library built for a
     *       different program (or rebuilt without the key) cannot answer,</li>
     *   <li>{@code JNI_OnLoad} refuses the load ({@code JNI_ERR}) when the
     *       backfill table does not match.</li>
     * </ul>
     */
    private void appendAntiDump(StringBuilder out, List<String> bindings) {
        if (antiDumpLoader == null) {
            return;
        }
        bindingCount = antiBackfill ? bindings.size() : 0;
        out.append("/* ---- Umbra native anti-dump layer ---- */\n");
        out.append("static const unsigned long long umbra_bind_key = ")
                .append(hex64(antiDumpKey)).append("ULL;\n\n");
        out.append("static unsigned long long umbra_mix(unsigned long long key, unsigned int nonce) {\n");
        out.append("    unsigned long long hash = 0xcbf29ce484222325ULL ^ key ^ (unsigned long long)nonce;\n");
        out.append("    hash *= 0x100000001b3ULL;\n");
        out.append("    hash ^= hash >> 33;\n");
        out.append("    hash *= 0xff51afd7ed558ccdULL;\n");
        out.append("    hash ^= hash >> 33;\n");
        out.append("    return hash;\n");
        out.append("}\n\n");
        if (antiBackfill) {
            appendRegistrationCheck(out);
            out.append("static jlong JNICALL umbra_challenge(JNIEnv* env, jclass cls, jint nonce) {\n");
            out.append("    (void)env; (void)cls;\n");
            out.append("    return (jlong)umbra_mix(umbra_bind_key, (unsigned int)nonce);\n");
            out.append("}\n\n");
        }
    }

    /**
     * Emits the registration-table self-check used when {@code native.antiBackfill}
     * is on.
     *
     * <p>The previous design verified the PE export table through
     * {@code GetProcAddress}, which no longer exists now that nothing is exported.
     * A rebuilt or patched library is instead caught by the SHA-256 fingerprint
     * the Java loader verifies before {@code System.load}, and this check keeps a
     * second line of defence inside the image itself: a library whose registrar
     * table has been patched to route bindings elsewhere fails the load.</p>
     */
    private void appendRegistrationCheck(StringBuilder out) {
        out.append("static int umbra_backfill_ok(void) {\n");
        out.append("    int i;\n");
        out.append("    if (UMBRA_OWNER_COUNT <= 0) {\n");
        out.append("        return 0;\n");
        out.append("    }\n");
        out.append("    for (i = 0; i < UMBRA_OWNER_COUNT; i++) {\n");
        out.append("        if (umbra_registrars[i] == NULL) {\n");
        out.append("            return 0;\n");
        out.append("        }\n");
        out.append("        if (umbra_owner_counts[i] <= 0) {\n");
        out.append("            return 0;\n");
        out.append("        }\n");
        out.append("    }\n");
        out.append("    return 1;\n");
        out.append("}\n\n");
    }

    private static String hex64(long value) {
        return "0x" + String.format(java.util.Locale.ROOT, "%016x", Long.valueOf(value));
    }

    private void appendOnLoad(StringBuilder out) {
        // Only the loader class is registered here. FindClass runs a class's static
        // initializer, so registering the business classes from JNI_OnLoad would
        // initialize them at library-load time; each owning class instead calls
        // loader.register(classId, Owner.class) from its own <clinit>, which is the
        // moment the class would have initialized anyway.
        out.append("JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {\n");
        out.append("    JNIEnv* env = NULL;\n");
        out.append("    (void)reserved;\n");
        out.append("    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {\n");
        out.append("        return JNI_ERR;\n");
        out.append("    }\n");
        if (antiDumpLoader != null && antiBackfill) {
            // Refuse a library whose registrar table was patched to route the
            // bindings elsewhere (the byte-level check is the loader's fingerprint).
            out.append("    if (!umbra_trace(\"backfill\", umbra_backfill_ok())) {\n");
            out.append("        return JNI_ERR;\n");
            out.append("    }\n");
        }
        if (registerLoader != null) {
            int count = antiBackfill ? 2 : 1;
            out.append("    {\n");
            out.append("        JNINativeMethod _m[").append(count).append("];\n");
            out.append("        jclass _loader;\n");
            out.append("        int _rc;\n");
            out.append("        umbra_lit_copy(").append(literalRef(registerLoader))
                    .append(", umbra_boot_name);\n");
            out.append("        _loader = (*env)->FindClass(env, umbra_boot_name);\n");
            out.append("        umbra_trace(\"find_class\", _loader != NULL);\n");
            out.append("        if (_loader == NULL) {\n");
            out.append("            (*env)->ExceptionClear(env);\n");
            out.append("            return JNI_ERR;\n");
            out.append("        }\n");
            out.append("        umbra_lit_copy(").append(literalRef(REGISTER_METHOD))
                    .append(", umbra_boot_reg);\n");
            out.append("        umbra_lit_copy(").append(literalRef(REGISTER_DESCRIPTOR))
                    .append(", umbra_boot_reg_sig);\n");
            out.append("        _m[0].name = umbra_boot_reg;\n");
            out.append("        _m[0].signature = umbra_boot_reg_sig;\n");
            out.append("        _m[0].fnPtr = (void*)(&umbra_register);\n");
            if (antiBackfill) {
                out.append("        umbra_lit_copy(").append(literalRef(CHALLENGE_METHOD))
                        .append(", umbra_boot_ch);\n");
                out.append("        umbra_lit_copy(").append(literalRef(CHALLENGE_DESCRIPTOR))
                        .append(", umbra_boot_ch_sig);\n");
                out.append("        _m[1].name = umbra_boot_ch;\n");
                out.append("        _m[1].signature = umbra_boot_ch_sig;\n");
                out.append("        _m[1].fnPtr = (void*)(&umbra_challenge);\n");
            }
            out.append("        _rc = (*env)->RegisterNatives(env, _loader, _m, ")
                    .append(count).append(");\n");
            out.append("        umbra_trace(\"register_natives\", _rc);\n");
            out.append("        if (_rc != 0) {\n");
            out.append("            (*env)->ExceptionClear(env);\n");
            out.append("            return JNI_ERR;\n");
            out.append("        }\n");
            out.append("    }\n");
        }
        out.append("    umbra_guard_attach(env);\n");
        out.append("    return JNI_VERSION_1_6;\n");
        out.append("}\n");
    }

    /**
     * Optional integration with the anti-debug guard library. The guard template
     * publishes its DLL path in the {@code umbra.guard.path} system property before
     * the native library is loaded; {@code JNI_OnLoad} resolves the exported
     * {@code umbra_guard_tick} entry point and every translated native method calls
     * it at entry. Without a guard the pointer stays NULL and the cost is one
     * predictable branch.
     */
    private static final String GUARD_TICK_C =
            "static int (*umbra_guard_tick_fn)(void);\n\n"
            + "static void umbra_guard_attach(JNIEnv* env) {\n"
            + "#ifdef _WIN32\n"
            + "    jclass system_class;\n"
            + "    jmethodID get_property;\n"
            + "    jstring key;\n"
            + "    jstring value;\n"
            + "    const char* path;\n"
            + "    system_class = (*env)->FindClass(env, \"java/lang/System\");\n"
            + "    if (system_class == NULL) { (*env)->ExceptionClear(env); return; }\n"
            + "    get_property = (*env)->GetStaticMethodID(env, system_class, \"getProperty\",\n"
            + "            \"(Ljava/lang/String;)Ljava/lang/String;\");\n"
            + "    if (get_property == NULL) { (*env)->ExceptionClear(env); return; }\n"
            + "    key = (*env)->NewStringUTF(env, \"umbra.guard.path\");\n"
            + "    if (key == NULL) { (*env)->ExceptionClear(env); return; }\n"
            + "    value = (jstring)(*env)->CallStaticObjectMethod(env, system_class, get_property, key);\n"
            + "    (*env)->DeleteLocalRef(env, key);\n"
            + "    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return; }\n"
            + "    if (value == NULL) return;\n"
            + "    path = (*env)->GetStringUTFChars(env, value, NULL);\n"
            + "    if (path != NULL) {\n"
            + "        HMODULE module = GetModuleHandleA(path);\n"
            + "        if (module == NULL) module = LoadLibraryA(path);\n"
            + "        if (module != NULL) {\n"
            + "            umbra_guard_tick_fn = (int (*)(void))GetProcAddress(module, \"umbra_guard_tick\");\n"
            + "        }\n"
            + "        (*env)->ReleaseStringUTFChars(env, value, path);\n"
            + "    }\n"
            + "#else\n"
            + "    (void)env;\n"
            + "#endif\n"
            + "}\n\n";

    static String defaultReturn(String cReturn) {        if ("void".equals(cReturn)) {
            return "return;";
        }
        if ("jobject".equals(cReturn)) {
            return "return NULL;";
        }
        return "return (" + cReturn + ")0;";
    }

    /** Emits a C string literal holding the modified UTF-8 bytes of {@code value}. */
    public static String cString(String value) {
        byte[] bytes = modifiedUtf8(value);
        StringBuilder out = new StringBuilder(bytes.length + 16);
        out.append('"');
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            if (b >= 0x20 && b < 0x7F && b != '"' && b != '\\' && b != '?') {
                out.append((char) b);
            } else {
                out.append('\\');
                out.append((char) ('0' + ((b >> 6) & 7)));
                out.append((char) ('0' + ((b >> 3) & 7)));
                out.append((char) ('0' + (b & 7)));
            }
        }
        out.append('"');
        return out.toString();
    }

    /** Encodes a Java string exactly like the class file modified UTF-8 format. */
    public static byte[] modifiedUtf8(String value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == 0) {
                out.write(0xC0);
                out.write(0x80);
            } else if (c < 0x80) {
                out.write(c);
            } else if (c < 0x800) {
                out.write(0xC0 | (c >> 6));
                out.write(0x80 | (c & 0x3F));
            } else {
                out.write(0xE0 | (c >> 12));
                out.write(0x80 | ((c >> 6) & 0x3F));
                out.write(0x80 | (c & 0x3F));
            }
        }
        return out.toByteArray();
    }

    // ------------------------------------------------------------------
    // Fixed C runtime
    // ------------------------------------------------------------------

    private static final String RUNTIME_C =
            "typedef struct {\n"
            + "    jmethodID mid;\n"
            + "    jfieldID fid;\n"
            + "    int ready;\n"
            + "} UMBRA_ID;\n\n"
            + "static jclass umbra_class(JNIEnv* env, jint index);\n"
            + "static jclass umbra_prim_class(JNIEnv* env, char kind);\n\n"
            + "static jfloat umbra_make_f(umbra_u32 bits) {\n"
            + "    jfloat value;\n"
            + "    memcpy(&value, &bits, sizeof(value));\n"
            + "    return value;\n"
            + "}\n\n"
            + "static jdouble umbra_make_d(umbra_u64 bits) {\n"
            + "    jdouble value;\n"
            + "    memcpy(&value, &bits, sizeof(value));\n"
            + "    return value;\n"
            + "}\n\n"
            + "static jint umbra_f2i(jfloat value) {\n"
            + "    if (value != value) return 0;\n"
            + "    if (value >= 2147483647.0f) return 2147483647;\n"
            + "    if (value <= -2147483648.0f) return (-2147483647 - 1);\n"
            + "    return (jint)value;\n"
            + "}\n\n"
            + "static jlong umbra_f2l(jfloat value) {\n"
            + "    if (value != value) return 0;\n"
            + "    if (value >= 9223372036854775808.0f) return 9223372036854775807LL;\n"
            + "    if (value < -9223372036854775808.0f) return (-9223372036854775807LL - 1);\n"
            + "    return (jlong)value;\n"
            + "}\n\n"
            + "static jint umbra_d2i(jdouble value) {\n"
            + "    if (value != value) return 0;\n"
            + "    if (value >= 2147483647.0) return 2147483647;\n"
            + "    if (value <= -2147483648.0) return (-2147483647 - 1);\n"
            + "    return (jint)value;\n"
            + "}\n\n"
            + "static jlong umbra_d2l(jdouble value) {\n"
            + "    if (value != value) return 0;\n"
            + "    if (value >= 9223372036854775808.0) return 9223372036854775807LL;\n"
            + "    if (value < -9223372036854775808.0) return (-9223372036854775807LL - 1);\n"
            + "    return (jlong)value;\n"
            + "}\n\n"
            + "static jint umbra_lcmp(jlong a, jlong b) {\n"
            + "    return a < b ? -1 : (a == b ? 0 : 1);\n"
            + "}\n\n"
            + "static jint umbra_fcmpl(jfloat a, jfloat b) {\n"
            + "    if (a != a || b != b) return -1;\n"
            + "    return a < b ? -1 : (a == b ? 0 : 1);\n"
            + "}\n\n"
            + "static jint umbra_fcmpg(jfloat a, jfloat b) {\n"
            + "    if (a != a || b != b) return 1;\n"
            + "    return a < b ? -1 : (a == b ? 0 : 1);\n"
            + "}\n\n"
            + "static jint umbra_dcmpl(jdouble a, jdouble b) {\n"
            + "    if (a != a || b != b) return -1;\n"
            + "    return a < b ? -1 : (a == b ? 0 : 1);\n"
            + "}\n\n"
            + "static jint umbra_dcmpg(jdouble a, jdouble b) {\n"
            + "    if (a != a || b != b) return 1;\n"
            + "    return a < b ? -1 : (a == b ? 0 : 1);\n"
            + "}\n\n"
            + "static jint umbra_idiv(JNIEnv* env, jint a, jint b) {\n"
            + "    if (b == 0) {\n"
            + "        jclass c = umbra_class(env, UMBRA_C_ARITHMETICEXCEPTION);\n"
            + "        if (c != NULL) (*env)->ThrowNew(env, c, \"/ by zero\");\n"
            + "        return 0;\n"
            + "    }\n"
            + "    if (b == -1) return (jint)(0u - (umbra_u32)a);\n"
            + "    return a / b;\n"
            + "}\n\n"
            + "static jint umbra_irem(JNIEnv* env, jint a, jint b) {\n"
            + "    if (b == 0) {\n"
            + "        jclass c = umbra_class(env, UMBRA_C_ARITHMETICEXCEPTION);\n"
            + "        if (c != NULL) (*env)->ThrowNew(env, c, \"/ by zero\");\n"
            + "        return 0;\n"
            + "    }\n"
            + "    if (b == -1) return 0;\n"
            + "    return a % b;\n"
            + "}\n\n"
            + "static jlong umbra_ldiv(JNIEnv* env, jlong a, jlong b) {\n"
            + "    if (b == 0) {\n"
            + "        jclass c = umbra_class(env, UMBRA_C_ARITHMETICEXCEPTION);\n"
            + "        if (c != NULL) (*env)->ThrowNew(env, c, \"/ by zero\");\n"
            + "        return 0;\n"
            + "    }\n"
            + "    if (b == -1) return (jlong)(0ull - (umbra_u64)a);\n"
            + "    return a / b;\n"
            + "}\n\n"
            + "static jlong umbra_lrem(JNIEnv* env, jlong a, jlong b) {\n"
            + "    if (b == 0) {\n"
            + "        jclass c = umbra_class(env, UMBRA_C_ARITHMETICEXCEPTION);\n"
            + "        if (c != NULL) (*env)->ThrowNew(env, c, \"/ by zero\");\n"
            + "        return 0;\n"
            + "    }\n"
            + "    if (b == -1) return 0;\n"
            + "    return a % b;\n"
            + "}\n\n"
            + "static int umbra_checkcast(JNIEnv* env, jobject obj, jclass cls) {\n"
            + "    jboolean ok;\n"
            + "    if (obj == NULL) return 1;\n"
            + "    ok = (*env)->IsInstanceOf(env, obj, cls);\n"
            + "    if ((*env)->ExceptionCheck(env)) return 0;\n"
            + "    if (ok) return 1;\n"
            + "    (*env)->ThrowNew(env, umbra_class(env, UMBRA_C_CLASSCASTEXCEPTION), \"cannot cast\");\n"
            + "    return 0;\n"
            + "}\n\n"
            + "static jmethodID umbra_array_new_mid;\n\n"
            + "static jobject umbra_newarray(JNIEnv* env, jclass component, jint length) {\n"
            + "    jclass arr;\n"
            + "    jvalue args[2];\n"
            + "    if (umbra_array_new_mid == NULL) {\n"
            + "        arr = umbra_class(env, UMBRA_C_ARRAY);\n"
            + "        if (arr == NULL) return NULL;\n"
            + "        umbra_array_new_mid = (*env)->GetStaticMethodID(env, arr, \"newInstance\",\n"
            + "                \"(Ljava/lang/Class;I)Ljava/lang/Object;\");\n"
            + "        if (umbra_array_new_mid == NULL) return NULL;\n"
            + "    }\n"
            + "    arr = umbra_class(env, UMBRA_C_ARRAY);\n"
            + "    if (arr == NULL) return NULL;\n"
            + "    args[0].l = (jobject)component;\n"
            + "    args[1].i = length;\n"
            + "    return (*env)->CallStaticObjectMethodA(env, arr, umbra_array_new_mid, args);\n"
            + "}\n\n"
            + "static jobject umbra_multi(JNIEnv* env, jclass* comps, const jint* lens, int dims, int level) {\n"
            + "    jint length = lens[level];\n"
            + "    jobject array = umbra_newarray(env, comps[level], length);\n"
            + "    jint i;\n"
            + "    if (array == NULL) return NULL;\n"
            + "    if (level + 1 >= dims) return array;\n"
            + "    for (i = 0; i < length; i++) {\n"
            + "        jobject sub = umbra_multi(env, comps, lens, dims, level + 1);\n"
            + "        if (sub == NULL) return NULL;\n"
            + "        (*env)->SetObjectArrayElement(env, (jobjectArray)array, i, sub);\n"
            + "        (*env)->DeleteLocalRef(env, sub);\n"
            + "        if ((*env)->ExceptionCheck(env)) return NULL;\n"
            + "    }\n"
            + "    return array;\n"
            + "}\n\n";

    private static final String PRIMITIVE_CLASS_C =
            "static jclass umbra_prim_class(JNIEnv* env, char kind) {\n"
            + "    static jclass cache[8];\n"
            + "    jint wrapper;\n"
            + "    int slot;\n"
            + "    jclass w;\n"
            + "    jfieldID typeField;\n"
            + "    jobject type;\n"
            + "    switch (kind) {\n"
            + "        case 'Z': slot = 0; wrapper = UMBRA_C_BOOLEAN; break;\n"
            + "        case 'B': slot = 1; wrapper = UMBRA_C_BYTE; break;\n"
            + "        case 'C': slot = 2; wrapper = UMBRA_C_CHARACTER; break;\n"
            + "        case 'S': slot = 3; wrapper = UMBRA_C_SHORT; break;\n"
            + "        case 'I': slot = 4; wrapper = UMBRA_C_INTEGER; break;\n"
            + "        case 'J': slot = 5; wrapper = UMBRA_C_LONG; break;\n"
            + "        case 'F': slot = 6; wrapper = UMBRA_C_FLOAT; break;\n"
            + "        case 'D': slot = 7; wrapper = UMBRA_C_DOUBLE; break;\n"
            + "        default: return NULL;\n"
            + "    }\n"
            + "    if (cache[slot] == NULL) {\n"
            + "        w = umbra_class(env, wrapper);\n"
            + "        if (w == NULL) return NULL;\n"
            + "        typeField = (*env)->GetStaticFieldID(env, w, \"TYPE\", \"Ljava/lang/Class;\");\n"
            + "        if (typeField == NULL) return NULL;\n"
            + "        type = (*env)->GetStaticObjectField(env, w, typeField);\n"
            + "        if (type == NULL) return NULL;\n"
            + "        cache[slot] = (jclass)(*env)->NewGlobalRef(env, type);\n"
            + "        (*env)->DeleteLocalRef(env, type);\n"
            + "        if (cache[slot] == NULL) return NULL;\n"
            + "    }\n"
            + "    return cache[slot];\n"
            + "}\n";
}
