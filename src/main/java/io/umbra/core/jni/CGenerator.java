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

    static final String[] RUNTIME_CLASSES = {
            "java/lang/NullPointerException",
            "java/lang/ClassCastException",
            "java/lang/ArithmeticException",
            "java/lang/reflect/Array",
            "java/lang/Integer",
            "java/lang/Long",
            "java/lang/Float",
            "java/lang/Double",
            "java/lang/Byte",
            "java/lang/Character",
            "java/lang/Short",
            "java/lang/Boolean",
            "java/lang/String"
    };

    private static final String[] RUNTIME_MACROS = {
            "NPE", "CLASSCASTEXCEPTION", "ARITHMETICEXCEPTION", "ARRAY",
            "INTEGER", "LONG", "FLOAT", "DOUBLE", "BYTE", "CHARACTER", "SHORT", "BOOLEAN",
            "STRING"
    };

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

    private long literalKey = 0x6A09E667F3BCC908L;

    private boolean intrinsics = true;

    private int intrinsicSites;

    private static final int LITERAL_MAX = 256;

    /** Domain separation between the member-name pool and the string pool. */
    static final int UMBRA_STR_SALT = 0x5EED;

    private String antiDumpLoader;
    private long antiDumpKey;
    private boolean antiBackfill;
    private int bindingCount;
    private int reflectClassLiteral;
    private int reflectModifiersLiteral;
    private int reflectModifiersSignature;

    private String registerLoader;

    private static byte[] loaderDigestKey;

    public static void configureLoaderDigestKey(byte[] key) {
        loaderDigestKey = key == null ? null : key.clone();
    }

    private byte[] keyRoot;

    private byte[] gateSecret;

    private boolean gateEnabled;

    public void configureKeyRoot(byte[] root) {
        this.keyRoot = root == null ? null : root.clone();
    }

    public boolean hasKeyRoot() {
        return keyRoot != null && registerLoader != null;
    }

    public byte[] keyRootBytes() {
        return keyRoot == null ? null : keyRoot.clone();
    }

    public void configureGate(byte[] secret, boolean enabled) {
        this.gateSecret = secret == null ? null : secret.clone();
        this.gateEnabled = enabled && this.gateSecret != null
                && this.gateSecret.length == KeyRootCode.KEY_SIZE;
    }

    public static final String CHALLENGE_METHOD = "verifyChallenge";

    public static final String CHALLENGE_DESCRIPTOR = "(I)J";

    public static final String REGISTER_METHOD = "register";

    public static final String REGISTER_DESCRIPTOR = "(ILjava/lang/Class;)I";

    private static final String REFLECT_METHOD_CLASS = "java/lang/reflect/Method";

    private static final String REFLECT_MODIFIERS = "getModifiers";

    private static final String REFLECT_MODIFIERS_DESCRIPTOR = "()I";

    public void configureAntiDump(String loaderInternalName, long key, boolean backfill) {
        this.antiDumpLoader = loaderInternalName;
        this.antiDumpKey = key;
        this.antiBackfill = backfill;
    }

    public void configureRegistration(String loaderInternalName) {
        this.registerLoader = loaderInternalName;
    }

    public int bindingCount() {
        return bindingCount;
    }

    public CGenerator() {
        for (int i = 0; i < RUNTIME_CLASSES.length; i++) {
            classIndex.put(RUNTIME_CLASSES[i], Integer.valueOf(i));
            classNames.add(RUNTIME_CLASSES[i]);
        }
    }

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

    public void configureLiteralKey(long key) {
        this.literalKey = key;
    }

    public void configureIntrinsics(boolean enabled) {
        this.intrinsics = enabled;
    }

    boolean intrinsicsEnabled() {
        return this.intrinsics;
    }

    void noteIntrinsic() {
        this.intrinsicSites++;
    }

    public int intrinsicCount() {
        return this.intrinsicSites;
    }

    private final Map<String, Integer> idSlots = new LinkedHashMap<String, Integer>();
    private int idSiteCount;

    /**
     * Allocates one {@code umbra_ids[]} slot per distinct member and reuses it
     * for every later reference, so N call sites of the same method resolve
     * the jmethodID once instead of N times.
     */
    int newIdSite(String owner, String name, String descriptor, boolean isStatic) {
        this.idSiteCount++;
        String key = owner + '\u0000' + name + '\u0000' + descriptor + '\u0000'
                + (isStatic ? '1' : '0');
        Integer existing = this.idSlots.get(key);
        if (existing != null) {
            return existing.intValue();
        }
        int slot = this.nextIdSite++;
        this.idSlots.put(key, Integer.valueOf(slot));
        return slot;
    }

    public int idSiteCount() {
        return this.idSiteCount;
    }

    public int uniqueIdCount() {
        return this.nextIdSite;
    }

    public void addMethod(MethodC method) {
        methods.add(method);
    }

    int methodCount() {
        return methods.size();
    }

    public String finish() {
        StringBuilder out = new StringBuilder(1 << 16);
        out.append("#include <jni.h>\n");
        out.append("#include <string.h>\n");
        out.append("#include <stdlib.h>\n");
        out.append("#include <stdio.h>\n");
        out.append("#include <math.h>\n");
        out.append("#ifdef _WIN32\n");
        out.append("#include <windows.h>\n");
        out.append("#endif\n\n");

        out.append("typedef unsigned int umbra_u32;\n");
        out.append("typedef unsigned long long umbra_u64;\n\n");

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
        if (antiBackfill) {
            reflectClassLiteral = literalRef(REFLECT_METHOD_CLASS);
            reflectModifiersLiteral = literalRef(REFLECT_MODIFIERS);
            reflectModifiersSignature = literalRef(REFLECT_MODIFIERS_DESCRIPTOR);
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
        if (hasKeyRoot()) {

        KeyRootCode.emit(out, keyRoot, literalKey, registerLoader, false,
                    gateSecret, gateEnabled, null);
        }
        appendOnLoad(out);
        appendBindLoaderExport(out);
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

    /**
     * Emits the Java string literal pool as encrypted UTF-16 code units.
     *
     * <p>The old table was {@code static const char umbra_str_N[]} fed straight
     * into {@code NewStringUTF}. That only works for modified UTF-8: NUL, emoji and
     * isolated surrogates were re-encoded by the compiler, and the literal itself
     * was plaintext inside the library. The pool below keeps the exact
     * {@code char[]} content, XORs each code unit with the same LCG keystream the
     * member-name pool uses, and rebuilds it with
     * {@code NewString(env, jchar[], len)} so UTF-16 semantics are preserved.</p>
     */
    private void appendStringConstants(StringBuilder out) {
        ByteArrayOutputStream pool = new ByteArrayOutputStream();
        StringBuilder offsets = new StringBuilder();
        StringBuilder lengths = new StringBuilder();
        int maxUnits = 1;
        for (int i = 0; i < strings.size(); i++) {
            String value = strings.get(i);
            if (value == null) {
                value = "";
            }
            byte[] cipher = encryptUtf16(this.literalKey, i, value);
            if (i > 0) {
                offsets.append(", ");
                lengths.append(", ");
            }
            offsets.append(pool.size());
            lengths.append(value.length());
            pool.write(cipher, 0, cipher.length);
            if (value.length() > maxUnits) {
                maxUnits = value.length();
            }
        }
        byte[] bytes = pool.toByteArray();
        out.append("#define UMBRA_STR_SALT ").append(UMBRA_STR_SALT).append('\n');
        out.append("#define UMBRA_STR_COUNT ").append(strings.size()).append('\n');
        out.append("#define UMBRA_STR_MAX_UNITS ").append(maxUnits).append("\n\n");
        out.append("static const unsigned char umbra_str_bytes[] = {\n");
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
        out.append("static const int umbra_str_off[UMBRA_STR_COUNT] = { ")
                .append(offsets).append(" };\n");
        out.append("static const int umbra_str_len[UMBRA_STR_COUNT] = { ")
                .append(lengths).append(" };\n\n");
        out.append("static void umbra_str_recover(int index, jchar* out) {\n");
        out.append("    int i;\n");
        out.append("    int len;\n");
        out.append("    umbra_u64 state;\n");
        out.append("    if (index < 0 || index >= UMBRA_STR_COUNT) {\n");
        out.append("        return;\n");
        out.append("    }\n");
        out.append("    len = umbra_str_len[index];\n");
        out.append("    state = UMBRA_LIT_KEY ^ (umbra_u64)(unsigned int)(index + UMBRA_STR_SALT);\n");
        out.append("    for (i = 0; i < len; i++) {\n");
        out.append("        unsigned int cipher;\n");
        out.append("        state = state * 6364136223846793005ULL + 1442695040888963407ULL;\n");
        out.append("        cipher = ((unsigned int)umbra_str_bytes[umbra_str_off[index] + i * 2] << 8)\n");
        out.append("                | (unsigned int)umbra_str_bytes[umbra_str_off[index] + i * 2 + 1];\n");
        out.append("        out[i] = (jchar)(cipher ^ (unsigned int)((state >> 33) & 0xFFFFu));\n");
        out.append("    }\n");
        out.append("}\n\n");
    }

    /** XORs every UTF-16 code unit with the shared LCG keystream. */
    static byte[] encryptUtf16(long key, int index, String value) {
        byte[] out = new byte[value.length() * 2];
        long state = key ^ (long) (index + UMBRA_STR_SALT);
        for (int i = 0; i < value.length(); i++) {
            state = state * 6364136223846793005L + 1442695040888963407L;
            int cipher = (value.charAt(i) ^ (int) ((state >>> 33) & 0xFFFF)) & 0xFFFF;
            out[i * 2] = (byte) (cipher >>> 8);
            out[i * 2 + 1] = (byte) cipher;
        }
        return out;
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

        out.append("    if (umbra_guard_tick_fn != NULL) {\n");
        out.append("        if (umbra_guard_tick_fn() != 0) {\n");
        out.append("            ").append(defaultReturn(method.cReturn)).append("\n");
        out.append("        }\n");
        out.append("    }\n");
        out.append(method.body);
        out.append("    ").append(defaultReturn(method.cReturn)).append('\n');
        out.append("}\n\n");
    }

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
        if (antiBackfill) {
            out.append("static int umbra_backfill_ok(JNIEnv* env, jclass owner, int class_id);\n\n");
        }
        out.append("static jint JNICALL umbra_register(JNIEnv* env, jclass self, jint classId,");
        out.append(" jclass owner) {\n");
        out.append("    jint rc;\n");
        out.append("    (void)self;\n");
        out.append("    switch (classId) {\n");
        for (int i = 0; i < ownerCount; i++) {
            out.append("        case ").append(i).append(":\n");
            out.append("            rc = umbra_bind_").append(i).append("(env, owner);\n");
            out.append("            if (rc != 0) {\n");
            out.append("                return rc;\n");
            out.append("            }\n");
            if (antiBackfill) {
                out.append("            if (!umbra_backfill_ok(env, owner, ").append(i)
                        .append(")) {\n");
                out.append("                return -8;\n");
                out.append("            }\n");
            }
            out.append("            return 0;\n");
        }
        out.append("        default:\n");
        out.append("            return -1;\n");
        out.append("    }\n");
        out.append("}\n\n");
        return bindings;
    }

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

    private void appendRegistrationCheck(StringBuilder out) {
        out.append("static jmethodID umbra_backfill_modifiers(JNIEnv* env) {\n");
        out.append("    static jmethodID cached = NULL;\n");
        out.append("    jclass method_class;\n");
        out.append("    char class_name[UMBRA_LIT_MAX];\n");
        out.append("    char method_name[UMBRA_LIT_MAX];\n");
        out.append("    char method_sig[UMBRA_LIT_MAX];\n");
        out.append("    if (cached != NULL) {\n");
        out.append("        return cached;\n");
        out.append("    }\n");
        out.append("    umbra_lit_copy(").append(reflectClassLiteral).append(", class_name);\n");
        out.append("    umbra_lit_copy(").append(reflectModifiersLiteral).append(", method_name);\n");
        out.append("    umbra_lit_copy(").append(reflectModifiersSignature).append(", method_sig);\n");
        out.append("    method_class = (*env)->FindClass(env, class_name);\n");
        out.append("    if (method_class == NULL) {\n");
        out.append("        (*env)->ExceptionClear(env);\n");
        out.append("        return NULL;\n");
        out.append("    }\n");
        out.append("    cached = (*env)->GetMethodID(env, method_class, method_name, method_sig);\n");
        out.append("    (*env)->DeleteLocalRef(env, method_class);\n");
        out.append("    if (cached == NULL) {\n");
        out.append("        (*env)->ExceptionClear(env);\n");
        out.append("    }\n");
        out.append("    return cached;\n");
        out.append("}\n\n");
        out.append("static int umbra_backfill_method(JNIEnv* env, jclass owner, int name_index,");
        out.append(" int sig_index, int is_static, jmethodID modifiers_id) {\n");
        out.append("    char name[UMBRA_LIT_MAX];\n");
        out.append("    char sig[UMBRA_LIT_MAX];\n");
        out.append("    jmethodID mid;\n");
        out.append("    jobject reflected;\n");
        out.append("    jint modifiers;\n");
        out.append("    umbra_lit_copy(name_index, name);\n");
        out.append("    umbra_lit_copy(sig_index, sig);\n");
        out.append("    if (is_static) {\n");
        out.append("        mid = (*env)->GetStaticMethodID(env, owner, name, sig);\n");
        out.append("    } else {\n");
        out.append("        mid = (*env)->GetMethodID(env, owner, name, sig);\n");
        out.append("    }\n");
        out.append("    if (mid == NULL) {\n");
        out.append("        (*env)->ExceptionClear(env);\n");
        out.append("        umbra_trace(name, -1);\n");
        out.append("        return 0;\n");
        out.append("    }\n");
        out.append("    reflected = (*env)->ToReflectedMethod(env, owner, mid, ");
        out.append("is_static ? JNI_TRUE : JNI_FALSE);\n");
        out.append("    if (reflected == NULL) {\n");
        out.append("        (*env)->ExceptionClear(env);\n");
        out.append("        umbra_trace(name, -2);\n");
        out.append("        return 0;\n");
        out.append("    }\n");
        out.append("    modifiers = (*env)->CallIntMethod(env, reflected, modifiers_id);\n");
        out.append("    (*env)->DeleteLocalRef(env, reflected);\n");
        out.append("    if ((*env)->ExceptionCheck(env)) {\n");
        out.append("        (*env)->ExceptionClear(env);\n");
        out.append("        umbra_trace(name, -3);\n");
        out.append("        return 0;\n");
        out.append("    }\n");
        out.append("    if ((modifiers & 0x100) == 0 || (modifiers & 0x400) != 0) {\n");
        out.append("        umbra_trace(name, (int)modifiers);\n");
        out.append("        return 0;\n");
        out.append("    }\n");
        out.append("    return 1;\n");
        out.append("}\n\n");
        Map<String, List<Integer>> byOwner = new LinkedHashMap<String, List<Integer>>();
        for (int i = 0; i < methods.size(); i++) {
            MethodC entry = methods.get(i);
            List<Integer> indexes = byOwner.get(entry.owner);
            if (indexes == null) {
                indexes = new ArrayList<Integer>();
                byOwner.put(entry.owner, indexes);
            }
            indexes.add(Integer.valueOf(i));
        }
        out.append("static int umbra_backfill_ok(JNIEnv* env, jclass owner, int class_id) {\n");
        out.append("    jmethodID modifiers_id;\n");
        out.append("    if (owner == NULL || UMBRA_OWNER_COUNT <= 0) {\n");
        out.append("        umbra_trace(\"backfill-owner\", 0);\n");
        out.append("        return 0;\n");
        out.append("    }\n");
        out.append("    modifiers_id = umbra_backfill_modifiers(env);\n");
        out.append("    if (modifiers_id == NULL) {\n");
        out.append("        umbra_trace(\"backfill-reflect\", 0);\n");
        out.append("        return 0;\n");
        out.append("    }\n");
        out.append("    switch (class_id) {\n");
        int ownerCount = 0;
        for (Map.Entry<String, List<Integer>> ownerEntry : byOwner.entrySet()) {
            out.append("    case ").append(ownerCount).append(":\n");
            for (Integer index : ownerEntry.getValue()) {
                MethodC method = methods.get(index.intValue());
                out.append("        if (!umbra_backfill_method(env, owner, ")
                        .append(literalRef(method.name)).append(", ")
                        .append(literalRef(method.descriptor)).append(", ")
                        .append(method.staticMethod ? 1 : 0).append(", modifiers_id)) {\n");
                out.append("            return 0;\n");
                out.append("        }\n");
            }
            out.append("        return 1;\n");
            ownerCount++;
        }
        out.append("    default:\n");
        out.append("        return 0;\n");
        out.append("    }\n");
        out.append("}\n\n");
    }

    private static String hex64(long value) {
        return "0x" + String.format(java.util.Locale.ROOT, "%016x", Long.valueOf(value));
    }

    private void appendBindLoaderExport(StringBuilder out) {
        // The bind diagnostics used to be unconditional: every protected program printed
        // the native method names it binds ("umbra-bind-names register=[...]") to stderr
        // at startup, which both leaked the un-renamed entry points and polluted the
        // program's output. Keep the code, compile it out by default.
        out.append("#ifdef UMBRA_BIND_DIAG\n");
        out.append("static void umbra_bind_stderr(const char* text) {\n");
        out.append("#ifdef _WIN32\n");
        out.append("    HANDLE handle = GetStdHandle(STD_ERROR_HANDLE);\n");
        out.append("    DWORD written = 0;\n");
        out.append("    if (handle != NULL && handle != INVALID_HANDLE_VALUE) {\n");
        out.append("        WriteFile(handle, text, (DWORD)strlen(text), &written, NULL);\n");
        out.append("    }\n");
        out.append("#else\n");
        out.append("    (void)text;\n");
        out.append("#endif\n");
        out.append("}\n\n");
        // appendOneBinding() prints the length of the bound name through this helper;
        // it was referenced but never emitted, so the whole unit failed to link and
        // native-code silently fell back to Java (native.methods=0).
        out.append("static void umbra_bind_stderr_int(int value) {\n");
        out.append("    char digits[16];\n");
        out.append("    int i = 0;\n");
        out.append("    unsigned int magnitude;\n");
        out.append("    if (value < 0) {\n");
        out.append("        umbra_bind_stderr(\"-\");\n");
        out.append("        magnitude = (unsigned int)(-(value + 1)) + 1u;\n");
        out.append("    } else {\n");
        out.append("        magnitude = (unsigned int)value;\n");
        out.append("    }\n");
        out.append("    if (magnitude == 0) {\n");
        out.append("        digits[i++] = '0';\n");
        out.append("    }\n");
        out.append("    while (magnitude > 0) {\n");
        out.append("        digits[i++] = (char)('0' + (magnitude % 10u));\n");
        out.append("        magnitude /= 10u;\n");
        out.append("    }\n");
        out.append("    while (i > 0) {\n");
        out.append("        char one[2];\n");
        out.append("        one[0] = digits[--i];\n");
        out.append("        one[1] = 0;\n");
        out.append("        umbra_bind_stderr(one);\n");
        out.append("    }\n");
        out.append("}\n");
        out.append("#else\n");
        out.append("static void umbra_bind_stderr(const char* text) { (void)text; }\n");
        out.append("static void umbra_bind_stderr_int(int value) { (void)value; }\n");
        out.append("#endif\n\n");
        out.append("JNIEXPORT jint JNICALL umbra_bind_loader(JNIEnv* env, jclass loader,\n");
        out.append("        const char* registerName, const char* challengeName) {\n");
        if (registerLoader == null) {
            out.append("    (void)env;\n");
            out.append("    (void)loader;\n");
            out.append("    return 0;\n");
            out.append("}\n");
            return;
        }
        out.append("    JNINativeMethod _m;\n");
        out.append("    char _name[UMBRA_LIT_MAX];\n");
        out.append("    char _sig[UMBRA_LIT_MAX];\n");
        out.append("    jmethodID _mid;\n");
        out.append("    int _rc;\n");
        out.append("    if (loader == NULL) {\n");
        out.append("        umbra_bind_stderr(\"umbra-bind-null-loader\\n\");\n");
        out.append("        return -2;\n");
        out.append("    }\n");
        out.append("    umbra_bind_stderr(\"umbra-bind-names register=[\");\n");
        out.append("    umbra_bind_stderr(registerName == NULL ? \"(null)\" : registerName);\n");
        out.append("    umbra_bind_stderr(\"] challenge=[\");\n");
        out.append("    umbra_bind_stderr(challengeName == NULL ? \"(null)\" : challengeName);\n");
        out.append("    umbra_bind_stderr(\"]\\n\");\n");
        appendOneBinding(out, REGISTER_METHOD, REGISTER_DESCRIPTOR, "umbra_register", "registerName", true);
        if (antiBackfill) {
            appendOneBinding(out, CHALLENGE_METHOD, CHALLENGE_DESCRIPTOR, "umbra_challenge", "challengeName", false);
        }
        out.append("    return 0;\n");
        out.append("}\n\n");
    }

    private void appendOneBinding(StringBuilder out, String name, String descriptor, String fn,
                                          String cName, boolean required) {
        out.append("    strcpy(_sig, \"").append(descriptor).append("\");\n");
        out.append("    if (_sig[0] == 0) { return -6; }\n");
        out.append("    if (").append(cName).append(" == NULL || ").append(cName).append("[0] == 0) { return -7; }\n");
        out.append("    _m.name = (char*)").append(cName).append(";\n");
        out.append("    umbra_bind_stderr(\"umbra-name-len=\");\n");
        out.append("    umbra_bind_stderr_int((int)strlen(_m.name));\n");
        out.append("    umbra_bind_stderr(\"umbra-name-value=\");\n");
        out.append("    umbra_bind_stderr(_m.name);\n");
        out.append("    umbra_bind_stderr(\"\\n\");\n");
        out.append("    _m.signature = _sig;\n");
        out.append("    _m.fnPtr = (void*)(&").append(fn).append(");\n");
        out.append("    umbra_bind_stderr(\"umbra-bind-check ").append(name).append("\\n\");\n");
        out.append("    umbra_bind_stderr(\"umbra-bind-sig=\");\n");
        out.append("    umbra_bind_stderr(_sig);\n");
        out.append("    umbra_bind_stderr(\"]\\n\");\n");
        // GetMethodID only looks up *instance* methods; register/verifyChallenge are
        // static natives, so the old lookup always returned NULL. The code then printed
        // "umbra-bind-skip" and still returned 0 without binding anything - the
        // class-encryption + native stack only failed later, as a bare
        // UnsatisfiedLinkError inside the protected program. GetStaticMethodID is the
        // matching lookup, and a missing entry point now fails the install.
        out.append("    _mid = (*env)->GetStaticMethodID(env, loader, _m.name, _sig);\n");
        out.append("    umbra_bind_stderr(\"umbra-bind-mid=\");\n");
        out.append("    umbra_bind_stderr(_mid == NULL ? \"0\\n\" : \"1\\n\");\n");
        out.append("    if (_mid == NULL) {\n");
        out.append("        (*env)->ExceptionDescribe(env);\n");
        out.append("        (*env)->ExceptionClear(env);\n");
        out.append("        umbra_bind_stderr(\"umbra-bind-missing ").append(name).append("\\n\");\n");
        out.append("        return -6;\n");
        out.append("    }\n");
        out.append("    {\n");
        out.append("        _rc = (*env)->RegisterNatives(env, loader, &_m, 1);\n");
        out.append("        umbra_bind_stderr(\"umbra-bind-rn=\");\n");
        out.append("        umbra_bind_stderr(_rc == 0 ? \"0\\n\" : \"1\\n\");\n");
        out.append("        if (_rc != 0) {\n");
        out.append("            (*env)->ExceptionDescribe(env);\n");
        out.append("            (*env)->ExceptionClear(env);\n");
        out.append("            umbra_bind_stderr(\"umbra-bind-fail ").append(name).append("\\n\");\n");
        out.append("            return -5;\n");
        out.append("        }\n");
        out.append("        umbra_bind_stderr(\"umbra-bind-ok ").append(name).append("\\n\");\n");
        out.append("    }\n");
    }

    private void appendOnLoad(StringBuilder out) {

        out.append("JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {\n");
        out.append("    JNIEnv* env = NULL;\n");
        out.append("    (void)reserved;\n");
        out.append("    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {\n");
        out.append("        return JNI_ERR;\n");
        out.append("    }\n");
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
            if (keyRoot != null) {

                out.append("#if UMBRA_GATE_ENABLED\n");
                out.append("        g_key_vm = vm;\n");
                out.append("        umbra_gate_start_watchdog();\n");
                out.append("#endif\n");
                out.append("        umbra_key_bind(env, _loader);\n");
            }
            out.append("    }\n");
        }
        out.append("    umbra_guard_attach(env);\n");
        out.append("    return JNI_VERSION_1_6;\n");
        out.append("}\n");
    }

    public static String keyBridgeSource(String loaderInternal, byte[] root, long secret,
                                         boolean forceTaint) {
        return keyBridgeSource(loaderInternal, root, secret, forceTaint, null, false);
    }

    public static String keyBridgeSource(String loaderInternal, byte[] root, long secret,
                                         boolean forceTaint, byte[] gateSecret,
                                         boolean gateEnabled) {
        return keyBridgeSource(loaderInternal, root, secret, forceTaint, gateSecret, gateEnabled,
                null);
    }

    public static String keyBridgeSource(String loaderInternal, byte[] root, long secret,
                                         boolean forceTaint, byte[] gateSecret,
                                         boolean gateEnabled, String moduleWhitelist) {
        return keyBridgeSource(loaderInternal, root, secret, forceTaint, gateSecret, gateEnabled,
                moduleWhitelist, 100);
    }

    public static String keyBridgeSource(String loaderInternal, byte[] root, long secret,
                                         boolean forceTaint, byte[] gateSecret,
                                         boolean gateEnabled, String moduleWhitelist,
                                         int handleScanMs) {
        return keyBridgeSource(loaderInternal, root, secret, forceTaint, gateSecret, gateEnabled,
                moduleWhitelist, handleScanMs, null);
    }

    public static String keyBridgeSource(String loaderInternal, byte[] root, long secret,
                                         boolean forceTaint, byte[] gateSecret,
                                         boolean gateEnabled, String moduleWhitelist,
                                        int handleScanMs, String suspiciousModules) {
        if (loaderInternal == null || loaderInternal.isEmpty()) {
            throw new IllegalArgumentException("the key bridge needs a loader class name");
        }
        StringBuilder out = new StringBuilder(1 << 15);
        out.append("#include <jni.h>\n");
        out.append("#include <string.h>\n");
        out.append("#include <stdlib.h>\n");
        out.append("#ifdef _WIN32\n");
        out.append("#include <windows.h>\n");

        out.append("#include <tlhelp32.h>\n");

        out.append("static char g_code_register_name[64];\n");
        out.append("static char g_code_challenge_name[64];\n");
        out.append("#endif\n\n");
        if (loaderDigestKey != null && loaderDigestKey.length == 32) {
            out.append("static const unsigned char umbra_loader_key[32] = {");
            for (int i = 0; i < loaderDigestKey.length; i++) {
                if (i > 0) {
                    out.append(',');
                }
                String octet = Integer.toHexString(loaderDigestKey[i] & 0xFF);
                out.append("0x").append(octet.length() == 1 ? "0" + octet : octet).append('u');
            }
            out.append("};\n");
        } else {
            out.append("static const unsigned char umbra_loader_key[32] = {0};\n");
        }
        KeyRootCode.emit(out, root, secret, loaderInternal, forceTaint, gateSecret, gateEnabled,
                moduleWhitelist, handleScanMs, suspiciousModules);
        out.append('\n');
        out.append("JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {\n");
        out.append("    JNIEnv* env = NULL;\n");
        out.append("    (void)reserved;\n");
        out.append("    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK");
        out.append(" || env == NULL) {\n");
        out.append("        return JNI_VERSION_1_6;\n");
        out.append("    }\n");
        out.append("    /* Nothing here reads a JVM property: the gate allowed dirs come from\n");
        out.append("       environment variables and jvm.dll, so class loading is never re-entered. */\n");
        out.append("#if UMBRA_GATE_ENABLED\n");
        out.append("    g_key_vm = vm;\n");
        out.append("    if (getenv(\"UMBRA_NO_GATE_WATCHDOG\") == NULL) umbra_gate_start_watchdog();\n");
        out.append("#endif\n");
        out.append("    (void)umbra_key_register(env);\n");
        out.append("    return JNI_VERSION_1_6;\n");
        out.append("}\n");
        return out.toString();
    }

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

    private static final String RUNTIME_C =
            "/* Member-id cache with explicit memory ordering. The slot\n"
            + " * payload (mid/fid) is published with a release store before\n"
            + " * the ready flag, and readers acquire the flag before touching\n"
            + " * the payload, so a concurrent first use can never observe\n"
            + " * ready==1 with a stale id. Non-GNU compilers fall back to\n"
            + " * plain accesses (single-threaded correctness only). */\n"
            + "#if defined(__GNUC__) || defined(__clang__)\n"
            + "#define UMBRA_ATOMIC_LOAD(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)\n"
            + "#define UMBRA_ATOMIC_STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)\n"
            + "#define UMBRA_ATOMIC_CAS(p, expected, desired) \\\n"
            + "    __atomic_compare_exchange_n((p), (expected), (desired), 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)\n"
            + "#else\n"
            + "#define UMBRA_ATOMIC_LOAD(p) (*(p))\n"
            + "#define UMBRA_ATOMIC_STORE(p, v) (*(p) = (v))\n"
            + "#define UMBRA_ATOMIC_CAS(p, expected, desired) \\\n"
            + "    ((*(p) == *(expected)) ? (*(p) = (desired), 1) : (*(expected) = *(p), 0))\n"
            + "#endif\n\n"
            + "typedef struct {\n"
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
            + "/* JVM frem/drem: % is illegal on floating-point operands in C, so\n"
            + " * the remainder needs fmodf/fmod. fmod follows IEC 60559 and keeps\n"
            + " * the JVM results for NaN, +/-Inf and signed zero. */\n"
            + "static jfloat umbra_frem(jfloat a, jfloat b) { return fmodf(a, b); }\n\n"
            + "static jdouble umbra_drem(jdouble a, jdouble b) { return fmod(a, b); }\n\n"
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
