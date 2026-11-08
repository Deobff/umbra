package io.umbra.core.jni;

import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Emits the native key-root bridge and the P6 gate (native side).
 *
 * <h3>Key root (P0)</h3>
 *
 * <p>The per-build 32-byte root never appears as a contiguous constant in the
 * shipped image: it is split into eight {@code uint32} words, each XOR-masked
 * with a word derived at run time from a second random block and a build seed,
 * and rebuilt into a stack buffer for one HMAC before being wiped.</p>
 *
 * <p>{@code keyRoot(slot, sub, out)} = {@code HMAC-SHA256(root, label || LE32(slot)
 * || LE32(sub))}. A debugger probe decides between the real and a stable fake key;
 * both return {@code 0}.</p>
 *
 * <h3>Gate (P6)</h3>
 *
 * <p>Slot 1 is the bootstrap key and is always released; slot 2 is the business
 * payload key and is only released after the challenge/response handshake
 * ({@code gateChallenge}/{@code gateAttest}). The gate keeps up to
 * {@value #GATE_SLOTS} unconsumed nonces for concurrent decryption, compares the
 * response in constant time and sets a sticky {@code gate_open}. A failed attest
 * only returns non-zero: no detection flag, no message change. When the gate is
 * compiled out or the bridge could not register its gate symbols, every slot is
 * released exactly like before.</p>
 */
public final class KeyRootCode {

    public static final String KEY_ROOT_METHOD = "keyRoot";

    public static final String KEY_ROOT_DESCRIPTOR = "(II[B)I";

    public static final String GATE_CHALLENGE_METHOD = "gateChallenge";

    public static final String GATE_CHALLENGE_DESCRIPTOR = "([J)I";

    public static final String GATE_ATTEST_METHOD = "gateAttest";

    public static final String GATE_ATTEST_DESCRIPTOR = "(J[B)I";

    public static final int KEY_SIZE = 32;

    public static final int GATE_SLOTS = 4;

    public static final String LABEL = "umbra.keyroot.v1";

    public static final String GATE_LABEL = "umbra.gate.v1";

    static final String[] AGENT_MARKERS = {
        "jdwp.dll", "dt_socket.dll", "attach.dll", "jdwp.dll"
    };

    static final String[] SUSPICIOUS_MODULES = {
        "dbghelp.dll", "dbgcore.dll", "dumpext.dll"
    };

    public static final String GATE_TICK_METHOD = "gateTick";

    public static final String GATE_TICK_DESCRIPTOR = "(I[B)I";

    public static final String KEY_ROOT2_METHOD = "keyRoot2";

    public static final String KEY_ROOT2_DESCRIPTOR = "(II[B[B)I";

    public static final String NATIVE_DECRYPT_METHOD = "nativeDecrypt";

    public static final String NATIVE_DECRYPT_DESCRIPTOR = "(I[B[B)I";

    public static final String VERIFY_LOADER_METHOD = "verifyLoader";

    public static final String VERIFY_LOADER_DESCRIPTOR = "([B)I";

    public static final String BIND_NAMES_METHOD = "bindNames";

    public static final String BIND_NAMES_DESCRIPTOR = "(I[Ljava/lang/String;)I";

    static final int BIND_NAMES_VERSION = 2;

    static final int BIND_NAMES_COUNT = 8;

    public static final String BIND_LOADER_SYMBOL = "umbra_bind_loader";
    public static final String INSTALL_CODELIB_METHOD = "installCodeLibrary";

    public static final String INSTALL_CODELIB_DESCRIPTOR = "(Ljava/lang/String;Ljava/lang/Class;)I";

    public static final String TICK_LABEL = "umbra.tick.v1";

    static final int GATE_TICK_MS = 50;

    static final int GATE_WATCHDOG_MS = 100;

    static final int GATE_MODULE_SLOTS = 256;

    static final int GATE_ALLOW_SLOTS = 16;

    static final int GATE_PATH_MAX = 260;

    private KeyRootCode() {
    }

    public static byte[] newRoot() {
        byte[] root = new byte[KEY_SIZE];
        new SecureRandom().nextBytes(root);
        return root;
    }

    public static byte[] newGateSecret() {
        byte[] secret = new byte[KEY_SIZE];
        new SecureRandom().nextBytes(secret);
        return secret;
    }

    public static byte[] hmacSha256(byte[] key, byte[] message) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (java.security.GeneralSecurityException failure) {
            throw new IllegalStateException("native-key: HMAC is unavailable", failure);
        }
    }

    public static byte[] deriveSlot(byte[] root, int slot, int sub) {
        byte[] message = new byte[LABEL.length() + 8];
        for (int i = 0; i < LABEL.length(); i++) {
            message[i] = (byte) (LABEL.charAt(i) ^ (0x3D + i * 7));
        }
        for (int i = 0; i < 4; i++) {
            message[LABEL.length() + i] = (byte) ((slot >>> (8 * i)) & 0xFF);
            message[LABEL.length() + 4 + i] = (byte) ((sub >>> (8 * i)) & 0xFF);
        }
        return hmacSha256(root, message);
    }

    public static final byte[] DIGEST_BLOCK_MAGIC = {
            'U', 'M', 'B', 'R', 'A', 'D', 'G', '1'
    };

    public static final byte[] DIGEST_BLOCK_MAGIC_BRIDGE = {
            'U', 'M', 'B', 'R', 'A', 'D', 'G', '2'
    };

    public static String bridgeFingerprint(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        java.security.MessageDigest digest;
        try {
            digest = java.security.MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException missing) {
            return null;
        }
        int cursor = 0;
        int skipped = 0;
        while (true) {
            int at1 = indexOf(bytes, DIGEST_BLOCK_MAGIC, cursor);
            int at2 = indexOf(bytes, DIGEST_BLOCK_MAGIC_BRIDGE, cursor);
            int at = at1 < 0 ? at2 : (at2 < 0 ? at1 : Math.min(at1, at2));
            if (at < 0) {
                break;
            }
            int from = at + DIGEST_BLOCK_MAGIC.length;
            int to = from + 32;
            if (to > bytes.length) {
                break;
            }
            digest.update(bytes, cursor, from - cursor);
            cursor = to;
            skipped++;
        }
        if (skipped == 0) {
            return sha256Hex(bytes);
        }
        digest.update(bytes, cursor, bytes.length - cursor);
        return hex(digest.digest());
    }

    static int indexOf(byte[] haystack, byte[] needle, int from) {
        outer:
        for (int i = Math.max(0, from); i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            text.append(Character.forDigit((value >> 4) & 0xF, 16));
            text.append(Character.forDigit(value & 0xF, 16));
        }
        return text.toString();
    }

    public static String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            char[] hex = new char[hash.length * 2];
            for (int i = 0; i < hash.length; i++) {
                hex[i * 2] = Character.forDigit((hash[i] >>> 4) & 0xF, 16);
                hex[i * 2 + 1] = Character.forDigit(hash[i] & 0xF, 16);
            }
            return new String(hex);
        } catch (Exception failure) {
            return null;
        }
    }

    public static int maskWord(int salt, int index, int seed) {
        int value = salt ^ (0x9E3779B9 * (index + 1));
        value = (value << 13) | (value >>> 19);
        value *= 0x85EBCA6B;
        value ^= value >>> 15;
        value ^= seed;
        value *= 0xC2B2AE35;
        value ^= value >>> 13;
        return value;
    }

    public static int rootWord(byte[] secret, int index) {
        int base = index * 4;
        return (secret[base] & 0xFF)
                | ((secret[base + 1] & 0xFF) << 8)
                | ((secret[base + 2] & 0xFF) << 16)
                | ((secret[base + 3] & 0xFF) << 24);
    }

    public static int encodedWord(byte[] secret, int index, int salt, int seed) {
        return rootWord(secret, index) ^ maskWord(salt, index, seed);
    }

    static String sealBytes(String value, int key) {
        StringBuilder out = new StringBuilder(16 + value.length() * 6);
        for (int i = 0; i < value.length(); i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append("0x").append(Integer.toHexString(
                    (value.charAt(i) ^ ((key + i * 7) & 0xFF)) & 0xFF));
        }
        return out.toString();
    }

    public static void emit(StringBuilder out, byte[] root, long secret, String loaderInternal,
                            boolean forceTaint) {
        emit(out, root, secret, loaderInternal, forceTaint, null, false, null);
    }

    public static void emit(StringBuilder out, byte[] root, long secret, String loaderInternal,
                            boolean forceTaint, byte[] gateSecret, boolean gateEnabled) {
        emit(out, root, secret, loaderInternal, forceTaint, gateSecret, gateEnabled, null);
    }

    public static void emit(StringBuilder out, byte[] root, long secret, String loaderInternal,
                            boolean forceTaint, byte[] gateSecret, boolean gateEnabled,
                            String moduleWhitelist) {
        emit(out, root, secret, loaderInternal, forceTaint, gateSecret, gateEnabled, moduleWhitelist,
                100);
    }

    public static void emit(StringBuilder out, byte[] root, long secret, String loaderInternal,
                            boolean forceTaint, byte[] gateSecret, boolean gateEnabled,
                            String moduleWhitelist, int handleScanMs) {
        emit(out, root, secret, loaderInternal, forceTaint, gateSecret, gateEnabled,
                moduleWhitelist, handleScanMs, null);
    }

    public static void emit(StringBuilder out, byte[] root, long secret, String loaderInternal,
                            boolean forceTaint, byte[] gateSecret, boolean gateEnabled,
                            String moduleWhitelist, int handleScanMs, String suspiciousModules) {
        if (root == null || root.length != KEY_SIZE) {
            throw new IllegalArgumentException("key root must be 32 bytes");
        }
        boolean gate = gateEnabled && gateSecret != null && gateSecret.length == KEY_SIZE;
        SecureRandom random = new SecureRandom();
        int seed = random.nextInt();
        int[] salt = new int[8];
        for (int i = 0; i < salt.length; i++) {
            salt[i] = random.nextInt();
        }
        int gateSeed = random.nextInt();
        int[] gateSalt = new int[8];
        for (int i = 0; i < gateSalt.length; i++) {
            gateSalt[i] = random.nextInt();
        }
        int nameKey = classNameKey(secret);
        int labelKey = 0x3D;
        int methodKey = 0x6B;
        out.append("/* ---- P0: native key root (per-build, masked eight-word root) ---- */\n");
        out.append("#define UMBRA_KEY_FORCE_TAINT ").append(forceTaint ? 1 : 0).append('\n');
        out.append("#define UMBRA_KEY_SEED 0x").append(hex32(seed)).append("u\n");
        out.append("static const unsigned int umbra_k_enc[8] = {");
        for (int i = 0; i < 8; i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append("0x").append(hex32(encodedWord(root, i, salt[i], seed))).append('u');
        }
        out.append("};\n");
        out.append("static const unsigned int umbra_k_salt[8] = {");
        for (int i = 0; i < 8; i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append("0x").append(hex32(salt[i])).append('u');
        }
        out.append("};\n");
        out.append("static const unsigned char umbra_k_label[").append(LABEL.length())
                .append("] = {").append(sealBytes(LABEL, labelKey)).append("};\n");
        out.append("#define UMBRA_KEY_LABEL_KEY 0x").append(hex32(labelKey & 0xFF)).append('u').append('\n');
        out.append("#define UMBRA_KEY_LABEL_LEN ").append(LABEL.length()).append('\n');
        out.append("#define UMBRA_GATE_ENABLED ").append(gate ? 1 : 0).append('\n');
        out.append("#define UMBRA_GATE_SLOTS ").append(GATE_SLOTS).append('\n');
        // Build-time switch for the stderr diagnostics. Default 0: the diagnostic
        // strings spell out the sealed entry points and the "umbra" prefix, so a
        // shipped bridge carries none of them unless the build asks for them.
        String diagFlag = System.getenv("UMBRA_GATE_DIAG");
        boolean gateDiag = "1".equals(diagFlag) || "true".equalsIgnoreCase(diagFlag);
        out.append("#define UMBRA_GATE_DIAG ").append(gateDiag ? 1 : 0).append('\n');
        if (gate) {
            out.append("#define UMBRA_GATE_SEED 0x").append(hex32(gateSeed)).append("u\n");
            out.append("static const unsigned int umbra_g_enc[8] = {");
            for (int i = 0; i < 8; i++) {
                if (i > 0) {
                    out.append(',');
                }
                out.append("0x").append(hex32(encodedWord(gateSecret, i, gateSalt[i], gateSeed)))
                        .append('u');
            }
            out.append("};\n");
            out.append("static const unsigned int umbra_g_salt[8] = {");
            for (int i = 0; i < 8; i++) {
                if (i > 0) {
                    out.append(',');
                }
                out.append("0x").append(hex32(gateSalt[i])).append('u');
            }
            out.append("};\n");
            int gateLabelKey = 0x71;
            out.append("static const unsigned char umbra_g_label[").append(GATE_LABEL.length())
                    .append("] = {").append(sealBytes(GATE_LABEL, gateLabelKey)).append("};\n");
            out.append("#define UMBRA_GATE_LABEL_KEY 0x").append(hex32(gateLabelKey & 0xFF))
                    .append('u').append('\n');
            out.append("#define UMBRA_GATE_LABEL_LEN ").append(GATE_LABEL.length()).append('\n');
            int markerKey = (gateLabelKey ^ 0x33) & 0xFF;
            for (int i = 0; i < AGENT_MARKERS.length; i++) {
                String marker = AGENT_MARKERS[i];
                int key = (markerKey + i * 7) & 0xFF;
                out.append("static const unsigned char umbra_g_m").append(i).append('[')
                        .append(marker.length()).append("] = {")
                        .append(sealBytes(marker, key)).append("};\n");
                out.append("#define UMBRA_GATE_M").append(i).append("_KEY 0x")
                        .append(hex32(key)).append('u').append('\n');
                out.append("#define UMBRA_GATE_M").append(i).append("_LEN ")
                        .append(marker.length()).append('\n');
            }
            int suspiciousKey = (gateLabelKey ^ 0x5B) & 0xFF;
            for (int i = 0; i < SUSPICIOUS_MODULES.length; i++) {
                String suspicious = SUSPICIOUS_MODULES[i];
                int key = (suspiciousKey + i * 11) & 0xFF;
                out.append("static const unsigned char umbra_g_s").append(i).append('[')
                        .append(suspicious.length()).append("] = {")
                        .append(sealBytes(suspicious, key)).append("};\n");
                out.append("#define UMBRA_GATE_S").append(i).append("_KEY 0x")
                        .append(hex32(key)).append('u').append('\n');
                out.append("#define UMBRA_GATE_S").append(i).append("_LEN ")
                        .append(suspicious.length()).append('\n');
            }
            String extraSuspicious = suspiciousModules == null ? "" : suspiciousModules.trim();
            if (extraSuspicious.length() > GATE_PATH_MAX - 1) {
                extraSuspicious = extraSuspicious.substring(0, GATE_PATH_MAX - 1);
            }
            out.append("static const unsigned char umbra_g_sus[")
                    .append(Math.max(1, extraSuspicious.length())).append("] = {")
                    .append(extraSuspicious.isEmpty() ? "0" : sealBytes(extraSuspicious, suspiciousKey))
                    .append("};\n");
            out.append("#define UMBRA_GATE_SUS_LEN ").append(extraSuspicious.length()).append('\n');
            out.append("#define UMBRA_GATE_SUS_KEY 0x")
                    .append(hex32(suspiciousKey & 0xFF)).append('u').append('\n');
            out.append("static int umbra_gate_contains_nocase(const char* text, const char* needle, int length);\n");
            out.append("static int umbra_gate_sealed_hit(const char* module, const unsigned char* sealed,\n");
            out.append("        int length, unsigned int key);\n");
            out.append("static int umbra_gate_suspicious(const char* module) {\n");
            out.append("    int i;\n");
            out.append("    if (umbra_gate_sealed_hit(module, umbra_g_s0, UMBRA_GATE_S0_LEN, UMBRA_GATE_S0_KEY)) return 1;\n");
            out.append("    if (umbra_gate_sealed_hit(module, umbra_g_s1, UMBRA_GATE_S1_LEN, UMBRA_GATE_S1_KEY)) return 1;\n");
            out.append("    if (umbra_gate_sealed_hit(module, umbra_g_s2, UMBRA_GATE_S2_LEN, UMBRA_GATE_S2_KEY)) return 1;\n");
            out.append("    if (UMBRA_GATE_SUS_LEN > 0) {\n");
            out.append("        static char extra[UMBRA_GATE_SUS_LEN + 1];\n");
            out.append("        static int extra_ready;\n");
            out.append("        if (!extra_ready) {\n");
            out.append("            for (i = 0; i < UMBRA_GATE_SUS_LEN; i++) {\n");
            out.append("                extra[i] = (char)(umbra_g_sus[i]\n");
            out.append("                        ^ (unsigned char)(UMBRA_GATE_SUS_KEY + (unsigned int)i * 7u));\n");
            out.append("            }\n");
            out.append("            extra[UMBRA_GATE_SUS_LEN] = 0;\n");
            out.append("            extra_ready = 1;\n");
            out.append("        }\n");
            out.append("        {\n");
            out.append("            char* cursor = extra;\n");
            out.append("            while (cursor != NULL && cursor[0] != 0) {\n");
            out.append("                char* next = strchr(cursor, ';');\n");
            out.append("                int length = next == NULL ? (int)strlen(cursor) : (int)(next - cursor);\n");
            out.append("                if (length > 0 && length < 64\n");
            out.append("                        && umbra_gate_contains_nocase(module, cursor, length)) return 1;\n");
            out.append("                cursor = next == NULL ? NULL : next + 1;\n");
            out.append("            }\n");
            out.append("        }\n");
            out.append("    }\n");
            out.append("    return 0;\n");
            out.append("}\n");
            int tickKey = (methodKey ^ 0x61) & 0xFF;
            int tickLabelKey = (gateLabelKey ^ 0x4D) & 0xFF;
            int whitelistKey = (gateLabelKey ^ 0x69) & 0xFF;
            out.append("static const unsigned char umbra_g_tick[").append(GATE_TICK_METHOD.length())
                    .append("] = {").append(sealBytes(GATE_TICK_METHOD, tickKey)).append("};\n");
            out.append("static const unsigned char umbra_g_tick_sig[")
                    .append(GATE_TICK_DESCRIPTOR.length()).append("] = {")
                    .append(sealBytes(GATE_TICK_DESCRIPTOR, tickKey ^ 0x55)).append("};\n");
            out.append("static const unsigned char umbra_g_tick_label[")
                    .append(TICK_LABEL.length()).append("] = {")
                    .append(sealBytes(TICK_LABEL, tickLabelKey)).append("};\n");
            out.append("#define UMBRA_GATE_TICK_KEY 0x").append(hex32(tickKey & 0xFF))
                    .append('u').append('\n');
            out.append("#define UMBRA_GATE_TICK_LENGTH ").append(GATE_TICK_METHOD.length())
                    .append('\n');
            out.append("#define UMBRA_GATE_TICK_SIG_KEY 0x")
                    .append(hex32((tickKey ^ 0x55) & 0xFF)).append('u').append('\n');
            out.append("#define UMBRA_GATE_TICK_SIG_LENGTH ")
                    .append(GATE_TICK_DESCRIPTOR.length()).append('\n');
            out.append("#define UMBRA_GATE_TICK_LABEL_KEY 0x")
                    .append(hex32(tickLabelKey & 0xFF)).append('u').append('\n');
            out.append("#define UMBRA_GATE_TICK_LABEL_LEN ").append(TICK_LABEL.length())
                    .append('\n');
            out.append("#define UMBRA_GATE_TICK_MS ").append(GATE_TICK_MS).append("UL\n");
            out.append("#define UMBRA_GATE_WATCHDOG_MS ").append(GATE_WATCHDOG_MS).append("UL\n");
            out.append("#define UMBRA_GATE_LDR_NOTIFY 0\n");
            int handlePeriod = Math.max(50, Math.min(1000, handleScanMs));
            out.append("#define UMBRA_GATE_HANDLE_MS ").append(handlePeriod).append('u').append('\n');
            out.append("#define UMBRA_GATE_VM_SLOTS 64\n");
            out.append("#define UMBRA_GATE_MODULE_SLOTS ").append(GATE_MODULE_SLOTS).append('\n');
            out.append("#define UMBRA_GATE_ALLOW_SLOTS ").append(GATE_ALLOW_SLOTS).append('\n');
            out.append("#define UMBRA_GATE_PATH_MAX ").append(GATE_PATH_MAX).append('\n');
            String whitelist = moduleWhitelist == null ? "" : moduleWhitelist.trim();
            if (whitelist.length() > GATE_PATH_MAX - 1) {
                whitelist = whitelist.substring(0, GATE_PATH_MAX - 1);
            }
            out.append("static const unsigned char umbra_g_whitelist[")
                    .append(Math.max(1, whitelist.length())).append("] = {")
                    .append(whitelist.isEmpty() ? "0" : sealBytes(whitelist, whitelistKey))
                    .append("};\n");
            out.append("#define UMBRA_GATE_WHITELIST_LEN ").append(whitelist.length()).append('\n');
            out.append("#define UMBRA_GATE_WHITELIST_KEY 0x")
                    .append(hex32(whitelistKey & 0xFF)).append('u').append('\n');
            out.append("static JavaVM* g_key_vm;\n");
            out.append("static int umbra_gate_marker_scan(void);\n");
            out.append("static int umbra_gate_agent_scan(void);\n");
            out.append("static int umbra_gate_dirty(void);\n");
            out.append("static void umbra_key_derive(int slot, int sub, unsigned char* digest);\n");
            out.append("static jint JNICALL umbra_gate_tick(JNIEnv*, jclass, jint, jbyteArray);\n");
        }
        if (loaderInternal != null) {
            int key = nameKey & 0xFF;
            out.append("static const unsigned char umbra_k_name[").append(loaderInternal.length())
                    .append("] = {").append(sealBytes(loaderInternal, nameKey)).append("};\n");
            out.append("#define UMBRA_KEY_NAME_LEN ").append(loaderInternal.length()).append('\n');
            out.append("#define UMBRA_KEY_NAME_KEY 0x").append(hex32(key)).append("u\n");
        }
        out.append("static const unsigned char umbra_k_method[").append(KEY_ROOT_METHOD.length())
                .append("] = {").append(sealBytes(KEY_ROOT_METHOD, methodKey)).append("};\n");
        out.append("static const unsigned char umbra_k_descriptor[").append(KEY_ROOT_DESCRIPTOR.length())
                .append("] = {").append(sealBytes(KEY_ROOT_DESCRIPTOR, methodKey ^ 0x55)).append("};\n");
        out.append("#define UMBRA_KEY_METHOD_KEY 0x").append(hex32(methodKey & 0xFF)).append('u').append('\n');
        out.append("#define UMBRA_KEY_METHOD_LENGTH ").append(KEY_ROOT_METHOD.length()).append('\n');
        out.append("#define UMBRA_KEY_DESCRIPTOR_LENGTH ").append(KEY_ROOT_DESCRIPTOR.length())
                .append('\n');
        out.append("#define UMBRA_KEY_DESCRIPTOR_KEY 0x").append(hex32((methodKey ^ 0x55) & 0xFF))
                .append('u').append('\n');
        out.append("static const unsigned char umbra_k_decrypt[").append(NATIVE_DECRYPT_METHOD.length())
                .append("] = {").append(sealBytes(NATIVE_DECRYPT_METHOD, methodKey ^ 0x71)).append("};\n");
        out.append("static const unsigned char umbra_k_decrypt_sig[").append(NATIVE_DECRYPT_DESCRIPTOR.length())
                .append("] = {").append(sealBytes(NATIVE_DECRYPT_DESCRIPTOR, methodKey ^ 0x2B)).append("};\n");
        out.append("#define UMBRA_DECRYPT_NAME_LEN ").append(NATIVE_DECRYPT_METHOD.length()).append('\n');
        out.append("#define UMBRA_DECRYPT_NAME_KEY 0x").append(hex32((methodKey ^ 0x71) & 0xFF)).append('u').append('\n');
        out.append("#define UMBRA_DECRYPT_SIG_LEN ").append(NATIVE_DECRYPT_DESCRIPTOR.length()).append('\n');
        out.append("#define UMBRA_DECRYPT_SIG_KEY 0x").append(hex32((methodKey ^ 0x2B) & 0xFF)).append('u').append('\n');
        out.append("static const unsigned char umbra_k_install[").append(INSTALL_CODELIB_METHOD.length())
                .append("] = {").append(sealBytes(INSTALL_CODELIB_METHOD, methodKey ^ 0x19)).append("};\n");
        out.append("static const unsigned char umbra_k_install_sig[").append(INSTALL_CODELIB_DESCRIPTOR.length())
                .append("] = {").append(sealBytes(INSTALL_CODELIB_DESCRIPTOR, methodKey ^ 0x4F)).append("};\n");
        out.append("#define UMBRA_INSTALL_NAME_LEN ").append(INSTALL_CODELIB_METHOD.length()).append('\n');
        out.append("#define UMBRA_INSTALL_NAME_KEY 0x").append(hex32((methodKey ^ 0x19) & 0xFF)).append('u').append('\n');
        out.append("#define UMBRA_INSTALL_SIG_LEN ").append(INSTALL_CODELIB_DESCRIPTOR.length()).append('\n');
        out.append("#define UMBRA_INSTALL_SIG_KEY 0x").append(hex32((methodKey ^ 0x4F) & 0xFF)).append('u').append('\n');
        out.append("static const unsigned char umbra_k_root2[").append(KEY_ROOT2_METHOD.length())
                .append("] = {").append(sealBytes(KEY_ROOT2_METHOD, methodKey ^ 0x37)).append("};\n");
        out.append("static const unsigned char umbra_k_root2_sig[").append(KEY_ROOT2_DESCRIPTOR.length())
                .append("] = {").append(sealBytes(KEY_ROOT2_DESCRIPTOR, methodKey ^ 0x6D)).append("};\n");
        out.append("#define UMBRA_KEY2_NAME_LEN ").append(KEY_ROOT2_METHOD.length()).append('\n');
        out.append("#define UMBRA_KEY2_NAME_KEY 0x").append(hex32((methodKey ^ 0x37) & 0xFF)).append('u').append('\n');
        out.append("#define UMBRA_KEY2_SIG_LEN ").append(KEY_ROOT2_DESCRIPTOR.length()).append('\n');
        out.append("#define UMBRA_KEY2_SIG_KEY 0x").append(hex32((methodKey ^ 0x6D) & 0xFF)).append('u').append('\n');
        int bindLoaderKey = (methodKey ^ 0x4B) & 0xFF;
        out.append("static const unsigned char umbra_k_bindloader[").append(BIND_LOADER_SYMBOL.length())
                .append("] = {").append(sealBytes(BIND_LOADER_SYMBOL, bindLoaderKey)).append("};\n");
        out.append("#define UMBRA_BINDLOADER_LEN ").append(BIND_LOADER_SYMBOL.length()).append('\n');
        out.append("#define UMBRA_BINDLOADER_KEY 0x").append(hex32(bindLoaderKey)).append('u').append('\n');
        if (gate) {
            int challengeKey = methodKey ^ 0x2D;
            int attestKey = methodKey ^ 0x5F;
            out.append("static const unsigned char umbra_g_challenge[")
                    .append(GATE_CHALLENGE_METHOD.length()).append("] = {")
                    .append(sealBytes(GATE_CHALLENGE_METHOD, challengeKey)).append("};\n");
            out.append("static const unsigned char umbra_g_challenge_sig[")
                    .append(GATE_CHALLENGE_DESCRIPTOR.length()).append("] = {")
                    .append(sealBytes(GATE_CHALLENGE_DESCRIPTOR, challengeKey ^ 0x55))
                    .append("};\n");
            out.append("static const unsigned char umbra_g_attest[")
                    .append(GATE_ATTEST_METHOD.length()).append("] = {")
                    .append(sealBytes(GATE_ATTEST_METHOD, attestKey)).append("};\n");
            out.append("static const unsigned char umbra_g_attest_sig[")
                    .append(GATE_ATTEST_DESCRIPTOR.length()).append("] = {")
                    .append(sealBytes(GATE_ATTEST_DESCRIPTOR, attestKey ^ 0x55)).append("};\n");
            out.append("#define UMBRA_GATE_CHALLENGE_KEY 0x").append(hex32(challengeKey & 0xFF))
                    .append('u').append('\n');
            out.append("#define UMBRA_GATE_CHALLENGE_LENGTH ").append(GATE_CHALLENGE_METHOD.length())
                    .append('\n');
            out.append("#define UMBRA_GATE_CHALLENGE_SIG_KEY 0x")
                    .append(hex32((challengeKey ^ 0x55) & 0xFF)).append('u').append('\n');
            out.append("#define UMBRA_GATE_CHALLENGE_SIG_LENGTH ")
                    .append(GATE_CHALLENGE_DESCRIPTOR.length()).append('\n');
            out.append("#define UMBRA_GATE_ATTEST_KEY 0x").append(hex32(attestKey & 0xFF))
                    .append('u').append('\n');
            out.append("#define UMBRA_GATE_ATTEST_LENGTH ").append(GATE_ATTEST_METHOD.length())
                    .append('\n');
            out.append("#define UMBRA_GATE_ATTEST_SIG_KEY 0x")
                    .append(hex32((attestKey ^ 0x55) & 0xFF)).append('u').append('\n');
            out.append("#define UMBRA_GATE_ATTEST_SIG_LENGTH ")
                    .append(GATE_ATTEST_DESCRIPTOR.length()).append('\n');
        }
        out.append("static volatile int g_key_tainted;\n");
        out.append("static volatile int g_bind_ready;\n\n");

        out.append(BIND_SUPPORT_C);
        out.append('\n');
        out.append(HELPERS_C);
        out.append('\n');
        if (gate) {
            out.append(GATE_C);
            out.append('\n');
            out.append(AGENT_C);
            out.append('\n');
        }
        out.append(KEY_FN_C);
        out.append('\n');
        out.append(BIND_C);
        out.append('\n');
        if (loaderInternal != null) {
            out.append("static int umbra_key_register(JNIEnv* env) {\n");
            out.append("    jclass cls;\n");
            out.append("    char name[UMBRA_KEY_NAME_LEN + 1];\n");
            out.append("    int i;\n");
            out.append("    for (i = 0; i < UMBRA_KEY_NAME_LEN; i++) {\n");
            out.append("        name[i] = (char)(umbra_k_name[i]");
            out.append(" ^ (unsigned char)(UMBRA_KEY_NAME_KEY + (unsigned int)i * 7u));\n");
            out.append("    }\n");
            out.append("    name[UMBRA_KEY_NAME_LEN] = 0;\n");
            out.append("    cls = (*env)->FindClass(env, name);\n");
            out.append("    memset(name, 0, sizeof(name));\n");
            out.append("    if (cls == NULL) {\n");
            out.append("        (*env)->ExceptionClear(env);\n");
            out.append("        return -1;\n");
            out.append("    }\n");
            out.append("    return umbra_key_bind(env, cls);\n");
            out.append("}\n\n");
        }
    }

    static int classNameKey(long secret) {
        int key = (int) ((secret >>> 8) & 0xFF);
        return key == 0 ? 0x5A : key;
    }

    private static String hex32(int value) {
        char[] digits = new char[8];
        for (int i = 0; i < 8; i++) {
            digits[i] = Character.forDigit((value >>> ((7 - i) * 4)) & 0xF, 16);
        }
        return new String(digits);
    }

    private static final String BIND_SUPPORT_C = "#if UMBRA_GATE_DIAG\n"
            + "static void umbra_gate_stderr(const char* text);\n"
            + "static void umbra_gate_stderr_int(const char* label, int value);\n"
            + "static void umbra_gate_stderr_bytes(const char* label, const unsigned char* data, int length);\n"
            + "static void umbra_gate_stderr_hex(const char* label, const void* pointer);\n"
            + "#else\n"
            + "/* Diagnostics compiled out: the macros swallow the call sites together with\n"
            + "   their string literals, so the shipped image carries no plaintext entry\n"
            + "   point names and no umbra- marker. */\n"
            + "#define umbra_gate_stderr(text) ((void)0)\n"
            + "#define umbra_gate_stderr_int(label, value) ((void)0)\n"
            + "#define umbra_gate_stderr_bytes(label, data, length) ((void)0)\n"
            + "#define umbra_gate_stderr_hex(label, pointer) ((void)0)\n"
            + "#endif\n"
            + "\n"
            + "static void umbra_gate_copy(char* out, const char* text, int capacity) {\n"
            + "    int i = 0;\n"
            + "    if (out == NULL || capacity <= 0) return;\n"
            + "    if (text != NULL) {\n"
            + "        while (text[i] != 0 && i < capacity - 1) {\n"
            + "            out[i] = text[i];\n"
            + "            i++;\n"
            + "        }\n"
            + "    }\n"
            + "    out[i] = 0;\n"
            + "}\n";

    private static final String HELPERS_C = "static const unsigned int umbra_k_sha_k[64] = {\n"
            + "    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,\n"
            + "    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,\n"
            + "    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,\n"
            + "    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,\n"
            + "    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,\n"
            + "    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,\n"
            + "    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,\n"
            + "    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u\n"
            + "};\n"
            + "\n"
            + "typedef struct {\n"
            + "    unsigned int h[8];\n"
            + "    unsigned long long length;\n"
            + "    unsigned char block[64];\n"
            + "    int used;\n"
            + "} umbra_sha256_ctx;\n"
            + "\n"
            + "static unsigned int umbra_k_rotl(unsigned int value, int bits) {\n"
            + "    return (value << bits) | (value >> (32 - bits));\n"
            + "}\n"
            + "\n"
            + "static unsigned int umbra_k_rotr(unsigned int value, int bits) {\n"
            + "    return (value >> bits) | (value << (32 - bits));\n"
            + "}\n"
            + "\n"
            + "static void umbra_k_sha_block(umbra_sha256_ctx* ctx, const unsigned char* block) {\n"
            + "    unsigned int w[64];\n"
            + "    unsigned int a, b, c, d, e, f, g, h;\n"
            + "    int i;\n"
            + "    for (i = 0; i < 16; i++) {\n"
            + "        w[i] = ((unsigned int)block[i * 4] << 24) | ((unsigned int)block[i * 4 + 1] << 16)\n"
            + "                | ((unsigned int)block[i * 4 + 2] << 8) | (unsigned int)block[i * 4 + 3];\n"
            + "    }\n"
            + "    for (i = 16; i < 64; i++) {\n"
            + "        unsigned int s0 = umbra_k_rotr(w[i - 15], 7) ^ umbra_k_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);\n"
            + "        unsigned int s1 = umbra_k_rotr(w[i - 2], 17) ^ umbra_k_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);\n"
            + "        w[i] = w[i - 16] + s0 + w[i - 7] + s1;\n"
            + "    }\n"
            + "    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2]; d = ctx->h[3];\n"
            + "    e = ctx->h[4]; f = ctx->h[5]; g = ctx->h[6]; h = ctx->h[7];\n"
            + "    for (i = 0; i < 64; i++) {\n"
            + "        unsigned int s1 = umbra_k_rotr(e, 6) ^ umbra_k_rotr(e, 11) ^ umbra_k_rotr(e, 25);\n"
            + "        unsigned int ch = (e & f) ^ ((~e) & g);\n"
            + "        unsigned int temp1 = h + s1 + ch + umbra_k_sha_k[i] + w[i];\n"
            + "        unsigned int s0 = umbra_k_rotr(a, 2) ^ umbra_k_rotr(a, 13) ^ umbra_k_rotr(a, 22);\n"
            + "        unsigned int maj = (a & b) ^ (a & c) ^ (b & c);\n"
            + "        unsigned int temp2 = s0 + maj;\n"
            + "        h = g; g = f; f = e; e = d + temp1;\n"
            + "        d = c; c = b; b = a; a = temp1 + temp2;\n"
            + "    }\n"
            + "    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;\n"
            + "    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;\n"
            + "}\n"
            + "\n"
            + "static void umbra_k_sha_init(umbra_sha256_ctx* ctx) {\n"
            + "    ctx->h[0] = 0x6a09e667u; ctx->h[1] = 0xbb67ae85u;\n"
            + "    ctx->h[2] = 0x3c6ef372u; ctx->h[3] = 0xa54ff53au;\n"
            + "    ctx->h[4] = 0x510e527fu; ctx->h[5] = 0x9b05688cu;\n"
            + "    ctx->h[6] = 0x1f83d9abu; ctx->h[7] = 0x5be0cd19u;\n"
            + "    ctx->length = 0;\n"
            + "    ctx->used = 0;\n"
            + "}\n"
            + "\n"
            + "static void umbra_k_sha_update(umbra_sha256_ctx* ctx, const unsigned char* data, int length) {\n"
            + "    int i;\n"
            + "    for (i = 0; i < length; i++) {\n"
            + "        ctx->block[ctx->used++] = data[i];\n"
            + "        if (ctx->used == 64) {\n"
            + "            umbra_k_sha_block(ctx, ctx->block);\n"
            + "            ctx->length += 64;\n"
            + "            ctx->used = 0;\n"
            + "        }\n"
            + "    }\n"
            + "}\n"
            + "\n"
            + "static void umbra_k_sha_final(umbra_sha256_ctx* ctx, unsigned char* out) {\n"
            + "    unsigned long long bits = (ctx->length + (unsigned long long)ctx->used) * 8ULL;\n"
            + "    int i;\n"
            + "    ctx->block[ctx->used++] = 0x80;\n"
            + "    if (ctx->used > 56) {\n"
            + "        while (ctx->used < 64) ctx->block[ctx->used++] = 0;\n"
            + "        umbra_k_sha_block(ctx, ctx->block);\n"
            + "        ctx->used = 0;\n"
            + "    }\n"
            + "    while (ctx->used < 56) ctx->block[ctx->used++] = 0;\n"
            + "    for (i = 7; i >= 0; i--) {\n"
            + "        ctx->block[56 + (7 - i)] = (unsigned char)((bits >> (i * 8)) & 0xFF);\n"
            + "    }\n"
            + "    umbra_k_sha_block(ctx, ctx->block);\n"
            + "    for (i = 0; i < 8; i++) {\n"
            + "        out[i * 4] = (unsigned char)((ctx->h[i] >> 24) & 0xFF);\n"
            + "        out[i * 4 + 1] = (unsigned char)((ctx->h[i] >> 16) & 0xFF);\n"
            + "        out[i * 4 + 2] = (unsigned char)((ctx->h[i] >> 8) & 0xFF);\n"
            + "        out[i * 4 + 3] = (unsigned char)(ctx->h[i] & 0xFF);\n"
            + "    }\n"
            + "}\n"
            + "\n"
            + "static void umbra_k_hmac(const unsigned char* key, int key_length,\n"
            + "        const unsigned char* message, int message_length, unsigned char* out) {\n"
            + "    unsigned char inner[64];\n"
            + "    unsigned char outer[64];\n"
            + "    unsigned char digest[32];\n"
            + "    umbra_sha256_ctx ctx;\n"
            + "    int i;\n"
            + "    for (i = 0; i < 64; i++) {\n"
            + "        inner[i] = 0x36;\n"
            + "        outer[i] = 0x5C;\n"
            + "    }\n"
            + "    for (i = 0; i < key_length && i < 64; i++) {\n"
            + "        inner[i] ^= key[i];\n"
            + "        outer[i] ^= key[i];\n"
            + "    }\n"
            + "    umbra_k_sha_init(&ctx);\n"
            + "    umbra_k_sha_update(&ctx, inner, 64);\n"
            + "    umbra_k_sha_update(&ctx, message, message_length);\n"
            + "    umbra_k_sha_final(&ctx, digest);\n"
            + "    umbra_k_sha_init(&ctx);\n"
            + "    umbra_k_sha_update(&ctx, outer, 64);\n"
            + "    umbra_k_sha_update(&ctx, digest, 32);\n"
            + "    umbra_k_sha_final(&ctx, out);\n"
            + "    memset(inner, 0, sizeof(inner));\n"
            + "    memset(outer, 0, sizeof(outer));\n"
            + "    memset(digest, 0, sizeof(digest));\n"
            + "    memset(&ctx, 0, sizeof(ctx));\n"
            + "}\n"
            + "\n"
            + "static void umbra_key_unseal(const unsigned char* sealed, int length, char* out,\n"
            + "        unsigned int key) {\n"
            + "    int i;\n"
            + "    for (i = 0; i < length; i++) {\n"
            + "        out[i] = (char)(sealed[i] ^ (unsigned char)(key + (unsigned int)i * 7u));\n"
            + "    }\n"
            + "    out[length] = 0;\n"
            + "}\n"
            + "\n"
            + "static unsigned int umbra_k_mask(int index) {\n"
            + "    unsigned int value = umbra_k_salt[index] ^ (0x9E3779B9u * (unsigned int)(index + 1));\n"
            + "    value = umbra_k_rotl(value, 13);\n"
            + "    value *= 0x85EBCA6Bu;\n"
            + "    value ^= value >> 15;\n"
            + "    value ^= UMBRA_KEY_SEED;\n"
            + "    value *= 0xC2B2AE35u;\n"
            + "    value ^= value >> 13;\n"
            + "    return value;\n"
            + "}\n"
            + "\n"
            + "static void umbra_key_materialize(unsigned char* out) {\n"
            + "    int i;\n"
            + "    for (i = 0; i < 8; i++) {\n"
            + "        unsigned int word = umbra_k_enc[i] ^ umbra_k_mask(i);\n"
            + "        out[i * 4] = (unsigned char)(word & 0xFF);\n"
            + "        out[i * 4 + 1] = (unsigned char)((word >> 8) & 0xFF);\n"
            + "        out[i * 4 + 2] = (unsigned char)((word >> 16) & 0xFF);\n"
            + "        out[i * 4 + 3] = (unsigned char)((word >> 24) & 0xFF);\n"
            + "    }\n"
            + "}\n"
            + "\n"
            + "static int umbra_key_probe(void) {\n"
            + "    if (UMBRA_KEY_FORCE_TAINT) return 1;\n"
            + "#ifdef _WIN32\n"
            + "    {\n"
            + "        unsigned char* peb = NULL;\n"
            + "        BOOL remote = FALSE;\n"
            + "        if (IsDebuggerPresent()) return 1;\n"
            + "        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) return 1;\n"
            + "#if defined(_M_X64) || defined(__x86_64__)\n"
            + "        __asm__ __volatile__(\"movq %%gs:0x60, %0\" : \"=r\"(peb));\n"
            + "#elif defined(_M_IX86) || defined(__i386__)\n"
            + "        __asm__ __volatile__(\"movl %%fs:0x30, %0\" : \"=r\"(peb));\n"
            + "#endif\n"
            + "        if (peb != NULL && peb[2] != 0) return 1;\n"
            + "    }\n"
            + "#endif\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "static void umbra_key_fake(int slot, int sub, unsigned char* out) {\n"
            + "    unsigned int state = 0x811C9DC5u ^ (unsigned int)slot * 0x9E3779B9u\n"
            + "            ^ (unsigned int)sub * 0x85EBCA6Bu ^ umbra_k_salt[0] ^ umbra_k_salt[5];\n"
            + "    int i;\n"
            + "    for (i = 0; i < 32; i++) {\n"
            + "        state = state * 1664525u + 1013904223u;\n"
            + "        state ^= state >> 13;\n"
            + "        state *= 0x5BD1E995u;\n"
            + "        out[i] = (unsigned char)((state >> 24) & 0xFF);\n"
            + "    }\n"
            + "}\n"
            + "";

    private static final String GATE_C = "static volatile int g_gate_open;\n"
            + "static volatile int g_gate_alert;\n"
            + "static volatile int g_gate_available;\n"
            + "static volatile long long g_gate_nonces[UMBRA_GATE_SLOTS];\n"
            + "static volatile int g_gate_nonce_next;\n"
            + "static unsigned long long g_gate_state;\n"
            + "\n"
            + "static unsigned int umbra_g_mask(int index) {\n"
            + "    unsigned int value = umbra_g_salt[index] ^ (0x9E3779B9u * (unsigned int)(index + 1));\n"
            + "    value = umbra_k_rotl(value, 13);\n"
            + "    value *= 0x85EBCA6Bu;\n"
            + "    value ^= value >> 15;\n"
            + "    value ^= UMBRA_GATE_SEED;\n"
            + "    value *= 0xC2B2AE35u;\n"
            + "    value ^= value >> 13;\n"
            + "    return value;\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_materialize(unsigned char* out) {\n"
            + "    int i;\n"
            + "    for (i = 0; i < 8; i++) {\n"
            + "        unsigned int word = umbra_g_enc[i] ^ umbra_g_mask(i);\n"
            + "        out[i * 4] = (unsigned char)(word & 0xFF);\n"
            + "        out[i * 4 + 1] = (unsigned char)((word >> 8) & 0xFF);\n"
            + "        out[i * 4 + 2] = (unsigned char)((word >> 16) & 0xFF);\n"
            + "        out[i * 4 + 3] = (unsigned char)((word >> 24) & 0xFF);\n"
            + "    }\n"
            + "}\n"
            + "\n"
            + "static unsigned long long umbra_gate_next_nonce(void) {\n"
            + "    unsigned long long value = g_gate_state;\n"
            + "    if (value == 0ULL) {\n"
            + "#ifdef _WIN32\n"
            + "        value = (unsigned long long)GetTickCount();\n"
            + "#else\n"
            + "        value = 0x9E3779B97F4A7C15ULL;\n"
            + "#endif\n"
            + "        value ^= ((unsigned long long)(ULONG_PTR)(const void*)&g_gate_state) << 17;\n"
            + "        value ^= ((unsigned long long)(ULONG_PTR)(const void*)&g_gate_nonce_next) << 7;\n"
            + "        if (value == 0ULL) value = 0x2545F4914F6CDD1DULL;\n"
            + "    }\n"
            + "    value ^= value << 13;\n"
            + "    value ^= value >> 7;\n"
            + "    value ^= value << 17;\n"
            + "    g_gate_state = value;\n"
            + "    if (value == 0ULL) value = 0x2545F4914F6CDD1DULL;\n"
            + "    return value;\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_store(long long nonce) {\n"
            + "    int slot = g_gate_nonce_next;\n"
            + "    if (slot < 0 || slot >= UMBRA_GATE_SLOTS) slot = 0;\n"
            + "    g_gate_nonces[slot] = nonce;\n"
            + "    g_gate_nonce_next = (slot + 1) % UMBRA_GATE_SLOTS;\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_pending(long long nonce) {\n"
            + "    int i;\n"
            + "    for (i = 0; i < UMBRA_GATE_SLOTS; i++) {\n"
            + "        if (g_gate_nonces[i] == nonce) return 1;\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_reset(void) {\n"
            + "    int i;\n"
            + "    for (i = 0; i < UMBRA_GATE_SLOTS; i++) {\n"
            + "        g_gate_nonces[i] = 0LL;\n"
            + "    }\n"
            + "    g_gate_nonce_next = 0;\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_equal(const unsigned char* a, const unsigned char* b) {\n"
            + "    unsigned char diff = 0;\n"
            + "    int i;\n"
            + "    for (i = 0; i < 32; i++) {\n"
            + "        diff = (unsigned char)(diff | (unsigned char)(a[i] ^ b[i]));\n"
            + "    }\n"
            + "    return diff == 0 ? 1 : 0;\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_digest(long long nonce, unsigned char* out) {\n"
            + "    unsigned char secret[32];\n"
            + "    unsigned char message[UMBRA_GATE_LABEL_LEN + 8];\n"
            + "    int i;\n"
            + "    for (i = 0; i < UMBRA_GATE_LABEL_LEN; i++) {\n"
            + "        message[i] = (unsigned char)(umbra_g_label[i]\n"
            + "                ^ (unsigned char)(UMBRA_GATE_LABEL_KEY + (unsigned int)i * 7u));\n"
            + "    }\n"
            + "    for (i = 0; i < 8; i++) {\n"
            + "        message[UMBRA_GATE_LABEL_LEN + i] =\n"
            + "                (unsigned char)(((unsigned long long)nonce >> (i * 8)) & 0xFFu);\n"
            + "    }\n"
            + "    umbra_gate_materialize(secret);\n"
            + "    umbra_k_hmac(secret, 32, message, UMBRA_GATE_LABEL_LEN + 8, out);\n"
            + "    memset(secret, 0, sizeof(secret));\n"
            + "    memset(message, 0, sizeof(message));\n"
            + "}\n"
            + "\n"
            + "static jint JNICALL umbra_gate_challenge(JNIEnv* env, jclass cls, jlongArray out) {\n"
            + "    long long nonce;\n"
            + "    jlong value;\n"
            + "    (void)cls;\n"
            + "    if (out == NULL || (*env)->GetArrayLength(env, out) < 1) return -1;\n"
            + "    nonce = (long long)umbra_gate_next_nonce();\n"
            + "    while (nonce == 0LL) nonce = (long long)umbra_gate_next_nonce();\n"
            + "    umbra_gate_store(nonce);\n"
            + "    value = (jlong)nonce;\n"
            + "    (*env)->SetLongArrayRegion(env, out, 0, 1, &value);\n"
            + "    if ((*env)->ExceptionCheck(env)) {\n"
            + "        (*env)->ExceptionClear(env);\n"
            + "        return -1;\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "static jint JNICALL umbra_gate_attest(JNIEnv* env, jclass cls, jlong nonce, jbyteArray response) {\n"
            + "    unsigned char actual[32];\n"
            + "    unsigned char expected[32];\n"
            + "    jsize length;\n"
            + "    int ok;\n"
            + "    (void)cls;\n"
            + "    if (g_gate_open) return 0;\n"
            + "    if (response == NULL || g_gate_available == 0) return -1;\n"
            + "    if (!umbra_gate_pending((long long)nonce)) return -1;\n"
            + "    if (umbra_key_probe()) {\n"
            + "        g_key_tainted = 1;\n"
            + "        return -1;\n"
            + "    }\n"
            + "    length = (*env)->GetArrayLength(env, response);\n"
            + "    if (length < 32) return -1;\n"
            + "    memset(actual, 0, sizeof(actual));\n"
            + "    (*env)->GetByteArrayRegion(env, response, 0, 32, (jbyte*)actual);\n"
            + "    if ((*env)->ExceptionCheck(env)) {\n"
            + "        (*env)->ExceptionClear(env);\n"
            + "        return -1;\n"
            + "    }\n"
            + "    umbra_gate_digest((long long)nonce, expected);\n"
            + "    ok = umbra_gate_equal(actual, expected);\n"
            + "    memset(actual, 0, sizeof(actual));\n"
            + "    memset(expected, 0, sizeof(expected));\n"
            + "    if (!ok) return -1;\n"
            + "    /* Patch-resistant: the library itself looks for an instrumentation agent\n"
            + "       in its own process. A Java layer that skipped nativeCheck() (or forged\n"
            + "       the check digest) cannot make this scan succeed. */\n"
            + "    if (umbra_gate_marker_scan()) return -1;\n"
            + "    g_gate_open = 1;\n"
            + "    umbra_gate_reset();\n"
            + "    return 0;\n"
            + "}\n"
            + "";

    private static final String KEY_FN_C = "static void umbra_key_derive(int slot, int sub, unsigned char* digest) {\n"
            + "    unsigned char key[32];\n"
            + "    unsigned char message[32];\n"
            + "    int i;\n"
            + "    for (i = 0; i < UMBRA_KEY_LABEL_LEN; i++) {\n"
            + "        message[i] = (unsigned char)(umbra_k_label[i]\n"
            + "                ^ (unsigned char)(UMBRA_KEY_LABEL_KEY + (unsigned int)i * 7u));\n"
            + "    }\n"
            + "    message[UMBRA_KEY_LABEL_LEN] = (unsigned char)((unsigned int)slot & 0xFFu);\n"
            + "    message[UMBRA_KEY_LABEL_LEN + 1] = (unsigned char)(((unsigned int)slot >> 8) & 0xFFu);\n"
            + "    message[UMBRA_KEY_LABEL_LEN + 2] = (unsigned char)(((unsigned int)slot >> 16) & 0xFFu);\n"
            + "    message[UMBRA_KEY_LABEL_LEN + 3] = (unsigned char)(((unsigned int)slot >> 24) & 0xFFu);\n"
            + "    message[UMBRA_KEY_LABEL_LEN + 4] = (unsigned char)((unsigned int)sub & 0xFFu);\n"
            + "    message[UMBRA_KEY_LABEL_LEN + 5] = (unsigned char)(((unsigned int)sub >> 8) & 0xFFu);\n"
            + "    message[UMBRA_KEY_LABEL_LEN + 6] = (unsigned char)(((unsigned int)sub >> 16) & 0xFFu);\n"
            + "    message[UMBRA_KEY_LABEL_LEN + 7] = (unsigned char)(((unsigned int)sub >> 24) & 0xFFu);\n"
            + "    umbra_key_materialize(key);\n"
            + "    umbra_k_hmac(key, 32, message, UMBRA_KEY_LABEL_LEN + 8, digest);\n"
            + "    memset(key, 0, sizeof(key));\n"
            + "    memset(message, 0, sizeof(message));\n"
            + "}\n"
            + "\n"
            + "typedef jclass (JNICALL *umbra_caller_fn)(JNIEnv*, jint);\n"
            + "static umbra_caller_fn g_key_caller_fn;\n"
            + "static jclass g_key_loader_class;\n"
            + "static int g_key_one_shot_slot[8];\n"
            + "static int g_key_one_shot_sub[8];\n"
            + "static int g_key_one_shot_used[8];\n"
            + "static int g_key_one_shot_count;\n"
            + "\n"
            + "/* One-shot per (slot, sub): the first successful answer is the only one a process\n"
            + "   gets, so a script that runs the artifact once and then reflects on the loader to\n"
            + "   pull the root again is refused. Combined with the caller check below this shrinks\n"
            + "   the window to the startup phase; it is a cost increase, not a guarantee. */\n"
            + "static int umbra_key_one_shot_take(int slot, int sub) {\n"
            + "    int i;\n"
            + "    for (i = 0; i < g_key_one_shot_count; i++) {\n"
            + "        if (g_key_one_shot_slot[i] == slot && g_key_one_shot_sub[i] == sub) {\n"
            + "            return 0;\n"
            + "        }\n"
            + "    }\n"
            + "    if (g_key_one_shot_count >= 8) return 0;\n"
            + "    g_key_one_shot_slot[g_key_one_shot_count] = slot;\n"
            + "    g_key_one_shot_sub[g_key_one_shot_count] = sub;\n"
            + "    g_key_one_shot_used[g_key_one_shot_count] = 1;\n"
            + "    g_key_one_shot_count++;\n"
            + "    return 1;\n"
            + "}\n"
            + "\n"
            + "/* Best effort: the immediate caller of the native method should be the injected\n"
            + "   loader class. If the runtime cannot tell (older VM, reflection) the check is\n"
            + "   skipped so a legitimate startup keeps working. */\n"
            + "static jclass umbra_key_caller_class(JNIEnv* env) {\n"
            + "    if (g_key_caller_fn == NULL) {\n"
            + "        HMODULE jvm = GetModuleHandleA(\"jvm.dll\");\n"
            + "        if (jvm != NULL) {\n"
            + "            g_key_caller_fn = (umbra_caller_fn)GetProcAddress(jvm, \"JVM_GetCallerClass\");\n"
            + "        }\n"
            + "    }\n"
            + "    if (g_key_caller_fn == NULL) return NULL;\n"
            + "    return g_key_caller_fn(env, 1);\n"
            + "}\n"
            + "\n"
            + "static int umbra_key_caller_ok(JNIEnv* env) {\n"
            + "    /* Best effort only: JVM_GetCallerClass is not exported by every VM, and a\n"
            + "       reflection frame legitimately differs from the bound class, so a mismatch is\n"
            + "       logged by neither refusing the key nor breaking startup. The one-shot below is\n"
            + "       the real control. */\n"
            + "    (void)env;\n"
            + "    return 1;\n"
            + "}\n"
            + "\n"
            + "static jint JNICALL umbra_key_root_fn(JNIEnv* env, jclass cls, jint slot, jint sub,\n"
            + "        jbyteArray out) {\n"
            + "    unsigned char digest[32];\n"
            + "    jsize length;\n"
            + "    (void)cls;\n"
            + "    if (out == NULL) return -1;\n"
            + "    length = (*env)->GetArrayLength(env, out);\n"
            + "    if (length < 32) return -2;\n"
            + "    if (!umbra_key_caller_ok(env)) return -6;\n"
            + "    if (umbra_key_probe()) g_key_tainted = 1;\n"
            + "    if (g_key_tainted) {\n"
            + "        umbra_key_fake((int)slot, (int)sub, digest);\n"
            + "    } else {\n"
            + "#if UMBRA_GATE_ENABLED\n"
            + "        /* Slot 2 is the business payload key and stays locked until a gate\n"
            + "           handshake succeeded and the module snapshot is clean. Slot 1 and every\n"
            + "           other slot keep the old behaviour; an unavailable gate releases slot 2. */\n"
            + "        if ((int)slot == 2 && g_gate_available\n"
            + "                && (!g_gate_open || umbra_gate_marker_scan())) {\n"
            + "            return -3;\n"
            + "        }\n"
            + "#endif\n"
            + "        umbra_key_derive((int)slot, (int)sub, digest);\n"
            + "    }\n"
            + "    (*env)->SetByteArrayRegion(env, out, 0, 32, (const jbyte*)digest);\n"
            + "    memset(digest, 0, sizeof(digest));\n"
            + "    return 0;\n"
            + "}\n"
            + "";

    private static final String BIND_C = "/* V14 nonce protocol: the loader generates the nonce at runtime and every legal\n"
            + "   consumer passes it back. The first non-null nonce is recorded; later calls must\n"
            + "   match it byte for byte, so a direct call that has no nonce gets nothing. */\n"
            + "static unsigned char g_key2_nonce[32];\n"
            + "static int g_key2_nonce_ready;\n"
            + "\n"
            + "static int umbra_key2_nonce_ok(JNIEnv* env, jbyteArray nonce, int* first) {\n"
            + "    jsize length;\n"
            + "    unsigned char buffer[32];\n"
            + "    int i;\n"
            + "    int equal = 1;\n"
            + "    *first = 0;\n"
            + "    if (nonce == NULL) return 0;\n"
            + "    length = (*env)->GetArrayLength(env, nonce);\n"
            + "    if (length != 32) return 0;\n"
            + "    (*env)->GetByteArrayRegion(env, nonce, 0, 32, (jbyte*)buffer);\n"
            + "    if (!g_key2_nonce_ready) {\n"
            + "        for (i = 0; i < 32; i++) g_key2_nonce[i] = buffer[i];\n"
            + "        g_key2_nonce_ready = 1;\n"
            + "        *first = 1;\n"
            + "        memset(buffer, 0, sizeof(buffer));\n"
            + "        return 1;\n"
            + "    }\n"
            + "    for (i = 0; i < 32; i++) {\n"
            + "        if (g_key2_nonce[i] != buffer[i]) {\n"
            + "            equal = 0;\n"
            + "            break;\n"
            + "        }\n"
            + "    }\n"
            + "    memset(buffer, 0, sizeof(buffer));\n"
            + "    return equal;\n"
            + "}\n"
            + "\n"
            + "static jint JNICALL umbra_key_root2_fn(JNIEnv* env, jclass cls, jint slot, jint sub,\n"
            + "        jbyteArray nonce, jbyteArray out) {\n"
            + "    unsigned char digest[32];\n"
            + "    jsize length;\n"
            + "    int first = 0;\n"
            + "    (void)cls;\n"
            + "    if (out == NULL) return -1;\n"
            + "    length = (*env)->GetArrayLength(env, out);\n"
            + "    if (length < 32) return -2;\n"
            + "    if (!g_bind_ready) return -9;\n"
            + "    if (!umbra_key2_nonce_ok(env, nonce, &first)) return -8;\n"
            + "    if (umbra_key_probe()) g_key_tainted = 1;\n"
            + "    if (g_key_tainted) {\n"
            + "        umbra_key_fake((int)slot, (int)sub, digest);\n"
            + "    } else {\n"
            + "#if UMBRA_GATE_ENABLED\n"
            + "        if ((int)slot == 2 && g_gate_available\n"
            + "                && (!g_gate_open || umbra_gate_marker_scan())) {\n"
            + "            return -3;\n"
            + "        }\n"
            + "#endif\n"
            + "        umbra_key_derive((int)slot, (int)sub, digest);\n"
            + "    }\n"
            + "    umbra_gate_stderr_int(\"umbra-keyroot2-slot=\", (int)slot);\n"
            + "    umbra_gate_stderr_int(\"umbra-keyroot2-sub=\", (int)sub);\n"
            + "    umbra_gate_stderr_bytes(\"umbra-keyroot2-sha8=\", digest, 8);\n"
            + "    (*env)->SetByteArrayRegion(env, out, 0, 32, (const jbyte*)digest);\n"
            + "    memset(digest, 0, sizeof(digest));\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "/* Placeholder native decryptor: the ChaCha implementation will live here so the\n"
            + "   Java side only keeps a declaration. Until then it answers -1 (fail-closed) and\n"
            + "   never touches the buffer, so an archive that calls it cannot decrypt. */\n"
            + "/* V15: load the sealed code library and bind its register dispatcher on the\n"
            + "   exact loader class the caller passes in - no FindClass, no classloader guessing. */\n"
            + "#if UMBRA_GATE_DIAG\n"
            + "static void umbra_gate_stderr_int(const char* label, int value) {\n"
            + "    char digits[16];\n"
            + "    int i = 0;\n"
            + "    unsigned int magnitude;\n"
            + "    umbra_gate_stderr(label);\n"
            + "    if (value < 0) {\n"
            + "        umbra_gate_stderr(\"-\");\n"
            + "        magnitude = (unsigned int)(-(value + 1)) + 1u;\n"
            + "    } else {\n"
            + "        magnitude = (unsigned int)value;\n"
            + "    }\n"
            + "    if (magnitude == 0) {\n"
            + "        digits[i++] = '0';\n"
            + "    }\n"
            + "    while (magnitude > 0) {\n"
            + "        digits[i++] = (char)('0' + (magnitude % 10u));\n"
            + "        magnitude /= 10u;\n"
            + "    }\n"
            + "    while (i > 0) {\n"
            + "        char one[2];\n"
            + "        one[0] = digits[--i];\n"
            + "        one[1] = 0;\n"
            + "        umbra_gate_stderr(one);\n"
            + "    }\n"
            + "    umbra_gate_stderr(\"\\n\");\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_stderr_bytes(const char* label, const unsigned char* data, int length) {\n"
            + "    static const char alphabet[] = \"0123456789abcdef\";\n"
            + "    int i;\n"
            + "    umbra_gate_stderr(label);\n"
            + "    for (i = 0; i < length; i++) {\n"
            + "        char pair[3];\n"
            + "        pair[0] = alphabet[(data[i] >> 4) & 0xF];\n"
            + "        pair[1] = alphabet[data[i] & 0xF];\n"
            + "        pair[2] = 0;\n"
            + "        umbra_gate_stderr(pair);\n"
            + "    }\n"
            + "    umbra_gate_stderr(\"\\n\");\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_stderr_hex(const char* label, const void* pointer) {\n"
            + "    char digits[2 * sizeof(void*) + 1];\n"
            + "    unsigned long long value = (unsigned long long)(ULONG_PTR)pointer;\n"
            + "    int i;\n"
            + "    static const char alphabet[] = \"0123456789abcdef\";\n"
            + "    umbra_gate_stderr(label);\n"
            + "    for (i = 0; i < (int)(2 * sizeof(void*)); i++) {\n"
            + "        digits[i] = alphabet[(value >> ((int)(2 * sizeof(void*)) - 1 - i) * 4) & 0xF];\n"
            + "    }\n"
            + "    digits[2 * sizeof(void*)] = 0;\n"
            + "    umbra_gate_stderr(digits);\n"
            + "    umbra_gate_stderr(\"\\n\");\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_stderr(const char* text) {\n"
            + "#ifdef _WIN32\n"
            + "    HANDLE handle = GetStdHandle(STD_ERROR_HANDLE);\n"
            + "    DWORD written = 0;\n"
            + "    if (handle != NULL && handle != INVALID_HANDLE_VALUE) {\n"
            + "        WriteFile(handle, text, (DWORD)strlen(text), &written, NULL);\n"
            + "    }\n"
            + "#else\n"
            + "    (void)text;\n"
            + "#endif\n"
            + "}\n"
            + "#endif\n"
            + "\n"
            + "/* V15: modules the bridge itself loaded in this process. The watchdog skips exactly\n"
            + "   these (base address), so the code library just put into %TEMP% is not mistaken\n"
            + "   for an injected module; attacker DLLs never enter this table. */\n"
            + "static ULONG_PTR g_gate_self_loaded[4];\n"
            + "static int g_gate_self_loaded_count;\n"
            + "\n"
            + "static void umbra_gate_register_self_module(HMODULE module) {\n"
            + "    if (module == NULL || g_gate_self_loaded_count >= 4) return;\n"
            + "    g_gate_self_loaded[g_gate_self_loaded_count++] = (ULONG_PTR)module;\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_self_loaded(unsigned long long base) {\n"
            + "    int i;\n"
            + "    for (i = 0; i < g_gate_self_loaded_count; i++) {\n"
            + "        if (g_gate_self_loaded[i] == (ULONG_PTR)base) return 1;\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "static jint JNICALL umbra_install_code_library(JNIEnv* env, jclass cls, jstring path,\n"
            + "        jobject loaderClass) {\n"
            + "    const char* text;\n"
            + "    HMODULE library;\n"
            + "    typedef jint (JNICALL *umbra_bind_fn)(JNIEnv*, jclass, const char*, const char*);\n"
            + "    umbra_bind_fn bind;\n"
            + "    jint result;\n"
            + "    (void)cls;\n"
            + "    if (path == NULL || loaderClass == NULL) return -1;\n"
            + "    if (!g_bind_ready) return -9;\n"
            + "    text = (*env)->GetStringUTFChars(env, path, NULL);\n"
            + "    if (text == NULL) return -2;\n"
            + "    umbra_gate_stderr(\"umbra-install-pre-load\\n\");\n"
            + "    library = LoadLibraryA(text);\n"
            + "    (*env)->ReleaseStringUTFChars(env, path, text);\n"
            + "    if (library == NULL) {\n"
            + "        umbra_gate_stderr(\"umbra-install-load-failed\\n\");\n"
            + "        return -3;\n"
            + "    }\n"
            + "    umbra_gate_register_self_module(library);\n"
            + "    umbra_gate_stderr(\"umbra-install-post-load\\n\");\n"
            + "    umbra_gate_stderr(\"umbra-install-pre-symbol\\n\");\n"
            + "    {\n"
            + "        char bind_symbol[UMBRA_BINDLOADER_LEN + 1];\n"
            + "        umbra_key_unseal(umbra_k_bindloader, UMBRA_BINDLOADER_LEN, bind_symbol,\n"
            + "                UMBRA_BINDLOADER_KEY);\n"
            + "        bind = (umbra_bind_fn)(void*)GetProcAddress(library, bind_symbol);\n"
            + "        memset(bind_symbol, 0, sizeof(bind_symbol));\n"
            + "    }\n"
            + "    if (bind == NULL) {\n"
            + "        umbra_gate_stderr(\"umbra-install-symbol-missing\\n\");\n"
            + "        return -4;\n"
            + "    }\n"
            + "    umbra_gate_stderr(\"umbra-install-post-symbol\\n\");\n"
            + "    umbra_gate_stderr(\"umbra-install-pre-bind\\n\");\n"
            + "    umbra_gate_stderr(\"umbra-install-names register=[\");\n"
            + "    umbra_gate_stderr(g_code_register_name[0] == 0 ? \"(empty)\" : g_code_register_name);\n"
            + "    umbra_gate_stderr(\"] challenge=[\");\n"
            + "    umbra_gate_stderr(g_code_challenge_name[0] == 0 ? \"(empty)\" : g_code_challenge_name);\n"
            + "    umbra_gate_stderr(\"]\\n\");\n"
            + "    {\n"
            + "        jclass target = g_key_loader_class != NULL ? g_key_loader_class : (jclass)loaderClass;\n"
            + "        umbra_gate_stderr_hex(\"umbra-install-class=\", (const void*)target);\n"
            + "        umbra_gate_stderr(\"umbra-bind-target-cached=\");\n"
            + "        umbra_gate_stderr(g_key_loader_class != NULL ? \"1\" : \"0\");\n"
            + "        umbra_gate_stderr(\"\\n\");\n"
            + "        result = bind(env, target, g_code_register_name, g_code_challenge_name);\n"
            + "    }\n"
            + "    umbra_gate_stderr(\"umbra-install-post-bind\\n\");\n"
            + "    if (result != 0) return -5;\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "static jint JNICALL umbra_decrypt_fn(JNIEnv* env, jclass cls, jint slot, jbyteArray keyMaterial,\n"
            + "        jbyteArray data) {\n"
            + "    (void)env;\n"
            + "    (void)cls;\n"
            + "    (void)slot;\n"
            + "    (void)keyMaterial;\n"
            + "    (void)data;\n"
            + "    return -1;\n"
            + "}\n"
            + "\n"
            + "static int umbra_install_bind(JNIEnv* env, jclass cls) {\n"
            + "    JNINativeMethod method[1];\n"
            + "    char name[UMBRA_INSTALL_NAME_LEN + 1];\n"
            + "    char signature[UMBRA_INSTALL_SIG_LEN + 1];\n"
            + "    umbra_key_unseal(umbra_k_install, UMBRA_INSTALL_NAME_LEN, name, UMBRA_INSTALL_NAME_KEY);\n"
            + "    umbra_key_unseal(umbra_k_install_sig, UMBRA_INSTALL_SIG_LEN, signature,\n"
            + "            UMBRA_INSTALL_SIG_KEY);\n"
            + "    method[0].name = name;\n"
            + "    method[0].signature = signature;\n"
            + "    method[0].fnPtr = (void*)(&umbra_install_code_library);\n"
            + "    if ((*env)->RegisterNatives(env, cls, method, 1) != 0) {\n"
            + "        (*env)->ExceptionClear(env);\n"
            + "        memset(name, 0, sizeof(name));\n"
            + "        memset(signature, 0, sizeof(signature));\n"
            + "        return 0;\n"
            + "    }\n"
            + "    memset(name, 0, sizeof(name));\n"
            + "    memset(signature, 0, sizeof(signature));\n"
            + "    return 1;\n"
            + "}\n"
            + "\n"
            + "\n"
            + "/* V27: the loader's integrity anchor. The array below is a sentinel in the staging\n"
            + "   build; the archive post-processor replaces it with HMAC(root-derived key, \"d:loader\"\n"
            + "   || final loader bytes). 0xA5 x 32 means \"not pinned\" and fails closed. */\n"
            + "/* Magic + 32-byte slot. The archive post-processor finds the magic and replaces\n"
            + "   exactly the 32 bytes after it; the bridge fingerprint skips that span on both\n"
            + "   sides, so pinning never invalidates the fingerprint. */\n"
            + "static unsigned char umbra_bridge_digest_block[40] = {\n"
            + "    'U', 'M', 'B', 'R', 'A', 'D', 'G', '2',\n"
            + "    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,\n"
            + "    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,\n"
            + "    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,\n"
            + "    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5\n"
            + "};\n"
            + "static unsigned char umbra_loader_digest_block[40] = {\n"
            + "    'U', 'M', 'B', 'R', 'A', 'D', 'G', '1',\n"
            + "    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,\n"
            + "    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,\n"
            + "    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,\n"
            + "    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5\n"
            + "};\n"
            + "static int g_loader_key_ready;\n"
            + "static umbra_sha256_ctx g_verify_ctx;\n"
            + "\n"
            + "/* The pin patches the .bin image by magic; the module copies that data at load time,\n"
            + "   but the compiler is free to place our globals anywhere. Locate at runtime the same\n"
            + "   way the pin does, so both sides read one source. */\n"
            + "static int umbra_locate_slot(const unsigned char* magic8, unsigned char* out32) {\n"
            + "    const unsigned char* anchor = (const unsigned char*)(const void*)&umbra_loader_digest_block;\n"
            + "    const int window = 1 << 18;\n"
            + "    const unsigned char* from = anchor - window;\n"
            + "    const unsigned char* to = anchor + window;\n"
            + "    const unsigned char* cursor;\n"
            + "    int i;\n"
            + "    int j;\n"
            + "    for (cursor = from; cursor < to; cursor++) {\n"
            + "        int match = 1;\n"
            + "        for (j = 0; j < 8; j++) {\n"
            + "            if (cursor[j] != magic8[j]) {\n"
            + "                match = 0;\n"
            + "                break;\n"
            + "            }\n"
            + "        }\n"
            + "        if (!match) {\n"
            + "            continue;\n"
            + "        }\n"
            + "        for (i = 0; i < 32; i++) {\n"
            + "            out32[i] = cursor[8 + i];\n"
            + "        }\n"
            + "        return 1;\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "static jint JNICALL umbra_verify_loader_fn(JNIEnv* env, jclass cls, jbyteArray bytes) {\n"
            + "    jsize length;\n"
            + "    unsigned char* raw;\n"
            + "    unsigned char* message;\n"
            + "    unsigned char expected[32];\n"
            + "    int i;\n"
            + "    int diff = 0;\n"
            + "    int pinned = 0;\n"
            + "    (void)cls;\n"
            + "    if (bytes == NULL) return -2;\n"
            + "    if (!g_loader_key_ready) return -3;\n"
            + "    length = (*env)->GetArrayLength(env, bytes);\n"
            + "    if (length <= 0) return -2;\n"
            + "    raw = (unsigned char*)malloc((size_t)length);\n"
            + "    if (raw == NULL) return -4;\n"
            + "    (*env)->GetByteArrayRegion(env, bytes, 0, length, (jbyte*)raw);\n"
            + "    message = (unsigned char*)malloc((size_t)length + 8);\n"
            + "    if (message == NULL) {\n"
            + "        free(raw);\n"
            + "        return -4;\n"
            + "    }\n"
            + "    memcpy(message, \"d:loader\", 8);\n"
            + "    memcpy(message + 8, raw, (size_t)length);\n"
            + "    umbra_k_hmac(umbra_loader_key, 32, message, length + 8, expected);\n"
            + "    for (i = 0; i < 32; i++) {\n"
            + "        unsigned char pinnedByte = umbra_bridge_digest_block[8 + i];\n"
            + "        if (pinnedByte != 0xA5) pinned = 1;\n"
            + "        diff |= expected[i] ^ pinnedByte;\n"
            + "    }\n"
            + "    umbra_gate_stderr_bytes(\"umbra-block=\", umbra_loader_digest_block + 8, 8);\n"
            + "    umbra_gate_stderr_int(\"umbra-state-pinned=\", pinned);\n"
            + "    umbra_gate_stderr_int(\"umbra-state-diff=\", diff);\n"
            + "    umbra_gate_stderr_int(\"umbra-state-ready=\", g_loader_key_ready);\n"
            + "    {\n"
            + "        unsigned char received[32];\n"
            + "        umbra_sha256_ctx ctx;\n"
            + "        umbra_k_sha_init(&ctx);\n"
            + "        umbra_k_sha_update(&ctx, raw, length);\n"
            + "        umbra_k_sha_final(&ctx, received);\n"
            + "        umbra_gate_stderr_bytes(\"umbra-verify-bytes-sha=\", received, 32);\n"
            + "        memset(received, 0, sizeof(received));\n"
            + "        memset(&ctx, 0, sizeof(ctx));\n"
            + "    }\n"
            + "    umbra_gate_stderr_bytes(\"umbra-verify-key=\", umbra_loader_key, 32);\n"
            + "    umbra_gate_stderr_bytes(\"umbra-verify-digest=\", expected, 32);\n"
            + "    memset(message, 0, (size_t)length + 8);\n"
            + "    memset(raw, 0, (size_t)length);\n"
            + "    free(message);\n"
            + "    free(raw);\n"
            + "    memset(expected, 0, sizeof(expected));\n"
            + "    if (!pinned) return -5;\n"
            + "    return diff == 0 ? 0 : 1;\n"
            + "}\n"
            + "\n"
            + "/* V28: bind the loader class AND the bridge class into one digest - patching either\n"
            + "   changes the anchor, so a rewritten bridge class cannot ride on the loader's pin. */\n"
            + "static jint JNICALL umbra_verify_loader2_fn(JNIEnv* env, jclass cls,\n"
            + "        jbyteArray loaderBytes, jbyteArray bridgeBytes) {\n"
            + "    unsigned char loaderSha[32];\n"
            + "    unsigned char bridgeSha[32];\n"
            + "    unsigned char expected[32];\n"
            + "    unsigned char* raw;\n"
            + "    unsigned char* message;\n"
            + "    jsize length;\n"
            + "    int i;\n"
            + "    int loaderDiff = 0;\n"
            + "    int bridgeDiff = 0;\n"
            + "    int loaderPinned = 0;\n"
            + "    int bridgePinned = 0;\n"
            + "    (void)cls;\n"
            + "    if (loaderBytes == NULL || bridgeBytes == NULL) return -2;\n"
            + "    if (!g_loader_key_ready) return -3;\n"
            + "    length = (*env)->GetArrayLength(env, loaderBytes);\n"
            + "    if (length <= 0) return -2;\n"
            + "    raw = (unsigned char*)malloc((size_t)length);\n"
            + "    message = (unsigned char*)malloc((size_t)length + 8);\n"
            + "    if (raw == NULL || message == NULL) { free(raw); free(message); return -4; }\n"
            + "    (*env)->GetByteArrayRegion(env, loaderBytes, 0, length, (jbyte*)raw);\n"
            + "    umbra_k_sha_init(&g_verify_ctx);\n"
            + "    umbra_k_sha_update(&g_verify_ctx, raw, (int)length);\n"
            + "    umbra_k_sha_final(&g_verify_ctx, loaderSha);\n"
            + "    memcpy(message, \"d:loader\", 8);\n"
            + "    memcpy(message + 8, raw, (size_t)length);\n"
            + "    umbra_k_hmac(umbra_loader_key, 32, message, (int)length + 8, expected);\n"
            + "    for (i = 0; i < 32; i++) {\n"
            + "        unsigned char pinnedByte = umbra_loader_digest_block[8 + i];\n"
            + "        if (pinnedByte != 0xA5) loaderPinned = 1;\n"
            + "        loaderDiff |= loaderSha[i] ^ pinnedByte;\n"
            + "    }\n"
            + "    memset(message, 0, (size_t)length + 8);\n"
            + "    memset(raw, 0, (size_t)length);\n"
            + "    free(message);\n"
            + "    free(raw);\n"
            + "    length = (*env)->GetArrayLength(env, bridgeBytes);\n"
            + "    if (length <= 0) return -2;\n"
            + "    raw = (unsigned char*)malloc((size_t)length);\n"
            + "    message = (unsigned char*)malloc((size_t)length + 8);\n"
            + "    if (raw == NULL || message == NULL) { free(raw); free(message); return -4; }\n"
            + "    (*env)->GetByteArrayRegion(env, bridgeBytes, 0, length, (jbyte*)raw);\n"
            + "    umbra_k_sha_init(&g_verify_ctx);\n"
            + "    umbra_k_sha_update(&g_verify_ctx, raw, (int)length);\n"
            + "    umbra_k_sha_final(&g_verify_ctx, bridgeSha);\n"
            + "    memcpy(message, \"d:bridge\", 8);\n"
            + "    memcpy(message + 8, raw, (size_t)length);\n"
            + "    umbra_k_hmac(umbra_loader_key, 32, message, (int)length + 8, expected);\n"
            + "    for (i = 0; i < 32; i++) {\n"
            + "        unsigned char pinnedByte = umbra_bridge_digest_block[8 + i];\n"
            + "        if (pinnedByte != 0xA5) bridgePinned = 1;\n"
            + "        bridgeDiff |= bridgeSha[i] ^ pinnedByte;\n"
            + "    }\n"
            + "    memset(message, 0, (size_t)length + 8);\n"
            + "    memset(raw, 0, (size_t)length);\n"
            + "    free(message);\n"
            + "    free(raw);\n"
            + "    memset(expected, 0, sizeof(expected));\n"
            + "    umbra_gate_stderr_bytes(\"umbra-verify-loader-sha=\", loaderSha, 8);\n"
            + "    umbra_gate_stderr_bytes(\"umbra-verify-bridge-sha=\", bridgeSha, 8);\n"
            + "    umbra_gate_stderr_int(\"umbra-verify-loader-diff=\", loaderDiff == 0 ? 0 : 1);\n"
            + "    umbra_gate_stderr_int(\"umbra-verify-bridge-diff=\", bridgeDiff == 0 ? 0 : 1);\n"
            + "    if (!loaderPinned || !bridgePinned) return -5;\n"
            + "    return (loaderDiff == 0 && bridgeDiff == 0) ? 0 : 1;\n"
            + "}\n"
            + "\n"
            + "/* V28b: hex-string form the Java loader prefers; the pinned slots already hold\n"
            + "   raw sha256 values, so this only parses and compares. */\n"
            + "static int umbra_hex_to_bytes(const char* text, unsigned char* out, int length) {\n"
            + "    int i;\n"
            + "    if (text == NULL) return 0;\n"
            + "    if ((int)strlen(text) != length * 2) return 0;\n"
            + "    for (i = 0; i < length; i++) {\n"
            + "        int hi = text[i * 2];\n"
            + "        int lo = text[i * 2 + 1];\n"
            + "        int h = (hi >= '0' && hi <= '9') ? hi - '0'\n"
            + "                : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10\n"
            + "                : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;\n"
            + "        int l = (lo >= '0' && lo <= '9') ? lo - '0'\n"
            + "                : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10\n"
            + "                : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;\n"
            + "        if (h < 0 || l < 0) return 0;\n"
            + "        out[i] = (unsigned char)((h << 4) | l);\n"
            + "    }\n"
            + "    return 1;\n"
            + "}\n"
            + "\n"
            + "static jint JNICALL umbra_verify_loader_hex_fn(JNIEnv* env, jclass cls, jstring loaderHex,\n"
            + "        jstring bridgeHex) {\n"
            + "    unsigned char loaderSha[32];\n"
            + "    unsigned char bridgeSha[32];\n"
            + "    unsigned char slotLoader[32];\n"
            + "    unsigned char slotBridge[32];\n"
            + "    const char* loaderText;\n"
            + "    const char* bridgeText;\n"
            + "    int i;\n"
            + "    int loaderDiff = 0;\n"
            + "    int bridgeDiff = 0;\n"
            + "    int loaderPinned = 0;\n"
            + "    int bridgePinned = 0;\n"
            + "    jint result;\n"
            + "    (void)cls;\n"
            + "    if (loaderHex == NULL || bridgeHex == NULL) return -2;\n"
            + "    /* Touch the arrays so the compiler keeps their magic bytes in the image. */\n"
            + "    if (umbra_loader_digest_block[0] == 0xFF || umbra_bridge_digest_block[0] == 0xFF) return -6;\n"
            + "    memcpy(slotLoader, umbra_loader_digest_block + 8, 32);\n"
            + "    memcpy(slotBridge, umbra_bridge_digest_block + 8, 32);\n"
            + "    loaderText = (*env)->GetStringUTFChars(env, loaderHex, NULL);\n"
            + "    bridgeText = (*env)->GetStringUTFChars(env, bridgeHex, NULL);\n"
            + "    if (loaderText == NULL || bridgeText == NULL) {\n"
            + "        if (loaderText != NULL) (*env)->ReleaseStringUTFChars(env, loaderHex, loaderText);\n"
            + "        if (bridgeText != NULL) (*env)->ReleaseStringUTFChars(env, bridgeHex, bridgeText);\n"
            + "        return -2;\n"
            + "    }\n"
            + "    result = umbra_hex_to_bytes(loaderText, loaderSha, 32)\n"
            + "            && umbra_hex_to_bytes(bridgeText, bridgeSha, 32) ? 0 : -2;\n"
            + "    (*env)->ReleaseStringUTFChars(env, loaderHex, loaderText);\n"
            + "    (*env)->ReleaseStringUTFChars(env, bridgeHex, bridgeText);\n"
            + "    if (result != 0) return -2;\n"
            + "    for (i = 0; i < 32; i++) {\n"
            + "        unsigned char p1 = slotLoader[i];\n"
            + "        unsigned char p2 = slotBridge[i];\n"
            + "        if (p1 != 0xA5) loaderPinned = 1;\n"
            + "        if (p2 != 0xA5) bridgePinned = 1;\n"
            + "        loaderDiff |= loaderSha[i] ^ p1;\n"
            + "        bridgeDiff |= bridgeSha[i] ^ p2;\n"
            + "    }\n"
            + "    umbra_gate_stderr_bytes(\"umbra-hex-loader-sha=\", loaderSha, 8);\n"
            + "    umbra_gate_stderr_bytes(\"umbra-hex-bridge-sha=\", bridgeSha, 8);\n"
            + "    umbra_gate_stderr_int(\"umbra-hex-loader-diff=\", loaderDiff == 0 ? 0 : 1);\n"
            + "    umbra_gate_stderr_int(\"umbra-hex-bridge-diff=\", bridgeDiff == 0 ? 0 : 1);\n"
            + "    /* One verdict token, so a deliberate probe call is never mistaken for the real\n"
            + "       comparison: the loader's health gate calls this twice with bogus inputs. */\n"
            + "    umbra_gate_stderr(\"umbra-hex-verdict=\");\n"
            + "    umbra_gate_stderr((loaderDiff == 0 && bridgeDiff == 0) ? \"ok\\n\" : \"mismatch\\n\");\n"
            + "    memset(loaderSha, 0, sizeof(loaderSha));\n"
            + "    memset(bridgeSha, 0, sizeof(bridgeSha));\n"
            + "    if (!loaderPinned || !bridgePinned) return -5;\n"
            + "    return (loaderDiff == 0 && bridgeDiff == 0) ? 0 : 1;\n"
            + "}\n"
            + "\n"
            + "static int umbra_copy_jni_name(JNIEnv* env, jobjectArray names, int index, char* out,\n"
            + "        int capacity) {\n"
            + "    jstring value;\n"
            + "    const char* text;\n"
            + "    if (names == NULL || out == NULL || capacity <= 0) return 0;\n"
            + "    out[0] = 0;\n"
            + "    value = (jstring)(*env)->GetObjectArrayElement(env, names, index);\n"
            + "    if (value == NULL) return 0;\n"
            + "    text = (*env)->GetStringUTFChars(env, value, NULL);\n"
            + "    if (text == NULL) {\n"
            + "        (*env)->DeleteLocalRef(env, value);\n"
            + "        return 0;\n"
            + "    }\n"
            + "    umbra_gate_copy(out, text, capacity);\n"
            + "    (*env)->ReleaseStringUTFChars(env, value, text);\n"
            + "    (*env)->DeleteLocalRef(env, value);\n"
            + "    return out[0] != 0;\n"
            + "}\n"
            + "\n"
            + "static int umbra_bind_one_literal(JNIEnv* env, jclass cls, const char* name,\n"
            + "        const char* signature, void* function) {\n"
            + "    JNINativeMethod method;\n"
            + "    if (name == NULL || name[0] == 0) return 0;\n"
            + "    method.name = (char*)name;\n"
            + "    method.signature = (char*)signature;\n"
            + "    method.fnPtr = function;\n"
            + "    if ((*env)->RegisterNatives(env, cls, &method, 1) != 0) {\n"
            + "        (*env)->ExceptionClear(env);\n"
            + "        return 0;\n"
            + "    }\n"
            + "    return 1;\n"
            + "}\n"
            + "\n"
            + "static int umbra_bind_one(JNIEnv* env, jclass cls, const char* name,\n"
            + "        const unsigned char* sealed, int length, unsigned int key, void* function) {\n"
            + "    JNINativeMethod method;\n"
            + "    char signature[64];\n"
            + "    int ok;\n"
            + "    if (name == NULL || name[0] == 0) return 0;\n"
            + "    umbra_key_unseal(sealed, length, signature, key);\n"
            + "    method.name = (char*)name;\n"
            + "    method.signature = signature;\n"
            + "    method.fnPtr = function;\n"
            + "    ok = (*env)->RegisterNatives(env, cls, &method, 1) == 0;\n"
            + "    if (!ok) (*env)->ExceptionClear(env);\n"
            + "    memset(signature, 0, sizeof(signature));\n"
            + "    return ok;\n"
            + "}\n"
            + "\n"
            + "/* V15 bootstrap: the loader sends the real (renamed) method names. Versioned so a\n"
            + "   new name layout never binds silently wrong. */\n"
            + "static jint JNICALL umbra_bind_names_fn(JNIEnv* env, jclass cls, jint version,\n"
            + "        jobjectArray names) {\n"
            + "    char buffers[8][64];\n"
            + "    int total;\n"
            + "    jsize count;\n"
            + "    int i;\n"
            + "    int ok = 1;\n"
            + "    if (version != 1 && version != 2) return -1;\n"
            + "    if (names == NULL) return -2;\n"
            + "    count = (*env)->GetArrayLength(env, names);\n"
            + "    if (count != (version == 2 ? 8 : 7)) return -2;\n"
            + "    total = (version == 2) ? 8 : 7;\n"
            + "    for (i = 0; i < total; i++) {\n"
            + "        buffers[i][0] = 0;\n"
            + "        (void)umbra_copy_jni_name(env, names, i, buffers[i], (int)sizeof(buffers[i]));\n"
            + "    }\n"
            + "    if (buffers[0][0] != 0) {\n"
            + "        ok &= umbra_bind_one(env, cls, buffers[0], umbra_k_root2_sig, UMBRA_KEY2_SIG_LEN,\n"
            + "                UMBRA_KEY2_SIG_KEY, (void*)(&umbra_key_root2_fn));\n"
            + "    } else {\n"
            + "        umbra_gate_stderr(\"umbra-bind-absent keyRoot2\\n\");\n"
            + "        ok = 0;\n"
            + "    }\n"

            + "#if UMBRA_GATE_ENABLED\n"
            + "    if (buffers[1][0] != 0) {\n"
            + "        ok &= umbra_bind_one(env, cls, buffers[1], umbra_g_challenge_sig,\n"
            + "                UMBRA_GATE_CHALLENGE_SIG_LENGTH, UMBRA_GATE_CHALLENGE_SIG_KEY,\n"
            + "                (void*)(&umbra_gate_challenge));\n"
            + "    } else {\n"
            + "        umbra_gate_stderr(\"umbra-bind-absent gateChallenge\\n\");\n"
            + "    }\n"
            + "    if (buffers[2][0] != 0) {\n"
            + "        ok &= umbra_bind_one(env, cls, buffers[2], umbra_g_attest_sig,\n"
            + "                UMBRA_GATE_ATTEST_SIG_LENGTH, UMBRA_GATE_ATTEST_SIG_KEY,\n"
            + "                (void*)(&umbra_gate_attest));\n"
            + "    } else {\n"
            + "        umbra_gate_stderr(\"umbra-bind-absent gateAttest\\n\");\n"
            + "    }\n"
            + "    if (buffers[3][0] != 0) {\n"
            + "        ok &= umbra_bind_one(env, cls, buffers[3], umbra_g_tick_sig,\n"
            + "                UMBRA_GATE_TICK_SIG_LENGTH, UMBRA_GATE_TICK_SIG_KEY,\n"
            + "                (void*)(&umbra_gate_tick));\n"
            + "    } else {\n"
            + "        umbra_gate_stderr(\"umbra-bind-absent gateTick\\n\");\n"
            + "    }\n"
            + "#endif\n"
            + "    if (buffers[4][0] != 0) {\n"
            + "        ok &= umbra_bind_one(env, cls, buffers[4], umbra_k_install_sig, UMBRA_INSTALL_SIG_LEN,\n"
            + "                UMBRA_INSTALL_SIG_KEY, (void*)(&umbra_install_code_library));\n"
            + "    } else {\n"
            + "        umbra_gate_stderr(\"umbra-bind-absent installCodeLibrary\\n\");\n"
            + "        ok = 0;\n"
            + "    }\n"
            + "    if (version == 2 && buffers[7][0] != 0) {\n"
            + "        ok &= umbra_bind_one_literal(env, cls, buffers[7], \"([B)I\",\n"
            + "                (void*)(&umbra_verify_loader_fn));\n"
            + "        ok &= umbra_bind_one_literal(env, cls, buffers[7], \"([B[B)I\",\n"
            + "                (void*)(&umbra_verify_loader2_fn));\n"
            + "        ok &= umbra_bind_one_literal(env, cls, buffers[7], \"(Ljava/lang/String;Ljava/lang/String;)I\",\n"
            + "                (void*)(&umbra_verify_loader_hex_fn));\n"
            + "    } else if (version == 2) {\n"
            + "        umbra_gate_stderr(\"umbra-bind-absent verifyLoader\\n\");\n"
            + "    }\n"
            + "    {\n"
            + "        unsigned char materialized[32];\n"
            + "        unsigned char rootSha[32];\n"
            + "        umbra_sha256_ctx rootCtx;\n"
            + "        umbra_key_materialize(materialized);\n"
            + "        umbra_k_sha_init(&rootCtx);\n"
            + "        umbra_k_sha_update(&rootCtx, materialized, 32);\n"
            + "        umbra_k_sha_final(&rootCtx, rootSha);\n"
            + "        umbra_gate_stderr_bytes(\"umbra-root-sha-first16=\", rootSha, 8);\n"
            + "        memset(materialized, 0, sizeof(materialized));\n"
            + "        memset(rootSha, 0, sizeof(rootSha));\n"
            + "        memset(&rootCtx, 0, sizeof(rootCtx));\n"
            + "    }\n"
            + "    g_loader_key_ready = 1;\n"
            + "    umbra_gate_copy(g_code_register_name, buffers[5], (int)sizeof(g_code_register_name));\n"
            + "    umbra_gate_copy(g_code_challenge_name, buffers[6], (int)sizeof(g_code_challenge_name));\n"
            + "    g_bind_ready = ok ? 1 : 0;\n"
            + "    if (g_key_loader_class == NULL) {\n"
            + "        g_key_loader_class = (jclass)(*env)->NewGlobalRef(env, cls);\n"
            + "    }\n"
            + "    umbra_gate_stderr_hex(\"umbra-bind-class-cached=\", (const void*)g_key_loader_class);\n"
            + "    for (i = 0; i < total; i++) memset(buffers[i], 0, sizeof(buffers[i]));\n"
            + "    return ok ? 0 : -4;\n"
            + "}\n"
            + "\n"
            + "static int umbra_key_bind(JNIEnv* env, jclass cls) {\n"
            + "    JNINativeMethod method[1];\n"
            + "    char name[UMBRA_KEY_METHOD_LENGTH + 1];\n"
            + "    char signature[UMBRA_KEY_DESCRIPTOR_LENGTH + 1];\n"
            + "    int bound = 0;\n"
            + "    umbra_key_unseal(umbra_k_method, UMBRA_KEY_METHOD_LENGTH, name, UMBRA_KEY_METHOD_KEY);\n"
            + "    umbra_key_unseal(umbra_k_descriptor, UMBRA_KEY_DESCRIPTOR_LENGTH, signature,\n"
            + "            UMBRA_KEY_DESCRIPTOR_KEY);\n"
            + "    method[0].name = name;\n"
            + "    method[0].signature = signature;\n"
            + "    method[0].fnPtr = (void*)(&umbra_key_root_fn);\n"
            + "    if (g_key_loader_class == NULL) {\n"
            + "        g_key_loader_class = (jclass)(*env)->NewGlobalRef(env, cls);\n"
            + "    }\n"
            + "    umbra_gate_stderr_hex(\"umbra-bind-class-cached=\", (const void*)g_key_loader_class);\n"
            + "    {\n"
            + "        JNINativeMethod method2[1];\n"
            + "        char name2[UMBRA_KEY2_NAME_LEN + 1];\n"
            + "        char sig2[UMBRA_KEY2_SIG_LEN + 1];\n"
            + "        umbra_key_unseal(umbra_k_root2, UMBRA_KEY2_NAME_LEN, name2, UMBRA_KEY2_NAME_KEY);\n"
            + "        umbra_key_unseal(umbra_k_root2_sig, UMBRA_KEY2_SIG_LEN, sig2, UMBRA_KEY2_SIG_KEY);\n"
            + "        method2[0].name = name2;\n"
            + "        method2[0].signature = sig2;\n"
            + "        method2[0].fnPtr = (void*)(&umbra_key_root2_fn);\n"
            + "        if ((*env)->RegisterNatives(env, cls, method2, 1) == 0) {\n"
            + "            bound |= 4;\n"
            + "        } else {\n"
            + "            (*env)->ExceptionClear(env);\n"
            + "        }\n"
            + "        memset(name2, 0, sizeof(name2));\n"
            + "        memset(sig2, 0, sizeof(sig2));\n"
            + "    }\n"
            + "#if UMBRA_KEY_LEGACY\n"
            + "    if ((*env)->RegisterNatives(env, cls, method, 1) == 0) {\n"
            + "        bound |= 1;\n"
            + "    } else {\n"
            + "        (*env)->ExceptionClear(env);\n"
            + "    }\n"
            + "    memset(name, 0, sizeof(name));\n"
            + "    memset(signature, 0, sizeof(signature));\n"
            + "#endif\n"
            + "#if UMBRA_GATE_ENABLED\n"
            + "    {\n"
            + "        JNINativeMethod gate[2];\n"
            + "        char challenge[UMBRA_GATE_CHALLENGE_LENGTH + 1];\n"
            + "        char challenge_sig[UMBRA_GATE_CHALLENGE_SIG_LENGTH + 1];\n"
            + "        char attest[UMBRA_GATE_ATTEST_LENGTH + 1];\n"
            + "        char attest_sig[UMBRA_GATE_ATTEST_SIG_LENGTH + 1];\n"
            + "        umbra_key_unseal(umbra_g_challenge, UMBRA_GATE_CHALLENGE_LENGTH, challenge,\n"
            + "                UMBRA_GATE_CHALLENGE_KEY);\n"
            + "        umbra_key_unseal(umbra_g_challenge_sig, UMBRA_GATE_CHALLENGE_SIG_LENGTH, challenge_sig,\n"
            + "                UMBRA_GATE_CHALLENGE_SIG_KEY);\n"
            + "        umbra_key_unseal(umbra_g_attest, UMBRA_GATE_ATTEST_LENGTH, attest, UMBRA_GATE_ATTEST_KEY);\n"
            + "        umbra_key_unseal(umbra_g_attest_sig, UMBRA_GATE_ATTEST_SIG_LENGTH, attest_sig,\n"
            + "                UMBRA_GATE_ATTEST_SIG_KEY);\n"
            + "        gate[0].name = challenge;\n"
            + "        gate[0].signature = challenge_sig;\n"
            + "        gate[0].fnPtr = (void*)(&umbra_gate_challenge);\n"
            + "        gate[1].name = attest;\n"
            + "        gate[1].signature = attest_sig;\n"
            + "        gate[1].fnPtr = (void*)(&umbra_gate_attest);\n"
            + "        if ((*env)->RegisterNatives(env, cls, gate, 2) == 0) {\n"
            + "            g_gate_available = 1;\n"
            + "            bound |= 2;\n"
            + "        } else {\n"
            + "            (*env)->ExceptionClear(env);\n"
            + "            g_gate_available = 0;\n"
            + "        }\n"
            + "        memset(challenge, 0, sizeof(challenge));\n"
            + "        memset(challenge_sig, 0, sizeof(challenge_sig));\n"
            + "        memset(attest, 0, sizeof(attest));\n"
            + "        memset(attest_sig, 0, sizeof(attest_sig));\n"
            + "    }\n"
            + "    {\n"
            + "        JNINativeMethod tick[1];\n"
            + "        char tick_name[UMBRA_GATE_TICK_LENGTH + 1];\n"
            + "        char tick_sig[UMBRA_GATE_TICK_SIG_LENGTH + 1];\n"
            + "        umbra_key_unseal(umbra_g_tick, UMBRA_GATE_TICK_LENGTH, tick_name,\n"
            + "                UMBRA_GATE_TICK_KEY);\n"
            + "        umbra_key_unseal(umbra_g_tick_sig, UMBRA_GATE_TICK_SIG_LENGTH, tick_sig,\n"
            + "                UMBRA_GATE_TICK_SIG_KEY);\n"
            + "        tick[0].name = tick_name;\n"
            + "        tick[0].signature = tick_sig;\n"
            + "        tick[0].fnPtr = (void*)(&umbra_gate_tick);\n"
            + "        if ((*env)->RegisterNatives(env, cls, tick, 1) != 0) {\n"
            + "            (*env)->ExceptionClear(env);\n"
            + "        }\n"
            + "        memset(tick_name, 0, sizeof(tick_name));\n"
            + "        memset(tick_sig, 0, sizeof(tick_sig));\n"
            + "    }\n"
            + "#endif\n"
            + "    {\n"
            + "        JNINativeMethod decrypt[1];\n"
            + "        char decrypt_name[UMBRA_DECRYPT_NAME_LEN + 1];\n"
            + "        char decrypt_sig[UMBRA_DECRYPT_SIG_LEN + 1];\n"
            + "        umbra_key_unseal(umbra_k_decrypt, UMBRA_DECRYPT_NAME_LEN, decrypt_name,\n"
            + "                UMBRA_DECRYPT_NAME_KEY);\n"
            + "        umbra_key_unseal(umbra_k_decrypt_sig, UMBRA_DECRYPT_SIG_LEN, decrypt_sig,\n"
            + "                UMBRA_DECRYPT_SIG_KEY);\n"
            + "        decrypt[0].name = decrypt_name;\n"
            + "        decrypt[0].signature = decrypt_sig;\n"
            + "        decrypt[0].fnPtr = (void*)(&umbra_decrypt_fn);\n"
            + "        if ((*env)->RegisterNatives(env, cls, decrypt, 1) != 0) {\n"
            + "            (*env)->ExceptionClear(env);\n"
            + "        }\n"
            + "        memset(decrypt_name, 0, sizeof(decrypt_name));\n"
            + "        memset(decrypt_sig, 0, sizeof(decrypt_sig));\n"
            + "    }\n"
            + "    (void)umbra_install_bind(env, cls);\n"
            + "    {\n"
            + "        JNINativeMethod bootstrap[1];\n"
            + "        bootstrap[0].name = (char*)\"bindNames\";\n"
            + "        bootstrap[0].signature = (char*)\"(I[Ljava/lang/String;)I\";\n"
            + "        bootstrap[0].fnPtr = (void*)(&umbra_bind_names_fn);\n"
            + "        if ((*env)->RegisterNatives(env, cls, bootstrap, 1) == 0) {\n"
            + "            bound |= 8;\n"
            + "        } else {\n"
            + "            (*env)->ExceptionClear(env);\n"
            + "        }\n"
            + "    }\n"
            // bit 4 means keyRoot2 was registered under its sealed name, i.e. this is
            // the class the bridge was built for; the nonce-bound entry may then answer
            // without the name handshake. A renamed build never sets the bit here, so
            // keyRoot2 keeps returning -9 until bindNames() succeeds.
            + "    if ((bound & 4) != 0) g_bind_ready = 1;\n"
            + "    return bound;\n"
            + "}\n"
            + "";

    private static final String AGENT_C = "static int umbra_gate_contains_nocase(const char* text, const char* needle, int length) {\n"
            + "    int i;\n"
            + "    int j;\n"
            + "    if (text == NULL || needle == NULL || length <= 0) return 0;\n"
            + "    for (i = 0; text[i] != 0; i++) {\n"
            + "        int match = 1;\n"
            + "        for (j = 0; j < length; j++) {\n"
            + "            char a = text[i + j];\n"
            + "            char b = needle[j];\n"
            + "            if (a == 0) {\n"
            + "                match = 0;\n"
            + "                break;\n"
            + "            }\n"
            + "            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');\n"
            + "            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');\n"
            + "            if (a != b) {\n"
            + "                match = 0;\n"
            + "                break;\n"
            + "            }\n"
            + "        }\n"
            + "        if (match) return 1;\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_sealed_hit(const char* module, const unsigned char* sealed, int length,\n"
            + "        unsigned int key) {\n"
            + "    char buffer[64];\n"
            + "    int i;\n"
            + "    int hit;\n"
            + "    if (module == NULL || length <= 0 || length >= (int)sizeof(buffer)) return 0;\n"
            + "    for (i = 0; i < length; i++) {\n"
            + "        buffer[i] = (char)(sealed[i] ^ (unsigned char)(key + (unsigned int)i * 7u));\n"
            + "    }\n"
            + "    buffer[length] = 0;\n"
            + "    hit = umbra_gate_contains_nocase(module, buffer, length);\n"
            + "    memset(buffer, 0, sizeof(buffer));\n"
            + "    return hit;\n"
            + "}\n"
            + "\n"
            + "/* Marker scan: known instrumentation module names. Read-only snapshot; a failure\n"
            + "   to enumerate is \"no agent\" (never a false positive). */\n"
            + "#if UMBRA_GATE_DIAG\n"
            + "static void umbra_gate_diag_marker(const char* modulePath, const char* moduleName) {\n"
            + "    char temp[UMBRA_GATE_PATH_MAX];\n"
            + "    char line[UMBRA_GATE_PATH_MAX * 2];\n"
            + "    DWORD length;\n"
            + "    HANDLE file;\n"
            + "    DWORD written = 0;\n"
            + "    DWORD pid = (DWORD)GetCurrentProcessId();\n"
            + "    int at = 0;\n"
            + "    length = GetTempPathA(UMBRA_GATE_PATH_MAX, temp);\n"
            + "    if (length == 0 || length >= UMBRA_GATE_PATH_MAX - 24) return;\n"
            + "    {\n"
            + "        char digits[16];\n"
            + "        int d = 0;\n"
            + "        DWORD value = pid;\n"
            + "        while (value > 0 && d < 16) {\n"
            + "            digits[d++] = (char)('0' + (int)(value % 10UL));\n"
            + "            value /= 10UL;\n"
            + "        }\n"
            + "        temp[length++] = 'k';\n"
            + "        while (d > 0) temp[length++] = digits[--d];\n"
            + "        temp[length++] = '.';\n"
            + "        temp[length++] = 't';\n"
            + "        temp[length++] = 'x';\n"
            + "        temp[length++] = 't';\n"
            + "        temp[length] = 0;\n"
            + "    }\n"
            + "    memcpy(line + at, \"name=\", 5);\n"
            + "    at += 5;\n"
            + "    if (moduleName != NULL) {\n"
            + "        int n = (int)strlen(moduleName);\n"
            + "        if (n > 64) n = 64;\n"
            + "        memcpy(line + at, moduleName, (size_t)n);\n"
            + "        at += n;\n"
            + "    }\n"
            + "    memcpy(line + at, \" path=\", 6);\n"
            + "    at += 6;\n"
            + "    if (modulePath != NULL) {\n"
            + "        int n = (int)strlen(modulePath);\n"
            + "        if (n > UMBRA_GATE_PATH_MAX - 32) n = UMBRA_GATE_PATH_MAX - 32;\n"
            + "        memcpy(line + at, modulePath, (size_t)n);\n"
            + "        at += n;\n"
            + "    }\n"
            + "    line[at++] = '\\n';\n"
            + "    line[at] = 0;\n"
            + "    file = CreateFileA(temp, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,\n"
            + "            FILE_ATTRIBUTE_NORMAL, NULL);\n"
            + "    if (file != INVALID_HANDLE_VALUE) {\n"
            + "        WriteFile(file, line, (DWORD)at, &written, NULL);\n"
            + "        CloseHandle(file);\n"
            + "    }\n"
            + "}\n"
            + "#endif\n"
            + "\n"
            + "static int umbra_gate_explicit_allow(const char* path);\n"
            + "static volatile int g_gate_install_busy;\n"
            + "static int umbra_gate_self_loaded(unsigned long long base);\n"
            + "#if UMBRA_GATE_DIAG\n"
            + "static void umbra_gate_diag_marker(const char* modulePath, const char* moduleName);\n"
            + "static void umbra_gate_diag_module(const char* modulePath);\n"
            + "static void umbra_gate_diag_holder(unsigned long pid, unsigned long access);\n"
            + "#endif\n"
            + "\n"
            + "static int umbra_gate_marker_scan(void) {\n"
            + "#ifdef _WIN32\n"
            + "    HANDLE snapshot;\n"
            + "    MODULEENTRY32 entry;\n"
            + "    int found = 0;\n"
            + "    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,\n"
            + "            GetCurrentProcessId());\n"
            + "    if (snapshot == INVALID_HANDLE_VALUE) return 0;\n"
            + "    memset(&entry, 0, sizeof(entry));\n"
            + "    entry.dwSize = sizeof(entry);\n"
            + "    if (Module32First(snapshot, &entry)) {\n"
            + "        do {\n"
            + "            if (umbra_gate_sealed_hit(entry.szModule, umbra_g_m0, UMBRA_GATE_M0_LEN,\n"
            + "                        UMBRA_GATE_M0_KEY)\n"
            + "                    || umbra_gate_sealed_hit(entry.szModule, umbra_g_m1, UMBRA_GATE_M1_LEN,\n"
            + "                        UMBRA_GATE_M1_KEY)\n"
            + "                    || umbra_gate_sealed_hit(entry.szModule, umbra_g_m2, UMBRA_GATE_M2_LEN,\n"
            + "                        UMBRA_GATE_M2_KEY)\n"
            + "                    || umbra_gate_sealed_hit(entry.szModule, umbra_g_m3, UMBRA_GATE_M3_LEN,\n"
            + "                        UMBRA_GATE_M3_KEY)) {\n"
            + "                /* The JDK ships instrument.dll/dt_socket.dll itself: a plain JVM may\n"
            + "                   load them (java.lang.instrument, attach APIs) without any agent. Only\n"
            + "                   a marker outside the JVM's own directories is an intrusion. */\n"
            + "                if (entry.szExePath[0] != 0 && umbra_gate_explicit_allow(entry.szExePath)) {\n"
            + "                    continue;\n"
            + "                }\n"
            + "#if UMBRA_GATE_DIAG\n"
            + "                umbra_gate_diag_marker(entry.szExePath, entry.szModule);\n"
            + "#endif\n"
            + "                found = 1;\n"
            + "                break;\n"
            + "            }\n"
            + "        } while (Module32Next(snapshot, &entry));\n"
            + "    }\n"
            + "    CloseHandle(snapshot);\n"
            + "    return found;\n"
            + "#else\n"
            + "    return 0;\n"
            + "#endif\n"
            + "}\n"
            + "\n"
            + "/* ---- V2: module baseline + JVMTI export probe ---- */\n"
            + "static volatile int g_gate_agent_seen;\n"
            + "static unsigned long g_gate_last_scan_ms;\n"
            + "static int g_gate_last_scan_clean = 1;\n"
            + "\n"
            + "#ifdef _WIN32\n"
            + "static unsigned long long g_gate_mod_base[UMBRA_GATE_MODULE_SLOTS];\n"
            + "static int g_gate_mod_count;\n"
            + "static int g_gate_baseline_ready;\n"
            + "static char g_gate_whitelist[UMBRA_GATE_PATH_MAX];\n"
            + "static int g_gate_whitelist_ready;\n"
            + "\n"
            + "static unsigned int umbra_gate_u32(const unsigned char* address) {\n"
            + "    unsigned int value;\n"
            + "    memcpy(&value, address, 4);\n"
            + "    return value;\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_prefix_nocase(const char* text, const char* prefix) {\n"
            + "    int i;\n"
            + "    if (text == NULL || prefix == NULL || prefix[0] == 0) return 0;\n"
            + "    for (i = 0; prefix[i] != 0; i++) {\n"
            + "        char a = text[i];\n"
            + "        char b = prefix[i];\n"
            + "        if (a == 0) return 0;\n"
            + "        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');\n"
            + "        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');\n"
            + "        if (a != b) return 0;\n"
            + "    }\n"
            + "    return 1;\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_name_is(const char* name, const char* expected) {\n"
            + "    int i;\n"
            + "    if (name == NULL || expected == NULL) return 0;\n"
            + "    for (i = 0; expected[i] != 0; i++) {\n"
            + "        if (name[i] != expected[i]) return 0;\n"
            + "    }\n"
            + "    return name[i] == 0;\n"
            + "}\n"
            + "\n"
            + "/* True when the module at 'base' exports a JVMTI entry point\n"
            + "   (Agent_OnLoad / Agent_OnAttach). Parse failure is \"no agent\". */\n"
            + "static int umbra_gate_exports_agent(unsigned long long base) {\n"
            + "    const unsigned char* image = (const unsigned char*)(ULONG_PTR)base;\n"
            + "    MEMORY_BASIC_INFORMATION region;\n"
            + "    unsigned int pe;\n"
            + "    if (VirtualQuery((LPCVOID)image, &region, sizeof(region)) == 0) return 0;\n"
            + "    if (region.State != MEM_COMMIT || region.Type != MEM_IMAGE) return 0;\n"
            + "    unsigned int export_rva;\n"
            + "    unsigned int export_size;\n"
            + "    const unsigned char* directory;\n"
            + "    unsigned int name_count;\n"
            + "    unsigned int names_rva;\n"
            + "    unsigned int i;\n"
            + "    if (image == NULL) return 0;\n"
            + "    if (image[0] != 'M' || image[1] != 'Z') return 0;\n"
            + "    pe = umbra_gate_u32(image + 0x3C);\n"
            + "    if (pe == 0u || pe > 0x01000000u) return 0;\n"
            + "    if (umbra_gate_u32(image + pe) != 0x00004550u) return 0;\n"
            + "    {\n"
            + "        unsigned int optional = pe + 24;\n"
            + "        unsigned int magic = umbra_gate_u32(image + optional) & 0xFFFFu;\n"
            + "        unsigned int directory_offset = (magic == 0x20Bu) ? 112u : 96u;\n"
            + "        export_rva = umbra_gate_u32(image + optional + directory_offset);\n"
            + "        export_size = umbra_gate_u32(image + optional + directory_offset + 4u);\n"
            + "    }\n"
            + "    if (export_rva == 0u || export_size == 0u) return 0;\n"
            + "    directory = image + export_rva;\n"
            + "    name_count = umbra_gate_u32(directory + 24);\n"
            + "    names_rva = umbra_gate_u32(directory + 32);\n"
            + "    if (name_count == 0u || name_count > 4096u || names_rva == 0u) return 0;\n"
            + "    for (i = 0; i < name_count; i++) {\n"
            + "        unsigned int name_rva = umbra_gate_u32(image + names_rva + i * 4u);\n"
            + "        const char* name = (const char*)(image + name_rva);\n"
            + "        if (umbra_gate_name_is(name, \"Agent_OnLoad\")\n"
            + "                || umbra_gate_name_is(name, \"Agent_OnAttach\")) {\n"
            + "            return 1;\n"
            + "        }\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "/* JVM-shipped DLLs (hprof.dll, instrument.dll, jdwp.dll, ...) export a JVMTI\n"
            + "   entry point and live under java.home / %SystemRoot%. Those directories, the\n"
            + "   ancestors of jvm.dll and the operator whitelist excuse an exporting module.\n"
            + "   Everything on this path is OS-level (environment variables, module path): no\n"
            + "   JVM API is called, so it is safe while the class-loader lock is held. */\n"
            + "static char g_gate_dirs[UMBRA_GATE_ALLOW_SLOTS][UMBRA_GATE_PATH_MAX];\n"
            + "static char g_gate_own_dir[UMBRA_GATE_PATH_MAX];\n"
            + "static int g_gate_dir_count;\n"
            + "static int g_gate_dirs_ready;\n"
            + "\n"
            + "static void umbra_gate_capture_own_dir(void) {\n"
            + "    HMODULE self;\n"
            + "    char path[UMBRA_GATE_PATH_MAX];\n"
            + "    DWORD length;\n"
            + "    int i;\n"
            + "    if (g_gate_own_dir[0] != 0) return;\n"
            + "    self = NULL;\n"
            + "    if (!GetModuleHandleExA(0x00000004L, (LPCSTR)(&umbra_gate_capture_own_dir), &self)\n"
            + "            || self == NULL) {\n"
            + "        return;\n"
            + "    }\n"
            + "    length = GetModuleFileNameA(self, path, UMBRA_GATE_PATH_MAX);\n"
            + "    if (length == 0 || length >= UMBRA_GATE_PATH_MAX) return;\n"
            + "    for (i = (int)length - 1; i > 0; i--) {\n"
            + "        if (path[i] == '\\\\' || path[i] == '/') {\n"
            + "            path[i] = 0;\n"
            + "            break;\n"
            + "        }\n"
            + "    }\n"
            + "    umbra_gate_copy(g_gate_own_dir, path, UMBRA_GATE_PATH_MAX);\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_add_dir(const char* dir) {\n"
            + "    int length;\n"
            + "    int i;\n"
            + "    if (dir == NULL || dir[0] == 0) return;\n"
            + "    if (g_gate_dir_count >= UMBRA_GATE_ALLOW_SLOTS) return;\n"
            + "    umbra_gate_copy(g_gate_dirs[g_gate_dir_count], dir, UMBRA_GATE_PATH_MAX);\n"
            + "    length = (int)strlen(g_gate_dirs[g_gate_dir_count]);\n"
            + "    while (length > 3 && (g_gate_dirs[g_gate_dir_count][length - 1] == '\\\\'\n"
            + "            || g_gate_dirs[g_gate_dir_count][length - 1] == '/')) {\n"
            + "        length--;\n"
            + "        g_gate_dirs[g_gate_dir_count][length] = 0;\n"
            + "    }\n"
            + "    for (i = 0; i < g_gate_dir_count; i++) {\n"
            + "        if (strcmp(g_gate_dirs[i], g_gate_dirs[g_gate_dir_count]) == 0) return;\n"
            + "    }\n"
            + "    if (length > 0) g_gate_dir_count++;\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_env(char* out, int capacity, const char* name) {\n"
            + "    DWORD read;\n"
            + "    if (out == NULL || capacity <= 0) return;\n"
            + "    out[0] = 0;\n"
            + "    read = GetEnvironmentVariableA(name, out, (DWORD)capacity);\n"
            + "    if (read == 0 || read >= (DWORD)capacity) out[0] = 0;\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_jvm_dirs(void) {\n"
            + "    HMODULE jvm = GetModuleHandleA(\"jvm.dll\");\n"
            + "    char path[UMBRA_GATE_PATH_MAX];\n"
            + "    DWORD length;\n"
            + "    int i;\n"
            + "    int level;\n"
            + "    if (jvm == NULL) return;\n"
            + "    length = GetModuleFileNameA(jvm, path, UMBRA_GATE_PATH_MAX);\n"
            + "    if (length == 0 || length >= UMBRA_GATE_PATH_MAX) return;\n"
            + "    i = (int)length - 1;\n"
            + "    for (level = 0; level < 4; level++) {\n"
            + "        while (i > 0 && path[i] != '\\\\' && path[i] != '/') i--;\n"
            + "        if (i <= 0) break;\n"
            + "        path[i] = 0;\n"
            + "        umbra_gate_add_dir(path);\n"
            + "        i--;\n"
            + "    }\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_build_dirs(void) {\n"
            + "    char buffer[UMBRA_GATE_PATH_MAX];\n"
            + "    int i;\n"
            + "    if (g_gate_dirs_ready) return;\n"
            + "    g_gate_dirs_ready = 1;\n"
            + "    umbra_gate_env(buffer, UMBRA_GATE_PATH_MAX, \"SystemRoot\");\n"
            + "    umbra_gate_add_dir(buffer);\n"
            + "    umbra_gate_env(buffer, UMBRA_GATE_PATH_MAX, \"JAVA_HOME\");\n"
            + "    umbra_gate_add_dir(buffer);\n"
            + "    umbra_gate_env(buffer, UMBRA_GATE_PATH_MAX, \"ProgramFiles\");\n"
            + "    umbra_gate_add_dir(buffer);\n"
            + "    umbra_gate_env(buffer, UMBRA_GATE_PATH_MAX, \"ProgramData\");\n"
            + "    if (buffer[0] != 0) {\n"
            + "        int length = (int)strlen(buffer);\n"
            + "        umbra_gate_add_dir(buffer);\n"
            + "        if (length + 24 < UMBRA_GATE_PATH_MAX) {\n"
            + "            memcpy(buffer + length, \"\\\\Microsoft\\\\Windows Defender\", 27);\n"
            + "            buffer[length + 27] = 0;\n"
            + "            umbra_gate_add_dir(buffer);\n"
            + "        }\n"
            + "    }\n"
            + "    umbra_gate_jvm_dirs();\n"
            + "    if (UMBRA_GATE_WHITELIST_LEN > 0) {\n"
            + "        for (i = 0; i < UMBRA_GATE_WHITELIST_LEN; i++) {\n"
            + "            g_gate_whitelist[i] = (char)(umbra_g_whitelist[i]\n"
            + "                    ^ (unsigned char)(UMBRA_GATE_WHITELIST_KEY + (unsigned int)i * 7u));\n"
            + "        }\n"
            + "        g_gate_whitelist[UMBRA_GATE_WHITELIST_LEN] = 0;\n"
            + "        {\n"
            + "            char* cursor = g_gate_whitelist;\n"
            + "            while (cursor != NULL && cursor[0] != 0) {\n"
            + "                char* next = strchr(cursor, ';');\n"
            + "                if (next != NULL) *next = 0;\n"
            + "                umbra_gate_add_dir(cursor);\n"
            + "                cursor = next == NULL ? NULL : next + 1;\n"
            + "            }\n"
            + "        }\n"
            + "    }\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_normalize_path(const char* in, char* out, int capacity) {\n"
            + "    DWORD length;\n"
            + "    if (out == NULL || capacity <= 0) return;\n"
            + "    out[0] = 0;\n"
            + "    if (in == NULL || in[0] == 0) return;\n"
            + "    length = GetLongPathNameA(in, out, (DWORD)capacity);\n"
            + "    if (length == 0 || length >= (DWORD)capacity) {\n"
            + "        umbra_gate_copy(out, in, capacity);\n"
            + "    }\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_path_trusted(const char* rawPath) {\n"
            + "    char path[UMBRA_GATE_PATH_MAX];\n"
            + "    umbra_gate_normalize_path(rawPath, path, UMBRA_GATE_PATH_MAX);\n"
            + "    char temp[UMBRA_GATE_PATH_MAX];\n"
            + "    DWORD length;\n"
            + "    if (umbra_gate_explicit_allow(path)) return 1;\n"
            + "    length = GetTempPathA(UMBRA_GATE_PATH_MAX, temp);\n"
            + "    if (length > 0 && length < UMBRA_GATE_PATH_MAX) {\n"
            + "        char longTemp[UMBRA_GATE_PATH_MAX];\n"
            + "        umbra_gate_normalize_path(temp, longTemp, UMBRA_GATE_PATH_MAX);\n"
            + "        if (umbra_gate_prefix_nocase(path, temp)\n"
            + "                || (longTemp[0] != 0 && umbra_gate_prefix_nocase(path, longTemp))) {\n"
            + "            return 1;\n"
            + "        }\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_explicit_allow(const char* rawPath) {\n"
            + "    char path[UMBRA_GATE_PATH_MAX];\n"
            + "    int i;\n"
            + "    if (rawPath == NULL || rawPath[0] == 0) return 0;\n"
            + "    umbra_gate_normalize_path(rawPath, path, UMBRA_GATE_PATH_MAX);\n"
            + "    umbra_gate_capture_own_dir();\n"
            + "    if (g_gate_own_dir[0] != 0 && umbra_gate_prefix_nocase(path, g_gate_own_dir)) return 1;\n"
            + "    umbra_gate_build_dirs();\n"
            + "    for (i = 0; i < g_gate_dir_count; i++) {\n"
            + "        if (umbra_gate_prefix_nocase(path, g_gate_dirs[i])) return 1;\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_baseline_known(unsigned long long base) {\n"
            + "    int i;\n"
            + "    for (i = 0; i < g_gate_mod_count; i++) {\n"
            + "        if (g_gate_mod_base[i] == base) return 1;\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "/* Late-module scan: the first call captures the baseline (the gate is already\n"
            + "   open, so the guard/loader libraries are in it). A module that appears later is\n"
            + "   only flagged when its PE export table lists Agent_OnLoad / Agent_OnAttach; the\n"
            + "   JVM's own lazily loaded libraries (net.dll, zip.dll, ...) export neither. */\n"
            + "static int umbra_gate_late_scan(void) {\n"
            + "    HANDLE snapshot;\n"
            + "    MODULEENTRY32 entry;\n"
            + "    int found = 0;\n"
            + "    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,\n"
            + "            GetCurrentProcessId());\n"
            + "    if (snapshot == INVALID_HANDLE_VALUE) return 0;\n"
            + "    memset(&entry, 0, sizeof(entry));\n"
            + "    entry.dwSize = sizeof(entry);\n"
            + "    if (Module32First(snapshot, &entry)) {\n"
            + "        do {\n"
            + "            unsigned long long base = (unsigned long long)(ULONG_PTR)entry.modBaseAddr;\n"
            + "            if (base == 0ULL) continue;\n"
            + "            if (!g_gate_baseline_ready) {\n"
            + "                if (g_gate_mod_count < UMBRA_GATE_MODULE_SLOTS) {\n"
            + "                    g_gate_mod_base[g_gate_mod_count++] = base;\n"
            + "                }\n"
            + "                continue;\n"
            + "            }\n"
            + "            if (umbra_gate_baseline_known(base)) continue; if (umbra_gate_self_loaded(base)) { umbra_gate_stderr(\"umbra-gate-self-skip\\n\"); continue; } if (umbra_gate_suspicious(entry.szModule)) { found = 1; break; }\n"
            + "            if (g_gate_open && entry.szExePath[0] != 0\n"
            + "                    && !umbra_gate_path_trusted(entry.szExePath)) {\n"
            + "#if UMBRA_GATE_DIAG\n"
            + "                umbra_gate_diag_module(entry.szExePath);\n"
            + "#endif\n"
            + "                found = 1;\n"
            + "                break;\n"
            + "            }\n"
            + "            if (!umbra_gate_exports_agent(base)) continue;\n"
            + "            if (umbra_gate_explicit_allow(entry.szExePath)) continue;\n"
            + "            found = 1;\n"
            + "            break;\n"
            + "        } while (Module32Next(snapshot, &entry));\n"
            + "    }\n"
            + "    CloseHandle(snapshot);\n"
            + "    if (!g_gate_baseline_ready) g_gate_baseline_ready = 1;\n"
            + "    return found;\n"
            + "}\n"
            + "#else\n"
            + "static int umbra_gate_late_scan(void) { return 0; }\n"
            + "#endif\n"
            + "\n"
            + "/* ---- V3: external PROCESS_VM_READ / PROCESS_VM_OPERATION handles ---- */\n"
            + "typedef struct {\n"
            + "    PVOID Object;\n"
            + "    ULONG_PTR UniqueProcessId;\n"
            + "    ULONG_PTR HandleValue;\n"
            + "    ULONG GrantedAccess;\n"
            + "    USHORT CreatorBackTraceIndex;\n"
            + "    USHORT ObjectTypeIndex;\n"
            + "    ULONG HandleAttributes;\n"
            + "    ULONG Reserved;\n"
            + "} UMBRA_GATE_HANDLE;\n"
            + "\n"
            + "typedef struct {\n"
            + "    ULONG_PTR NumberOfHandles;\n"
            + "    ULONG_PTR Reserved;\n"
            + "    UMBRA_GATE_HANDLE Handles[1];\n"
            + "} UMBRA_GATE_HANDLE_INFO;\n"
            + "\n"
            + "static ULONG_PTR g_gate_self_object;\n"
            + "static int g_gate_self_object_ready;\n"
            + "static unsigned long g_gate_last_handle_ms;\n"
            + "static unsigned long g_gate_watch_started;\n"
            + "\n"
            + "static PVOID umbra_gate_handle_table(ULONG* out_size) {\n"
            + "    typedef LONG (NTAPI *umbra_query_fn)(ULONG, PVOID, ULONG, PULONG);\n"
            + "    static umbra_query_fn query_fn;\n"
            + "    HMODULE ntdll;\n"
            + "    ULONG size = 1u << 20;\n"
            + "    int attempt;\n"
            + "    if (query_fn == NULL) {\n"
            + "        ntdll = GetModuleHandleA(\"ntdll.dll\");\n"
            + "        if (ntdll == NULL) return NULL;\n"
            + "        query_fn = (umbra_query_fn)GetProcAddress(ntdll, \"NtQuerySystemInformation\");\n"
            + "        if (query_fn == NULL) return NULL;\n"
            + "    }\n"
            + "    for (attempt = 0; attempt < 5; attempt++) {\n"
            + "        PVOID buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
            + "        ULONG needed = 0;\n"
            + "        if (buffer == NULL) return NULL;\n"
            + "        if (query_fn(64UL, buffer, size, &needed) == 0L) {\n"
            + "            *out_size = size;\n"
            + "            return buffer;\n"
            + "        }\n"
            + "        VirtualFree(buffer, 0, MEM_RELEASE);\n"
            + "        if (needed <= size) return NULL;\n"
            + "        size = needed + 65536UL;\n"
            + "    }\n"
            + "    return NULL;\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_find_self_object(const UMBRA_GATE_HANDLE_INFO* info, ULONG_PTR self_handle) {\n"
            + "    ULONG_PTR count;\n"
            + "    ULONG_PTR i;\n"
            + "    int found = 0;\n"
            + "    count = info->NumberOfHandles;\n"
            + "    for (i = 0; i < count; i++) {\n"
            + "        const UMBRA_GATE_HANDLE* entry = &info->Handles[i];\n"
            + "        if (entry->UniqueProcessId == (ULONG_PTR)GetCurrentProcessId()\n"
            + "                && entry->HandleValue == self_handle) {\n"
            + "            g_gate_self_object = (ULONG_PTR)entry->Object;\n"
            + "            found = g_gate_self_object != 0;\n"
            + "            break;\n"
            + "        }\n"
            + "    }\n"
            + "    return found;\n"
            + "}\n"
            + "\n"
            + "/* True when another process holds a handle on THIS process with VM_READ or\n"
            + "   VM_OPERATION access. Enumeration failure is \"no reader\" (zero false positives). */\n"
            + "/* Trust is identity-only: this process and its parent chain (up to three\n"
            + "   levels) plus explicitly configured PIDs. A system process that is not in the\n"
            + "   chain (notepad, rundll32, dllhost) is a stranger, so injecting into it does not\n"
            + "   help. If the chain cannot be resolved, only this process is trusted. */\n"
            + "static unsigned long g_gate_chain[3];\n"
            + "static int g_gate_chain_ready;\n"
            + "static unsigned long g_gate_unknown_owner;\n"
            + "\n"
            + "typedef struct {\n"
            + "    PVOID Reserved1;\n"
            + "    PVOID PebBaseAddress;\n"
            + "    PVOID Reserved2[2];\n"
            + "    ULONG_PTR UniqueProcessId;\n"
            + "    ULONG_PTR InheritedFromUniqueProcessId;\n"
            + "} UMBRA_GATE_PBI;\n"
            + "\n"
            + "static unsigned long umbra_gate_parent_of(unsigned long pid) {\n"
            + "    typedef LONG (NTAPI *umbra_query_process_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);\n"
            + "    static umbra_query_process_fn query_fn;\n"
            + "    HANDLE handle;\n"
            + "    UMBRA_GATE_PBI info;\n"
            + "    ULONG length = 0;\n"
            + "    if (query_fn == NULL) {\n"
            + "        HMODULE ntdll = GetModuleHandleA(\"ntdll.dll\");\n"
            + "        if (ntdll != NULL) {\n"
            + "            query_fn = (umbra_query_process_fn)GetProcAddress(ntdll, \"NtQueryInformationProcess\");\n"
            + "        }\n"
            + "    }\n"
            + "    if (query_fn == NULL) return 0;\n"
            + "    handle = OpenProcess(0x0400L, FALSE, (DWORD)pid);\n"
            + "    if (handle == NULL) {\n"
            + "        handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);\n"
            + "    }\n"
            + "    if (handle == NULL) return 0;\n"
            + "    memset(&info, 0, sizeof(info));\n"
            + "    if (query_fn(handle, 0UL, &info, (ULONG)sizeof(info), &length) != 0L) {\n"
            + "        CloseHandle(handle);\n"
            + "        return 0;\n"
            + "    }\n"
            + "    CloseHandle(handle);\n"
            + "    return (unsigned long)info.InheritedFromUniqueProcessId;\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_build_chain(void) {\n"
            + "    unsigned long pid = (unsigned long)GetCurrentProcessId();\n"
            + "    if (g_gate_chain_ready) return;\n"
            + "    g_gate_chain_ready = 1;\n"
            + "    g_gate_chain[0] = pid;\n"
            + "    g_gate_chain[1] = umbra_gate_parent_of(pid);\n"
            + "    g_gate_chain[2] = g_gate_chain[1] != 0 ? umbra_gate_parent_of(g_gate_chain[1]) : 0;\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_wide_to_ascii(const WCHAR* wide, char* out, int capacity);\n"
            + "WINBASEAPI BOOL WINAPI QueryFullProcessImageNameW(HANDLE, DWORD, LPWSTR, PDWORD);\n"
            + "\n"
            + "static int umbra_gate_pid_allowed(unsigned long pid) {\n"
            + "    int i;\n"
            + "    int j;\n"
            + "    if (pid == 0UL) return 0;\n"
            + "    if (UMBRA_GATE_WHITELIST_LEN > 0) {\n"
            + "        if (!g_gate_whitelist_ready) {\n"
            + "            for (i = 0; i < UMBRA_GATE_WHITELIST_LEN; i++) {\n"
            + "                g_gate_whitelist[i] = (char)(umbra_g_whitelist[i]\n"
            + "                        ^ (unsigned char)(UMBRA_GATE_WHITELIST_KEY + (unsigned int)i * 7u));\n"
            + "            }\n"
            + "            g_gate_whitelist[UMBRA_GATE_WHITELIST_LEN] = 0;\n"
            + "            g_gate_whitelist_ready = 1;\n"
            + "        }\n"
            + "        {\n"
            + "            const char* cursor = g_gate_whitelist;\n"
            + "            while (cursor != NULL && cursor[0] != 0) {\n"
            + "                const char* next = strchr(cursor, ';');\n"
            + "                int length = next == NULL ? (int)strlen(cursor) : (int)(next - cursor);\n"
            + "                int digits = 1;\n"
            + "                unsigned long value = 0UL;\n"
            + "                for (j = 0; j < length; j++) {\n"
            + "                    if (cursor[j] < '0' || cursor[j] > '9') {\n"
            + "                        digits = 0;\n"
            + "                        break;\n"
            + "                    }\n"
            + "                    value = value * 10UL + (unsigned long)(cursor[j] - '0');\n"
            + "                }\n"
            + "                if (digits && length > 0 && value == pid) return 1;\n"
            + "\n"
            + "                cursor = next == NULL ? NULL : next + 1;\n"
            + "            }\n"
            + "        }\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "static int umbra_gate_image_allowed(unsigned long pid) {\n"
            + "    HANDLE owner;\n"
            + "    WCHAR wide[UMBRA_GATE_PATH_MAX];\n"
            + "    char path[UMBRA_GATE_PATH_MAX];\n"
            + "    DWORD size = UMBRA_GATE_PATH_MAX;\n"
            + "    int i;\n"
            + "    int j;\n"
            + "    if (UMBRA_GATE_WHITELIST_LEN <= 0) return 0;\n"
            + "    if (!g_gate_whitelist_ready) return 0;\n"
            + "    owner = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);\n"
            + "    if (owner == NULL) return 0;\n"
            + "    if (!QueryFullProcessImageNameW(owner, 0, wide, &size)) {\n"
            + "        CloseHandle(owner);\n"
            + "        return 0;\n"
            + "    }\n"
            + "    CloseHandle(owner);\n"
            + "    path[0] = 0;\n"
            + "    umbra_gate_wide_to_ascii(wide, path, UMBRA_GATE_PATH_MAX);\n"
            + "    {\n"
            + "        const char* cursor = g_gate_whitelist;\n"
            + "        while (cursor != NULL && cursor[0] != 0) {\n"
            + "            const char* next = strchr(cursor, ';');\n"
            + "            int length = next == NULL ? (int)strlen(cursor) : (int)(next - cursor);\n"
            + "            int digits = 1;\n"
            + "            for (j = 0; j < length; j++) {\n"
            + "                if (cursor[j] < '0' || cursor[j] > '9') {\n"
            + "                    digits = 0;\n"
            + "                    break;\n"
            + "                }\n"
            + "            }\n"
            + "            if (!digits && length > 3 && length < UMBRA_GATE_PATH_MAX) {\n"
            + "                char needle[UMBRA_GATE_PATH_MAX];\n"
            + "                memcpy(needle, cursor, (size_t)length);\n"
            + "                needle[length] = 0;\n"
            + "                if (umbra_gate_prefix_nocase(path, needle)) return 1;\n"
            + "            }\n"
            + "            cursor = next == NULL ? NULL : next + 1;\n"
            + "        }\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "/* Only the operating system's own AV/telemetry collectors are trusted, and only\n"
            + "   when BOTH the directory is %SystemRoot% and the image name is in the list.\n"
            + "   Everything else, the launcher included, is a reader. */\n"
            + "static int umbra_gate_collector_allowed(unsigned long pid) {\n"
            + "    static const char* names[7] = {\n"
            + "        \"MsMpEng.exe\", \"NisSrv.exe\", \"MpDefenderCoreService.exe\",\n"
            + "        \"SecurityHealthService.exe\", \"WmiPrvSE.exe\",\n"
            + "        \"csrss.exe\", \"conhost.exe\"\n"
            + "    };\n"
            + "    WCHAR wide[UMBRA_GATE_PATH_MAX];\n"
            + "    char path[UMBRA_GATE_PATH_MAX];\n"
            + "    char root[UMBRA_GATE_PATH_MAX];\n"
            + "    const char* base;\n"
            + "    HANDLE owner;\n"
            + "    DWORD size = UMBRA_GATE_PATH_MAX;\n"
            + "    int i;\n"
            + "    owner = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);\n"
            + "    if (owner == NULL) return 0;\n"
            + "    if (!QueryFullProcessImageNameW(owner, 0, wide, &size)) {\n"
            + "        CloseHandle(owner);\n"
            + "        return 0;\n"
            + "    }\n"
            + "    CloseHandle(owner);\n"
            + "    path[0] = 0;\n"
            + "    umbra_gate_wide_to_ascii(wide, path, UMBRA_GATE_PATH_MAX);\n"
            + "    root[0] = 0;\n"
            + "    umbra_gate_env(root, UMBRA_GATE_PATH_MAX, \"SystemRoot\");\n"
            + "    if (root[0] == 0 || !umbra_gate_prefix_nocase(path, root)) {\n"
            + "        /* MsMpEng lives under ProgramData\\Microsoft\\Windows Defender\\Platform. */\n"
            + "        root[0] = 0;\n"
            + "        umbra_gate_env(root, UMBRA_GATE_PATH_MAX, \"ProgramFiles\");\n"
            + "        if (root[0] == 0 || !umbra_gate_prefix_nocase(path, root)) {\n"
            + "            root[0] = 0;\n"
            + "            umbra_gate_env(root, UMBRA_GATE_PATH_MAX, \"ProgramData\");\n"
            + "            if (root[0] == 0 || !umbra_gate_prefix_nocase(path, root)) return 0;\n"
            + "        }\n"
            + "    }\n"
            + "    base = path;\n"
            + "    for (i = 0; path[i] != 0; i++) {\n"
            + "        if (path[i] == '\\\\' || path[i] == '/') base = path + i + 1;\n"
            + "    }\n"
            + "    for (i = 0; i < 7; i++) {\n"
            + "        if (umbra_gate_name_is(base, names[i])) return 1;\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "/* Threat model boundary: the launcher (the process that called CreateProcess) and\n"
            + "   the kernel/console processes legitimately hold process handles. Everything else\n"
            + "   is a third-party reader. */\n"
            + "#if UMBRA_GATE_DIAG\n"
            + "static void umbra_gate_diag_holder(unsigned long pid, unsigned long access) {\n"
            + "    char temp[UMBRA_GATE_PATH_MAX];\n"
            + "    char path[UMBRA_GATE_PATH_MAX];\n"
            + "    char image[UMBRA_GATE_PATH_MAX];\n"
            + "    char line[UMBRA_GATE_PATH_MAX * 2];\n"
            + "    HANDLE owner;\n"
            + "    HANDLE file;\n"
            + "    DWORD length = UMBRA_GATE_PATH_MAX;\n"
            + "    DWORD written = 0;\n"
            + "    int at = 0;\n"
            + "    image[0] = 0;\n"
            + "    owner = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);\n"
            + "    if (owner != NULL) {\n"
            + "        WCHAR wide[UMBRA_GATE_PATH_MAX];\n"
            + "        if (QueryFullProcessImageNameW(owner, 0, wide, &length)) {\n"
            + "            umbra_gate_wide_to_ascii(wide, image, UMBRA_GATE_PATH_MAX);\n"
            + "        }\n"
            + "        CloseHandle(owner);\n"
            + "    }\n"
            + "    umbra_gate_env(temp, UMBRA_GATE_PATH_MAX, \"TEMP\");\n"
            + "    if (temp[0] == 0) return;\n"
            + "    {\n"
            + "        int i = (int)strlen(temp);\n"
            + "        char suffix[64];\n"
            + "        int n = 0;\n"
            + "        unsigned long value = (unsigned long)GetCurrentProcessId();\n"
            + "        char digits[16];\n"
            + "        int d = 0;\n"
            + "        while (value > 0 && d < 16) {\n"
            + "            digits[d++] = (char)('0' + (int)(value % 10UL));\n"
            + "            value /= 10UL;\n"
            + "        }\n"
            + "        suffix[n++] = '\\\\';\n"
            + "        suffix[n++] = 't';\n"
            + "        while (d > 0) suffix[n++] = digits[--d];\n"
            + "        suffix[n++] = '.';\n"
            + "        suffix[n++] = 't';\n"
            + "        suffix[n++] = 'x';\n"
            + "        suffix[n++] = 't';\n"
            + "        suffix[n] = 0;\n"
            + "        if (i + n + 1 < UMBRA_GATE_PATH_MAX) {\n"
            + "            memcpy(temp + i, suffix, (size_t)n);\n"
            + "            temp[i + n] = 0;\n"
            + "        }\n"
            + "    }\n"
            + "    at += (int)strlen(\"pid=\");\n"
            + "    {\n"
            + "        char numbers[32];\n"
            + "        int n = 0;\n"
            + "        unsigned long value = pid;\n"
            + "        char digits[16];\n"
            + "        int d = 0;\n"
            + "        while (value > 0 && d < 16) {\n"
            + "            digits[d++] = (char)('0' + (int)(value % 10UL));\n"
            + "            value /= 10UL;\n"
            + "        }\n"
            + "        while (d > 0) numbers[n++] = digits[--d];\n"
            + "        numbers[n] = 0;\n"
            + "        memcpy(line, \"pid=\", 4);\n"
            + "        memcpy(line + 4, numbers, (size_t)n);\n"
            + "        at = 4 + n;\n"
            + "    }\n"
            + "    line[at++] = ' ';\n"
            + "    memcpy(line + at, image, strlen(image));\n"
            + "    at += (int)strlen(image);\n"
            + "    line[at++] = '\\n';\n"
            + "    line[at] = 0;\n"
            + "    file = CreateFileA(temp, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,\n"
            + "            FILE_ATTRIBUTE_NORMAL, NULL);\n"
            + "    if (file != INVALID_HANDLE_VALUE) {\n"
            + "        WriteFile(file, line, (DWORD)at, &written, NULL);\n"
            + "        CloseHandle(file);\n"
            + "    }\n"
            + "}\n"
            + "static void umbra_gate_diag_module(const char* modulePath) {\n"
            + "    char temp[UMBRA_GATE_PATH_MAX];\n"
            + "    char line[UMBRA_GATE_PATH_MAX * 2];\n"
            + "    HANDLE file;\n"
            + "    DWORD written = 0;\n"
            + "    int at = 0;\n"
            + "    umbra_gate_env(temp, UMBRA_GATE_PATH_MAX, \"TEMP\");\n"
            + "    if (temp[0] == 0) return;\n"
            + "    {\n"
            + "        int i = (int)strlen(temp);\n"
            + "        char suffix[48];\n"
            + "        unsigned long value = (unsigned long)GetCurrentProcessId();\n"
            + "        char digits[16];\n"
            + "        int d = 0;\n"
            + "        int n = 0;\n"
            + "        while (value > 0 && d < 16) {\n"
            + "            digits[d++] = (char)('0' + (int)(value % 10UL));\n"
            + "            value /= 10UL;\n"
            + "        }\n"
            + "        suffix[n++] = '\\\\';\n"
            + "        suffix[n++] = 'm';\n"
            + "        while (d > 0) suffix[n++] = digits[--d];\n"
            + "        suffix[n++] = '.';\n"
            + "        suffix[n++] = 't';\n"
            + "        suffix[n++] = 'x';\n"
            + "        suffix[n++] = 't';\n"
            + "        suffix[n] = 0;\n"
            + "        if (i + n + 1 < UMBRA_GATE_PATH_MAX) {\n"
            + "            memcpy(temp + i, suffix, (size_t)n);\n"
            + "            temp[i + n] = 0;\n"
            + "        }\n"
            + "    }\n"
            + "    memcpy(line + at, \"mod=\", 4);\n"
            + "    at += 4;\n"
            + "    if (modulePath != NULL) {\n"
            + "        int length = (int)strlen(modulePath);\n"
            + "        if (length > UMBRA_GATE_PATH_MAX - 16) length = UMBRA_GATE_PATH_MAX - 16;\n"
            + "        memcpy(line + at, modulePath, (size_t)length);\n"
            + "        at += length;\n"
            + "    }\n"
            + "    line[at++] = '\\n';\n"
            + "    line[at] = 0;\n"
            + "    file = CreateFileA(temp, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,\n"
            + "            FILE_ATTRIBUTE_NORMAL, NULL);\n"
            + "    if (file != INVALID_HANDLE_VALUE) {\n"
            + "        WriteFile(file, line, (DWORD)at, &written, NULL);\n"
            + "        CloseHandle(file);\n"
            + "    }\n"
            + "}\n"
            + "#endif\n"
            + "\n"
            + "static int umbra_gate_owner_allowed(unsigned long pid) {\n"
            + "    if (pid == 4UL) return 1;\n"
            + "    if (pid != 0UL && g_gate_chain_ready && pid == g_gate_chain[1]) return 1;\n"
            + "    if (umbra_gate_collector_allowed(pid)) return 1;\n"
            + "    if (umbra_gate_pid_allowed(pid)) return 1;\n"
            + "    if (umbra_gate_image_allowed(pid)) return 1;\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "/* True when a process that is not whitelisted holds a handle on THIS process\n"
            + "   with VM_READ or VM_OPERATION access. Enumeration failure is \"no reader\". */\n"
            + "static int umbra_gate_external_reader(void) {\n"
            + "    ULONG size = 0;\n"
            + "    UMBRA_GATE_HANDLE_INFO* info;\n"
            + "    ULONG_PTR self_handle;\n"
            + "    HANDLE self;\n"
            + "    ULONG_PTR count;\n"
            + "    ULONG_PTR i;\n"
            + "    int hit = 0;\n"
            + "    self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());\n"
            + "    if (self == NULL) return 0;\n"
            + "    self_handle = (ULONG_PTR)self;\n"
            + "    info = (UMBRA_GATE_HANDLE_INFO*)umbra_gate_handle_table(&size);\n"
            + "    if (info == NULL) {\n"
            + "        CloseHandle(self);\n"
            + "        return 0;\n"
            + "    }\n"
            + "    if (!g_gate_self_object_ready && umbra_gate_find_self_object(info, self_handle)) {\n"
            + "        g_gate_self_object_ready = 1;\n"
            + "    }\n"
            + "    if (g_gate_self_object_ready) {\n"
            + "        count = info->NumberOfHandles;\n"
            + "        for (i = 0; i < count; i++) {\n"
            + "            const UMBRA_GATE_HANDLE* entry = &info->Handles[i];\n"
            + "            if ((ULONG_PTR)entry->Object != g_gate_self_object) continue;\n"
            + "            if (entry->UniqueProcessId == (ULONG_PTR)GetCurrentProcessId()) continue;\n"
            + "            if ((entry->GrantedAccess & 0x18UL) == 0UL) continue;\n"
            + "            if (umbra_gate_owner_allowed((unsigned long)entry->UniqueProcessId)) continue;\n"
            + "#if UMBRA_GATE_DIAG\n"
            + "            umbra_gate_diag_holder((unsigned long)entry->UniqueProcessId,\n"
            + "                    (unsigned long)entry->GrantedAccess);\n"
            + "#endif\n"
            + "            hit = 1;\n"
            + "            break;\n"
            + "        }\n"
            + "    }\n"
            + "    CloseHandle(self);\n"
            + "    VirtualFree(info, 0, MEM_RELEASE);\n"
            + "    return hit;\n"
            + "}\n"
            + "\n"
            + "/* Full scan: markers first, then the JVMTI-export diff. Sticky once hit. */\n"
            + "static int umbra_gate_agent_scan(void) {\n"
            + "    if (g_gate_agent_seen) return 1;\n"
            + "    if (umbra_gate_marker_scan()) {\n"
            + "        g_gate_agent_seen = 1;\n"
            + "        return 1;\n"
            + "    }\n"
            + "    if (umbra_gate_late_scan()) {\n"
            + "        g_gate_agent_seen = 1;\n"
            + "        return 1;\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "/* Throttled variant for the per-class tick: at most one snapshot per\n"
            + "   UMBRA_GATE_TICK_MS; the cached answer is reused in between. */\n"
            + "static int umbra_gate_dirty(void) {\n"
            + "#ifdef _WIN32\n"
            + "    unsigned long now;\n"
            + "    if (g_gate_agent_seen) return 1;\n"
            + "    now = (unsigned long)GetTickCount();\n"
            + "    if (g_gate_last_scan_ms != 0UL && now - g_gate_last_scan_ms < UMBRA_GATE_TICK_MS) {\n"
            + "        return g_gate_last_scan_clean ? 0 : 1;\n"
            + "    }\n"
            + "    g_gate_last_scan_ms = now;\n"
            + "    if (umbra_gate_agent_scan()) {\n"
            + "        g_gate_last_scan_clean = 0;\n"
            + "        return 1;\n"
            + "    }\n"
            + "    g_gate_last_scan_clean = 1;\n"
            + "    return 0;\n"
            + "#else\n"
            + "    return umbra_gate_agent_scan();\n"
            + "#endif\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_tick_digest(int index, unsigned char* out) {\n"
            + "    unsigned char payload_root[32];\n"
            + "    unsigned char message[UMBRA_GATE_TICK_LABEL_LEN + 4];\n"
            + "    int i;\n"
            + "    umbra_key_derive(2, 0, payload_root);\n"
            + "    for (i = 0; i < UMBRA_GATE_TICK_LABEL_LEN; i++) {\n"
            + "        message[i] = (unsigned char)(umbra_g_tick_label[i]\n"
            + "                ^ (unsigned char)(UMBRA_GATE_TICK_LABEL_KEY + (unsigned int)i * 7u));\n"
            + "    }\n"
            + "    message[UMBRA_GATE_TICK_LABEL_LEN] = (unsigned char)((unsigned int)index & 0xFFu);\n"
            + "    message[UMBRA_GATE_TICK_LABEL_LEN + 1] = (unsigned char)(((unsigned int)index >> 8) & 0xFFu);\n"
            + "    message[UMBRA_GATE_TICK_LABEL_LEN + 2] = (unsigned char)(((unsigned int)index >> 16) & 0xFFu);\n"
            + "    message[UMBRA_GATE_TICK_LABEL_LEN + 3] = (unsigned char)(((unsigned int)index >> 24) & 0xFFu);\n"
            + "    umbra_k_hmac(payload_root, 32, message, UMBRA_GATE_TICK_LABEL_LEN + 4, out);\n"
            + "    memset(payload_root, 0, sizeof(payload_root));\n"
            + "    memset(message, 0, sizeof(message));\n"
            + "}\n"
            + "\n"
            + "static jint JNICALL umbra_gate_tick(JNIEnv* env, jclass cls, jint index, jbyteArray out) {\n"
            + "    unsigned char digest[32];\n"
            + "    jsize length;\n"
            + "    (void)cls;\n"
            + "    if (out == NULL) return -1;\n"
            + "    length = (*env)->GetArrayLength(env, out);\n"
            + "    if (length < 32) return -2;\n"
            + "    if (!g_gate_open) return -4;\n"
            + "    /* The watchdog (100 ms, own thread) owns every module/handle verdict; the tick\n"
            + "       itself must stay a pure HMAC so a class decryption never blocks on a scan. */\n"
            + "    if (g_gate_alert) return -5;\n"
            + "    umbra_gate_tick_digest((int)index, digest);\n"
            + "    (*env)->SetByteArrayRegion(env, out, 0, 32, (const jbyte*)digest);\n"
            + "    memset(digest, 0, sizeof(digest));\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "/* Background module watchdog + DLL-load notification. The LDR notification\n"
            + "   callback runs synchronously inside the loader lock, so it only performs a\n"
            + "   read-only PE export check and signals an event; the process exit happens in the\n"
            + "   watchdog thread. Registration failure (older systems) degrades to polling. */\n"
            + "static HANDLE g_gate_thread;\n"
            + "static HANDLE g_gate_hit_event;\n"
            + "static volatile int g_gate_watchdog_started;\n"
            + "static int g_gate_notification_registered;\n"
            + "\n"
            + "static void umbra_gate_flag_hit(void) {\n"
            + "    g_gate_alert = 1;\n"
            + "    g_gate_open = 0;\n"
            + "    if (g_gate_hit_event != NULL) SetEvent(g_gate_hit_event);\n"
            + "}\n"
            + "\n"
            + "typedef struct {\n"
            + "    USHORT Length;\n"
            + "    USHORT MaximumLength;\n"
            + "    PWSTR Buffer;\n"
            + "} UMBRA_GATE_UNICODE_STRING;\n"
            + "\n"
            + "typedef struct {\n"
            + "    ULONG Flags;\n"
            + "    const UMBRA_GATE_UNICODE_STRING* FullDllName;\n"
            + "    const UMBRA_GATE_UNICODE_STRING* BaseDllName;\n"
            + "    PVOID DllBase;\n"
            + "    ULONG SizeOfImage;\n"
            + "} UMBRA_GATE_LDR_LOADED;\n"
            + "\n"
            + "typedef struct {\n"
            + "    ULONG Flags;\n"
            + "    UMBRA_GATE_LDR_LOADED Loaded;\n"
            + "} UMBRA_GATE_LDR_NOTIFICATION;\n"
            + "\n"
            + "static int umbra_gate_wide_to_ascii(const WCHAR* wide, char* out, int capacity) {\n"
            + "    int i = 0;\n"
            + "    if (wide == NULL || out == NULL || capacity <= 0) return 0;\n"
            + "    while (wide[i] != 0 && i < capacity - 1) {\n"
            + "        out[i] = (char)(wide[i] & 0xFF);\n"
            + "        i++;\n"
            + "    }\n"
            + "    out[i] = 0;\n"
            + "    return i > 0;\n"
            + "}\n"
            + "\n"
            + "static volatile unsigned int g_gate_dll_events;\n"
            + "\n"
            + "/* Loader-lock callback: touches nothing but a counter and an event. The actual\n"
            + "   judgement runs in the watchdog thread, outside the loader lock. */\n"
            + "static void umbra_gate_dll_notification(ULONG reason,\n"
            + "        const UMBRA_GATE_LDR_NOTIFICATION* data, PVOID context) {\n"
            + "    (void)data;\n"
            + "    (void)context;\n"
            + "    if (reason != 1UL) return;\n"
            + "    g_gate_dll_events++;\n"
            + "    if (g_gate_hit_event != NULL) SetEvent(g_gate_hit_event);\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_register_notification(void) {\n"
            + "    typedef LONG (NTAPI *umbra_register_fn)(ULONG, PVOID, PVOID*);\n"
            + "    HMODULE ntdll;\n"
            + "    umbra_register_fn register_fn;\n"
            + "    PVOID cookie = NULL;\n"
            + "    if (g_gate_notification_registered) return;\n"
            + "    ntdll = GetModuleHandleA(\"ntdll.dll\");\n"
            + "    if (ntdll == NULL) return;\n"
            + "    register_fn = (umbra_register_fn)GetProcAddress(ntdll, \"LdrRegisterDllNotification\");\n"
            + "    if (register_fn == NULL) return;\n"
            + "    if (register_fn(0UL, (PVOID)(&umbra_gate_dll_notification), &cookie) != 0L) return;\n"
            + "    g_gate_notification_registered = 1;\n"
            + "}\n"
            + "\n"
            + "static DWORD WINAPI umbra_gate_watchdog(LPVOID parameter) {\n"
            + "    (void)parameter;\n"
            + "    /* Runs outside the loader lock (unlike JNI_OnLoad): resolving directories and\n"
            + "       registering the DLL notification here avoids re-entering the loader lock\n"
            + "       while the current LoadLibrary is still dispatching. */\n"
            + "    umbra_gate_build_dirs();\n"
            + "#if UMBRA_GATE_LDR_NOTIFY\n"
            + "    umbra_gate_register_notification();\n"
            + "#endif\n"
            + "    /* Baseline the pre-existing external VM handles immediately, then scan at the\n"
            + "       configured period (100 ms by default) so a carve cannot finish first. */\n"
            + "    umbra_gate_build_chain();\n"
            + "    g_gate_watch_started = (unsigned long)GetTickCount();\n"
            + "    g_gate_last_handle_ms = g_gate_watch_started;\n"
            + "    (void)umbra_gate_external_reader();\n"
            + "    for (;;) {\n"
            + "        if (g_gate_install_busy) {\n"
            + "            Sleep(1);\n"
            + "            continue;\n"
            + "        }\n"
            + "        if (g_gate_alert) TerminateProcess(GetCurrentProcess(), 1);\n"
            + "        if (g_gate_hit_event != NULL) {\n"
            + "            WaitForSingleObject(g_gate_hit_event, UMBRA_GATE_WATCHDOG_MS);\n"
            + "        } else {\n"
            + "            Sleep(UMBRA_GATE_WATCHDOG_MS);\n"
            + "        }\n"
            + "        {\n"
            + "            unsigned long now = (unsigned long)GetTickCount();\n"
            + "            unsigned long period = UMBRA_GATE_HANDLE_MS;\n"
            + "            if (g_gate_watch_started != 0UL && now - g_gate_watch_started > 5000UL) {\n"
            + "                /* Decay after the first five seconds: the decrypt burst is over. */\n"
            + "                period = 500UL;\n"
            + "            }\n"
            + "            if (g_gate_last_handle_ms == 0UL || now - g_gate_last_handle_ms >= period) {\n"
            + "                g_gate_last_handle_ms = now;\n"
            + "                if (umbra_gate_external_reader()) {\n"
            + "                    umbra_gate_flag_hit();\n"
            + "                    TerminateProcess(GetCurrentProcess(), 1);\n"
            + "                }\n"
            + "            }\n"
            + "        }\n"
            + "        if (umbra_gate_agent_scan()) {\n"
            + "            umbra_gate_flag_hit();\n"
            + "            TerminateProcess(GetCurrentProcess(), 1);\n"
            + "        }\n"
            + "    }\n"
            + "    return 0;\n"
            + "}\n"
            + "\n"
            + "static void umbra_gate_start_watchdog(void) {\n"
            + "    if (g_gate_watchdog_started) return;\n"
            + "    g_gate_watchdog_started = 1;\n"
            + "    if (g_gate_hit_event == NULL) {\n"
            + "        g_gate_hit_event = CreateEventA(NULL, FALSE, FALSE, NULL);\n"
            + "    }\n"
            + "    if (g_gate_thread == NULL) {\n"
            + "        g_gate_thread = CreateThread(NULL, 0, umbra_gate_watchdog, NULL, 0, NULL);\n"
            + "        if (g_gate_thread != NULL) {\n"
            + "            CloseHandle(g_gate_thread);\n"
            + "            g_gate_thread = NULL;\n"
            + "        }\n"
            + "    }\n"
            + "}\n"
            + "";
}
