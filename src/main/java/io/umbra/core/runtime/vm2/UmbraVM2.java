package io.umbra.core.runtime.vm2;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Hardened stack-machine interpreter for bytecode virtualized by Umbra's VM2
 * engine. This class is a runtime <b>template</b>: {@code VirtualizationPass}
 * copies it into the protected program under a random synthetic name and
 * remaps its self references. It must therefore stay completely self-contained
 * (JDK only, no nested/anonymous classes, no invokedynamic, Java 8 level).
 *
 * <h3>Execution model</h3>
 *
 * <p>A payload is a number of encrypted {@code int[]} blocks plus a small
 * {@code int[]} header (see {@code Vm2Format} in the obfuscator for the exact
 * layout). The first call decrypts, verifies and decodes the payload once; the
 * decoded state is cached and shared by all threads, while stacks and local
 * variable arrays are per execution (pooled per thread). The dispatch loop is a
 * single computed {@code switch} over the real JVM opcode numbers, with the
 * opcodes looked up through a per-program permutation table.</p>
 *
 * <p>Values live in two parallel stacks: a {@code long[]} for primitive values
 * (int/float stored as raw bits, long/double as raw 64 bit values) and an
 * {@code Object[]} for references, plus a per-slot width array so that the
 * {@code dup}/{@code pop2} family keeps exact JVM semantics without boxing.
 * Wide values occupy a single interpreter slot and are marked by width 2 in the
 * JVM's terms.</p>
 *
 * <p>Exceptions thrown by interpreted instructions are matched against the
 * translated handler table (start/end pc, catch type, target) exactly like the
 * JVM; finally blocks are ordinary translated catch-all handlers. When nothing
 * matches, the throwable is rethrown with {@code sneakyThrow}, so callers see
 * the original exception type without wrapping.</p>
 */
public final class UmbraVM2 {

    private UmbraVM2() {
    }

    // ---- wire format (kept in sync with Vm2Format) ----
    /** Legacy payload version: shared opcode map, no rolling opcode key. */
    private static final int FORMAT = 3;
    /** Current payload version: adds the rolling opcode-key layer. */
    private static final int ROLLING_FORMAT = 4;

    private static final int FLAG_ENCRYPT = 1;
    private static final int FLAG_NESTED = 2;
    private static final int FLAG_OPCODES = 4;

    private static final int META_LEN = 8;
    private static final int HEADER = 10;

    // ---- superinstructions (vm2.fusion), mirrored from Vm2Format ----
    private static final int SUPER_BASE = 202;
    private static final int SUPER_IADD_LL = 202;
    private static final int SUPER_ISUB_LL = 203;
    private static final int SUPER_IMUL_LL = 204;
    private static final int SUPER_IAND_LL = 205;
    private static final int SUPER_IOR_LL = 206;
    private static final int SUPER_IXOR_LL = 207;
    private static final int SUPER_ILOAD_CONST_ADD = 208;
    private static final int SUPER_ILOAD_CONST_SUB = 209;
    private static final int SUPER_ILOAD_CONST_MUL = 210;
    private static final int SUPER_ILOAD_CONST_AND = 211;
    private static final int SUPER_ILOAD_CONST_OR = 212;
    private static final int SUPER_ILOAD_CONST_XOR = 213;
    private static final int SUPER_IF_ICMPEQ_LL = 214;
    private static final int SUPER_IF_ICMPNE_LL = 215;
    private static final int SUPER_IF_ICMPLT_LL = 216;
    private static final int SUPER_IF_ICMPGE_LL = 217;
    private static final int SUPER_IF_ICMPGT_LL = 218;
    private static final int SUPER_IF_ICMPLE_LL = 219;
    private static final int SUPER_LADD_LL = 220;
    private static final int SUPER_LSUB_LL = 221;
    private static final int SUPER_LMUL_LL = 222;
    private static final int SUPER_LAND_LL = 223;
    private static final int SUPER_LOR_LL = 224;
    private static final int SUPER_LXOR_LL = 225;
    private static final int SUPER_ALOAD_GETFIELD = 226;
    private static final int SUPER_CONST_ISTORE = 227;
    private static final int SUPER_LAST = 227;

    private static final int KIND_UNUSED = 0;
    private static final int KIND_INT = 1;
    private static final int KIND_LONG = 2;
    private static final int KIND_FLOAT = 3;
    private static final int KIND_DOUBLE = 4;
    private static final int KIND_REF = 5;

    private static final int OUTER_PUSH = 0;
    private static final int OUTER_XOR = 1;
    private static final int OUTER_ADD = 2;
    private static final int OUTER_MUL = 3;
    private static final int OUTER_ROTL = 4;
    private static final int OUTER_MIX = 5;
    private static final int OUTER_NOT = 6;
    private static final int OUTER_DUP = 7;
    private static final int OUTER_SWAP = 8;
    private static final int OUTER_HALT = 9;
    private static final int OUTER_PUSH2 = 10;

    private static final long GOLDEN = 0x9E3779B97F4A7C15L;

    // ---- decoded state layout (Object[] so that no nested classes are needed) ----
    private static final int STATE_CODE = 0;
    /** Pre-decoded real opcodes, one int per code slot (valid at opcode slots). */
    private static final int STATE_OPS = 1;
    private static final int STATE_CONSTS = 2;
    private static final int STATE_REFS = 3;
    private static final int STATE_HANDLERS = 4;
    private static final int STATE_INFO = 5;
    private static final int STATE_KINDS = 6;
    private static final int STATE_REF_CACHE = 7;

    // ---- resolved call-site bundle layout (Object[]) ----
    private static final int INFO_KIND = 0;
    private static final int INFO_METHOD = 1;
    private static final int INFO_CTOR = 2;
    private static final int INFO_ARGS = 3;
    private static final int INFO_RETURN = 4;
    private static final int INFO_NAME = 5;
    private static final int INFO_OPCODE = 6;

    private static final Object[] NO_ARGS = new Object[0];

    // ---- reusable thread-local frame layout ----
    private static final int FRAME_NS = 0;
    private static final int FRAME_RS = 1;
    private static final int FRAME_WS = 2;
    private static final int FRAME_NL = 3;
    private static final int FRAME_RL = 4;
    private static final int FRAME_NEXT = 5;

    /** Decoded payload cache, keyed by the holder's meta array identity. */
    private static final ConcurrentHashMap<Object, Object> STATES =
            new ConcurrentHashMap<Object, Object>();
    private static final ConcurrentHashMap<String, Object> TYPES =
            new ConcurrentHashMap<String, Object>();
    private static final ConcurrentHashMap<String, Object> METHODS =
            new ConcurrentHashMap<String, Object>();
    private static final ConcurrentHashMap<String, Object> FIELDS =
            new ConcurrentHashMap<String, Object>();
    private static final ConcurrentHashMap<String, Object> CONSTRUCTORS =
            new ConcurrentHashMap<String, Object>();
    private static final ConcurrentHashMap<String, Object> PARAMETERS =
            new ConcurrentHashMap<String, Object>();
    private static final ConcurrentHashMap<String, Object> ARGUMENTS =
            new ConcurrentHashMap<String, Object>();

    /** Free frame chain for the current thread. */
    private static final ThreadLocal FRAMES = new ThreadLocal();

    // ==================================================================
    // Entry point
    // ==================================================================

    /**
     * Bootstrap of a virtualized call site.
     *
     * <p>A virtualized method body contains exactly one {@code invokedynamic}:
     * its descriptor only carries the boxed locals array, its name is random and
     * its single static argument is the payload id. The interpreter entry is
     * resolved here, once per call site, through its signature - so neither the
     * entry name nor the holder classes are referenced as strings by the caller,
     * and the linked call site is a constant method handle.</p>
     *
     * @param caller    lookup of the class containing the call site (unused)
     * @param name      random call-site name (unused)
     * @param type      call-site type, {@code (Object[])Object}
     * @param payloadId payload bound to this call site
     */
    public static CallSite bootstrap(MethodHandles.Lookup caller, String name, MethodType type,
                                     int payloadId) throws Throwable {
        MethodHandles.Lookup lookup = MethodHandles.lookup();
        Method[] candidates = lookup.lookupClass().getDeclaredMethods();
        for (int i = 0; i < candidates.length; i++) {
            Method candidate = candidates[i];
            if (!Modifier.isStatic(candidate.getModifiers())
                    || !Object.class.equals(candidate.getReturnType())) {
                continue;
            }
            Class<?>[] parameters = candidate.getParameterTypes();
            if (parameters.length != 2 || parameters[0] != int.class
                    || parameters[1] != Object[].class) {
                continue;
            }
            MethodHandle entry = lookup.unreflect(candidate);
            return new ConstantCallSite(MethodHandles.insertArguments(entry, 0,
                    Integer.valueOf(payloadId)));
        }
        throw new IllegalStateException("VM2 interpreter entry is missing");
    }

    /**
     * Executes one virtualized method body.
     *
     * @param meta   header built by the holder class initializer
     * @param map    shared per-program opcode permutation table ({@code encoded ->
     *               real opcode}), or {@code null} when permutation is disabled
     * @param blocks encrypted payload blocks (first one is the outer program
     *               when the payload is nested)
     * @param locals boxed arguments; slot 0 holds {@code this} for instance methods
     * @return boxed return value, or {@code null} for {@code void}
     */
    public static Object run(int[] meta, int[] map, int[][] blocks, Object[] locals) {
        Object[] state = stateFor(meta, map, blocks);
        int[] code = (int[]) state[STATE_CODE];
        int[] ops = (int[]) state[STATE_OPS];
        Object[] consts = (Object[]) state[STATE_CONSTS];
        String[] refs = (String[]) state[STATE_REFS];
        int[] handlers = (int[]) state[STATE_HANDLERS];
        int[] info = (int[]) state[STATE_INFO];
        int[] kinds = (int[]) state[STATE_KINDS];
        Object[] refCache = (Object[]) state[STATE_REF_CACHE];
        int maxLocals = info[0];
        int argSlots = info[1];
        int stackHint = info[2];

        Object[] frame = acquireFrame(stackHint, maxLocals);
        long[] ns = (long[]) frame[FRAME_NS];
        Object[] rs = (Object[]) frame[FRAME_RS];
        byte[] ws = (byte[]) frame[FRAME_WS];
        long[] nl = (long[]) frame[FRAME_NL];
        Object[] rl = (Object[]) frame[FRAME_RL];

        for (int s = 0; s < argSlots; s++) {
            int kind = kinds[s];
            if (kind == KIND_INT) {
                nl[s] = toInt(locals[s]);
            } else if (kind == KIND_LONG) {
                nl[s] = toLong(locals[s]);
            } else if (kind == KIND_FLOAT) {
                nl[s] = Float.floatToRawIntBits(toFloat(locals[s]));
            } else if (kind == KIND_DOUBLE) {
                nl[s] = Double.doubleToRawLongBits(toDouble(locals[s]));
            } else if (kind == KIND_REF) {
                rl[s] = locals[s];
            }
        }

        int sp = 0;
        int pc = 0;
        try {
            while (true) {
                try {
                    while (true) {
                        int p = pc;
                        if (p < 0 || p >= code.length) {
                            throw new IllegalStateException("Umbra VM2 pc out of range: " + p
                                    + " of " + code.length);
                        }
                        // Opcodes are decoded once at payload load time (format 3:
                        // permutation table only; format 4: rolling key + table),
                        // so the hot loop is a plain array read.
                        int op = ops[p++];
                        // Fused superinstructions execute a whole opcode run with
                        // one dispatch; their target/next pc is returned packed.
                        if (op >= SUPER_BASE && op <= SUPER_LAST) {
                            long packed = vmSuper(op, code, p, ns, rs, ws, nl, rl, refs,
                                    refCache, sp);
                            sp = (int) packed;
                            pc = (int) (packed >>> 32);
                            continue;
                        }
                        // Computed dispatch over opcode families keeps the main
                        // switch below HotSpot's HugeMethodLimit.
                        if (op >= 87 && op <= 95) {
                            sp = vmStack(op, ns, rs, ws, sp);
                            pc = p;
                            continue;
                        }
                        if ((op >= 96 && op <= 131) || (op >= 133 && op <= 152)) {
                            sp = vmNumeric(op, ns, ws, sp);
                            pc = p;
                            continue;
                        }
                        if (op >= 46 && op <= 53) {
                            sp = vmArrayLoad(op, ns, rs, ws, sp);
                            pc = p;
                            continue;
                        }
                        if (op >= 79 && op <= 86) {
                            sp = vmArrayStore(op, ns, rs, sp);
                            pc = p;
                            continue;
                        }
                        switch (op) {
                            case 0: // NOP
                                pc = p;
                                break;
                            case 1: // ACONST_NULL
                                rs[sp] = null;
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            case 2: case 3: case 4: case 5: case 6: case 7: case 8:
                                // ICONST_M1 .. ICONST_5
                                ns[sp] = op - 3;
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            case 9: case 10: // LCONST_0, LCONST_1
                                ns[sp] = op - 9;
                                ws[sp] = 2;
                                sp++;
                                pc = p;
                                break;
                            case 11: case 12: case 13: // FCONST_0..2
                                ns[sp] = Float.floatToRawIntBits(op - 11);
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            case 14: case 15: // DCONST_0, DCONST_1
                                ns[sp] = Double.doubleToRawLongBits(op - 14);
                                ws[sp] = 2;
                                sp++;
                                pc = p;
                                break;
                            case 16: case 17: // BIPUSH, SIPUSH
                                ns[sp] = code[p++];
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            case 18: { // LDC
                                Object value = consts[code[p++]];
                                if (value instanceof String[]) {
                                    String[] marker = (String[]) value;
                                    if (marker.length == 2 && "C".equals(marker[0])) {
                                        value = resolveDescriptor(marker[1]);
                                    }
                                }
                                if (value instanceof Integer) {
                                    ns[sp] = ((Integer) value).intValue();
                                    ws[sp] = 1;
                                } else if (value instanceof Long) {
                                    ns[sp] = ((Long) value).longValue();
                                    ws[sp] = 2;
                                } else if (value instanceof Float) {
                                    ns[sp] = Float.floatToRawIntBits(((Float) value).floatValue());
                                    ws[sp] = 1;
                                } else if (value instanceof Double) {
                                    ns[sp] = Double.doubleToRawLongBits(((Double) value).doubleValue());
                                    ws[sp] = 2;
                                } else {
                                    rs[sp] = value;
                                    ws[sp] = 1;
                                }
                                sp++;
                                pc = p;
                                break;
                            }
                            case 21: // ILOAD
                                ns[sp] = nl[code[p++]];
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            case 22: // LLOAD
                                ns[sp] = nl[code[p++]];
                                ws[sp] = 2;
                                sp++;
                                pc = p;
                                break;
                            case 23: // FLOAD
                                ns[sp] = (int) nl[code[p++]];
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            case 24: // DLOAD
                                ns[sp] = nl[code[p++]];
                                ws[sp] = 2;
                                sp++;
                                pc = p;
                                break;
                            case 25: // ALOAD
                                rs[sp] = rl[code[p++]];
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            case 54: // ISTORE
                                nl[code[p++]] = ns[--sp];
                                pc = p;
                                break;
                            case 55: // LSTORE
                                nl[code[p++]] = ns[--sp];
                                pc = p;
                                break;
                            case 56: // FSTORE
                                nl[code[p++]] = (int) ns[--sp];
                                pc = p;
                                break;
                            case 57: // DSTORE
                                nl[code[p++]] = ns[--sp];
                                pc = p;
                                break;
                            case 58: // ASTORE
                                rl[code[p++]] = rs[--sp];
                                pc = p;
                                break;
                            case 132: { // IINC
                                int var = code[p++];
                                int delta = code[p++];
                                nl[var] = (int) nl[var] + delta;
                                pc = p;
                                break;
                            }
                            case 153: // IFEQ
                                pc = ((int) ns[--sp]) == 0 ? code[p] : p + 1;
                                break;
                            case 154: // IFNE
                                pc = ((int) ns[--sp]) != 0 ? code[p] : p + 1;
                                break;
                            case 155: // IFLT
                                pc = ((int) ns[--sp]) < 0 ? code[p] : p + 1;
                                break;
                            case 156: // IFGE
                                pc = ((int) ns[--sp]) >= 0 ? code[p] : p + 1;
                                break;
                            case 157: // IFGT
                                pc = ((int) ns[--sp]) > 0 ? code[p] : p + 1;
                                break;
                            case 158: // IFLE
                                pc = ((int) ns[--sp]) <= 0 ? code[p] : p + 1;
                                break;
                            case 159: { // IF_ICMPEQ
                                int b = (int) ns[--sp];
                                int a = (int) ns[--sp];
                                pc = a == b ? code[p] : p + 1;
                                break;
                            }
                            case 160: { // IF_ICMPNE
                                int b = (int) ns[--sp];
                                int a = (int) ns[--sp];
                                pc = a != b ? code[p] : p + 1;
                                break;
                            }
                            case 161: { // IF_ICMPLT
                                int b = (int) ns[--sp];
                                int a = (int) ns[--sp];
                                pc = a < b ? code[p] : p + 1;
                                break;
                            }
                            case 162: { // IF_ICMPGE
                                int b = (int) ns[--sp];
                                int a = (int) ns[--sp];
                                pc = a >= b ? code[p] : p + 1;
                                break;
                            }
                            case 163: { // IF_ICMPGT
                                int b = (int) ns[--sp];
                                int a = (int) ns[--sp];
                                pc = a > b ? code[p] : p + 1;
                                break;
                            }
                            case 164: { // IF_ICMPLE
                                int b = (int) ns[--sp];
                                int a = (int) ns[--sp];
                                pc = a <= b ? code[p] : p + 1;
                                break;
                            }
                            case 165: { // IF_ACMPEQ
                                Object b = rs[--sp];
                                Object a = rs[--sp];
                                pc = a == b ? code[p] : p + 1;
                                break;
                            }
                            case 166: { // IF_ACMPNE
                                Object b = rs[--sp];
                                Object a = rs[--sp];
                                pc = a != b ? code[p] : p + 1;
                                break;
                            }
                            case 167: // GOTO
                                pc = code[p];
                                break;
                            case 170: { // TABLESWITCH
                                int dflt = code[p++];
                                int low = code[p++];
                                int high = code[p++];
                                int key = (int) ns[--sp];
                                if (key < low || key > high) {
                                    pc = dflt;
                                } else {
                                    pc = code[p + (key - low)];
                                }
                                break;
                            }
                            case 171: { // LOOKUPSWITCH
                                int dflt = code[p++];
                                int pairs = code[p++];
                                int key = (int) ns[--sp];
                                int found = dflt;
                                for (int i = 0; i < pairs; i++) {
                                    int match = code[p++];
                                    int target = code[p++];
                                    if (match == key) {
                                        found = target;
                                        for (int j = i + 1; j < pairs; j++) {
                                            p += 2;
                                        }
                                        break;
                                    }
                                }
                                pc = found;
                                break;
                            }
                            case 172: // IRETURN
                                return Integer.valueOf((int) ns[--sp]);
                            case 173: // LRETURN
                                return Long.valueOf(ns[--sp]);
                            case 174: // FRETURN
                                return Float.valueOf(Float.intBitsToFloat((int) ns[--sp]));
                            case 175: // DRETURN
                                return Double.valueOf(Double.longBitsToDouble(ns[--sp]));
                            case 176: // ARETURN
                                return rs[--sp];
                            case 177: // RETURN
                                return null;
                            case 178: { // GETSTATIC
                                Object[] holder = fieldFor(refs[code[p++]]);
                                Field field = (Field) holder[0];
                                char sort = ((Character) holder[1]).charValue();
                                Object value = getFieldValue(field);
                                sp = pushValue(ns, rs, ws, sp, sort, value);
                                pc = p;
                                break;
                            }
                            case 179: { // PUTSTATIC
                                Object[] holder = fieldFor(refs[code[p++]]);
                                Field field = (Field) holder[0];
                                char sort = ((Character) holder[1]).charValue();
                                sp = storeField(field, sort, null, ns, rs, ws, sp);
                                pc = p;
                                break;
                            }
                            case 180: { // GETFIELD
                                Object[] holder = fieldFor(refs[code[p++]]);
                                Field field = (Field) holder[0];
                                char sort = ((Character) holder[1]).charValue();
                                Object receiver = rs[--sp];
                                Object value = getFieldValue(field, receiver);
                                sp = pushValue(ns, rs, ws, sp, sort, value);
                                pc = p;
                                break;
                            }
                            case 181: { // PUTFIELD
                                Object[] holder = fieldFor(refs[code[p++]]);
                                Field field = (Field) holder[0];
                                char sort = ((Character) holder[1]).charValue();
                                Object receiver = rs[sp - 2];
                                sp = storeField(field, sort, receiver, ns, rs, ws, sp);
                                sp--;
                                pc = p;
                                break;
                            }
                            case 182: case 183: case 184: case 185:
                                sp = invoke(refs, refCache, code[p++], op, ns, rs, ws, sp, rl);
                                pc = p;
                                break;
                            case 186: // INVOKEDYNAMIC
                                throw new IllegalStateException("Umbra VM2: invokedynamic is not supported");
                            case 187: { // NEW (vm2.news only)
                                String token = typeTokenFromRef(refs[code[p++]]);
                                Object[] marker = new Object[] { resolveInternal(token) };
                                rs[sp] = marker;
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            }
                            case 188: { // NEWARRAY
                                int type = code[p++];
                                int length = (int) ns[--sp];
                                rs[sp] = newArray(type, length);
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            }
                            case 189: { // ANEWARRAY
                                String token = typeTokenFromRef(refs[code[p++]]);
                                int length = (int) ns[--sp];
                                rs[sp] = Array.newInstance(resolveInternal(token), length);
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            }
                            case 190: { // ARRAYLENGTH
                                Object array = rs[sp - 1];
                                rs[sp - 1] = null;
                                ns[sp - 1] = Array.getLength(array);
                                ws[sp - 1] = 1;
                                pc = p;
                                break;
                            }
                            case 191: { // ATHROW
                                Object throwable = rs[--sp];
                                if (throwable == null) {
                                    throw new NullPointerException();
                                }
                                sneakyThrow((Throwable) throwable);
                                pc = p;
                                break;
                            }
                            case 192: { // CHECKCAST
                                String token = typeTokenFromRef(refs[code[p++]]);
                                Object value = rs[sp - 1];
                                if (value != null && !resolveInternal(token).isInstance(value)) {
                                    throw new ClassCastException(value.getClass().getName()
                                            + " cannot be cast to " + token);
                                }
                                pc = p;
                                break;
                            }
                            case 193: { // INSTANCEOF
                                String token = typeTokenFromRef(refs[code[p++]]);
                                Object value = rs[--sp];
                                rs[sp] = null;
                                ns[sp] = resolveInternal(token).isInstance(value) ? 1 : 0;
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            }
                            case 194: case 195: // MONITORENTER, MONITOREXIT
                                throw new IllegalStateException(
                                        "Umbra VM2: monitor instructions are not supported");
                            case 197: { // MULTIANEWARRAY
                                String token = typeTokenFromRef(refs[code[p++]]);
                                int dims = code[p++];
                                int[] sizes = new int[dims];
                                for (int i = dims - 1; i >= 0; i--) {
                                    sizes[i] = (int) ns[--sp];
                                }
                                rs[sp] = Array.newInstance(elementType(token), sizes);
                                ws[sp] = 1;
                                sp++;
                                pc = p;
                                break;
                            }
                            case 198: // IFNULL
                                pc = rs[--sp] == null ? code[p] : p + 1;
                                break;
                            case 199: // IFNONNULL
                                pc = rs[--sp] != null ? code[p] : p + 1;
                                break;
                            default:
                                throw new IllegalStateException(
                                        "Umbra VM2: unsupported opcode " + op);
                        }
                    }
                } catch (Throwable thrown) {
                    int target = -1;
                    for (int h = 0; h < handlers.length; h += 4) {
                        if (pc < handlers[h] || pc >= handlers[h + 1]) {
                            continue;
                        }
                        int typeRef = handlers[h + 2];
                        if (typeRef < 0
                                || resolveInternal(typeTokenFromRef(refs[typeRef])).isInstance(thrown)) {
                            target = handlers[h + 3];
                            break;
                        }
                    }
                    if (target < 0) {
                        sneakyThrow(thrown);
                        return null;
                    }
                    sp = 1;
                    rs[0] = thrown;
                    ws[0] = 1;
                    pc = target;
                }
            }
        } finally {
            releaseFrame(frame);
        }
    }

    // ==================================================================
    // Dispatch families
    //
    // The opcode families below are executed by small static methods instead
    // of being inlined into the main dispatch switch. Two reasons: the switch
    // stays well below HotSpot's HugeMethodLimit so the interpreter loop is
    // actually JIT compiled, and the family entry point is a set of computed
    // range checks rather than one giant lookup chain.
    // ==================================================================

    /** POP/DUP/SWAP family (opcodes 87..95). */
    private static int vmStack(int op, long[] ns, Object[] rs, byte[] ws, int sp) {
        switch (op) {
            case 87: // POP
                return sp - 1;
            case 88: // POP2
                return sp - (ws[sp - 1] == 2 ? 1 : 2);
            case 89: // DUP
                ns[sp] = ns[sp - 1];
                rs[sp] = rs[sp - 1];
                ws[sp] = ws[sp - 1];
                return sp + 1;
            case 90: { // DUP_X1: v2,v1 -> v1,v2,v1
                long n1 = ns[sp - 1];
                Object r1 = rs[sp - 1];
                byte w1 = ws[sp - 1];
                ns[sp] = n1;
                rs[sp] = r1;
                ws[sp] = w1;
                ns[sp - 1] = ns[sp - 2];
                rs[sp - 1] = rs[sp - 2];
                ws[sp - 1] = ws[sp - 2];
                ns[sp - 2] = n1;
                rs[sp - 2] = r1;
                ws[sp - 2] = w1;
                return sp + 1;
            }
            case 91: { // DUP_X2
                long n1 = ns[sp - 1];
                Object r1 = rs[sp - 1];
                byte w1 = ws[sp - 1];
                if (ws[sp - 2] == 2) {
                    ns[sp] = n1;
                    rs[sp] = r1;
                    ws[sp] = w1;
                    ns[sp - 1] = ns[sp - 2];
                    rs[sp - 1] = rs[sp - 2];
                    ws[sp - 1] = ws[sp - 2];
                    ns[sp - 2] = n1;
                    rs[sp - 2] = r1;
                    ws[sp - 2] = w1;
                } else {
                    long n2 = ns[sp - 2];
                    Object r2 = rs[sp - 2];
                    byte w2 = ws[sp - 2];
                    ns[sp] = n1;
                    rs[sp] = r1;
                    ws[sp] = w1;
                    ns[sp - 1] = n2;
                    rs[sp - 1] = r2;
                    ws[sp - 1] = w2;
                    ns[sp - 2] = ns[sp - 3];
                    rs[sp - 2] = rs[sp - 3];
                    ws[sp - 2] = ws[sp - 3];
                    ns[sp - 3] = n1;
                    rs[sp - 3] = r1;
                    ws[sp - 3] = w1;
                }
                return sp + 1;
            }
            case 92: // DUP2
                if (ws[sp - 1] == 2) {
                    ns[sp] = ns[sp - 1];
                    rs[sp] = rs[sp - 1];
                    ws[sp] = 2;
                    return sp + 1;
                }
                ns[sp] = ns[sp - 2];
                rs[sp] = rs[sp - 2];
                ws[sp] = ws[sp - 2];
                ns[sp + 1] = ns[sp - 1];
                rs[sp + 1] = rs[sp - 1];
                ws[sp + 1] = ws[sp - 1];
                return sp + 2;
            case 93: // DUP2_X1
                if (ws[sp - 1] == 2) {
                    long n1 = ns[sp - 1];
                    Object r1 = rs[sp - 1];
                    ns[sp] = n1;
                    rs[sp] = r1;
                    ws[sp] = 2;
                    ns[sp - 1] = ns[sp - 2];
                    rs[sp - 1] = rs[sp - 2];
                    ws[sp - 1] = ws[sp - 2];
                    ns[sp - 2] = n1;
                    rs[sp - 2] = r1;
                    ws[sp - 2] = 2;
                    return sp + 1;
                }
                {
                    long n1 = ns[sp - 1];
                    Object r1 = rs[sp - 1];
                    byte w1 = ws[sp - 1];
                    long n2 = ns[sp - 2];
                    Object r2 = rs[sp - 2];
                    byte w2 = ws[sp - 2];
                    ns[sp + 1] = n1;
                    rs[sp + 1] = r1;
                    ws[sp + 1] = w1;
                    ns[sp] = n2;
                    rs[sp] = r2;
                    ws[sp] = w2;
                    ns[sp - 1] = ns[sp - 3];
                    rs[sp - 1] = rs[sp - 3];
                    ws[sp - 1] = ws[sp - 3];
                    ns[sp - 2] = n1;
                    rs[sp - 2] = r1;
                    ws[sp - 2] = w1;
                    ns[sp - 3] = n2;
                    rs[sp - 3] = r2;
                    ws[sp - 3] = w2;
                    return sp + 2;
                }
            case 94: // DUP2_X2
                if (ws[sp - 1] == 2 && ws[sp - 2] == 2) {
                    long n1 = ns[sp - 1];
                    Object r1 = rs[sp - 1];
                    ns[sp] = n1;
                    rs[sp] = r1;
                    ws[sp] = 2;
                    ns[sp - 1] = ns[sp - 2];
                    rs[sp - 1] = rs[sp - 2];
                    ws[sp - 1] = 2;
                    ns[sp - 2] = n1;
                    rs[sp - 2] = r1;
                    ws[sp - 2] = 2;
                    return sp + 1;
                }
                if (ws[sp - 1] == 2) {
                    long n1 = ns[sp - 1];
                    Object r1 = rs[sp - 1];
                    ns[sp] = n1;
                    rs[sp] = r1;
                    ws[sp] = 2;
                    ns[sp - 1] = ns[sp - 2];
                    rs[sp - 1] = rs[sp - 2];
                    ws[sp - 1] = ws[sp - 2];
                    ns[sp - 2] = ns[sp - 3];
                    rs[sp - 2] = rs[sp - 3];
                    ws[sp - 2] = ws[sp - 3];
                    ns[sp - 3] = n1;
                    rs[sp - 3] = r1;
                    ws[sp - 3] = 2;
                    return sp + 1;
                }
                if (ws[sp - 2] == 2) {
                    long n1 = ns[sp - 1];
                    Object r1 = rs[sp - 1];
                    byte w1 = ws[sp - 1];
                    ns[sp] = n1;
                    rs[sp] = r1;
                    ws[sp] = w1;
                    ns[sp - 1] = ns[sp - 2];
                    rs[sp - 1] = rs[sp - 2];
                    ws[sp - 1] = 2;
                    ns[sp - 2] = n1;
                    rs[sp - 2] = r1;
                    ws[sp - 2] = w1;
                    return sp + 1;
                }
                {
                    long n1 = ns[sp - 1];
                    Object r1 = rs[sp - 1];
                    byte w1 = ws[sp - 1];
                    long n2 = ns[sp - 2];
                    Object r2 = rs[sp - 2];
                    byte w2 = ws[sp - 2];
                    ns[sp + 1] = n1;
                    rs[sp + 1] = r1;
                    ws[sp + 1] = w1;
                    ns[sp] = n2;
                    rs[sp] = r2;
                    ws[sp] = w2;
                    ns[sp - 1] = ns[sp - 3];
                    rs[sp - 1] = rs[sp - 3];
                    ws[sp - 1] = ws[sp - 3];
                    ns[sp - 2] = ns[sp - 4];
                    rs[sp - 2] = rs[sp - 4];
                    ws[sp - 2] = ws[sp - 4];
                    ns[sp - 3] = n1;
                    rs[sp - 3] = r1;
                    ws[sp - 3] = w1;
                    ns[sp - 4] = n2;
                    rs[sp - 4] = r2;
                    ws[sp - 4] = w2;
                    return sp + 2;
                }
            default: { // SWAP
                long n1 = ns[sp - 1];
                Object r1 = rs[sp - 1];
                byte w1 = ws[sp - 1];
                ns[sp - 1] = ns[sp - 2];
                rs[sp - 1] = rs[sp - 2];
                ws[sp - 1] = ws[sp - 2];
                ns[sp - 2] = n1;
                rs[sp - 2] = r1;
                ws[sp - 2] = w1;
                return sp;
            }
        }
    }

    /** Arithmetic, conversion and comparison family (opcodes 96..152). */
    private static int vmNumeric(int op, long[] ns, byte[] ws, int sp) {
        switch (op) {
            case 96: // IADD
                ns[sp - 2] = (int) ns[sp - 2] + (int) ns[sp - 1];
                return sp - 1;
            case 97: // LADD
                ns[sp - 2] = ns[sp - 2] + ns[sp - 1];
                return sp - 1;
            case 98: // FADD
                ns[sp - 2] = Float.floatToRawIntBits(
                        Float.intBitsToFloat((int) ns[sp - 2]) + Float.intBitsToFloat((int) ns[sp - 1]));
                return sp - 1;
            case 99: // DADD
                ns[sp - 2] = Double.doubleToRawLongBits(
                        Double.longBitsToDouble(ns[sp - 2]) + Double.longBitsToDouble(ns[sp - 1]));
                return sp - 1;
            case 100: // ISUB
                ns[sp - 2] = (int) ns[sp - 2] - (int) ns[sp - 1];
                return sp - 1;
            case 101: // LSUB
                ns[sp - 2] = ns[sp - 2] - ns[sp - 1];
                return sp - 1;
            case 102: // FSUB
                ns[sp - 2] = Float.floatToRawIntBits(
                        Float.intBitsToFloat((int) ns[sp - 2]) - Float.intBitsToFloat((int) ns[sp - 1]));
                return sp - 1;
            case 103: // DSUB
                ns[sp - 2] = Double.doubleToRawLongBits(
                        Double.longBitsToDouble(ns[sp - 2]) - Double.longBitsToDouble(ns[sp - 1]));
                return sp - 1;
            case 104: // IMUL
                ns[sp - 2] = (int) ns[sp - 2] * (int) ns[sp - 1];
                return sp - 1;
            case 105: // LMUL
                ns[sp - 2] = ns[sp - 2] * ns[sp - 1];
                return sp - 1;
            case 106: // FMUL
                ns[sp - 2] = Float.floatToRawIntBits(
                        Float.intBitsToFloat((int) ns[sp - 2]) * Float.intBitsToFloat((int) ns[sp - 1]));
                return sp - 1;
            case 107: // DMUL
                ns[sp - 2] = Double.doubleToRawLongBits(
                        Double.longBitsToDouble(ns[sp - 2]) * Double.longBitsToDouble(ns[sp - 1]));
                return sp - 1;
            case 108: // IDIV
                ns[sp - 2] = (int) ns[sp - 2] / (int) ns[sp - 1];
                return sp - 1;
            case 109: // LDIV
                ns[sp - 2] = ns[sp - 2] / ns[sp - 1];
                return sp - 1;
            case 110: // FDIV
                ns[sp - 2] = Float.floatToRawIntBits(
                        Float.intBitsToFloat((int) ns[sp - 2]) / Float.intBitsToFloat((int) ns[sp - 1]));
                return sp - 1;
            case 111: // DDIV
                ns[sp - 2] = Double.doubleToRawLongBits(
                        Double.longBitsToDouble(ns[sp - 2]) / Double.longBitsToDouble(ns[sp - 1]));
                return sp - 1;
            case 112: // IREM
                ns[sp - 2] = (int) ns[sp - 2] % (int) ns[sp - 1];
                return sp - 1;
            case 113: // LREM
                ns[sp - 2] = ns[sp - 2] % ns[sp - 1];
                return sp - 1;
            case 114: // FREM
                ns[sp - 2] = Float.floatToRawIntBits(
                        Float.intBitsToFloat((int) ns[sp - 2]) % Float.intBitsToFloat((int) ns[sp - 1]));
                return sp - 1;
            case 115: // DREM
                ns[sp - 2] = Double.doubleToRawLongBits(
                        Double.longBitsToDouble(ns[sp - 2]) % Double.longBitsToDouble(ns[sp - 1]));
                return sp - 1;
            case 116: // INEG
                ns[sp - 1] = -(int) ns[sp - 1];
                return sp;
            case 117: // LNEG
                ns[sp - 1] = -ns[sp - 1];
                return sp;
            case 118: // FNEG
                ns[sp - 1] = Float.floatToRawIntBits(-Float.intBitsToFloat((int) ns[sp - 1]));
                return sp;
            case 119: // DNEG
                ns[sp - 1] = Double.doubleToRawLongBits(-Double.longBitsToDouble(ns[sp - 1]));
                return sp;
            case 120: // ISHL
                ns[sp - 2] = (int) ns[sp - 2] << (int) ns[sp - 1];
                return sp - 1;
            case 121: // LSHL
                ns[sp - 2] = ns[sp - 2] << (int) ns[sp - 1];
                return sp - 1;
            case 122: // ISHR
                ns[sp - 2] = (int) ns[sp - 2] >> (int) ns[sp - 1];
                return sp - 1;
            case 123: // LSHR
                ns[sp - 2] = ns[sp - 2] >> (int) ns[sp - 1];
                return sp - 1;
            case 124: // IUSHR
                ns[sp - 2] = (int) ns[sp - 2] >>> (int) ns[sp - 1];
                return sp - 1;
            case 125: // LUSHR
                ns[sp - 2] = ns[sp - 2] >>> (int) ns[sp - 1];
                return sp - 1;
            case 126: // IAND
                ns[sp - 2] = (int) ns[sp - 2] & (int) ns[sp - 1];
                return sp - 1;
            case 127: // LAND
                ns[sp - 2] = ns[sp - 2] & ns[sp - 1];
                return sp - 1;
            case 128: // IOR
                ns[sp - 2] = (int) ns[sp - 2] | (int) ns[sp - 1];
                return sp - 1;
            case 129: // LOR
                ns[sp - 2] = ns[sp - 2] | ns[sp - 1];
                return sp - 1;
            case 130: // IXOR
                ns[sp - 2] = (int) ns[sp - 2] ^ (int) ns[sp - 1];
                return sp - 1;
            case 131: // LXOR
                ns[sp - 2] = ns[sp - 2] ^ ns[sp - 1];
                return sp - 1;
            case 133: // I2L
                ns[sp - 1] = (long) (int) ns[sp - 1];
                ws[sp - 1] = 2;
                return sp;
            case 134: // I2F
                ns[sp - 1] = Float.floatToRawIntBits((float) (int) ns[sp - 1]);
                ws[sp - 1] = 1;
                return sp;
            case 135: // I2D
                ns[sp - 1] = Double.doubleToRawLongBits((double) (int) ns[sp - 1]);
                ws[sp - 1] = 2;
                return sp;
            case 136: // L2I
                ns[sp - 1] = (int) ns[sp - 1];
                ws[sp - 1] = 1;
                return sp;
            case 137: // L2F
                ns[sp - 1] = Float.floatToRawIntBits((float) ns[sp - 1]);
                ws[sp - 1] = 1;
                return sp;
            case 138: // L2D
                ns[sp - 1] = Double.doubleToRawLongBits((double) ns[sp - 1]);
                ws[sp - 1] = 2;
                return sp;
            case 139: // F2I
                ns[sp - 1] = (int) Float.intBitsToFloat((int) ns[sp - 1]);
                ws[sp - 1] = 1;
                return sp;
            case 140: // F2L
                ns[sp - 1] = (long) Float.intBitsToFloat((int) ns[sp - 1]);
                ws[sp - 1] = 2;
                return sp;
            case 141: // F2D
                ns[sp - 1] = Double.doubleToRawLongBits(
                        (double) Float.intBitsToFloat((int) ns[sp - 1]));
                ws[sp - 1] = 2;
                return sp;
            case 142: // D2I
                ns[sp - 1] = (int) Double.longBitsToDouble(ns[sp - 1]);
                ws[sp - 1] = 1;
                return sp;
            case 143: // D2L
                ns[sp - 1] = (long) Double.longBitsToDouble(ns[sp - 1]);
                ws[sp - 1] = 2;
                return sp;
            case 144: // D2F
                ns[sp - 1] = Float.floatToRawIntBits(
                        (float) Double.longBitsToDouble(ns[sp - 1]));
                ws[sp - 1] = 1;
                return sp;
            case 145: // I2B
                ns[sp - 1] = (byte) (int) ns[sp - 1];
                ws[sp - 1] = 1;
                return sp;
            case 146: // I2C
                ns[sp - 1] = (char) (int) ns[sp - 1];
                ws[sp - 1] = 1;
                return sp;
            case 147: // I2S
                ns[sp - 1] = (short) (int) ns[sp - 1];
                ws[sp - 1] = 1;
                return sp;
            case 148: { // LCMP
                long a = ns[sp - 2];
                long b = ns[sp - 1];
                ns[sp - 2] = a < b ? -1 : (a == b ? 0 : 1);
                ws[sp - 2] = 1;
                return sp - 1;
            }
            case 149: { // FCMPL
                float a = Float.intBitsToFloat((int) ns[sp - 2]);
                float b = Float.intBitsToFloat((int) ns[sp - 1]);
                ns[sp - 2] = Float.isNaN(a) || Float.isNaN(b) ? -1
                        : (a == b ? 0 : (a < b ? -1 : 1));
                ws[sp - 2] = 1;
                return sp - 1;
            }
            case 150: { // FCMPG
                float a = Float.intBitsToFloat((int) ns[sp - 2]);
                float b = Float.intBitsToFloat((int) ns[sp - 1]);
                ns[sp - 2] = Float.isNaN(a) || Float.isNaN(b) ? 1
                        : (a == b ? 0 : (a < b ? -1 : 1));
                ws[sp - 2] = 1;
                return sp - 1;
            }
            case 151: { // DCMPL
                double a = Double.longBitsToDouble(ns[sp - 2]);
                double b = Double.longBitsToDouble(ns[sp - 1]);
                ns[sp - 2] = Double.isNaN(a) || Double.isNaN(b) ? -1
                        : (a == b ? 0 : (a < b ? -1 : 1));
                ws[sp - 2] = 1;
                return sp - 1;
            }
            default: { // DCMPG
                double a = Double.longBitsToDouble(ns[sp - 2]);
                double b = Double.longBitsToDouble(ns[sp - 1]);
                ns[sp - 2] = Double.isNaN(a) || Double.isNaN(b) ? 1
                        : (a == b ? 0 : (a < b ? -1 : 1));
                ws[sp - 2] = 1;
                return sp - 1;
            }
        }
    }

    /** Array load family (opcodes 46..53). */
    private static int vmArrayLoad(int op, long[] ns, Object[] rs, byte[] ws, int sp) {
        int index = (int) ns[--sp];
        Object array = rs[--sp];
        switch (op) {
            case 46: // IALOAD
                ns[sp] = Array.getInt(array, index);
                ws[sp] = 1;
                break;
            case 47: // LALOAD
                ns[sp] = Array.getLong(array, index);
                ws[sp] = 2;
                break;
            case 48: // FALOAD
                ns[sp] = Float.floatToRawIntBits(Array.getFloat(array, index));
                ws[sp] = 1;
                break;
            case 49: // DALOAD
                ns[sp] = Double.doubleToRawLongBits(Array.getDouble(array, index));
                ws[sp] = 2;
                break;
            case 50: // AALOAD
                rs[sp] = Array.get(array, index);
                ws[sp] = 1;
                break;
            case 51: // BALOAD
                if (array instanceof boolean[]) {
                    ns[sp] = Array.getBoolean(array, index) ? 1 : 0;
                } else {
                    ns[sp] = Array.getByte(array, index);
                }
                ws[sp] = 1;
                break;
            case 52: // CALOAD
                ns[sp] = Array.getChar(array, index);
                ws[sp] = 1;
                break;
            default: // SALOAD
                ns[sp] = Array.getShort(array, index);
                ws[sp] = 1;
                break;
        }
        return sp + 1;
    }

    /** Array store family (opcodes 79..86). */
    private static int vmArrayStore(int op, long[] ns, Object[] rs, int sp) {
        long bits;
        Object ref = null;
        if (op == 83) {
            ref = rs[--sp];
            bits = 0L;
        } else {
            bits = ns[--sp];
        }
        int index = (int) ns[--sp];
        Object array = rs[--sp];
        switch (op) {
            case 79: // IASTORE
                Array.setInt(array, index, (int) bits);
                break;
            case 80: // LASTORE
                Array.setLong(array, index, bits);
                break;
            case 81: // FASTORE
                Array.setFloat(array, index, Float.intBitsToFloat((int) bits));
                break;
            case 82: // DASTORE
                Array.setDouble(array, index, Double.longBitsToDouble(bits));
                break;
            case 83: // AASTORE
                Array.set(array, index, ref);
                break;
            case 84: // BASTORE
                if (array instanceof boolean[]) {
                    Array.setBoolean(array, index, (int) bits != 0);
                } else {
                    Array.setByte(array, index, (byte) bits);
                }
                break;
            case 85: // CASTORE
                Array.setChar(array, index, (char) bits);
                break;
            default: // SASTORE
                Array.setShort(array, index, (short) bits);
                break;
        }
        return sp;
    }

    // ==================================================================
    // Superinstructions (vm2.fusion)
    //
    // A fused instruction has the same observable effect as the opcode run it
    // replaced; the translator only fuses runs that are adjacent in the
    // instruction list and never contain a branch target or handler boundary.
    // The helper returns {@code (nextPc << 32) | sp}, so the dispatch loop pays
    // one call per fused run instead of one dispatch per original opcode.
    // ==================================================================

    private static long vmSuper(int op, int[] code, int p, long[] ns, Object[] rs, byte[] ws,
                                long[] nl, Object[] rl, String[] refs, Object[] refCache, int sp) {
        switch (op) {
            case SUPER_IADD_LL:
            case SUPER_ISUB_LL:
            case SUPER_IMUL_LL:
            case SUPER_IAND_LL:
            case SUPER_IOR_LL:
            case SUPER_IXOR_LL: {
                int a = (int) nl[code[p]];
                int b = (int) nl[code[p + 1]];
                ns[sp] = intArithmetic(op, a, b);
                ws[sp] = 1;
                return pack(sp + 1, p + 2);
            }
            case SUPER_ILOAD_CONST_ADD:
            case SUPER_ILOAD_CONST_SUB:
            case SUPER_ILOAD_CONST_MUL:
            case SUPER_ILOAD_CONST_AND:
            case SUPER_ILOAD_CONST_OR:
            case SUPER_ILOAD_CONST_XOR: {
                int a = (int) nl[code[p]];
                int b = code[p + 1];
                ns[sp] = intArithmeticConstant(op, a, b);
                ws[sp] = 1;
                return pack(sp + 1, p + 2);
            }
            case SUPER_IF_ICMPEQ_LL:
            case SUPER_IF_ICMPNE_LL:
            case SUPER_IF_ICMPLT_LL:
            case SUPER_IF_ICMPGE_LL:
            case SUPER_IF_ICMPGT_LL:
            case SUPER_IF_ICMPLE_LL: {
                int b = (int) nl[code[p + 1]];
                int a = (int) nl[code[p]];
                boolean taken;
                switch (op) {
                    case SUPER_IF_ICMPEQ_LL: taken = a == b; break;
                    case SUPER_IF_ICMPNE_LL: taken = a != b; break;
                    case SUPER_IF_ICMPLT_LL: taken = a < b; break;
                    case SUPER_IF_ICMPGE_LL: taken = a >= b; break;
                    case SUPER_IF_ICMPGT_LL: taken = a > b; break;
                    default: taken = a <= b; break;
                }
                return pack(sp, taken ? code[p + 2] : p + 3);
            }
            case SUPER_LADD_LL:
            case SUPER_LSUB_LL:
            case SUPER_LMUL_LL:
            case SUPER_LAND_LL:
            case SUPER_LOR_LL:
            case SUPER_LXOR_LL: {
                long a = nl[code[p]];
                long b = nl[code[p + 1]];
                long value;
                switch (op) {
                    case SUPER_LADD_LL: value = a + b; break;
                    case SUPER_LSUB_LL: value = a - b; break;
                    case SUPER_LMUL_LL: value = a * b; break;
                    case SUPER_LAND_LL: value = a & b; break;
                    case SUPER_LOR_LL: value = a | b; break;
                    default: value = a ^ b; break;
                }
                ns[sp] = value;
                ws[sp] = 2;
                return pack(sp + 1, p + 2);
            }
            case SUPER_ALOAD_GETFIELD: {
                Object[] holder = fieldFor(refs[code[p + 1]]);
                Field field = (Field) holder[0];
                char sort = ((Character) holder[1]).charValue();
                Object receiver = rl[code[p]];
                Object value = getFieldValue(field, receiver);
                int next = pushValue(ns, rs, ws, sp, sort, value);
                return pack(next, p + 2);
            }
            case SUPER_CONST_ISTORE:
                nl[code[p + 1]] = code[p];
                return pack(sp, p + 2);
            default:
                throw new IllegalStateException(
                        "Umbra VM2: unsupported superinstruction " + op);
        }
    }

    private static int intArithmetic(int op, int a, int b) {
        switch (op) {
            case SUPER_IADD_LL: return a + b;
            case SUPER_ISUB_LL: return a - b;
            case SUPER_IMUL_LL: return a * b;
            case SUPER_IAND_LL: return a & b;
            case SUPER_IOR_LL: return a | b;
            default: return a ^ b;
        }
    }

    private static int intArithmeticConstant(int op, int a, int b) {
        switch (op) {
            case SUPER_ILOAD_CONST_ADD: return a + b;
            case SUPER_ILOAD_CONST_SUB: return a - b;
            case SUPER_ILOAD_CONST_MUL: return a * b;
            case SUPER_ILOAD_CONST_AND: return a & b;
            case SUPER_ILOAD_CONST_OR: return a | b;
            default: return a ^ b;
        }
    }

    private static long pack(int sp, int pc) {
        return (((long) pc) << 32) | (sp & 0xFFFFFFFFL);
    }

    /**
     * Operand count of one instruction; mirrors {@code Vm2Format.operandSlots}
     * and is used to validate/decode the code stream before execution.
     */
    private static int operandSlots(int opcode, int[] code, int opcodeSlot) {
        switch (opcode) {
            case SUPER_IADD_LL:
            case SUPER_ISUB_LL:
            case SUPER_IMUL_LL:
            case SUPER_IAND_LL:
            case SUPER_IOR_LL:
            case SUPER_IXOR_LL:
            case SUPER_ILOAD_CONST_ADD:
            case SUPER_ILOAD_CONST_SUB:
            case SUPER_ILOAD_CONST_MUL:
            case SUPER_ILOAD_CONST_AND:
            case SUPER_ILOAD_CONST_OR:
            case SUPER_ILOAD_CONST_XOR:
            case SUPER_LADD_LL:
            case SUPER_LSUB_LL:
            case SUPER_LMUL_LL:
            case SUPER_LAND_LL:
            case SUPER_LOR_LL:
            case SUPER_LXOR_LL:
            case SUPER_ALOAD_GETFIELD:
            case SUPER_CONST_ISTORE:
                return 2;
            case SUPER_IF_ICMPEQ_LL:
            case SUPER_IF_ICMPNE_LL:
            case SUPER_IF_ICMPLT_LL:
            case SUPER_IF_ICMPGE_LL:
            case SUPER_IF_ICMPGT_LL:
            case SUPER_IF_ICMPLE_LL:
                return 3;
            case 16: case 17: case 18: // BIPUSH, SIPUSH, LDC
            case 21: case 22: case 23: case 24: case 25: // xLOAD
            case 54: case 55: case 56: case 57: case 58: // xSTORE
            case 169: // RET
            case 188: // NEWARRAY
            case 178: case 179: case 180: case 181: // xFIELD
            case 182: case 183: case 184: case 185: // INVOKEx
            case 187: // NEW
            case 189: case 192: case 193: // ANEWARRAY, CHECKCAST, INSTANCEOF
            case 167: // GOTO
            case 198: case 199: // IFNULL, IFNONNULL
            case 153: case 154: case 155: case 156: case 157: case 158:
            case 159: case 160: case 161: case 162: case 163: case 164:
            case 165: case 166:
                return 1;
            case 132: // IINC
            case 197: // MULTIANEWARRAY
                return 2;
            case 170: { // TABLESWITCH
                int high = code[opcodeSlot + 3];
                int low = code[opcodeSlot + 2];
                return 3 + (high - low + 1);
            }
            case 171: { // LOOKUPSWITCH
                int pairs = code[opcodeSlot + 2];
                return 2 + 2 * pairs;
            }
            default:
                return 0;
        }
    }

    /** Initial rolling opcode-key state (mirrors {@code Vm2Format.rollSeed}). */
    private static long rollSeed(long key) {
        long roll = key ^ 0x243F6A8885A308D3L;
        roll ^= roll << 13;
        roll ^= roll >>> 7;
        roll ^= roll << 17;
        roll *= 0x9E3779B97F4A7C15L;
        roll ^= roll >>> 29;
        if (roll == 0L) {
            roll = 0x51ED270B1F2A3C4DL;
        }
        return roll;
    }

    /** Advances the rolling opcode-key state (mirrors {@code Vm2Format.rollStep}). */
    private static long rollStep(long roll, int encodedOpcode) {
        return roll * 0x9E3779B97F4A7C15L ^ (((long) encodedOpcode) + 1L);
    }

    // ==================================================================
    // Payload decoding
    // ==================================================================

    /**
     * Decoded payloads kept at once.
     *
     * <p>Every parsed payload holds its plaintext instruction stream, so an
     * unbounded cache means a heap dump taken after warm-up contains the whole
     * protected program. The cache is therefore capacity- and time-bounded: the
     * oldest payload is dropped when the cap is reached, and payloads expire after
     * {@link #STATE_TTL_NANOS}.</p>
     */
    private static final int STATE_CACHE_MAX = 128;
    /** Age after which a decoded payload is dropped even if the program keeps running. */
    private static final long STATE_TTL_NANOS = 5_000_000_000L;
    /** Minimum gap between expiry sweeps (bounds the cost of the bookkeeping). */
    private static final long STATE_SWEEP_NANOS = 250_000_000L;
    /** Decode timestamp per cached payload, used for the age check. */
    private static final java.util.concurrent.ConcurrentHashMap<Object, Long> STATE_STAMPS =
            new java.util.concurrent.ConcurrentHashMap<Object, Long>();
    private static volatile long stateSweptAt;

    private static Object[] stateFor(int[] meta, int[] map, int[][] blocks) {
        // The block array is assembled by the call site on every invocation, so
        // it cannot identify a payload; the meta array is the stable holder.
        Object key = meta != null ? meta : blocks;
        Object existing = STATES.get(key);
        if (existing != null) {
            expireStates();
            return (Object[]) existing;
        }
        synchronized (key) {
            existing = STATES.get(key);
            if (existing != null) {
                return (Object[]) existing;
            }
            Object[] state = parse(meta, map, blocks);
            STATES.put(key, state);
            STATE_STAMPS.put(key, Long.valueOf(System.nanoTime()));
            trimStates();
            return state;
        }
    }

    /**
     * Drops payloads older than {@link #STATE_TTL_NANOS}.
     *
     * <p>References are only removed, never zeroed: another thread may still be
     * executing the array it obtained before the sweep, so clearing the contents
     * would corrupt a live dispatch.</p>
     */
    private static void expireStates() {
        long now = System.nanoTime();
        if (now - stateSweptAt < STATE_SWEEP_NANOS) {
            return;
        }
        stateSweptAt = now;
        for (Object key : STATE_STAMPS.keySet()) {
            Long stamp = STATE_STAMPS.get(key);
            if (stamp != null && now - stamp.longValue() > STATE_TTL_NANOS) {
                STATE_STAMPS.remove(key);
                STATES.remove(key);
            }
        }
    }

    /** Evicts the oldest decoded payload once the cap is exceeded. */
    private static void trimStates() {
        int size = STATES.size();
        if (size <= STATE_CACHE_MAX) {
            return;
        }
        Object oldestKey = null;
        long oldestStamp = Long.MAX_VALUE;
        for (Object key : STATE_STAMPS.keySet()) {
            Long stamp = STATE_STAMPS.get(key);
            if (stamp == null) {
                continue;
            }
            if (stamp.longValue() < oldestStamp) {
                oldestStamp = stamp.longValue();
                oldestKey = key;
            }
        }
        if (oldestKey != null) {
            STATE_STAMPS.remove(oldestKey);
            STATES.remove(oldestKey);
        }
    }

    private static Object[] parse(int[] meta, int[] map, int[][] blocks) {
        if (meta == null || meta.length < META_LEN || meta[0] != magicFor(meta)) {
            throw tampered("header");
        }
        int payloadId = meta[6] >>> 16;
        try {
            return parsePayload(meta, map, blocks);
        } catch (IllegalStateException e) {
            throw new IllegalStateException("Umbra VM2 payload #" + payloadId + " rejected: "
                    + e.getMessage(), e);
        }
    }

    private static Object[] parsePayload(int[] meta, int[] map, int[][] blocks) {
        if (map != null && map.length != 256) {
            throw tampered("opcode map");
        }
        long key = metaKey(meta);
        int flags = meta[6] & 0xFFFF;
        boolean encrypted = (flags & FLAG_ENCRYPT) != 0;
        boolean nested = (flags & FLAG_NESTED) != 0 && encrypted;
        int payloadBlocks = meta[4];
        int plainLen = meta[3];
        if (payloadBlocks < 1 || plainLen < HEADER) {
            throw tampered("dimensions");
        }
        int expectedBlocks = payloadBlocks + (nested ? 1 : 0);
        if (blocks == null || blocks.length != expectedBlocks) {
            throw tampered("block count");
        }
        long stage = key;
        if (nested) {
            int[] outer = new int[blocks[0].length];
            System.arraycopy(blocks[0], 0, outer, 0, outer.length);
            crypt(outer, key);
            stage = runOuterProgram(outer, key, meta[7], plainLen, payloadBlocks);
            if (stage == 0L) {
                // The writer applies the same fallback when a generated outer
                // program happens to fold to zero.
                stage = key ^ 0x5DEECE66DL;
            }
        }
        int[] plain = new int[plainLen];
        int position = 0;
        int first = nested ? 1 : 0;
        for (int b = first; b < blocks.length; b++) {
            int[] block = blocks[b];
            if (position + block.length > plainLen) {
                throw tampered("block overflow");
            }
            System.arraycopy(block, 0, plain, position, block.length);
            position += block.length;
        }
        if (position != plainLen) {
            throw tampered("block size");
        }
        if (encrypted) {
            crypt(plain, stage);
        }
        int format = plain[1];
        if (plain[0] != payloadMagic(key) || (format != FORMAT && format != ROLLING_FORMAT)) {
            throw tampered("format");
        }
        int codeLen = plain[3];
        int constCount = plain[4];
        int refCount = plain[5];
        int handlerCount = plain[6];
        int maxLocals = plain[7];
        int argSlots = plain[8];
        int stackHint = plain[9];
        if (codeLen <= 0 || codeLen > 4 * 1024 * 1024 || constCount < 0 || refCount < 0
                || handlerCount < 0 || maxLocals < 0 || maxLocals > 0xFFFF
                || argSlots < 0 || argSlots > maxLocals || stackHint < 8) {
            throw tampered("header values");
        }
        int cursor = HEADER;
        int[] kinds = new int[argSlots];
        for (int i = 0; i < argSlots; i++) {
            int kind = plain[cursor++];
            if (kind < KIND_UNUSED || kind > KIND_REF) {
                throw tampered("argument kinds");
            }
            kinds[i] = kind;
        }
        Object[] consts = new Object[constCount];
        for (int i = 0; i < constCount; i++) {
            int tag = plain[cursor++];
            switch (tag) {
                case 1: // int
                    consts[i] = Integer.valueOf(plain[cursor++]);
                    break;
                case 2: { // long
                    long lo = plain[cursor++];
                    long hi = plain[cursor++];
                    consts[i] = Long.valueOf((hi << 32) ^ (lo & 0xFFFFFFFFL));
                    break;
                }
                case 3: // float
                    consts[i] = Float.valueOf(Float.intBitsToFloat(plain[cursor++]));
                    break;
                case 4: { // double
                    long lo = plain[cursor++];
                    long hi = plain[cursor++];
                    consts[i] = Double.valueOf(
                            Double.longBitsToDouble((hi << 32) ^ (lo & 0xFFFFFFFFL)));
                    break;
                }
                case 5: { // string
                    int length = plain[cursor++];
                    if (length < 0 || cursor + length > plain.length) {
                        throw tampered("string length");
                    }
                    char[] chars = new char[length];
                    for (int c = 0; c < length; c++) {
                        chars[c] = (char) plain[cursor++];
                    }
                    consts[i] = new String(chars);
                    break;
                }
                case 6: { // class literal
                    int length = plain[cursor++];
                    if (length < 0 || cursor + length > plain.length) {
                        throw tampered("class descriptor");
                    }
                    char[] chars = new char[length];
                    for (int c = 0; c < length; c++) {
                        chars[c] = (char) plain[cursor++];
                    }
                    // Lazy: keep the descriptor and resolve the class at first
                    // execution, so payload parsing never needs the program class
                    // loader (nested container layouts, arbitrary first caller thread).
                    consts[i] = new String[] { "C", new String(chars) };
                    break;
                }
                default:
                    throw tampered("constant tag");
            }
        }
        String[] refs = new String[refCount];
        for (int i = 0; i < refCount; i++) {
            int length = plain[cursor++];
            if (length < 0 || cursor + length > plain.length) {
                throw tampered("ref length");
            }
            char[] chars = new char[length];
            for (int c = 0; c < length; c++) {
                chars[c] = (char) plain[cursor++];
            }
            refs[i] = new String(chars);
        }
        int[] handlers = new int[handlerCount * 4];
        for (int i = 0; i < handlers.length; i++) {
            handlers[i] = plain[cursor++];
        }
        for (int h = 0; h < handlers.length; h += 4) {
            if (handlers[h] < 0 || handlers[h] > codeLen || handlers[h + 1] < handlers[h]
                    || handlers[h + 1] > codeLen || handlers[h + 3] < 0
                    || handlers[h + 3] >= codeLen || handlers[h + 2] < -1
                    || handlers[h + 2] >= refCount) {
                throw tampered("handler table");
            }
        }
        if (cursor + codeLen != plain.length) {
            throw tampered("code length");
        }
        int codeStart = cursor;
        // Operand masking always uses the first-stage key (the one derived
        // directly from meta); the second stage only encrypts the payload.
        for (int i = 0; i < codeLen; i++) {
            plain[codeStart + i] ^= mask(key, i);
        }
        if (integrity(plain) != meta[5]) {
            throw tampered("integrity");
        }
        int[] code = new int[codeLen];
        System.arraycopy(plain, codeStart, code, 0, codeLen);
        // Decode the instruction stream once, before the first execution.
        // Format 4 additionally XORs every opcode slot with an 8-bit mask from
        // a rolling state that is chained over the preceding opcodes; format 3
        // payloads only need the (shared) permutation table. Walking the stream
        // also validates operand counts, so a malformed payload is rejected at
        // load time instead of corrupting the interpreter later.
        boolean rolling = format >= ROLLING_FORMAT;
        long roll = rolling ? rollSeed(key) : 0L;
        int[] ops = new int[codeLen];
        int scan = 0;
        while (scan < codeLen) {
            int stored = code[scan];
            int encoded = rolling ? (stored ^ (int) (roll >>> 56)) : stored;
            int op;
            if (map == null) {
                op = encoded;
            } else if (encoded < 0 || encoded >= map.length) {
                throw tampered("opcode range at " + scan);
            } else {
                op = map[encoded];
            }
            if (op < 0 || op > 255) {
                throw tampered("opcode at " + scan);
            }
            ops[scan] = op;
            if (rolling) {
                roll = rollStep(roll, encoded);
            }
            int operands = operandSlots(op, code, scan);
            if (operands < 0 || scan + 1 + operands > codeLen) {
                throw tampered("code stream at " + scan);
            }
            scan += 1 + operands;
        }
        Object[] state = new Object[8];
        state[STATE_CODE] = code;
        state[STATE_OPS] = ops;
        state[STATE_CONSTS] = consts;
        state[STATE_REFS] = refs;
        state[STATE_HANDLERS] = handlers;
        state[STATE_INFO] = new int[] { maxLocals, argSlots, stackHint, flags };
        state[STATE_KINDS] = kinds;
        state[STATE_REF_CACHE] = new Object[refCount];
        return state;
    }

    private static IllegalStateException tampered(String what) {
        return new IllegalStateException("Umbra VM2 payload rejected (" + what + ")");
    }

    private static long metaKey(int[] meta) {
        long key = (((long) meta[1]) << 32) ^ (((long) meta[2]) & 0xFFFFFFFFL)
                ^ (((long) meta[7]) * GOLDEN);
        if (key == 0L) {
            key = 0x51ED270B1F2A3C4DL;
        }
        return key;
    }

    /** Mirrors {@code Vm2Format.magicFor}: per-payload marker, no fixed literal. */
    private static int magicFor(int[] meta) {
        return (int) (metaKey(meta) >>> 32) ^ meta[7] ^ 0x2B;
    }

    /** Mirrors {@code Vm2Format.payloadMagic}: payload marker derived from the key. */
    private static int payloadMagic(long key) {
        long mixed = key ^ (key >>> 32) ^ 0x2B;
        mixed *= GOLDEN;
        return (int) (mixed >>> 32) ^ (int) mixed;
    }

    private static int mask(long key, int index) {
        long h = key ^ (((long) index) * GOLDEN);
        h ^= h >>> 33;
        h *= 0xFF51AFD7ED558CCDL;
        h ^= h >>> 33;
        h *= 0xC4CEB9FE1A85EC53L;
        h ^= h >>> 33;
        return (int) h;
    }

    private static void crypt(int[] data, long key) {
        long state = key == 0L ? 0x2545F4914F6CDD1DL : key;
        for (int i = 0; i < data.length; i++) {
            state ^= state << 13;
            state ^= state >>> 7;
            state ^= state << 17;
            data[i] ^= (int) (state >>> 32);
        }
    }

    private static int integrity(int[] data) {
        int hash = 0x811C9DC5;
        for (int i = 0; i < data.length; i++) {
            int value = data[i];
            hash ^= value & 0xFF;
            hash *= 0x01000193;
            hash ^= (value >>> 8) & 0xFF;
            hash *= 0x01000193;
            hash ^= (value >>> 16) & 0xFF;
            hash *= 0x01000193;
            hash ^= (value >>> 24) & 0xFF;
            hash *= 0x01000193;
        }
        return hash;
    }

    private static long runOuterProgram(int[] program, long key1, int salt, int plainLen,
                                        int blockCount) {
        if (program.length < 1) {
            throw tampered("outer program");
        }
        int length = program[0];
        if (length < 0 || length > program.length - 1) {
            throw tampered("outer program length");
        }
        long[] stack = new long[32];
        int sp = 0;
        stack[sp++] = key1;
        stack[sp++] = salt;
        stack[sp++] = plainLen;
        stack[sp++] = blockCount;
        int pc = 1;
        int limit = 1 + length;
        while (pc < limit) {
            int op = program[pc++];
            switch (op) {
                case OUTER_PUSH:
                    stack[sp++] = program[pc++];
                    break;
                case OUTER_PUSH2: {
                    long lo = program[pc++];
                    long hi = program[pc++];
                    stack[sp++] = (hi << 32) ^ (lo & 0xFFFFFFFFL);
                    break;
                }
                case OUTER_XOR:
                    sp--;
                    stack[sp - 1] ^= stack[sp];
                    break;
                case OUTER_ADD:
                    sp--;
                    stack[sp - 1] += stack[sp];
                    break;
                case OUTER_MUL:
                    sp--;
                    stack[sp - 1] *= stack[sp];
                    break;
                case OUTER_ROTL: {
                    sp--;
                    int amount = (int) (stack[sp] & 63L);
                    stack[sp - 1] = (stack[sp - 1] << amount) | (stack[sp - 1] >>> (64 - amount));
                    break;
                }
                case OUTER_MIX: {
                    long value = stack[sp - 1];
                    value ^= value << 13;
                    value ^= value >>> 7;
                    value ^= value << 17;
                    stack[sp - 1] = value;
                    break;
                }
                case OUTER_NOT:
                    stack[sp - 1] = ~stack[sp - 1];
                    break;
                case OUTER_DUP:
                    stack[sp] = stack[sp - 1];
                    sp++;
                    break;
                case OUTER_SWAP: {
                    long value = stack[sp - 1];
                    stack[sp - 1] = stack[sp - 2];
                    stack[sp - 2] = value;
                    break;
                }
                case OUTER_HALT:
                    return stack[sp - 1];
                default:
                    throw tampered("outer opcode");
            }
            if (sp <= 0 || sp > stack.length - 4) {
                throw tampered("outer stack");
            }
        }
        return stack[sp - 1];
    }

    // ==================================================================
    // Frames (per thread, pooled across re-entrant calls too)
    // ==================================================================

    private static Object[] acquireFrame(int stackHint, int maxLocals) {
        Object[] frame = (Object[]) FRAMES.get();
        if (frame == null) {
            frame = newFrame();
        } else {
            FRAMES.set(frame[FRAME_NEXT]);
            frame[FRAME_NEXT] = null;
        }
        if (((long[]) frame[FRAME_NS]).length < stackHint) {
            frame[FRAME_NS] = new long[stackHint];
            frame[FRAME_RS] = new Object[stackHint];
            frame[FRAME_WS] = new byte[stackHint];
        }
        if (((long[]) frame[FRAME_NL]).length < maxLocals) {
            frame[FRAME_NL] = new long[maxLocals];
            frame[FRAME_RL] = new Object[maxLocals];
        }
        return frame;
    }

    private static void releaseFrame(Object[] frame) {
        Object[] rs = (Object[]) frame[FRAME_RS];
        for (int i = 0; i < rs.length; i++) {
            rs[i] = null;
        }
        Object[] rl = (Object[]) frame[FRAME_RL];
        for (int i = 0; i < rl.length; i++) {
            rl[i] = null;
        }
        frame[FRAME_NEXT] = FRAMES.get();
        FRAMES.set(frame);
    }

    private static Object[] newFrame() {
        return new Object[] {
                new long[32], new Object[32], new byte[32], new long[32], new Object[32], null
        };
    }

    // ==================================================================
    // Invocation
    // ==================================================================

    private static int invoke(String[] refs, Object[] refCache, int refIndex, int opcode,
                              long[] ns, Object[] rs, byte[] ws, int sp, Object[] rl) {
        Object[] info = invokeInfo(refs, refCache, refIndex, opcode);
        char[] argChars = (char[]) info[INFO_ARGS];
        int argumentCount = argChars.length;
        Object[] args = argumentCount == 0 ? NO_ARGS : new Object[argumentCount];
        try {
            for (int i = argumentCount - 1; i >= 0; i--) {
                sp--;
                args[i] = boxArgument(argChars[i], ns[sp], rs[sp]);
            }
            Object receiver = null;
            if (opcode != 184) {
                sp--;
                receiver = rs[sp];
                rs[sp] = null;
            }
            char result = ((Character) info[INFO_RETURN]).charValue();
            if (((Integer) info[INFO_KIND]).intValue() == 1) {
                if (!(receiver instanceof Object[]) || ((Object[]) receiver).length != 1
                        || !(((Object[]) receiver)[0] instanceof Class)) {
                    throw new IllegalStateException("Umbra VM2: uninitialized object expected");
                }
                Constructor<?> constructor = (Constructor<?>) info[INFO_CTOR];
                Object created = constructor.newInstance(args);
                for (int i = 0; i < sp; i++) {
                    if (rs[i] == receiver) {
                        rs[i] = created;
                    }
                }
                for (int i = 0; i < rl.length; i++) {
                    if (rl[i] == receiver) {
                        rl[i] = created;
                    }
                }
                return sp;
            }
            Method method = (Method) info[INFO_METHOD];
            // Array clone() is a JVM intrinsic: Object.clone is not invokable
            // from an unnamed module on JDK 9+, so emulate it.
            if (receiver != null && receiver.getClass().isArray()
                    && "clone".equals(info[INFO_NAME]) && argumentCount == 0) {
                Object copy = arrayClone(receiver);
                if (result == 'V') {
                    return sp;
                }
                return pushValue(ns, rs, ws, sp, result, copy);
            }
            Object value = method.invoke(receiver, args);
            if (result == 'V') {
                return sp;
            }
            return pushValue(ns, rs, ws, sp, result, value);
        } catch (InvocationTargetException e) {
            sneakyThrow(e.getCause());
            return sp;
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Umbra VM2 cannot access " + refs[refIndex], e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Umbra VM2 argument mismatch for " + refs[refIndex], e);
        } catch (InstantiationException e) {
            throw new IllegalStateException("Umbra VM2 cannot instantiate " + refs[refIndex], e);
        }
    }



    /**
     * Resolves and caches one call site: reflection target, argument kinds and
     * return kind. The cache lives in the decoded payload state, so repeated
     * calls never parse the reference string again.
     */
    private static Object[] invokeInfo(String[] refs, Object[] refCache, int refIndex, int opcode) {
        Object cached = refCache[refIndex];
        if (cached != null) {
            Object[] info = (Object[]) cached;
            if (((Integer) info[INFO_OPCODE]).intValue() == opcode) {
                return info;
            }
        }
        String ref = refs[refIndex];
        int first = ref.indexOf('|');
        int second = ref.indexOf('|', first + 1);
        int third = ref.indexOf('|', second + 1);
        String ownerToken = ref.substring(first + 1, second);
        String name = ref.substring(second + 1, third);
        String desc = ref.substring(third + 1);
        char[] argChars = argumentChars(desc);
        char result = desc.charAt(desc.indexOf(')') + 1);
        Object[] info = new Object[7];
        if (opcode == 183 && "<init>".equals(name)) {
            info[INFO_KIND] = Integer.valueOf(1);
            info[INFO_CTOR] = constructorFor(resolveInternal(ownerToken), desc, argChars.length);
        } else {
            info[INFO_KIND] = Integer.valueOf(0);
            info[INFO_METHOD] = methodFor(ref, opcode);
        }
        info[INFO_ARGS] = argChars;
        info[INFO_RETURN] = Character.valueOf(result);
        info[INFO_NAME] = name;
        info[INFO_OPCODE] = Integer.valueOf(opcode);
        refCache[refIndex] = info;
        return info;
    }

    private static Object[] fieldFor(String ref) {
        Object cached = FIELDS.get(ref);
        if (cached != null) {
            return (Object[]) cached;
        }
        int first = ref.indexOf('|');
        int second = ref.indexOf('|', first + 1);
        int third = ref.indexOf('|', second + 1);
        String ownerToken = ref.substring(first + 1, second);
        String name = ref.substring(second + 1, third);
        String desc = ref.substring(third + 1);
        Class<?> owner = resolveInternal(ownerToken);
        Field field = null;
        for (Class<?> current = owner; current != null; current = current.getSuperclass()) {
            try {
                Field candidate = current.getDeclaredField(name);
                if (descriptorOf(candidate.getType()).equals(desc)) {
                    field = candidate;
                    break;
                }
            } catch (NoSuchFieldException ignored) {
                // continue with the superclass
            }
            field = findInterfaceField(current, name, desc);
            if (field != null) {
                break;
            }
        }
        if (field == null) {
            throw new IllegalStateException("Umbra VM2 cannot resolve field " + ref);
        }
        makeAccessible(field);
        Object[] holder = new Object[] { field, Character.valueOf(sortOf(field.getType())) };
        FIELDS.put(ref, holder);
        return holder;
    }

    private static Field findInterfaceField(Class<?> type, String name, String desc) {
        Class<?>[] interfaces = type.getInterfaces();
        for (int i = 0; i < interfaces.length; i++) {
            try {
                Field candidate = interfaces[i].getDeclaredField(name);
                if (descriptorOf(candidate.getType()).equals(desc)) {
                    return candidate;
                }
            } catch (NoSuchFieldException ignored) {
                // continue with nested interfaces
            }
            Field nested = findInterfaceField(interfaces[i], name, desc);
            if (nested != null) {
                return nested;
            }
        }
        return null;
    }

    private static Method methodFor(String ref, int opcode) {
        String key = opcode + "|" + ref;
        Object cached = METHODS.get(key);
        if (cached != null) {
            return (Method) cached;
        }
        int first = ref.indexOf('|');
        int second = ref.indexOf('|', first + 1);
        int third = ref.indexOf('|', second + 1);
        String ownerToken = ref.substring(first + 1, second);
        String name = ref.substring(second + 1, third);
        String desc = ref.substring(third + 1);
        Class<?> owner = resolveInternal(ownerToken);
        Class<?>[] parameters = parameterTypes(desc);
        Method method = null;
        if (opcode == 182 || opcode == 185) {
            try {
                method = owner.getMethod(name, parameters);
            } catch (NoSuchMethodException ignored) {
                method = findDeclared(owner, name, parameters);
            }
        } else {
            method = findDeclared(owner, name, parameters);
        }
        if (method == null) {
            throw new IllegalStateException("Umbra VM2 cannot resolve method " + ref);
        }
        makeAccessible(method);
        METHODS.put(key, method);
        return method;
    }

    private static Method findDeclared(Class<?> type, String name, Class<?>[] parameters) {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                return current.getDeclaredMethod(name, parameters);
            } catch (NoSuchMethodException ignored) {
                // keep walking
            }
            Method fromInterface = findInInterfaces(current, name, parameters);
            if (fromInterface != null) {
                return fromInterface;
            }
        }
        return null;
    }

    private static Method findInInterfaces(Class<?> type, String name, Class<?>[] parameters) {
        Class<?>[] interfaces = type.getInterfaces();
        for (int i = 0; i < interfaces.length; i++) {
            try {
                return interfaces[i].getDeclaredMethod(name, parameters);
            } catch (NoSuchMethodException ignored) {
                // keep walking
            }
            Method nested = findInInterfaces(interfaces[i], name, parameters);
            if (nested != null) {
                return nested;
            }
        }
        return null;
    }

    private static Constructor<?> constructorFor(Class<?> type, String desc, int count) {
        String key = descriptorOf(type) + desc;
        Object cached = CONSTRUCTORS.get(key);
        if (cached != null) {
            return (Constructor<?>) cached;
        }
        Class<?>[] parameters = parameterTypes(desc);
        try {
            Constructor<?> constructor = type.getDeclaredConstructor(parameters);
            makeAccessible(constructor);
            CONSTRUCTORS.put(key, constructor);
            return constructor;
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException("Umbra VM2 cannot resolve constructor " + key);
        }
    }

    private static Class<?>[] parameterTypes(String desc) {
        Object cached = PARAMETERS.get(desc);
        if (cached != null) {
            return (Class<?>[]) cached;
        }
        int count = 0;
        int i = 1;
        while (desc.charAt(i) != ')') {
            while (desc.charAt(i) == '[') {
                i++;
            }
            if (desc.charAt(i) == 'L') {
                i = desc.indexOf(';', i) + 1;
            } else {
                i++;
            }
            count++;
        }
        Class<?>[] types = new Class<?>[count];
        int position = 1;
        for (int index = 0; index < count; index++) {
            int start = position;
            while (desc.charAt(position) == '[') {
                position++;
            }
            if (desc.charAt(position) == 'L') {
                position = desc.indexOf(';', position) + 1;
            } else {
                position++;
            }
            types[index] = resolveDescriptor(desc.substring(start, position));
        }
        PARAMETERS.put(desc, types);
        return types;
    }

    private static char[] argumentChars(String desc) {
        Object cached = ARGUMENTS.get(desc);
        if (cached != null) {
            return (char[]) cached;
        }
        char[] types = new char[parameterTypes(desc).length];
        int position = 1;
        for (int index = 0; index < types.length; index++) {
            char kind = desc.charAt(position);
            if (kind == '[') {
                while (desc.charAt(position) == '[') {
                    position++;
                }
                if (desc.charAt(position) == 'L') {
                    position = desc.indexOf(';', position) + 1;
                } else {
                    position++;
                }
                types[index] = 'L';
            } else if (kind == 'L') {
                position = desc.indexOf(';', position) + 1;
                types[index] = 'L';
            } else {
                position++;
                types[index] = kind;
            }
        }
        ARGUMENTS.put(desc, types);
        return types;
    }

    // ==================================================================
    // Values
    // ==================================================================

    private static int pushValue(long[] ns, Object[] rs, byte[] ws, int sp, char sort, Object value) {
        switch (sort) {
            case 'Z':
                ns[sp] = value instanceof Boolean
                        ? (((Boolean) value).booleanValue() ? 1 : 0) : toInt(value);
                ws[sp] = 1;
                return sp + 1;
            case 'B':
            case 'S':
            case 'I':
                ns[sp] = toInt(value);
                ws[sp] = 1;
                return sp + 1;
            case 'C':
                ns[sp] = value instanceof Character
                        ? ((Character) value).charValue() : toInt(value);
                ws[sp] = 1;
                return sp + 1;
            case 'J':
                ns[sp] = toLong(value);
                ws[sp] = 2;
                return sp + 1;
            case 'F':
                ns[sp] = Float.floatToRawIntBits(toFloat(value));
                ws[sp] = 1;
                return sp + 1;
            case 'D':
                ns[sp] = Double.doubleToRawLongBits(toDouble(value));
                ws[sp] = 2;
                return sp + 1;
            default:
                rs[sp] = value;
                ws[sp] = 1;
                return sp + 1;
        }
    }

    private static Object boxArgument(char sort, long bits, Object ref) {
        switch (sort) {
            case 'Z':
                return Boolean.valueOf((int) bits != 0);
            case 'B':
                return Byte.valueOf((byte) bits);
            case 'C':
                return Character.valueOf((char) bits);
            case 'S':
                return Short.valueOf((short) bits);
            case 'I':
                return Integer.valueOf((int) bits);
            case 'J':
                return Long.valueOf(bits);
            case 'F':
                return Float.valueOf(Float.intBitsToFloat((int) bits));
            case 'D':
                return Double.valueOf(Double.longBitsToDouble(bits));
            default:
                return ref;
        }
    }

    private static int storeField(Field field, char sort, Object receiver, long[] ns, Object[] rs,
                                  byte[] ws, int sp) {
        Object value;
        switch (sort) {
            case 'Z':
            case 'B':
            case 'S':
            case 'I':
            case 'C':
            case 'J':
            case 'F':
            case 'D':
                sp--;
                value = boxArgument(sort, ns[sp], rs[sp]);
                break;
            default:
                sp--;
                value = rs[sp];
                rs[sp] = null;
                break;
        }
        try {
            field.set(receiver, value);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Umbra VM2 cannot write field " + field.getName(), e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Umbra VM2 field type mismatch " + field.getName(), e);
        }
        return sp;
    }

    private static Object getFieldValue(Field field) {
        try {
            return field.get(null);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Umbra VM2 cannot read field " + field.getName(), e);
        }
    }

    private static Object getFieldValue(Field field, Object receiver) {
        try {
            return field.get(receiver);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Umbra VM2 cannot read field " + field.getName(), e);
        }
    }

    private static Object newArray(int type, int length) {        switch (type) {
            case 4: return new boolean[length];
            case 5: return new char[length];
            case 6: return new float[length];
            case 7: return new double[length];
            case 8: return new byte[length];
            case 9: return new short[length];
            case 10: return new int[length];
            case 11: return new long[length];
            default:
                throw new IllegalStateException("Umbra VM2: bad NEWARRAY type " + type);
        }
    }

    /** Emulates the JVM's array clone intrinsic (also works on JDK 9+). */
    private static Object arrayClone(Object array) {
        int length = Array.getLength(array);
        Object copy = Array.newInstance(array.getClass().getComponentType(), length);
        System.arraycopy(array, 0, copy, 0, length);
        return copy;
    }

    // ==================================================================
    // Types and coercion
    // ==================================================================

    private static String typeTokenFromRef(String ref) {
        if (ref.startsWith("T|")) {
            return ref.substring(2);
        }
        return ref;
    }

    /**
     * Resolves an internal class name or array descriptor (payload {@code T|}
     * references, field/method owners). Renamed classes may legitimately be a
     * single character long, so this must never interpret the token as a
     * primitive descriptor.
     */
    private static Class<?> resolveInternal(String token) {
        String key = "N:" + token;
        Object cached = TYPES.get(key);
        if (cached != null) {
            return (Class<?>) cached;
        }
        Class<?> type = forName(token.replace('/', '.'));
        TYPES.put(key, type);
        return type;
    }

    /** Resolves a field/method/type descriptor ({@code I}, {@code La;}, {@code [I}). */
    private static Class<?> resolveDescriptor(String token) {
        String key = "D:" + token;
        Object cached = TYPES.get(key);
        if (cached != null) {
            return (Class<?>) cached;
        }
        Class<?> type;
        if (token.startsWith("[")) {
            type = forName(token.replace('/', '.'));
        } else if (token.length() == 1) {
            type = primitive(token.charAt(0));
        } else if (token.startsWith("L") && token.endsWith(";")) {
            type = forName(token.substring(1, token.length() - 1).replace('/', '.'));
        } else {
            type = forName(token.replace('/', '.'));
        }
        TYPES.put(key, type);
        return type;
    }

    /**
     * Loads a class through the class loader chain a protected program may be
     * running under.
     *
     * <p>The interpreter helper itself is injected at the JAR root, but the
     * program's classes may live in a nested container: for a Spring Boot fat
     * JAR or a WAR they are loaded by the container loader (for example
     * {@code LaunchedURLClassLoader}) which is installed as the thread context
     * class loader. The helper's own loader (the system application loader)
     * cannot see {@code BOOT-INF/classes}, so the context loader is tried first,
     * then the helper's loader and finally the system loader. Flat JARs keep
     * working because all three candidates are the same application loader.</p>
     */
    private static Class<?> forName(String dottedName) {
        ClassNotFoundException failure = null;
        ClassLoader context = null;
        try {
            context = Thread.currentThread().getContextClassLoader();
        } catch (RuntimeException ignored) {
            context = null;
        }
        if (context != null) {
            try {
                return Class.forName(dottedName, false, context);
            } catch (ClassNotFoundException e) {
                failure = e;
            }
        }
        ClassLoader own = UmbraVM2.class.getClassLoader();
        if (own != null && own != context) {
            try {
                return Class.forName(dottedName, false, own);
            } catch (ClassNotFoundException e) {
                failure = e;
            }
        }
        ClassLoader system = ClassLoader.getSystemClassLoader();
        if (system != null && system != own && system != context) {
            try {
                return Class.forName(dottedName, false, system);
            } catch (ClassNotFoundException e) {
                failure = e;
            }
        }
        throw new IllegalStateException("Umbra VM2 cannot load type " + dottedName
                + " (context loader " + (context == null ? "none" : context.getClass().getName())
                + ", helper loader " + (own == null ? "bootstrap" : own.getClass().getName())
                + ")", failure);
    }


    private static Class<?> elementType(String descriptor) {
        int index = 0;
        while (index < descriptor.length() && descriptor.charAt(index) == '[') {
            index++;
        }
        return resolveDescriptor(descriptor.substring(index));
    }

    private static Class<?> primitive(char kind) {
        switch (kind) {
            case 'Z': return boolean.class;
            case 'B': return byte.class;
            case 'C': return char.class;
            case 'S': return short.class;
            case 'I': return int.class;
            case 'J': return long.class;
            case 'F': return float.class;
            case 'D': return double.class;
            case 'V': return void.class;
            default:
                throw new IllegalStateException("Umbra VM2: bad primitive " + kind);
        }
    }

    private static char sortOf(Class<?> type) {
        if (type == boolean.class) {
            return 'Z';
        }
        if (type == byte.class) {
            return 'B';
        }
        if (type == char.class) {
            return 'C';
        }
        if (type == short.class) {
            return 'S';
        }
        if (type == int.class) {
            return 'I';
        }
        if (type == long.class) {
            return 'J';
        }
        if (type == float.class) {
            return 'F';
        }
        if (type == double.class) {
            return 'D';
        }
        return 'L';
    }

    private static String descriptorOf(Class<?> type) {
        if (type == boolean.class) {
            return "Z";
        }
        if (type == byte.class) {
            return "B";
        }
        if (type == char.class) {
            return "C";
        }
        if (type == short.class) {
            return "S";
        }
        if (type == int.class) {
            return "I";
        }
        if (type == long.class) {
            return "J";
        }
        if (type == float.class) {
            return "F";
        }
        if (type == double.class) {
            return "D";
        }
        if (type == void.class) {
            return "V";
        }
        if (type.isArray()) {
            return type.getName().replace('.', '/');
        }
        return "L" + type.getName().replace('.', '/') + ";";
    }

    private static void makeAccessible(AccessibleObject object) {
        try {
            object.setAccessible(true);
        } catch (RuntimeException ignored) {
            // public members of exported packages stay callable
        }
    }

    /*
     * The JVM stores boolean/byte/char/short values as sign/zero extended ints
     * on the operand stack; reflection may hand back Boolean or Character
     * boxes, so every numeric unboxing path accepts both representations.
     */
    private static int toInt(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1 : 0;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        return ((Number) value).intValue();
    }

    private static long toLong(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1L : 0L;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        return ((Number) value).longValue();
    }

    private static float toFloat(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1f : 0f;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        return ((Number) value).floatValue();
    }

    private static double toDouble(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1d : 0d;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        return ((Number) value).doubleValue();
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> void sneakyThrow(Throwable throwable) throws T {
        throw (T) throwable;
    }
}
