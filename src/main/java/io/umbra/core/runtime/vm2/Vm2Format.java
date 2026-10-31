package io.umbra.core.runtime.vm2;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Wire format and cryptography of the Umbra VM2 virtualization engine.
 *
 * <p>This class is used by {@code VirtualizationPass} when {@code vm2.enabled}
 * is set. It is <b>not</b> injected into the protected program: the interpreter
 * template ({@link UmbraVM2}) repeats the handful of numeric constants and the
 * decryption primitives it needs, because runtime templates must be
 * self-contained single class files. {@code VmTest} round-trips a real payload
 * through both sides, so the two implementations cannot drift apart silently.</p>
 *
 * <h3>Payload layout (one virtualized method)</h3>
 *
 * <p>The payload is spread over one holder class per block: each block holder
 * keeps its {@code int[]} in a private static field behind a static accessor,
 * and a separate meta holder exposes the {@code int[8]} header the same way.
 * No class ever holds the assembled {@code int[][]} - the call site builds it
 * from the accessors - so a reflective dump of one holder class yields only
 * 1/N of the payload. {@code meta} describes the payload:</p>
 *
 * <pre>
 * meta[0]  magic (per payload, see {@link #magicFor})
 * meta[1]  low  half of the per-method key
 * meta[2]  high half of the per-method key
 * meta[3]  number of payload ints (blocks concatenated)
 * meta[4]  number of payload blocks (block holder classes)
 * meta[5]  FNV-1a 32 integrity of the unmasked payload
 * meta[6]  flags (encrypt, nested, opcode permutation, try/catch)
 * meta[7]  salt (mixed into the key)
 * </pre>
 *
 * <p>Each block is stored as a 6-bit-per-char ASCII string inside its own
 * synthetic holder class; the holder's {@code <clinit>} decodes the string into
 * a fresh {@code int[]} with a constant-size loop (6 bytes per payload int
 * instead of a separate constant/bytecode sequence per int). When
 * {@code vm2.nested} is on, {@code blocks[0]} is an encrypted <em>outer
 * program</em>: a tiny stack program (see {@link #OUTER_*}) that derives the
 * second-stage key from the first-stage key. The remaining blocks are the
 * actual payload, encrypted with that second-stage key. The payload itself is:</p>
 *
 * <pre>
 * [magic][format][flags][codeLen][constCount][refCount][handlerCount]
 * [maxLocals][argSlots][stackHint]
 * [argKind x argSlots]
 * [constants: tag + data]
 * [refs: length + UTF-16 chars]
 * [handlers: start, end, typeRef, target] x handlerCount
 * [code: codeLen ints]           (masked with a key/index mask)
 * </pre>
 *
 * <p>The code ints are masked <em>after</em> the integrity value is computed;
 * the interpreter unmasks the code region, verifies the integrity and only then
 * uses the payload. Opcodes are written into the stream in permuted form; the
 * per-program permutation table is emitted once in a shared holder and passed
 * to the interpreter as an argument (format 3, previously it was copied into
 * every payload).</p>
 *
 * <h3>Format 4: rolling opcode key</h3>
 *
 * <p>{@link #ROLLING_FORMAT} keeps the format-3 layout but additionally XORs
 * every opcode slot with an 8-bit mask derived from a 64-bit rolling state.
 * The state starts at {@code rollSeed(stageOneKey)} and after each decoded
 * instruction advances with {@code rollStep(roll, encodedOpcode)} — it is
 * chained over the <em>permuted</em> opcode value so every instruction's key
 * byte depends on every opcode before it in the stream. A static dump of a
 * payload therefore no longer yields a directly decodable instruction sequence:
 * the reader must first know the per-method key and walk the stream from the
 * start. Format 3 payloads (no rolling layer) remain readable
 * ({@link #serializeLegacy}); the interpreter accepts both versions.</p>
 *
 * <h3>Superinstructions</h3>
 *
 * <p>{@code vm2.fusion} lets the translator replace short opcode runs (for
 * example {@code ILOAD a; ILOAD b; IADD}) with one superinstruction from the
 * reserved range {@link #SUPER_BASE}..{@link #SUPER_LAST}. Superinstructions
 * are real opcode numbers above the JVM's 200 opcodes, so they travel through
 * the same permutation table and rolling layer as ordinary opcodes; the
 * interpreter executes them with the exact semantics of the replaced run.</p>
 */
public final class Vm2Format {

    private Vm2Format() {
    }

    /** Legacy format version of the serialized payload (3 = shared opcode map). */
    public static final int FORMAT = 3;
    /**
     * Current payload format: format 3 plus the rolling opcode-key layer.
     * Readers accept both {@link #FORMAT} and this version.
     */
    public static final int ROLLING_FORMAT = 4;
    /** ASCII characters used to encode one payload int in a block string. */
    public static final int CHARS_PER_INT = 6;
    /** Maximum number of payload ints per block string (class-file friendly). */
    public static final int MAX_INTS_PER_BLOCK = 6000;
    /** First character of the 64 symbol block alphabet (0x20 .. 0x5F). */
    public static final char BLOCK_BASE = 0x20;

    public static final int FLAG_ENCRYPT = 1;
    public static final int FLAG_NESTED = 2;
    public static final int FLAG_OPCODES = 4;
    public static final int FLAG_TRYS = 8;

    // ------------------------------------------------------------------
    // Superinstructions (vm2.fusion)
    //
    // Real opcode numbers above the JVM set (0..201 because GOTO_W/JSR_W are
    // never emitted by ASM for class files below the 32K method limit and the
    // remaining numbers are unused). Operand layout per superinstruction is
    // documented next to its constant and mirrored exactly by UmbraVM2.
    // ------------------------------------------------------------------

    /** First superinstruction opcode; all of them fit below 256. */
    public static final int SUPER_BASE = 202;
    /** ILOAD a; ILOAD b; IADD (operands: a, b). */
    public static final int SUPER_IADD_LL = 202;
    /** ILOAD a; ILOAD b; ISUB (operands: a, b). */
    public static final int SUPER_ISUB_LL = 203;
    /** ILOAD a; ILOAD b; IMUL (operands: a, b). */
    public static final int SUPER_IMUL_LL = 204;
    /** ILOAD a; ILOAD b; IAND (operands: a, b). */
    public static final int SUPER_IAND_LL = 205;
    /** ILOAD a; ILOAD b; IOR (operands: a, b). */
    public static final int SUPER_IOR_LL = 206;
    /** ILOAD a; ILOAD b; IXOR (operands: a, b). */
    public static final int SUPER_IXOR_LL = 207;
    /** ILOAD a; constant; IADD (operands: a, constant). */
    public static final int SUPER_ILOAD_CONST_ADD = 208;
    /** ILOAD a; constant; ISUB (operands: a, constant). */
    public static final int SUPER_ILOAD_CONST_SUB = 209;
    /** ILOAD a; constant; IMUL (operands: a, constant). */
    public static final int SUPER_ILOAD_CONST_MUL = 210;
    /** ILOAD a; constant; IAND (operands: a, constant). */
    public static final int SUPER_ILOAD_CONST_AND = 211;
    /** ILOAD a; constant; IOR (operands: a, constant). */
    public static final int SUPER_ILOAD_CONST_OR = 212;
    /** ILOAD a; constant; IXOR (operands: a, constant). */
    public static final int SUPER_ILOAD_CONST_XOR = 213;
    /** ILOAD a; ILOAD b; IF_ICMPEQ target (operands: a, b, target). */
    public static final int SUPER_IF_ICMPEQ_LL = 214;
    /** ILOAD a; ILOAD b; IF_ICMPNE target (operands: a, b, target). */
    public static final int SUPER_IF_ICMPNE_LL = 215;
    /** ILOAD a; ILOAD b; IF_ICMPLT target (operands: a, b, target). */
    public static final int SUPER_IF_ICMPLT_LL = 216;
    /** ILOAD a; ILOAD b; IF_ICMPGE target (operands: a, b, target). */
    public static final int SUPER_IF_ICMPGE_LL = 217;
    /** ILOAD a; ILOAD b; IF_ICMPGT target (operands: a, b, target). */
    public static final int SUPER_IF_ICMPGT_LL = 218;
    /** ILOAD a; ILOAD b; IF_ICMPLE target (operands: a, b, target). */
    public static final int SUPER_IF_ICMPLE_LL = 219;
    /** LLOAD a; LLOAD b; LADD (operands: a, b). */
    public static final int SUPER_LADD_LL = 220;
    /** LLOAD a; LLOAD b; LSUB (operands: a, b). */
    public static final int SUPER_LSUB_LL = 221;
    /** LLOAD a; LLOAD b; LMUL (operands: a, b). */
    public static final int SUPER_LMUL_LL = 222;
    /** LLOAD a; LLOAD b; LAND (operands: a, b). */
    public static final int SUPER_LAND_LL = 223;
    /** LLOAD a; LLOAD b; LOR (operands: a, b). */
    public static final int SUPER_LOR_LL = 224;
    /** LLOAD a; LLOAD b; LXOR (operands: a, b). */
    public static final int SUPER_LXOR_LL = 225;
    /** ALOAD a; GETFIELD ref (operands: a, fieldRef). */
    public static final int SUPER_ALOAD_GETFIELD = 226;
    /** ICONST/BIPUSH/SIPUSH constant; ISTORE a (operands: constant, a). */
    public static final int SUPER_CONST_ISTORE = 227;
    /** Last superinstruction opcode. */
    public static final int SUPER_LAST = 227;

    /** Header ints before the argument-kind table. */
    public static final int HEADER = 10;
    /** Number of ints in the holder meta array. */
    public static final int META_LEN = 8;

    // Constant tags of the serialized constant pool.
    public static final int CONST_INT = 1;
    public static final int CONST_LONG = 2;
    public static final int CONST_FLOAT = 3;
    public static final int CONST_DOUBLE = 4;
    public static final int CONST_STRING = 5;
    public static final int CONST_CLASS = 6;

    // Local variable kinds used by the argument-kind table.
    public static final int KIND_UNUSED = 0;
    public static final int KIND_INT = 1;
    public static final int KIND_LONG = 2;
    public static final int KIND_FLOAT = 3;
    public static final int KIND_DOUBLE = 4;
    public static final int KIND_REF = 5;

    // Outer (stage one) mini program opcodes.
    public static final int OUTER_PUSH = 0;
    public static final int OUTER_XOR = 1;
    public static final int OUTER_ADD = 2;
    public static final int OUTER_MUL = 3;
    public static final int OUTER_ROTL = 4;
    public static final int OUTER_MIX = 5;
    public static final int OUTER_NOT = 6;
    public static final int OUTER_DUP = 7;
    public static final int OUTER_SWAP = 8;
    public static final int OUTER_HALT = 9;
    public static final int OUTER_PUSH2 = 10;

    private static final long GOLDEN = 0x9E3779B97F4A7C15L;

    // ------------------------------------------------------------------
    // Key derivation and cryptography (mirrored by UmbraVM2)
    // ------------------------------------------------------------------

    /** Derives the per-method key from the holder meta array. */
    public static long metaKey(int[] meta) {
        long key = (((long) meta[1]) << 32) ^ (((long) meta[2]) & 0xFFFFFFFFL)
                ^ (((long) meta[7]) * GOLDEN);
        if (key == 0L) {
            key = 0x51ED270B1F2A3C4DL;
        }
        return key;
    }

    /**
     * Magic stored in the holder {@code meta} array ({@code meta[0]}). It is
     * derived from key material the reader already needs, so every payload
     * carries a different marker and no fixed literal exists in the build or in
     * the injected interpreter that could serve as a fingerprint. The reader
     * can recompute it because {@code meta[1]}, {@code meta[2]} and
     * {@code meta[7]} are read before the check.
     */
    public static int magicFor(int[] meta) {
        return (int) (metaKey(meta) >>> 32) ^ meta[7] ^ 0x2B;
    }

    /**
     * Magic stored at the start of the serialized payload ({@code plain[0]}).
     * Derived from the per-method key instead of a constant; both sides compute
     * it from the value they already share.
     */
    public static int payloadMagic(long key) {
        long mixed = key ^ (key >>> 32) ^ 0x2B;
        mixed *= GOLDEN;
        return (int) (mixed >>> 32) ^ (int) mixed;
    }

    /** Position-dependent operand mask applied to the serialized code stream. */
    public static int mask(long key, int index) {
        long h = key ^ (((long) index) * GOLDEN);
        h ^= h >>> 33;
        h *= 0xFF51AFD7ED558CCDL;
        h ^= h >>> 33;
        h *= 0xC4CEB9FE1A85EC53L;
        h ^= h >>> 33;
        return (int) h;
    }

    /** XORs the array with the keystream derived from {@code key}. */
    public static void crypt(int[] data, long key) {
        long state = key == 0L ? 0x2545F4914F6CDD1DL : key;
        for (int i = 0; i < data.length; i++) {
            state ^= state << 13;
            state ^= state >>> 7;
            state ^= state << 17;
            data[i] ^= (int) (state >>> 32);
        }
    }

    /** FNV-1a 32 over the payload; the interpreter compares it with {@code meta[5]}. */
    public static int integrity(int[] data) {
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

    // ------------------------------------------------------------------
    // Rolling opcode-key layer (format 4, mirrored by UmbraVM2)
    // ------------------------------------------------------------------

    /**
     * Initial rolling state of a payload. Derived from the first-stage key, so
     * the mask sequence differs per virtualized method even though the opcode
     * permutation table is shared by the whole program.
     */
    public static long rollSeed(long key) {
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

    /** The 8-bit opcode mask contributed by one rolling state. */
    public static int rollMask(long roll) {
        return (int) (roll >>> 56);
    }

    /**
     * Advances the rolling state by one instruction. The chain is keyed on the
     * <em>permuted</em> opcode value (what is stored in the stream before the
     * rolling XOR), so the reader can update the state before consulting the
     * decoder table.
     */
    public static long rollStep(long roll, int encodedOpcode) {
        return roll * 0x9E3779B97F4A7C15L ^ (((long) encodedOpcode) + 1L);
    }

    // ------------------------------------------------------------------
    // Opcode permutation
    // ------------------------------------------------------------------

    /**
     * Builds a per-program opcode permutation.
     *
     * <p>All 256 byte values are permuted, so the reserved superinstruction
     * numbers ({@link #SUPER_BASE}..{@link #SUPER_LAST}) travel through the
     * same table as the JVM opcodes. Unused JVM opcode slots are mapped too,
     * which keeps the table size fixed and gives the decoder no implicit
     * "invalid" values to special-case.</p>
     *
     * @return an array {@code encodedByReal} where {@code encodedByReal[opcode]}
     *         is the number stored in the payload and
     *         {@code encodedByReal[256]} is the number of real opcodes covered
     */
    public static int[] opcodePermutation(Random random) {
        int[] pool = new int[256];
        for (int i = 0; i < pool.length; i++) {
            pool[i] = i;
        }
        for (int i = pool.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            int tmp = pool[i];
            pool[i] = pool[j];
            pool[j] = tmp;
        }
        int[] encodedByReal = new int[257];
        for (int opcode = 0; opcode < 256; opcode++) {
            encodedByReal[opcode] = pool[opcode];
        }
        encodedByReal[256] = 256;
        return encodedByReal;
    }

    /** Builds the decoder table ({@code encoded -> real}) stored in the payload. */
    public static int[] decoderTable(int[] encodedByReal) {
        int[] table = new int[256];
        for (int i = 0; i < table.length; i++) {
            table[i] = -1;
        }
        int count = encodedByReal[256];
        for (int opcode = 0; opcode < count; opcode++) {
            table[encodedByReal[opcode]] = opcode;
        }
        return table;
    }

    /**
     * Number of operand ints that follow an opcode slot. This is the single
     * source of truth shared by the translator, the payload validator and the
     * reference decoder in the tests; {@code UmbraVM2} carries an identical copy
     * because runtime templates must be self-contained.
     *
     * @param opcode     real opcode (JVM or superinstruction)
     * @param code       code stream
     * @param opcodeSlot slot of the opcode inside {@code code}
     */
    public static int operandSlots(int opcode, int[] code, int opcodeSlot) {
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
            case 16: // BIPUSH
            case 17: // SIPUSH
            case 18: // LDC
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

    // ------------------------------------------------------------------
    // Outer ("stage one") program
    // ------------------------------------------------------------------

    /**
     * Generates a random outer program. The program starts with its own length
     * in ints, followed by the mini instructions. It is interpreted with the
     * initial stack {@code [key1, salt, plainLen, blockCount]} and its top of
     * stack becomes the second-stage key.
     */
    public static int[] generateOuterProgram(Random random) {
        IntList code = new IntList();
        int ops = 7 + random.nextInt(6);
        int depth = 4;
        for (int i = 0; i < ops; i++) {
            int choice = random.nextInt(depth >= 2 ? 11 : 4);
            switch (choice) {
                case 0:
                case 1:
                case 2:
                    code.add(OUTER_PUSH);
                    code.add(random.nextInt());
                    depth++;
                    break;
                case 3:
                    code.add(OUTER_PUSH2);
                    code.add(random.nextInt());
                    code.add(random.nextInt());
                    depth++;
                    break;
                case 4:
                    code.add(OUTER_XOR);
                    depth--;
                    break;
                case 5:
                    code.add(OUTER_ADD);
                    depth--;
                    break;
                case 6:
                    code.add(OUTER_MUL);
                    depth--;
                    break;
                case 7:
                    code.add(OUTER_ROTL);
                    depth--;
                    break;
                case 8:
                    code.add(OUTER_MIX);
                    break;
                case 9:
                    if (random.nextBoolean()) {
                        code.add(OUTER_DUP);
                        depth++;
                    } else {
                        code.add(OUTER_NOT);
                    }
                    break;
                case 10:
                    code.add(OUTER_SWAP);
                    break;
                default:
                    code.add(OUTER_NOT);
                    break;
            }
            if (depth < 1) {
                code.add(OUTER_PUSH);
                code.add(random.nextInt());
                depth++;
            }
        }
        code.add(OUTER_HALT);
        int[] program = new int[code.size() + 1];
        program[0] = code.size();
        for (int i = 0; i < code.size(); i++) {
            program[i + 1] = code.get(i);
        }
        return program;
    }

    /**
     * Executes an outer program (identical to the interpreter implementation)
     * and returns the derived second-stage key.
     */
    public static long runOuterProgram(int[] program, long key1, int salt, int plainLen, int blockCount) {
        if (program.length < 1) {
            throw new IllegalStateException("empty outer program");
        }
        int length = program[0];
        if (length < 0 || length > program.length - 1) {
            throw new IllegalStateException("malformed outer program");
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
                    throw new IllegalStateException("bad outer opcode " + op);
            }
            if (sp <= 0 || sp > stack.length - 4) {
                throw new IllegalStateException("outer program stack imbalance");
            }
        }
        return stack[sp - 1];
    }

    // ------------------------------------------------------------------
    // Translation result and serialization
    // ------------------------------------------------------------------

    /** A finished virtualized method body, before payload encoding. */
    public static final class Program {
        public final int[] code;
        public final Object[] constants;
        public final String[] refs;
        public final int[] handlers;
        public final int maxLocals;
        public final int argSlots;
        public final int[] argKinds;
        public final int stackHint;
        public final int flags;
        /**
         * Ascending slots of the opcode ints inside {@link #code}, used to apply
         * the format-4 rolling layer. {@code null} for legacy (format 3)
         * programs, which are serialized with {@link #serializeLegacy}.
         */
        public final int[] opcodePositions;

        public Program(int[] code, Object[] constants, String[] refs, int[] handlers,
                       int maxLocals, int argSlots, int[] argKinds, int stackHint, int flags) {
            this(code, constants, refs, handlers, maxLocals, argSlots, argKinds, stackHint,
                    flags, null);
        }

        public Program(int[] code, Object[] constants, String[] refs, int[] handlers,
                       int maxLocals, int argSlots, int[] argKinds, int stackHint, int flags,
                       int[] opcodePositions) {
            this.code = code;
            this.constants = constants;
            this.refs = refs;
            this.handlers = handlers;
            this.maxLocals = maxLocals;
            this.argSlots = argSlots;
            this.argKinds = argKinds;
            this.stackHint = stackHint;
            this.flags = flags;
            this.opcodePositions = opcodePositions;
        }
    }

    /** Encoded payload plus its integrity value. */
    public static final class Encoded {
        public final int[] payload;
        public final int integrity;

        Encoded(int[] payload, int integrity) {
            this.payload = payload;
            this.integrity = integrity;
        }
    }

    /**
     * Serializes a translated program with the current format
     * ({@link #ROLLING_FORMAT}): the opcode slots listed in
     * {@link Program#opcodePositions} are XORed with the rolling opcode key
     * before the position mask is applied.
     *
     * <p>The opcode permutation table is <em>not</em> part of the payload any
     * more: it is identical for every method of a program, so the pass emits it
     * once in a shared holder and passes it to the interpreter as an argument
     * (see {@code FORMAT} 3/4).</p>
     *
     * @param program translated method with opcode positions
     * @param key     per-method key (used for the operand mask and the rolling layer)
     * @return masked payload and its pre-mask integrity
     */
    public static Encoded serialize(Program program, long key) {
        if (program.opcodePositions == null) {
            throw new IllegalStateException("format-4 payload needs opcode positions");
        }
        return serialize(program, key, ROLLING_FORMAT, program.opcodePositions);
    }

    /**
     * Serializes a translated program in the legacy format 3 (no rolling
     * opcode layer). Kept for reader-compatibility tests and for programs whose
     * opcode positions are not tracked.
     */
    public static Encoded serializeLegacy(Program program, long key) {
        return serialize(program, key, FORMAT, null);
    }

    private static Encoded serialize(Program program, long key, int format, int[] opcodePositions) {
        IntList out = new IntList(program.code.length + program.constants.length * 3 + 64);
        out.add(payloadMagic(key));
        out.add(format);
        out.add(program.flags);
        out.add(program.code.length);
        out.add(program.constants.length);
        out.add(program.refs.length);
        out.add(program.handlers.length / 4);
        out.add(program.maxLocals);
        out.add(program.argSlots);
        out.add(program.stackHint);
        for (int i = 0; i < program.argSlots; i++) {
            out.add(program.argKinds[i]);
        }
        for (int i = 0; i < program.constants.length; i++) {
            Object value = program.constants[i];
            if (value instanceof Integer) {
                out.add(CONST_INT);
                out.add(((Integer) value).intValue());
            } else if (value instanceof Long) {
                long number = ((Long) value).longValue();
                out.add(CONST_LONG);
                out.add((int) number);
                out.add((int) (number >>> 32));
            } else if (value instanceof Float) {
                out.add(CONST_FLOAT);
                out.add(Float.floatToRawIntBits(((Float) value).floatValue()));
            } else if (value instanceof Double) {
                long bits = Double.doubleToRawLongBits(((Double) value).doubleValue());
                out.add(CONST_DOUBLE);
                out.add((int) bits);
                out.add((int) (bits >>> 32));
            } else if (value instanceof String) {
                out.add(CONST_STRING);
                writeString(out, (String) value);
            } else if (value instanceof org.objectweb.asm.Type) {
                out.add(CONST_CLASS);
                writeString(out, ((org.objectweb.asm.Type) value).getDescriptor());
            } else {
                throw new IllegalStateException("unsupported VM2 constant " + value);
            }
        }
        for (int i = 0; i < program.refs.length; i++) {
            writeString(out, program.refs[i]);
        }
        for (int i = 0; i < program.handlers.length; i++) {
            out.add(program.handlers[i]);
        }
        int codeStart = out.size();
        for (int i = 0; i < program.code.length; i++) {
            out.add(program.code[i]);
        }
        int[] payload = out.toArray();
        if (format >= ROLLING_FORMAT) {
            long roll = rollSeed(key);
            int previous = -1;
            for (int i = 0; i < opcodePositions.length; i++) {
                int slot = opcodePositions[i];
                if (slot < 0 || slot >= program.code.length) {
                    throw new IllegalStateException("opcode position out of range: " + slot);
                }
                if (slot <= previous) {
                    throw new IllegalStateException("opcode positions must be ascending: " + slot);
                }
                previous = slot;
                int encoded = payload[codeStart + slot];
                payload[codeStart + slot] = encoded ^ rollMask(roll);
                roll = rollStep(roll, encoded);
            }
        }
        int integrity = integrity(payload);
        for (int i = 0; i < program.code.length; i++) {
            payload[codeStart + i] ^= mask(key, i);
        }
        return new Encoded(payload, integrity);
    }

    private static void writeString(IntList out, String value) {
        out.add(value.length());
        for (int i = 0; i < value.length(); i++) {
            out.add(value.charAt(i));
        }
    }

    /** Splits a payload into {@code count} contiguous blocks. */
    public static List<int[]> split(int[] payload, int count) {
        if (count < 1) {
            count = 1;
        }
        if (count > payload.length) {
            count = payload.length;
        }
        List<int[]> blocks = new ArrayList<int[]>(count);
        int base = 0;
        int remainder = payload.length % count;
        int size = payload.length / count;
        for (int i = 0; i < count; i++) {
            int length = size + (i < remainder ? 1 : 0);
            int[] block = new int[length];
            System.arraycopy(payload, base, block, 0, length);
            blocks.add(block);
            base += length;
        }
        return blocks;
    }

    /** Serializes the constant pool helper used by tests and diagnostics. */
    public static String describe(Program program) {
        StringBuilder out = new StringBuilder();
        out.append("code=").append(program.code.length)
                .append(" constants=").append(program.constants.length)
                .append(" refs=").append(program.refs.length)
                .append(" handlers=").append(program.handlers.length / 4)
                .append(" maxLocals=").append(program.maxLocals);
        return out.toString();
    }

    /**
     * Encodes a payload block as a printable-ASCII string: every int becomes six
     * chars from the 0x20..0x5F range (six 6-bit groups, the last group only
     * carries the two top bits). The holder class initializer decodes the string
     * with a small loop, so the class file cost is ~6 bytes per payload int
     * instead of a constant-pool int plus store bytecode per element.
     */
    public static String encodeBlock(int[] values) {
        char[] encoded = new char[values.length * CHARS_PER_INT];
        int position = 0;
        for (int i = 0; i < values.length; i++) {
            int value = values[i];
            for (int group = 0; group < CHARS_PER_INT; group++) {
                encoded[position++] = (char) (BLOCK_BASE + ((value >>> (group * 6)) & 0x3F));
            }
        }
        return new String(encoded);
    }

    /** Inverse of {@link #encodeBlock(int[])} (kept for tests/diagnostics). */
    public static int[] decodeBlock(String encoded) {
        if ((encoded.length() % CHARS_PER_INT) != 0) {
            throw new IllegalArgumentException("malformed VM2 block string");
        }
        int[] values = new int[encoded.length() / CHARS_PER_INT];
        for (int i = 0; i < values.length; i++) {
            int value = 0;
            for (int group = 0; group < CHARS_PER_INT; group++) {
                value |= (encoded.charAt(i * CHARS_PER_INT + group) - BLOCK_BASE) << (group * 6);
            }
            values[i] = value;
        }
        return values;
    }

    /** Number of block classes needed for a payload of the given size. */
    public static int blockCount(int payloadInts, int requestedBlocks) {
        int count = Math.max(1, requestedBlocks);
        int needed = (payloadInts + MAX_INTS_PER_BLOCK - 1) / MAX_INTS_PER_BLOCK;
        return Math.min(payloadInts, Math.max(count, needed));
    }

    /** Growable int array (avoids boxing while building payloads). */
    public static final class IntList {
        private int[] values;
        private int size;

        public IntList() {
            this(64);
        }

        public IntList(int capacity) {
            values = new int[Math.max(16, capacity)];
        }

        public void add(int value) {
            if (size == values.length) {
                int[] grown = new int[values.length * 2];
                System.arraycopy(values, 0, grown, 0, values.length);
                values = grown;
            }
            values[size++] = value;
        }

        public int get(int index) {
            return values[index];
        }

        public void set(int index, int value) {
            values[index] = value;
        }

        public int size() {
            return size;
        }

        public int[] toArray() {
            int[] out = new int[size];
            System.arraycopy(values, 0, out, 0, size);
            return out;
        }
    }

    /** Ordered constant pool builder shared by the translator. */
    public static final class ConstantPool {
        private final List<Object> values = new ArrayList<Object>();
        private final Map<Object, Integer> index = new LinkedHashMap<Object, Integer>();

        public int add(Object value) {
            Integer existing = index.get(value);
            if (existing != null) {
                return existing.intValue();
            }
            int position = values.size();
            values.add(value);
            index.put(value, Integer.valueOf(position));
            return position;
        }

        public Object[] toArray() {
            return values.toArray(new Object[0]);
        }
    }
}
