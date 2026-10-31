package io.umbra.core.runtime;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Cantrip dialect interpreter used by the optional Cantrip layer.
 *
 * <p>The program is a sequence of classic Cantrip commands
 * ({@code > < + - . [ ]}) plus the dialect command {@code ~<int>;} which sets
 * the current cell to a signed integer. VM2 payload chunks are emitted as
 * {@code ~value;.} sequences: the ciphertext integers are reconstructed by the
 * interpreter instead of by a plain array-initialisation loop.</p>
 *
 * <p>Single self-contained class, JDK only, no nested classes.</p>
 */
public final class UmbraCantrip {

    private UmbraCantrip() {
    }

    /** Executes all chunks and returns the values emitted by {@code .}. */
    public static int[] run(String[] chunks) {
        if (chunks == null || chunks.length == 0) {
            return new int[0];
        }
        StringBuilder joined = new StringBuilder();
        for (int i = 0; i < chunks.length; i++) {
            if (chunks[i] != null) {
                joined.append(chunks[i]);
            }
        }
        String program = joined.toString();
        int[] tape = new int[64];
        int pointer = 0;
        int[] output = new int[Math.max(16, program.length() / 8)];
        int outputLength = 0;
        int[] loopStack = new int[32];
        int loopDepth = 0;
        int pc = 0;
        while (pc < program.length()) {
            char command = program.charAt(pc);
            if (command == '~') {
                int start = pc + 1;
                int end = program.indexOf(';', start);
                if (end < 0) {
                    throw new IllegalStateException("Cantrip: unterminated literal");
                }
                long value;
                try {
                    value = Long.parseLong(program.substring(start, end));
                } catch (NumberFormatException failure) {
                    throw new IllegalStateException("Cantrip: bad literal");
                }
                tape[pointer] = (int) value;
                pc = end + 1;
                continue;
            }
            switch (command) {
                case '>':
                    pointer++;
                    if (pointer >= tape.length) {
                        int[] grown = new int[tape.length * 2];
                        System.arraycopy(tape, 0, grown, 0, tape.length);
                        tape = grown;
                    }
                    break;
                case '<':
                    pointer--;
                    if (pointer < 0) {
                        throw new IllegalStateException("Cantrip: tape underflow");
                    }
                    break;
                case '+':
                    tape[pointer]++;
                    break;
                case '-':
                    tape[pointer]--;
                    break;
                case '.':
                    if (outputLength == output.length) {
                        int[] grown = new int[output.length * 2];
                        System.arraycopy(output, 0, grown, 0, output.length);
                        output = grown;
                    }
                    output[outputLength++] = tape[pointer];
                    break;
                case '[':
                    if (tape[pointer] == 0) {
                        pc = skipForward(program, pc);
                    } else {
                        if (loopDepth == loopStack.length) {
                            int[] grown = new int[loopStack.length * 2];
                            System.arraycopy(loopStack, 0, grown, 0, loopStack.length);
                            loopStack = grown;
                        }
                        loopStack[loopDepth++] = pc;
                    }
                    break;
                case ']':
                    if (tape[pointer] != 0) {
                        if (loopDepth == 0) {
                            throw new IllegalStateException("Cantrip: unbalanced loop");
                        }
                        pc = loopStack[loopDepth - 1];
                    } else if (loopDepth > 0) {
                        loopDepth--;
                    }
                    break;
                default:
                    // Formatting/whitespace and unknown dialect hints are ignored.
                    break;
            }
            pc++;
        }
        int[] result = new int[outputLength];
        System.arraycopy(output, 0, result, 0, outputLength);
        return result;
    }

    private static int skipForward(String program, int openIndex) {
        int depth = 0;
        for (int i = openIndex; i < program.length(); i++) {
            char c = program.charAt(i);
            if (c == '[') {
                depth++;
            } else if (c == ']') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        throw new IllegalStateException("Cantrip: unbalanced loop");
    }

    // ---------------------------------------------------------------- sealed layer
    //
    // The second virtualization layer stores each dialect program twice removed
    // from its syntax: the command characters are substituted through a per-build
    // permutation (a different opcode table for every build), then the text is
    // ChaCha20-encrypted and Base64-encoded. A static reader therefore sees opaque
    // base64 blobs instead of `~value;.` programs, and has to reimplement both the
    // cipher and the permutation to recover the payload integers. The interpreter
    // only exposes decode-and-run; the dialect semantics stay inside `run`.

    /** Decodes sealed chunks and executes them. */
    public static int[] runSealed(String[] sealed, int key) {
        return run(decode(sealed, key));
    }

    /** Seals plain dialect chunks (build side): substitute, encrypt, base64. */
    public static String[] seal(String[] plain, int key) {
        if (plain == null) {
            return new String[0];
        }
        int[] table = permutation(key);
        byte[] keyBytes = keyBytes(key);
        byte[] nonce = nonce(key);
        String[] out = new String[plain.length];
        for (int i = 0; i < plain.length; i++) {
            String text = plain[i] == null ? "" : plain[i];
            char[] chars = text.toCharArray();
            for (int c = 0; c < chars.length; c++) {
                chars[c] = (char) table[chars[c] & 0x7F];
            }
            byte[] bytes = new String(chars).getBytes(StandardCharsets.UTF_8);
            out[i] = Base64.getEncoder().encodeToString(chacha20(keyBytes, nonce, bytes));
        }
        return out;
    }

    /** Reverses {@link #seal(String[], int)} without executing the program. */
    public static String[] decode(String[] sealed, int key) {
        if (sealed == null) {
            return new String[0];
        }
        int[] table = permutation(key);
        int[] inverse = new int[128];
        for (int i = 0; i < 128; i++) {
            inverse[table[i]] = i;
        }
        byte[] keyBytes = keyBytes(key);
        byte[] nonce = nonce(key);
        String[] out = new String[sealed.length];
        for (int i = 0; i < sealed.length; i++) {
            byte[] bytes = Base64.getDecoder().decode(sealed[i] == null ? "" : sealed[i]);
            String text = new String(chacha20(keyBytes, nonce, bytes), StandardCharsets.UTF_8);
            char[] chars = text.toCharArray();
            for (int c = 0; c < chars.length; c++) {
                chars[c] = (char) inverse[chars[c] & 0x7F];
            }
            out[i] = new String(chars);
        }
        return out;
    }

    /** Per-build opcode table: a deterministic permutation of the 128 low code points. */
    private static int[] permutation(int key) {
        int[] table = new int[128];
        for (int i = 0; i < 128; i++) {
            table[i] = i;
        }
        long state = 0x2545F4914F6CDD1DL ^ (key & 0xFFFFFFFFL);
        for (int i = 127; i > 0; i--) {
            state ^= state << 13;
            state ^= state >>> 7;
            state ^= state << 17;
            int j = (int) ((state >>> 33) % (i + 1));
            int tmp = table[i];
            table[i] = table[j];
            table[j] = tmp;
        }
        return table;
    }

    /** Expands the 32-bit dialect key into a 256-bit ChaCha20 key. */
    private static byte[] keyBytes(int key) {
        byte[] out = new byte[32];
        long state = 0x9E3779B97F4A7C15L ^ (key & 0xFFFFFFFFL);
        for (int block = 0; block < 8; block++) {
            state ^= state << 13;
            state ^= state >>> 7;
            state ^= state << 17;
            long value = state * 0x2545F4914F6CDD1DL;
            for (int i = 0; i < 4; i++) {
                out[block * 4 + i] = (byte) (value >>> (8 * i));
            }
        }
        return out;
    }

    /** 96-bit nonce derived from the dialect key (unique per build). */
    private static byte[] nonce(int key) {
        byte[] bytes = keyBytes(key);
        byte[] nonce = new byte[12];
        for (int i = 0; i < 12; i++) {
            nonce[i] = (byte) (bytes[i] ^ bytes[i + 12] ^ (i * 31));
        }
        return nonce;
    }

    /** ChaCha20 (20 rounds, 32-bit counter starting at 1) mirroring the string layer. */
    private static byte[] chacha20(byte[] key, byte[] nonce, byte[] data) {
        byte[] out = data.clone();
        int[] state = new int[16];
        int[] working = new int[16];
        int[] block = new int[16];
        try {
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;
            for (int i = 0; i < 8; i++) {
                state[4 + i] = readIntLE(key, i * 4);
            }
            state[12] = 1;
            state[13] = readIntLE(nonce, 0);
            state[14] = readIntLE(nonce, 4);
            state[15] = readIntLE(nonce, 8);
            for (int offset = 0; offset < out.length; offset += 64) {
                System.arraycopy(state, 0, working, 0, 16);
                for (int round = 0; round < 10; round++) {
                    quarterRound(working, 0, 4, 8, 12);
                    quarterRound(working, 1, 5, 9, 13);
                    quarterRound(working, 2, 6, 10, 14);
                    quarterRound(working, 3, 7, 11, 15);
                    quarterRound(working, 0, 5, 10, 15);
                    quarterRound(working, 1, 6, 11, 12);
                    quarterRound(working, 2, 7, 8, 13);
                    quarterRound(working, 3, 4, 9, 14);
                }
                for (int i = 0; i < 16; i++) {
                    block[i] = working[i] + state[i];
                }
                int length = Math.min(64, out.length - offset);
                for (int i = 0; i < length; i++) {
                    out[offset + i] ^= (byte) (block[i >>> 2] >>> (8 * (i & 3)));
                }
                state[12]++;
            }
            return out;
        } finally {
            Arrays.fill(working, 0);
            Arrays.fill(block, 0);
            Arrays.fill(state, 0);
        }
    }

    private static void quarterRound(int[] x, int a, int b, int c, int d) {
        x[a] += x[b];
        x[d] = Integer.rotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = Integer.rotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = Integer.rotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = Integer.rotateLeft(x[b] ^ x[c], 7);
    }

    private static int readIntLE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }
}
