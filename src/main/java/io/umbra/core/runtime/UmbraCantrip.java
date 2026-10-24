package io.umbra.core.runtime;

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
}
