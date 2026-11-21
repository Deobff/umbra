package io.umbra.core.jni.payload;

import java.util.Arrays;

/**
 * Probability tables of the LZMA model (12 states, 16 position states per
 * {@code pb}, 4 distance slots) with the LZMA initial value 1024.
 *
 * <p>Ported verbatim from the reference implementation's {@code LzmaState}; the
 * table shapes are fixed by the LZMA bitstream format.</p>
 */
abstract class LzmaState {

    final int posMask;
    final int[] reps = new int[4];
    final LzmaStateBox state = new LzmaStateBox();
    final short[][] isMatch = new short[12][16];
    final short[] isRep = new short[12];
    final short[] isRep0 = new short[12];
    final short[] isRep1 = new short[12];
    final short[] isRep2 = new short[12];
    final short[][] isRep0Long = new short[12][16];
    final short[][] distSlots = new short[4][64];
    final short[][] distSpecial = new short[][]{
            new short[2], new short[2], new short[4], new short[4],
            new short[8], new short[8], new short[16], new short[16],
            new short[32], new short[32]
    };
    final short[] distAlign = new short[16];

    LzmaState(int pb) {
        this.posMask = (1 << pb) - 1;
    }

    void reset() {
        Arrays.fill(this.reps, 0);
        this.state.state = 0;
        for (short[] row : this.isMatch) {
            Arrays.fill(row, (short) 1024);
        }
        Arrays.fill(this.isRep, (short) 1024);
        Arrays.fill(this.isRep0, (short) 1024);
        Arrays.fill(this.isRep1, (short) 1024);
        Arrays.fill(this.isRep2, (short) 1024);
        for (short[] row : this.isRep0Long) {
            Arrays.fill(row, (short) 1024);
        }
        for (short[] row : this.distSlots) {
            Arrays.fill(row, (short) 1024);
        }
        for (short[] row : this.distSpecial) {
            Arrays.fill(row, (short) 1024);
        }
        Arrays.fill(this.distAlign, (short) 1024);
    }
}
