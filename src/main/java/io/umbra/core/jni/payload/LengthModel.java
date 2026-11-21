package io.umbra.core.jni.payload;

import java.util.Arrays;

/** Low/mid/high length coder tables (3 + 3 + 8 bits) with LZMA's 1024 start. */
abstract class LengthModel {

    final short[] choice = new short[2];
    final short[][] low = new short[16][8];
    final short[][] mid = new short[16][8];
    final short[] high = new short[256];

    final void reset() {
        Arrays.fill(this.choice, (short) 1024);
        for (short[] row : this.low) {
            Arrays.fill(row, (short) 1024);
        }
        for (short[] row : this.mid) {
            Arrays.fill(row, (short) 1024);
        }
        Arrays.fill(this.high, (short) 1024);
    }
}
