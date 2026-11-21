package io.umbra.core.jni.payload;

import java.io.IOException;

/**
 * Binary range decoder for the LZMA probability model.
 *
 * <p>Ported from the reference implementation's {@code RangeDecoder}: the 11-bit
 * multiply, the 2048-total probability scale and the 5-bit adaptation shift are
 * the LZMA constants, so these numbers must not be "improved".</p>
 */
public abstract class RangeDecoder {

    public int range;
    public int code;

    public abstract void normalize() throws IOException;

    public final int decodeBit(short[] probs, int index) throws IOException {
        this.normalize();
        short prob = probs[index];
        int bound = (this.range >>> 11) * prob;
        if ((this.code ^ Integer.MIN_VALUE) < (bound ^ Integer.MIN_VALUE)) {
            this.range = bound;
            probs[index] = (short) (prob + ((2048 - prob) >>> 5));
            return 0;
        }
        this.range -= bound;
        this.code -= bound;
        probs[index] = (short) (prob - (prob >>> 5));
        return 1;
    }

    public final int decodeBitTree(short[] probs) throws IOException {
        int symbol = 1;
        do {
            symbol = (symbol << 1) | this.decodeBit(probs, symbol);
        } while (symbol < probs.length);
        return symbol - probs.length;
    }

    public final int decodeReverseBitTree(short[] probs) throws IOException {
        int symbol = 1;
        int i = 0;
        int result = 0;
        do {
            int bit = this.decodeBit(probs, symbol);
            symbol = (symbol << 1) | bit;
            result |= bit << i++;
        } while (symbol < probs.length);
        return result;
    }
}
