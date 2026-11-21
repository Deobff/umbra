package io.umbra.core.jni.payload;

import java.io.IOException;

/** Decodes a match length: choice -> low (3 bits) / mid (3 bits) / high (8 bits). */
final class LengthDecoder extends LengthModel {

    private final LzmaDecoder decoder;

    LengthDecoder(LzmaDecoder decoder) {
        this.decoder = decoder;
    }

    int decode(int posState) throws IOException {
        if (this.decoder.rc.decodeBit(this.choice, 0) == 0) {
            return this.decoder.rc.decodeBitTree(this.low[posState]) + 2;
        }
        if (this.decoder.rc.decodeBit(this.choice, 1) == 0) {
            return this.decoder.rc.decodeBitTree(this.mid[posState]) + 2 + 8;
        }
        return this.decoder.rc.decodeBitTree(this.high) + 2 + 8 + 8;
    }
}
