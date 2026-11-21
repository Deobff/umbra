package io.umbra.core.jni.payload;

import java.util.Arrays;

/** One literal subcoder: 768 probabilities, i.e. a full 8-bit bit-tree with context. */
abstract class LiteralModel {

    final short[] probs = new short[768];

    final void reset() {
        Arrays.fill(this.probs, (short) 1024);
    }
}
