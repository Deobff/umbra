package io.umbra.core.jni.payload;

/** Literal context parameters: {@code lc} literal bits and the {@code lp} position mask. */
abstract class DistanceParams {

    final int lc;
    final int posMask;

    DistanceParams(int lc, int lp) {
        this.lc = lc;
        this.posMask = (1 << lp) - 1;
    }
}
