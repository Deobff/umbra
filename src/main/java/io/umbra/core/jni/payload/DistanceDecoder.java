package io.umbra.core.jni.payload;

/**
 * The {@code 1 << (lc + lp)} literal subcoders plus their reset.
 *
 * <p>the reference implementation names this class {@code DistanceDecoder} although it holds the
 * literal coders; the name is kept so the port stays line-by-line comparable.</p>
 */
final class DistanceDecoder extends DistanceParams {

    final BitTreeDecoder[] subcoders;
    final LzmaDecoder decoder;

    DistanceDecoder(LzmaDecoder decoder, int lc, int lp) {
        super(lc, lp);
        this.decoder = decoder;
        this.subcoders = new BitTreeDecoder[1 << (lc + lp)];
        for (int i = 0; i < this.subcoders.length; ++i) {
            this.subcoders[i] = new BitTreeDecoder(this);
        }
    }

    void reset() {
        for (BitTreeDecoder subcoder : this.subcoders) {
            subcoder.reset();
        }
    }
}
