package io.umbra.core.jni.payload;

/** Literal subcoder of a {@link DistanceDecoder}, kept as a type for parity. */
final class BitTreeDecoder extends LiteralModel {

    final DistanceDecoder parent;

    BitTreeDecoder(DistanceDecoder parent) {
        this.parent = parent;
    }
}
