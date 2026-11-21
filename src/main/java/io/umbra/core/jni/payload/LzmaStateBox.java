package io.umbra.core.jni.payload;

/** Mutable LZMA state index; a box because the decoder shares it across helpers. */
public final class LzmaStateBox {

    public int state;
}
