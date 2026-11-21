package io.umbra.core.jni.payload;

import java.io.IOException;

/**
 * Range-decoder input buffer.
 *
 * <p>The compressed remainder of a chunk is stored <em>end-aligned</em> in a
 * fixed 65531-byte buffer (LZMA2 caps a chunk at 64 KiB, and the first five
 * bytes, the header byte plus the four code bytes, are consumed separately), so
 * {@link #pos} starts at the buffer end and runs forward.</p>
 */
public final class ByteBufferRangeSource extends RangeDecoder {

    public final byte[] buf = new byte[65531];
    public int pos = this.buf.length;

    @Override
    public void normalize() throws IOException {
        if ((this.range & 0xFF000000) == 0) {
            if (this.pos >= this.buf.length) {
                throw new IOException("lzma: range coder overran the chunk");
            }
            this.code = (this.code << 8) | (this.buf[this.pos++] & 0xFF);
            this.range <<= 8;
        }
    }
}
