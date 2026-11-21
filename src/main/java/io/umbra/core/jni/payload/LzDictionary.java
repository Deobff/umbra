package io.umbra.core.jni.payload;

import java.io.IOException;

/**
 * LZMA match dictionary: a byte ring buffer that also hands out the already
 * decoded bytes a match copy refers to.
 *
 * <p>Ported from the reference implementation's {@code LzDictionary} (same field
 * layout and same wraparound copy). The preset-dictionary constructor was left
 * out: an LZMA2 stream always signals its own dictionary reset in the chunk
 * header, so nothing outside the stream seeds the dictionary.</p>
 */
public final class LzDictionary {

    public final byte[] buf;
    public final int size;
    public int start;
    public int pos;
    public int full;
    public int limit;
    public int pendingLen;
    public int pendingDist;

    public LzDictionary(int dictSize) {
        this.size = dictSize;
        this.buf = new byte[dictSize];
    }

    /** Byte at {@code dist} bytes behind the write head. */
    public int getByte(int dist) {
        int offset = this.pos - dist - 1;
        if (dist >= this.pos) {
            offset += this.size;
        }
        return this.buf[offset] & 0xFF;
    }

    /**
     * Copies {@code len} bytes from {@code dist} behind the write head, stopping
     * at {@link #limit}; the remainder is remembered in
     * {@link #pendingLen}/{@link #pendingDist} and finishes on the next call.
     */
    public void repeat(int dist, int len) throws IOException {
        if (dist < 0 || dist >= this.full) {
            throw new IOException("lzma: match distance " + dist + " outside " + this.full);
        }
        int left = Math.min(this.limit - this.pos, len);
        this.pendingLen = len - left;
        this.pendingDist = dist;
        int back = this.pos - dist - 1;
        if (back < 0) {
            if (this.full != this.size) {
                throw new IOException("lzma: dictionary wrap before full");
            }
            back += this.size;
            int copySize = Math.min(this.size - back, left);
            if (copySize > dist + 1) {
                throw new IOException("lzma: overlapping wrap copy");
            }
            System.arraycopy(this.buf, back, this.buf, this.pos, copySize);
            this.pos += copySize;
            back = 0;
            left -= copySize;
            if (left == 0) {
                return;
            }
        }
        if (back >= this.pos || left <= 0) {
            throw new IOException("lzma: corrupt match copy");
        }
        do {
            int copySize = Math.min(left, this.pos - back);
            System.arraycopy(this.buf, back, this.buf, this.pos, copySize);
            this.pos += copySize;
            left -= copySize;
        } while (left > 0);
        if (this.full < this.pos) {
            this.full = this.pos;
        }
    }
}
