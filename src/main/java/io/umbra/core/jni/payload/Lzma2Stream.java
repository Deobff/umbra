package io.umbra.core.jni.payload;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Read-only decoder for a raw LZMA2 stream (the format produced by
 * {@code xz --format=raw --lzma2}, i.e. no container header at all).
 *
 * <p>Ported from the reference implementation's {@code JNICLoader}, which is the
 * only piece of that project that actually runs inside a protected program. The
 * chunk framing is the whole format:</p>
 *
 * <pre>
 * control byte c
 *   c == 0                 end of stream
 *   c == 1 or c &gt;= 224     reset properties and dictionary, then a chunk
 *   c &gt;= 128              LZMA chunk: (c &amp; 0x1F) &lt;&lt; 16 | u16 + 1 output bytes,
 *                          u16 + 1 compressed bytes, optional props byte
 *   c == 2                 stored chunk: u16 + 1 literal bytes, no reset
 * </pre>
 *
 * <p>An LZMA chunk body is {@code props?}, one byte that must be zero, four
 * big-endian code bytes, then {@code compressedSize - 5} bytes of range-coder
 * input stored end-aligned in a 65531-byte buffer.</p>
 */
public final class Lzma2Stream extends InputStream {

    /** Same default as the the reference implementation loader: 16 MiB, rounded to a multiple of 16. */
    public static final int DEFAULT_DICT_SIZE = 0x1000000;

    private final DataInputStream in;
    private final LzDictionary lz;
    private final ByteBufferRangeSource rc = new ByteBufferRangeSource();
    private final byte[] one = new byte[1];

    private LzmaDecoder lzma;
    private int uncompressedSize;
    private boolean lzmaChunk;
    private boolean needDictReset = true;
    private boolean needProps = true;
    private boolean endReached;
    private IOException failure;

    public Lzma2Stream(InputStream in) {
        this(in, DEFAULT_DICT_SIZE);
    }

    public Lzma2Stream(InputStream in, int dictSize) {
        if (in == null) {
            throw new NullPointerException("in");
        }
        if (dictSize < 4096 || dictSize > 0x7FFFFFF0) {
            throw new IllegalArgumentException("dictionary size out of range: " + dictSize);
        }
        this.in = new DataInputStream(in);
        this.lz = new LzDictionary((dictSize + 15) & 0xFFFFFFF0);
    }

    @Override
    public int read() throws IOException {
        if (read(this.one, 0, 1) == -1) {
            return -1;
        }
        return this.one[0] & 0xFF;
    }

    @Override
    public int read(byte[] buf, int off, int len) throws IOException {
        if (off < 0 || len < 0 || off + len < 0 || off + len > buf.length) {
            throw new IndexOutOfBoundsException();
        }
        if (len == 0) {
            return 0;
        }
        if (this.failure != null) {
            throw this.failure;
        }
        if (this.endReached) {
            return -1;
        }
        try {
            int size = 0;
            while (len > 0) {
                if (this.uncompressedSize == 0) {
                    decodeChunkHeader();
                    if (this.endReached) {
                        return size == 0 ? -1 : size;
                    }
                }
                int copySizeMax = Math.min(this.uncompressedSize, len);
                if (!this.lzmaChunk) {
                    int n = Math.min(this.lz.size - this.lz.pos, copySizeMax);
                    this.in.readFully(this.lz.buf, this.lz.pos, n);
                    this.lz.pos += n;
                    if (this.lz.full < this.lz.pos) {
                        this.lz.full = this.lz.pos;
                    }
                } else {
                    if (this.lz.size - this.lz.pos <= copySizeMax) {
                        this.lz.limit = this.lz.size;
                    } else {
                        this.lz.limit = this.lz.pos + copySizeMax;
                    }
                    this.lzma.decode();
                }
                int copied = this.lz.pos - this.lz.start;
                if (this.lz.pos == this.lz.size) {
                    this.lz.pos = 0;
                }
                System.arraycopy(this.lz.buf, this.lz.start, buf, off, copied);
                this.lz.start = this.lz.pos;
                off += copied;
                len -= copied;
                size += copied;
                this.uncompressedSize -= copied;
                if (this.uncompressedSize == 0
                        && (this.rc.pos != this.rc.buf.length || this.rc.code != 0
                        || this.lz.pendingLen > 0)) {
                    throw new IOException("lzma: chunk did not consume its range input");
                }
            }
            return size;
        } catch (IOException e) {
            this.failure = e;
            throw e;
        }
    }

    private void decodeChunkHeader() throws IOException {
        int control = this.in.readUnsignedByte();
        if (control == 0) {
            this.endReached = true;
            return;
        }
        if (control >= 224 || control == 1) {
            this.needProps = true;
            this.needDictReset = false;
            this.lz.start = 0;
            this.lz.pos = 0;
            this.lz.full = 0;
            this.lz.limit = 0;
            this.lz.buf[this.lz.size - 1] = 0;
        } else if (this.needDictReset) {
            throw new IOException("lzma: first chunk must reset the dictionary");
        }
        if (control >= 128) {
            this.lzmaChunk = true;
            this.uncompressedSize = (control & 0x1F) << 16;
            this.uncompressedSize += this.in.readUnsignedShort() + 1;
            int compressedSize = this.in.readUnsignedShort() + 1;
            if (control >= 192) {
                this.needProps = false;
                decodeProps();
            } else {
                if (this.needProps) {
                    throw new IOException("lzma: chunk needs properties first");
                }
                if (control >= 160 && this.lzma != null) {
                    this.lzma.reset();
                }
            }
            if (compressedSize < 5) {
                throw new IOException("lzma: compressed chunk smaller than its header");
            }
            if (this.in.readUnsignedByte() != 0) {
                throw new IOException("lzma: reserved chunk byte is not zero");
            }
            this.rc.code = this.in.readInt();
            this.rc.range = -1;
            int remaining = compressedSize - 5;
            this.rc.pos = this.rc.buf.length - remaining;
            this.in.readFully(this.rc.buf, this.rc.pos, remaining);
        } else {
            if (control > 2) {
                throw new IOException("lzma: unknown control byte " + control);
            }
            this.lzmaChunk = false;
            this.uncompressedSize = this.in.readUnsignedShort() + 1;
        }
    }

    private void decodeProps() throws IOException {
        int props = this.in.readUnsignedByte();
        if (props > 224) {
            throw new IOException("lzma: invalid properties byte " + props);
        }
        int pb = props / 45;
        props -= pb * 9 * 5;
        int lp = props / 9;
        int lc = props - lp * 9;
        if (lc + lp > 4) {
            throw new IOException("lzma: lc + lp above 4");
        }
        this.lzma = new LzmaDecoder(this.lz, this.rc, lc, lp, pb);
    }

    @Override
    public int available() throws IOException {
        return this.lzmaChunk ? this.uncompressedSize
                : Math.min(this.uncompressedSize, this.in.available());
    }

    @Override
    public void close() throws IOException {
        this.in.close();
    }
}
