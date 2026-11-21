package io.umbra.core.jni.payload;

import java.io.ByteArrayOutputStream;

/**
 * Minimal LZMA2 encoder: <em>stored</em> chunks only.
 *
 * <p>LZMA2 defines two chunk kinds: a range-coded LZMA chunk and a stored chunk
 * (control 2, or control 1 when it also resets the dictionary). An encoder that
 * only emits stored chunks is a valid LZMA2 producer, needs no match finder and
 * no range encoder, and its output is decoded byte-for-byte by any conforming
 * decoder, including {@link Lzma2Stream} and {@code xz -d --format=raw}.</p>
 *
 * <p>Format produced (per chunk of at most 65536 bytes, first chunk resets the
 * dictionary):</p>
 *
 * <pre>
 *   0x01 | (n-1)&gt;&gt;8 | (n-1)&amp;0xFF | n literal bytes     (first chunk)
 *   0x02 | (n-1)&gt;&gt;8 | (n-1)&amp;0xFF | n literal bytes     (later chunks)
 *   0x00                                                (end marker)
 * </pre>
 *
 * <p>Stored chunks do not shrink the payload; the jar entry still goes through
 * zip deflate. The container is what changes: one stream, platform slices by
 * offset. Real compression needs an LZMA match encoder, which is deliberately
 * not faked here.</p>
 */
public final class Lzma2Writer {

    /** LZMA2's stored-chunk limit: 16-bit size field plus one. */
    public static final int MAX_STORED_CHUNK = 65536;

    private Lzma2Writer() {
    }

    public static byte[] encode(byte[] raw) {
        if (raw == null) {
            throw new NullPointerException("raw");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(
                raw.length + (raw.length / MAX_STORED_CHUNK + 1) * 3 + 1);
        int offset = 0;
        boolean first = true;
        while (offset < raw.length) {
            int n = Math.min(MAX_STORED_CHUNK, raw.length - offset);
            out.write(first ? 1 : 2);
            out.write((n - 1) >>> 8);
            out.write((n - 1) & 0xFF);
            out.write(raw, offset, n);
            offset += n;
            first = false;
        }
        out.write(0);
        return out.toByteArray();
    }
}
