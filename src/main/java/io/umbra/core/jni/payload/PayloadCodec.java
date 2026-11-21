package io.umbra.core.jni.payload;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Payload encode/slice helpers used by the build side and by the tests.
 *
 * <p>The runtime loader carries its own tiny store-chunk decoder (it must stay a
 * single self-contained class), so this class exists to (a) produce the payload
 * and (b) decode it with the full ported decoder so both paths can be compared
 * byte for byte.</p>
 */
public final class PayloadCodec {

    private PayloadCodec() {
    }

    public static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    /** Decodes the whole stream with the full LZMA2 decoder. */
    public static byte[] decodeAll(byte[] payload) throws IOException {
        return decodeAll(payload, Lzma2Stream.DEFAULT_DICT_SIZE);
    }

    public static byte[] decodeAll(byte[] payload, int dictSize) throws IOException {
        Lzma2Stream stream = new Lzma2Stream(new ByteArrayInputStream(payload), dictSize);
        try {
            return readAll(stream);
        } finally {
            stream.close();
        }
    }

    /**
     * Extracts {@code [start, end)} from the decompressed payload.
     *
     * <p>Decoding stops after {@code end} bytes: the tail of the stream is never
     * touched, which is the whole point of the layout table.</p>
     */
    public static byte[] decodeSlice(byte[] payload, long start, long end) throws IOException {
        if (start < 0 || end < start) {
            throw new IllegalArgumentException("bad slice " + start + ".." + end);
        }
        Lzma2Stream stream = new Lzma2Stream(new ByteArrayInputStream(payload));
        try {
            long position = 0L;
            byte[] discard = new byte[8192];
            while (position < start) {
                long want = Math.min(discard.length, start - position);
                int read = stream.read(discard, 0, (int) want);
                if (read < 0) {
                    throw new IOException("payload ended before offset " + start);
                }
                position += read;
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.min(end - start, 1 << 20));
            byte[] buffer = new byte[8192];
            while (position < end) {
                int want = (int) Math.min(buffer.length, end - position);
                int read = stream.read(buffer, 0, want);
                if (read < 0) {
                    throw new IOException("payload ended at " + position + ", wanted " + end);
                }
                out.write(buffer, 0, read);
                position += read;
            }
            return out.toByteArray();
        } finally {
            stream.close();
        }
    }

    public static byte[] concat(java.util.List<byte[]> parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int cursor = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, cursor, part.length);
            cursor += part.length;
        }
        return out;
    }
}
