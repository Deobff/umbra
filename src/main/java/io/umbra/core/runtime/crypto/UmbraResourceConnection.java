package io.umbra.core.runtime.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;

/**
 * URLConnection that lazily decrypts one encrypted resource payload.
 *
 * <p>Runtime template: a separate top-level class (no nested classes allowed, the
 * injected copy is a single class file).</p>
 *
 * <p><b>Residual-memory policy.</b> The decrypted bytes are never stored in a
 * field: {@link #getInputStream()} hands the caller a stream over a freshly
 * decrypted buffer (the stream owns it), and {@link #getContentLength()} decrypts
 * once, records the length and immediately wipes its copy. A process-memory dump
 * therefore cannot carve a long-lived plaintext resource out of this object.</p>
 */
public final class UmbraResourceConnection extends URLConnection {

    private final UmbraClassLoader owner;

    private int length = -1;

    public UmbraResourceConnection(URL url, UmbraClassLoader owner) {
        super(url);
        this.owner = owner;
    }

    @Override
    public void connect() {

    }

    @Override
    public InputStream getInputStream() throws IOException {
        return new ByteArrayInputStream(owner.resourceContent(url.getFile()));
    }

    @Override
    public int getContentLength() {
        if (length < 0) {
            byte[] probe = null;
            try {
                probe = owner.resourceContent(url.getFile());
                length = probe.length;
            } catch (IOException unreadable) {
                return -1;
            } finally {
                if (probe != null) {
                    Arrays.fill(probe, (byte) 0);
                }
            }
        }
        return length;
    }

    @Override
    public long getContentLengthLong() {
        return getContentLength();
    }

    @Override
    public String getContentType() {
        String name = url == null ? null : url.getFile();
        if (name == null) {
            return null;
        }
        int query = name.indexOf('?');
        if (query >= 0) {
            name = name.substring(0, query);
        }
        return guessContentTypeFromName(name);
    }
}
