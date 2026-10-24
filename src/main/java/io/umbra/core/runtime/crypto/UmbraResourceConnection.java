package io.umbra.core.runtime.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

/**
 * URLConnection that lazily decrypts one encrypted resource payload.
 *
 * <p>Runtime template: a separate top-level class (no nested classes allowed).
 * The buffer is decrypted on first connect and served through a
 * {@link ByteArrayInputStream}; content length and content type are exposed so
 * frameworks that probe the connection before reading keep working.</p>
 */
public final class UmbraResourceConnection extends URLConnection {

    private final UmbraClassLoader owner;
    private byte[] data;
    private boolean loaded;

    public UmbraResourceConnection(URL url, UmbraClassLoader owner) {
        super(url);
        this.owner = owner;
    }

    @Override
    public void connect() throws IOException {
        if (!loaded) {
            data = owner.resourceContent(url.getFile());
            loaded = true;
        }
    }

    @Override
    public InputStream getInputStream() throws IOException {
        connect();
        return new ByteArrayInputStream(data);
    }

    @Override
    public int getContentLength() {
        try {
            connect();
            return data.length;
        } catch (IOException unreadable) {
            return -1;
        }
    }

    @Override
    public long getContentLengthLong() {
        try {
            connect();
            return data.length;
        } catch (IOException unreadable) {
            return -1L;
        }
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
