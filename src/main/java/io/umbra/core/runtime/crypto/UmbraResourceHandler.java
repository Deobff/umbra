package io.umbra.core.runtime.crypto;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

/**
 * URLStreamHandler that serves decrypted resources from an encrypted archive.
 *
 * <p>Runtime template: a separate top-level class because nested/anonymous
 * classes are not allowed in templates. The loader creates
 * {@code new URL("umbra", "r", -1, encodedName, new UmbraResourceHandler(this))}
 * so {@code getResource(...)} returns a URL whose {@code openStream()} /
 * {@code openConnection()} decrypt the payload on demand - no plaintext is
 * ever written to disk.</p>
 */
public final class UmbraResourceHandler extends URLStreamHandler {

    private final UmbraClassLoader owner;

    public UmbraResourceHandler(UmbraClassLoader owner) {
        this.owner = owner;
    }

    @Override
    protected URLConnection openConnection(URL url) throws IOException {
        return new UmbraResourceConnection(url, owner);
    }

    @Override
    protected int getDefaultPort() {
        return -1;
    }
}
