package io.umbra.core.pass.impl.noise;

import org.objectweb.asm.Attribute;
import org.objectweb.asm.ByteVector;
import org.objectweb.asm.ClassWriter;

/**
 * A class-file attribute with an arbitrary name and payload.
 *
 * <p>The JVM ignores attributes it does not define (JVMS 4.7), so this is the
 * carrier for all custom noise. Instances are pure data: they are never read
 * back from bytes (Umbra's class reader drops unknown attributes), only written
 * into the output.</p>
 */
public final class NoiseAttribute extends Attribute {

    private final byte[] payload;

    public NoiseAttribute(String name, byte[] payload) {
        super(name == null || name.isEmpty() ? "Noise" : name);
        this.payload = payload == null ? new byte[0] : payload;
    }

    /** Payload length in bytes, used for budget accounting. */
    public int payloadLength() {
        return payload.length;
    }

    @Override
    protected ByteVector write(ClassWriter classWriter, byte[] code, int codeLength,
                               int maxStack, int maxLocals) {
        return new ByteVector().putByteArray(payload, 0, payload.length);
    }
}
