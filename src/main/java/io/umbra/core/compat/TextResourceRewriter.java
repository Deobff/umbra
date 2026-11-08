package io.umbra.core.compat;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Rewrites class names inside text resources that reference classes by name:
 *
 * <ul>
 *   <li>{@code META-INF/services/*} (file name and content, including the
 *       prefixed copy under {@code BOOT-INF/classes/} or {@code WEB-INF/classes/});</li>
 *   <li>{@code META-INF/spring.factories} and {@code META-INF/spring.handlers}
 *       (interfaces and implementations);</li>
 *   <li>{@code META-INF/spring/*.imports} (auto-configuration lists);</li>
 *   <li>{@code META-INF/native-image/**} JSON/properties configuration.</li>
 * </ul>
 *
 * <p>Names are replaced with a token scan, so the surrounding format (comments,
 * keys, JSON structure) is preserved byte-for-byte outside the replaced names.
 * Binary or non-UTF-8 resources are left untouched.</p>
 */
public final class TextResourceRewriter {

    public static final String SERVICES_PREFIX = "META-INF/services/";
    public static final String SPRING_FACTORIES = "META-INF/spring.factories";
    public static final String SPRING_HANDLERS = "META-INF/spring.handlers";
    public static final String SPRING_PREFIX = "META-INF/spring/";
    public static final String NATIVE_IMAGE_PREFIX = "META-INF/native-image/";

    private TextResourceRewriter() {
    }

    public static final class Result {
        private final String logicalName;
        private final byte[] bytes;
        private final boolean changed;

        Result(String logicalName, byte[] bytes, boolean changed) {
            this.logicalName = logicalName;
            this.bytes = bytes;
            this.changed = changed;
        }

        public String logicalName() {
            return logicalName;
        }

        public byte[] bytes() {
            return bytes;
        }

        public boolean changed() {
            return changed;
        }
    }

    public static boolean handles(String logicalName) {
        if (logicalName == null) {
            return false;
        }
        if (logicalName.startsWith(SERVICES_PREFIX)) {
            return true;
        }
        if (SPRING_FACTORIES.equals(logicalName) || SPRING_HANDLERS.equals(logicalName)) {
            return true;
        }
        if (logicalName.startsWith(SPRING_PREFIX) && logicalName.endsWith(".imports")) {
            return true;
        }
        return logicalName.startsWith(NATIVE_IMAGE_PREFIX);
    }

    public static Result rewrite(String logicalName, byte[] bytes, ClassRenameMap rename) {
        if (bytes == null || rename == null || rename.isEmpty() || !handles(logicalName)) {
            return new Result(logicalName, bytes, false);
        }
        String text = decodeUtf8(bytes);
        if (text == null) {
            return new Result(logicalName, bytes, false);
        }
        String rewritten = rename.rewriteDottedNames(text);
        String newName = logicalName;
        if (logicalName.startsWith(SERVICES_PREFIX)) {
            String service = logicalName.substring(SERVICES_PREFIX.length());
            if (service.indexOf('/') < 0) {
                newName = SERVICES_PREFIX + rename.mapDotted(service);
            }
        }
        if (rewritten.equals(text) && newName.equals(logicalName)) {
            return new Result(logicalName, bytes, false);
        }
        return new Result(newName, rewritten.getBytes(StandardCharsets.UTF_8), true);
    }

    static String decodeUtf8(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return bytes == null ? null : "";
        }
        for (byte b : bytes) {
            if (b == 0) {
                return null;
            }
        }
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            CharBuffer decoded = decoder.decode(ByteBuffer.wrap(bytes));
            return decoded.toString();
        } catch (CharacterCodingException notText) {
            return null;
        }
    }
}
