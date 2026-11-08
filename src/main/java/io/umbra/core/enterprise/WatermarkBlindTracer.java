package io.umbra.core.enterprise;

import io.umbra.core.pass.impl.WmChaCha20;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.ClassReader;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class WatermarkBlindTracer {

    private static final byte[] PRIVATE_KEY = new byte[]{0, -122, -24, -44, -63, -119, 6, -50, 1, -60, 78, 106, -12, -67, 5, -52, 42, 26, -97, -58, -24, -28, 84, 121, 59, 86, -74, 22, -26, -31, -94, 34, -99, 69, -49, 20, 0, 104, 54, -15, -125, -28, 36, 122, 125, 75, -7, -77, 40, -116, -39, 27, 36, 39, 13, 11, 16, -72, 117, -33, 21, 75, -74, -36, -54, 37, 32, 67, -123, -108, 73, -42, -37, 41, -109, 118, 74, -8, 61, 54, 0, 117, 36, 21, 37, 123, -51, 117, 27, 6, -15, -78, -104, 71, 14, -115, -12, 83, -83, -54, -125, -114, 89, 67, 50, -24, -73, -40, -73, -2, -19, -118, -91, 16, 71, 13, 27, -102, -48, -42, 79, 97, -60, 6, 42, -81, -74, 107, -77, -125, 115, 70, 97, 103, -48, 57, 75, 29, -63, 60, -25, -107, 24, -4, -58, -107, 125, -54, -21, -49, 27, 22, 57, -65, -56, 103, -125, 117, 77, -108, -24, 74, -5, 113, -113, 18, 124, -58, -109, -62, -106, -73, -59, 85, -23, 18, -16, 57, 78, 23, 109, 57, 124, -64, -127, -53, -37, -121, -54, 109, 25, -42, -7, 21, 70, -47, -27, -65, 56, 0, 4, 51, -86, 78, 101, 79, -18, -28, 120, -111, 69, 40, -111, -107, -104, 60, -93, 43, -120, 19, -99, -11, -105, -16, 90, 54, -81, 16, -123, 25, 25, -102, 16, 78, -82, 119, 112, -14, 73, 14, -115, 127, -46, 13, -12, -21, 26, -89, -63, 84, 50, -103, 14, 95, 33, 64, 1};

    private static final byte[] MODULES = new byte[]{0, -99, 82, 5, -109, -69, -32, 51, 126, 67, 127, 125, 30, -97, -86, -59, 81, 4, 3, 50, 15, 14, 61, -89, -46, 105, -102, 51, -118, 99, -22, 109, -93, 87, -82, -84, 57, -90, 106, -73, 20, -33, -42, -104, -30, -70, 4, 8, 39, -100, 106, 80, -60, 108, -52, -120, 94, 111, 9, -116, -57, -80, 110, -66, -47, 29, 59, 87, -117, 24, -5, 97, -66, 46, 90, -10, -34, 120, -12, -42, 43, 80, -99, 27, 33, -12, 13, 64, 20, 24, -28, 106, -71, -77, 43, 48, -7, -59, -125, 105, 13, 2, 56, -40, 103, 74, 100, 118, -39, -76, 46, -29, 86, 111, -45, -27, 25, -58, -33, 73, 54, -4, 21, -96, -112, -78, 51, 33, -10, -54, -111, -103, -15, -55, 110, -66, -127, -26, -122, 107, 44, 87, -66, 57, 29, 34, -53, 26, -89, -74, -68, -11, 81, 96, -114, 44, -72, -32, -101, 83, 22, -18, -115, 114, -86, 127, 0, -39, 63, 104, -53, -128, -4, -74, -127, -93, 98, -96, 33, -126, -75, 30, 16, -49, 26, 106, 49, -85, 74, -81, 10, -84, -13, -29, 96, -41, 120, -59, 37, 37, 111, -48, 33, -55, -35, -49, -33, 2, -117, -48, -6, -50, -63, -90, 3, -127, -85, 108, -71, -76, 17, -109, -6, -26, 60, -101, -65, 12, -9, -111, 35, 15, -45, 110, 11, 125, 30, -60, 99, -90, 77, 57, -128, 113, 11, -33, 25, -84, 20, -111, -5, 62, -118, 19, 39, 38, -37};

    private static final BigInteger EXP = new BigInteger(1, PRIVATE_KEY);

    private static final BigInteger MOD = new BigInteger(1, MODULES);

    private static final int PATTERN_LENGTH = 7;

    private WatermarkBlindTracer() {
    }

    public static Set<String> trace(java.nio.file.Path jar) throws IOException {
        Set<String> result = new LinkedHashSet<String>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }
                byte[] bytes;
                try (java.io.InputStream in = zip.getInputStream(entry)) {
                    bytes = readAll(in);
                }
                ClassNode node = new ClassNode();
                try {
                    new ClassReader(bytes).accept(node, ClassReader.SKIP_FRAMES);
                } catch (RuntimeException unreadable) {
                    continue;
                }
                for (MethodNode method : node.methods) {
                    String magic = matchMagic(method);
                    if (magic == null) {
                        continue;
                    }
                    try {
                        result.add(decrypt(magic));
                    } catch (RuntimeException unreadable) {
                    }
                }
            }
        }
        return result;
    }

    private static String matchMagic(MethodNode method) {
        AbstractInsnNode node = method.instructions.getFirst();
        LdcInsnNode target = null;
        int match = 0;
        while (match < PATTERN_LENGTH) {
            if (node == null) {
                return null;
            }
            switch (match) {
                case 0:
                    if (!(node instanceof LabelNode)) {
                        return null;
                    }
                    break;
                case 1:
                case 2:
                case 3:
                case 4:
                    if (!(node instanceof LineNumberNode)) {
                        return null;
                    }
                    break;
                case 5:
                    if (!(node instanceof LdcInsnNode)) {
                        return null;
                    }
                    target = (LdcInsnNode) node;
                    break;
                case 6:
                    if (!(node instanceof InsnNode)) {
                        return null;
                    }
                    break;
                default:
                    return null;
            }
            node = node.getNext();
            match++;
        }
        if (target == null || !(target.cst instanceof String)) {
            return null;
        }
        return (String) target.cst;
    }

    private static String decrypt(String origin) {
        try {
            byte[] src = origin.getBytes(StandardCharsets.ISO_8859_1);
            DataInputStream stream = new DataInputStream(new ByteArrayInputStream(src));
            int keyLength = stream.readInt();
            byte[] encodedKey = new byte[keyLength];
            stream.readFully(encodedKey);
            BigInteger iKey = new BigInteger(1, encodedKey);
            byte[] rawKey = iKey.modPow(EXP, MOD).toByteArray();
            byte[] key = new byte[32];
            int computedKeyLength = rawKey.length - 32;
            System.arraycopy(rawKey, Math.max(computedKeyLength, 0), key,
                    computedKeyLength < 0 ? -computedKeyLength : 0,
                    Math.min(32, 32 + computedKeyLength));
            int nonceLength = stream.readInt();
            byte[] encodedNonce = new byte[nonceLength];
            stream.readFully(encodedNonce);
            BigInteger iNonce = new BigInteger(1, encodedNonce);
            byte[] rawNonce = iNonce.modPow(EXP, MOD).toByteArray();
            byte[] nonce = new byte[8];
            int computedNonceLength = rawNonce.length - 8;
            System.arraycopy(rawNonce, Math.max(computedNonceLength, 0), nonce,
                    computedNonceLength < 0 ? -computedNonceLength : 0,
                    Math.min(8, 8 + computedNonceLength));
            int length = stream.readInt();
            byte[] encodedData = new byte[length];
            stream.readFully(encodedData);
            byte[] data = new byte[encodedData.length];
            WmChaCha20 crypto = new WmChaCha20(key, nonce, 0);
            crypto.decrypt(data, encodedData, data.length);
            return new String(data, StandardCharsets.UTF_8);
        } catch (IOException failure) {
            throw new RuntimeException(failure);
        } catch (WmChaCha20.WrongKeySizeException failure) {
            throw new RuntimeException(failure);
        } catch (WmChaCha20.WrongNonceSizeException failure) {
            throw new RuntimeException(failure);
        }
    }

    private static byte[] readAll(java.io.InputStream in) throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
}
