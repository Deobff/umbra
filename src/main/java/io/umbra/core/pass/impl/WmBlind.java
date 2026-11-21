package io.umbra.core.pass.impl;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

public final class WmBlind {

    public static final byte[] PUBLIC_KEY = new byte[]{1, 0, 1};

    public static final byte[] MODULES = new byte[]{0, -99, 82, 5, -109, -69, -32, 51, 126, 67, 127, 125, 30, -97, -86, -59, 81, 4, 3, 50, 15, 14, 61, -89, -46, 105, -102, 51, -118, 99, -22, 109, -93, 87, -82, -84, 57, -90, 106, -73, 20, -33, -42, -104, -30, -70, 4, 8, 39, -100, 106, 80, -60, 108, -52, -120, 94, 111, 9, -116, -57, -80, 110, -66, -47, 29, 59, 87, -117, 24, -5, 97, -66, 46, 90, -10, -34, 120, -12, -42, 43, 80, -99, 27, 33, -12, 13, 64, 20, 24, -28, 106, -71, -77, 43, 48, -7, -59, -125, 105, 13, 2, 56, -40, 103, 74, 100, 118, -39, -76, 46, -29, 86, 111, -45, -27, 25, -58, -33, 73, 54, -4, 21, -96, -112, -78, 51, 33, -10, -54, -111, -103, -15, -55, 110, -66, -127, -26, -122, 107, 44, 87, -66, 57, 29, 34, -53, 26, -89, -74, -68, -11, 81, 96, -114, 44, -72, -32, -101, 83, 22, -18, -115, 114, -86, 127, 0, -39, 63, 104, -53, -128, -4, -74, -127, -93, 98, -96, 33, -126, -75, 30, 16, -49, 26, 106, 49, -85, 74, -81, 10, -84, -13, -29, 96, -41, 120, -59, 37, 37, 111, -48, 33, -55, -35, -49, -33, 2, -117, -48, -6, -50, -63, -90, 3, -127, -85, 108, -71, -76, 17, -109, -6, -26, 60, -101, -65, 12, -9, -111, 35, 15, -45, 110, 11, 125, 30, -60, 99, -90, 77, 57, -128, 113, 11, -33, 25, -84, 20, -111, -5, 62, -118, 19, 39, 38, -37};

    public static final int INJECT_TIMES = 3;

    private WmBlind() {
    }

    public static byte[] createMagicInformation(String text, Random random, boolean reproducible)
            throws Exception {
        BigInteger exp = new BigInteger(1, PUBLIC_KEY);
        BigInteger mod = new BigInteger(1, MODULES);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataOutputStream stream = new DataOutputStream(output);
        byte[] src = text.getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[32];
        byte[] nonce = new byte[8];
        // Both paths now draw from the caller's seed-derived Random. The
        // "fresh randomness per build" behaviour came from an unseeded
        // SecureRandom, which also broke reproducibility for a pinned seed; a
        // build only looks different because the CLI draws a new seed unless
        // --seed pins one.
        random.nextBytes(key);
        random.nextBytes(nonce);
        BigInteger iKey = new BigInteger(1, key);
        BigInteger iNonce = new BigInteger(1, nonce);
        byte[] encodedKey = iKey.modPow(exp, mod).toByteArray();
        byte[] encodedNonce = iNonce.modPow(exp, mod).toByteArray();
        WmChaCha20 crypto = new WmChaCha20(key, nonce, 0);
        byte[] encodedData = new byte[src.length];
        crypto.encrypt(encodedData, src, src.length);
        stream.writeInt(encodedKey.length);
        stream.write(encodedKey, 0, encodedKey.length);
        stream.writeInt(encodedNonce.length);
        stream.write(encodedNonce, 0, encodedNonce.length);
        stream.writeInt(encodedData.length);
        stream.write(encodedData, 0, encodedData.length);
        stream.flush();
        return output.toByteArray();
    }

    public static String buildWatermarking(String id, long seed, boolean reproducible) {
        StringBuilder builder = new StringBuilder();
        builder.append("build-time: ")
                .append(new SimpleDateFormat("yyyy-MM-dd-HH:mm:ss")
                        .format(reproducible ? new Date(0L) : new Date()))
                .append('\n');
        builder.append("username: ").append(userName()).append('\n');
        builder.append("watermark: ").append(id == null ? "" : id).append('\n');
        builder.append("marker: ").append("wm1|").append(Long.toHexString(seed)).append('\n');
        builder.append("seed: ").append(Long.toHexString(seed));
        return builder.toString();
    }

    private static String userName() {
        String name = System.getProperty("user.name");
        return name == null ? "" : name;
    }

    public static int inject(List<ClassNode> wrappers, String id, long seed, Random random,
                             int times, boolean reproducible) throws Exception {
        if (wrappers.isEmpty()) {
            return 0;
        }
        List<ClassNode> pool = new ArrayList<ClassNode>(wrappers);
        Set<ClassNode> injected = new HashSet<ClassNode>();
        int count = 0;
        for (int i = 0; i < times; i++) {
            ClassNode cw = pool.get(random.nextInt(pool.size()));
            if (!injected.add(cw)) {
                continue;
            }
            MethodNode method = findOrCreateMethod(cw, random);
            String magic = new String(
                    createMagicInformation(buildWatermarking(id, seed, reproducible), random,
                            reproducible),
                    StandardCharsets.ISO_8859_1);
            InsnList list = new InsnList();
            LabelNode label = new LabelNode();
            list.add(label);
            list.add(new LineNumberNode(random.nextInt(), label));
            list.add(new LineNumberNode(random.nextInt(), label));
            list.add(new LineNumberNode(random.nextInt(), label));
            list.add(new LineNumberNode(random.nextInt(), label));
            list.add(new LdcInsnNode(magic));
            list.add(new InsnNode(Opcodes.POP));
            method.instructions.insert(list);
            count++;
        }
        return count;
    }

    private static MethodNode findOrCreateMethod(ClassNode cw, Random random) {
        List<MethodNode> filtered = new ArrayList<MethodNode>();
        for (MethodNode method : cw.methods) {
            if ((method.access & Opcodes.ACC_NATIVE) != 0
                    || (method.access & Opcodes.ACC_ABSTRACT) != 0) {
                continue;
            }
            filtered.add(method);
        }
        if (filtered.isEmpty()) {
            return orCreateClinit(cw);
        }
        return filtered.get(random.nextInt(filtered.size()));
    }

    private static MethodNode orCreateClinit(ClassNode cw) {
        for (MethodNode method : cw.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method;
            }
        }
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 0;
        clinit.maxStack = 1;
        cw.methods.add(clinit);
        return clinit;
    }

    public static boolean isWatermarkMethod(MethodNode method) {
        AbstractInsnNode insn = method.instructions.getFirst();
        int match = 0;
        int length = 7;
        AbstractInsnNode node = insn;
        while (match < length) {
            if (node == null) {
                return false;
            }
            switch (match) {
                case 0:
                    if (!(node instanceof LabelNode)) {
                        return false;
                    }
                    break;
                case 1:
                case 2:
                case 3:
                case 4:
                    if (!(node instanceof LineNumberNode)) {
                        return false;
                    }
                    break;
                case 5:
                    if (!(node instanceof LdcInsnNode)) {
                        return false;
                    }
                    break;
                case 6:
                    if (!(node instanceof InsnNode)) {
                        return false;
                    }
                    break;
                default:
                    return false;
            }
            node = node.getNext();
            match++;
        }
        return true;
    }
}
