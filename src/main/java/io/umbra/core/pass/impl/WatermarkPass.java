package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.model.ClassPool;
import io.umbra.core.util.Cipher;
import io.umbra.core.util.Jars;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Embeds a deterministic, vendor-neutral watermark.
 *
 * <p>A protected archive must not advertise the tool that produced it: earlier
 * versions wrote {@code Umbra-Watermark: UMBRA|<id>|1.0.0|seed=<hex>} and
 * {@code Umbra-Version} into the output manifest, plus a
 * {@code Created-By: Umbra 1.0.0} attribute. That handed an analyst the tool
 * name, its version and the build seed (which drives class naming), so the
 * manifest is now left untouched by default. {@code watermark.manifest=true}
 * restores a <em>neutral</em> {@code Build-Marker} attribute for deployments
 * that must trace leaks; the marker itself never contains the seed.</p>
 *
 * <p>{@code watermark.blind} (default true) stops writing the marker as a
 * synthetic field constant, which {@code javap} prints and one ASM pass deletes.
 * The digest is XORed with a per-build keystream derived through
 * {@link Cipher#hmacSha256(byte[], byte[])} and split into four fragments that
 * only exist as {@code LDC <fragment>}{@code POP} pairs inside synthetic methods
 * nobody calls; each pair is surrounded by decoy {@code LineNumberTable} entries
 * whose count encodes the fragment index. The cleared payload never appears as a
 * readable string, and a single fragment is meaningless on its own.
 * {@code watermark.blind=false} keeps the old field form, which
 * {@code WatermarkTracer} still recognises.</p>
 */
public final class WatermarkPass implements Pass {

    public static final String MARKER_PREFIX = "wm1|";

    public static final String MANIFEST_ATTRIBUTE = "Build-Marker";

    public static final String BLIND_KEY = "watermark.blind";

    public static final String FRAGMENTS_STAT = "watermark.fragments";

    public static final int FRAGMENT_COUNT = 4;

    public static final int HINT_INDEX = 4;

    public static final int MIN_LINE_NUMBERS = 2;

    private static final String BLIND_LABEL = "wm-blind";

    private static final String HINT_LABEL = "umbra.watermark.hint";

    private static final int FRAGMENT_CLASSES = 4;

    private static final long NAME_SALT = 0x574D424C2D31L;

    private static final long STREAM_SALT = 0x6A09E667F3BCC909L;

    @Override
    public String name() {
        return "watermark";
    }

    @Override
    public int order() {
        return 110;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().watermark().enabled();
    }

    @Override
    public void run(PassContext context) {
        byte[] digest = digest(context);
        String payload = MARKER_PREFIX + Cipher.hex(digest);
        boolean blind = context.config().optionBool(BLIND_KEY, true);
        String location = null;
        int fragments = 0;
        if (blind) {
            try {
                List<ClassNode> pool = targets(context.classes());
                Random blindRandom = new Random(context.config().seed() ^ NAME_SALT);
                boolean reproducible = !context.config().preserveTimestamps();
                int injected = WmBlind.inject(pool, context.config().watermark().id(),
                        context.config().seed(), blindRandom, WmBlind.INJECT_TIMES, reproducible);
                if (injected > 0) {
                    location = pool.isEmpty() ? null : "rsa-blind x" + injected;
                    fragments = injected;
                }
            } catch (Exception blindFailure) {
                context.log().warn("watermark: RSA-blind injection failed (%s); "
                        + "falling back to the field marker", blindFailure.getMessage());
            }
        }
        if (location == null) {
            blind = false;
            location = context.runtime().embedWatermark(context.classes(), payload);
        }
        context.stats().add(BLIND_KEY, blind ? 1 : 0);
        context.stats().add(FRAGMENTS_STAT, fragments);

        if (context.config().optionBool("watermark.manifest", false)) {
            writeManifestMarker(context, payload);
        }

        context.stats().add("watermark.embedded", 1);
        context.log().info("watermark: embedded in %s",
                location == null ? "no location" : location);
    }

    static String payload(PassContext context) {
        return MARKER_PREFIX + Cipher.hex(digest(context));
    }

    static byte[] digest(PassContext context) {
        String id = context.config().watermark().id();
        if (id == null) {
            id = "";
        }
        byte[] message = (id + "|" + context.config().seed()).getBytes(StandardCharsets.UTF_8);
        byte[] key = watermarkKey(context);
        byte[] hash;
        int bytes;
        if (key != null) {
            hash = Cipher.hmacSha256(key, message);
            bytes = 16;
        } else {
            hash = Cipher.sha256(("build|" + context.config().seed())
                    .getBytes(StandardCharsets.UTF_8));
            bytes = 8;
            context.log().warn("watermark: no watermark.key is set, so the marker is a build "
                    + "fingerprint only and carries no customer id; set "
                    + "watermark.key=<base64 32 bytes> to enable leak tracing");
            context.stats().add("watermark.keyed", 0);
        }
        if (key != null) {
            context.stats().add("watermark.keyed", 1);
        }
        return Cipher.first(hash, bytes);
    }

    public static byte[] keystream(long seed, int length) {
        byte[] key = Cipher.hmacSha256(Cipher.le64(seed ^ STREAM_SALT), Cipher.utf8(BLIND_LABEL));
        return Cipher.first(key, length);
    }

    public static byte[] hintMask(int length) {
        return Cipher.first(Cipher.sha256(Cipher.utf8(HINT_LABEL)), length);
    }

    private static String embedBlind(PassContext context, byte[] digest) {
        List<ClassNode> targets = targets(context.classes());
        if (targets.isEmpty()) {
            return null;
        }
        byte[] stream = keystream(context.config().seed(), digest.length);
        List<String> fragments = split(xor(digest, stream));
        fragments.add(Cipher.hex(xor(stream, hintMask(digest.length))));
        Random random = new Random(context.config().seed() ^ NAME_SALT);
        String location = null;
        for (int i = 0; i < fragments.size(); i++) {
            ClassNode target = targets.get(i % targets.size());
            String name = uniqueName(target, random);
            target.methods.add(fragmentMethod(name, fragments.get(i), i, random));
            if (location == null) {
                location = target.name + "." + name;
            }
        }
        return location;
    }

    private static List<ClassNode> targets(ClassPool pool) {
        List<String> names = new ArrayList<String>(pool.classes().keySet());
        Collections.sort(names);
        List<ClassNode> targets = new ArrayList<ClassNode>(FRAGMENT_CLASSES);
        for (String name : names) {
            ClassNode node = pool.getClass(name);
            if (node == null || node.name == null || "module-info".equals(node.name)) {
                continue;
            }
            if (pool.isGenerated(node.name) || pool.isFrozen(node.name)) {
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION
                    | Opcodes.ACC_MODULE)) != 0) {
                continue;
            }
            targets.add(node);
            if (targets.size() >= FRAGMENT_CLASSES) {
                break;
            }
        }
        return targets;
    }

    private static List<String> split(byte[] data) {
        int part = Math.max(1, data.length / FRAGMENT_COUNT);
        List<String> fragments = new ArrayList<String>(FRAGMENT_COUNT);
        for (int i = 0; i < FRAGMENT_COUNT; i++) {
            byte[] slice = new byte[part];
            System.arraycopy(data, i * part, slice, 0, part);
            fragments.add(Cipher.hex(slice));
        }
        return fragments;
    }

    private static byte[] xor(byte[] left, byte[] right) {
        byte[] out = new byte[left.length];
        for (int i = 0; i < left.length; i++) {
            out[i] = (byte) (left[i] ^ right[i]);
        }
        return out;
    }

    private static MethodNode fragmentMethod(String name, String fragment, int index,
                                             Random random) {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, "()V", null, null);
        InsnList insns = method.instructions;
        LabelNode start = new LabelNode();
        insns.add(start);
        int lines = MIN_LINE_NUMBERS + index;
        for (int i = 0; i < lines; i++) {
            insns.add(new LineNumberNode(random.nextInt(9000) + 1, start));
        }
        insns.add(new LdcInsnNode(fragment));
        insns.add(new InsnNode(Opcodes.POP));
        LabelNode end = new LabelNode();
        insns.add(end);
        insns.add(new LineNumberNode(random.nextInt(9000) + 1, end));
        insns.add(new InsnNode(Opcodes.RETURN));
        method.maxStack = 1;
        method.maxLocals = 0;
        return method;
    }

    private static String uniqueName(ClassNode node, Random random) {
        Set<String> taken = new HashSet<String>();
        for (MethodNode method : node.methods) {
            taken.add(method.name + method.desc);
        }
        String candidate;
        do {
            candidate = "z$" + Integer.toHexString(random.nextInt() & 0xFFFFFFF);
        } while (taken.contains(candidate + "()V"));
        return candidate;
    }

    private static byte[] watermarkKey(PassContext context) {
        String raw = context.config().option("watermark.key", "").trim();
        if (raw.isEmpty()) {
            return null;
        }
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(raw);
            if (decoded.length < 16) {
                throw new IllegalStateException("watermark.key must be at least 16 bytes");
            }
            return decoded;
        } catch (IllegalArgumentException malformed) {
            throw new IllegalStateException("watermark.key must be Base64-encoded", malformed);
        }
    }

    private static void writeManifestMarker(PassContext context, String payload) {
        ClassPool pool = context.classes();
        ClassPool.Resource manifest = pool.resource("META-INF/MANIFEST.MF");
        Map<String, String> attributes;
        long time = 0L;
        int method = Opcodes.ACC_PUBLIC;
        if (manifest != null) {
            attributes = new LinkedHashMap<String, String>(Jars.parseManifest(manifest.bytes()));
            time = manifest.time();
            method = manifest.method();
        } else {
            attributes = new LinkedHashMap<String, String>();
            attributes.put("Manifest-Version", "1.0");
        }
        attributes.put(MANIFEST_ATTRIBUTE, payload);
        pool.putResource("META-INF/MANIFEST.MF", Jars.writeManifest(attributes), time, method);
    }
}
