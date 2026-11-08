package io.umbra.core.enterprise;

import io.umbra.core.util.Cipher;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Extracts watermark payloads from a protected JAR.
 *
 * <p>Current builds no longer leave a readable marker behind: the digest is
 * XORed with a per-build keystream and dropped into the constant pool as four
 * numbered fragments that only occur as {@code LDC <fragment>}{@code POP} pairs
 * inside synthetic methods, each guarded by decoy line numbers. The number of
 * line-number entries in front of a pair encodes its fragment index; index
 * {@code 4} holds the keystream hint. Tracing walks the code of every class,
 * regroups the fragments, undoes the XOR and prints the familiar
 * {@code wm1|<hex>} string.</p>
 *
 * <p>Artifacts produced by older builds are still recognised: they carry a
 * {@code wm1|<hex>} constant in a synthetic field and/or a
 * {@code Umbra-Watermark} manifest attribute, and pre-3.1 archives use an
 * {@code UMBRA|...} payload.</p>
 */
public final class WatermarkTracer {

    private static final String PREFIX = "wm1|";

    private static final String LEGACY_PREFIX = "UMBRA|";

    private static final int FRAGMENTS = 4;

    private static final int HINT_INDEX = 4;

    private static final int MIN_LINE_NUMBERS = 2;

    private static final String HINT_LABEL = "umbra.watermark.hint";

    private WatermarkTracer() {
    }

    public static List<String> trace(Path jar) throws IOException {
        Set<String> marks = new LinkedHashSet<String>();
        List<Fragment> fragments = new ArrayList<Fragment>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            ZipEntry manifest = zip.getEntry("META-INF/MANIFEST.MF");
            if (manifest != null) {
                try (InputStream in = zip.getInputStream(manifest)) {
                    Map<String, String> attributes = io.umbra.core.util.Jars.parseManifest(readAll(in));
                    report(marks, attributes.get("Build-Marker"));
                    report(marks, attributes.get("Umbra-Watermark"));
                }
            }
            java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }
                final String entryName = entry.getName();
                try (InputStream in = zip.getInputStream(entry)) {
                    ClassNode node = new ClassNode();
                    new ClassReader(readAll(in)).accept(node, 0);
                    collectFields(marks, entryName, node);
                    collectFragments(fragments, entryName, node);
                } catch (RuntimeException ignored) {

                }
            }
        }
        String reconstructed = reconstruct(fragments);
        if (reconstructed != null) {
            marks.add(reconstructed);
        }
        return new ArrayList<String>(marks);
    }

    private static void collectFields(Set<String> marks, String entryName, ClassNode node) {
        for (FieldNode field : node.fields) {
            if (!(field.value instanceof String)) {
                continue;
            }
            String text = (String) field.value;
            if (text.startsWith(PREFIX) || text.startsWith(LEGACY_PREFIX)) {
                marks.add(entryName + " " + node.name + "." + field.name + " = " + text);
            }
        }
    }

    private static void collectFragments(List<Fragment> fragments, String entryName,
                                         ClassNode node) {
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof LdcInsnNode)) {
                    continue;
                }
                Object constant = ((LdcInsnNode) insn).cst;
                if (!(constant instanceof String)) {
                    continue;
                }
                AbstractInsnNode next = insn.getNext();
                if (next == null || next.getOpcode() != Opcodes.POP) {
                    continue;
                }
                int index = lineNumbers(insn) - MIN_LINE_NUMBERS;
                if (index < 0 || index > HINT_INDEX) {
                    continue;
                }
                String hex = (String) constant;
                if (!isHex(hex)) {
                    continue;
                }
                fragments.add(new Fragment(entryName, node.name, method.name, index, hex));
            }
        }
    }

    private static int lineNumbers(AbstractInsnNode insn) {
        int count = 0;
        for (AbstractInsnNode previous = insn.getPrevious(); previous != null;
             previous = previous.getPrevious()) {
            if (!(previous instanceof LineNumberNode)) {
                break;
            }
            count++;
        }
        return count;
    }

    private static boolean isHex(String text) {
        if (text == null || text.isEmpty() || (text.length() & 1) != 0) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    private static String reconstruct(List<Fragment> fragments) {
        Set<Integer> lengths = new LinkedHashSet<Integer>();
        for (Fragment fragment : fragments) {
            if (fragment.index < FRAGMENTS) {
                lengths.add(Integer.valueOf(fragment.hex.length()));
            }
        }
        for (Integer length : lengths) {
            String[] parts = new String[FRAGMENTS];
            Fragment hint = null;
            Fragment first = null;
            for (Fragment fragment : fragments) {
                if (fragment.index == HINT_INDEX) {
                    if (hint == null && fragment.hex.length() == length.intValue() * 4) {
                        hint = fragment;
                    }
                    continue;
                }
                if (fragment.hex.length() != length.intValue()) {
                    continue;
                }
                if (parts[fragment.index] == null) {
                    parts[fragment.index] = fragment.hex;
                    if (fragment.index == 0) {
                        first = fragment;
                    }
                }
            }
            if (hint == null || first == null) {
                continue;
            }
            StringBuilder joined = new StringBuilder(length.intValue() * FRAGMENTS);
            boolean complete = true;
            for (int i = 0; i < FRAGMENTS; i++) {
                if (parts[i] == null) {
                    complete = false;
                    break;
                }
                joined.append(parts[i]);
            }
            if (!complete) {
                continue;
            }
            byte[] blinded = unhex(joined.toString());
            byte[] stream = xor(unhex(hint.hex), hintMask(blinded.length));
            String mark = PREFIX + Cipher.hex(xor(blinded, stream));
            return first.entryName + " " + first.className + "." + first.methodName
                    + " = " + mark;
        }
        return null;
    }

    private static byte[] hintMask(int length) {
        return Cipher.first(Cipher.sha256(Cipher.utf8(HINT_LABEL)), length);
    }

    private static byte[] xor(byte[] left, byte[] right) {
        byte[] out = new byte[left.length];
        for (int i = 0; i < left.length; i++) {
            out[i] = (byte) (left[i] ^ right[i]);
        }
        return out;
    }

    private static byte[] unhex(String text) {
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static void report(Set<String> marks, String value) {
        if (value == null || value.isEmpty()) {
            return;
        }
        if (value.startsWith(PREFIX) || value.startsWith(LEGACY_PREFIX)) {
            marks.add("manifest: " + value);
        }
    }

    public static boolean looksClassEncrypted(Path jar) {
        int classes = 0;
        int sealed = 0;
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                if (name.endsWith(".class")) {
                    classes++;
                } else if (name.indexOf('.') < 0 && entry.getSize() > 64) {
                    sealed++;
                }
            }
        } catch (IOException ignored) {
            return false;
        }
        return sealed > 100 && classes < 16;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static final class Fragment {
        private final String entryName;
        private final String className;
        private final String methodName;
        private final int index;
        private final String hex;

        Fragment(String entryName, String className, String methodName, int index, String hex) {
            this.entryName = entryName;
            this.className = className;
            this.methodName = methodName;
            this.index = index;
            this.hex = hex;
        }
    }
}
