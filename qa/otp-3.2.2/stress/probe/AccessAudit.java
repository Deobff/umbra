import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Static access audit for a decrypted Umbra payload set.
 *
 * <p>Rebuilds the member table of every class and reports bytecode references
 * that the JVM can only reject at link time: {@code private} members of another
 * class, and members that do not exist on the referenced owner (or its
 * superclasses). Both failures are lazy in HotSpot, so they surface only when
 * the containing instruction is first executed.</p>
 *
 * <p>Usage: {@code java -cp asm.jar;asm-tree.jar;. AccessAudit <dir-of-class-files>}</p>
 */
public final class AccessAudit {

    private static final Map<String, ClassNode> CLASSES = new TreeMap<String, ClassNode>();
    private static final Map<String, Map<String, Integer>> METHOD_ACCESS =
            new HashMap<String, Map<String, Integer>>();
    private static final Map<String, Map<String, Integer>> FIELD_ACCESS =
            new HashMap<String, Map<String, Integer>>();

    public static void main(String[] args) throws Exception {
        File root = new File(args.length > 0 ? args[0] : "dumps");
        List<File> files = new ArrayList<File>();
        collect(root, files);
        Collections.sort(files);
        for (File file : files) {
            ClassNode node = read(file);
            if (node == null) {
                System.out.println("UNREADABLE " + file);
                continue;
            }
            CLASSES.put(node.name, node);
            Map<String, Integer> methods = new HashMap<String, Integer>();
            for (MethodNode method : node.methods) {
                methods.put(method.name + method.desc, Integer.valueOf(method.access));
            }
            METHOD_ACCESS.put(node.name, methods);
            Map<String, Integer> fields = new HashMap<String, Integer>();
            for (FieldNode field : node.fields) {
                fields.put(field.name + ":" + field.desc, Integer.valueOf(field.access));
            }
            FIELD_ACCESS.put(node.name, fields);
        }
        System.out.println("classes loaded      : " + CLASSES.size());

        List<String> privateHits = new ArrayList<String>();
        List<String> missingHits = new ArrayList<String>();
        Set<String> privateTargets = new TreeSet<String>();
        Set<String> privateCallers = new TreeSet<String>();

        for (ClassNode node : CLASSES.values()) {
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof MethodInsnNode) {
                        MethodInsnNode call = (MethodInsnNode) insn;
                        checkMethod(node, method, call.owner, call.name, call.desc,
                                privateHits, missingHits, privateTargets, privateCallers);
                    } else if (insn instanceof FieldInsnNode) {
                        FieldInsnNode access = (FieldInsnNode) insn;
                        checkField(node, method, access.owner, access.name, access.desc,
                                privateHits, missingHits, privateTargets, privateCallers);
                    } else if (insn instanceof InvokeDynamicInsnNode) {
                        InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) insn;
                        checkHandle(node, method, indy.bsm, privateHits, missingHits,
                                privateTargets, privateCallers);
                        for (Object arg : indy.bsmArgs) {
                            if (arg instanceof Handle) {
                                checkHandle(node, method, (Handle) arg, privateHits, missingHits,
                                        privateTargets, privateCallers);
                            }
                        }
                    } else if (insn instanceof LdcInsnNode) {
                        Object constant = ((LdcInsnNode) insn).cst;
                        if (constant instanceof Handle) {
                            checkHandle(node, method, (Handle) constant, privateHits, missingHits,
                                    privateTargets, privateCallers);
                        }
                    }
                }
            }
        }

        System.out.println();
        System.out.println("== cross-class access to private members ==");
        System.out.println("references          : " + privateHits.size());
        System.out.println("distinct targets    : " + privateTargets.size());
        System.out.println("caller classes      : " + privateCallers.size());
        for (String target : privateTargets) {
            System.out.println("  target " + target);
        }
        for (String caller : privateCallers) {
            System.out.println("  caller " + caller);
        }
        for (String hit : privateHits) {
            System.out.println("  " + hit);
        }

        System.out.println();
        System.out.println("== references to members that do not resolve ==");
        System.out.println("references          : " + missingHits.size());
        for (String hit : missingHits) {
            System.out.println("  " + hit);
        }
    }

    private static void checkMethod(ClassNode caller, MethodNode method, String owner, String name, String desc,
                                    List<String> privateHits, List<String> missingHits,
                                    Set<String> privateTargets, Set<String> privateCallers) {
        if (owner.startsWith("[")) {
            return;
        }
        String key = name + desc;
        int[] access = resolveMethod(owner, key);
        if (access == null) {
            if (CLASSES.containsKey(owner) && !"java/lang/Object".equals(owner)) {
                missingHits.add(caller.name + "." + method.name + method.desc
                        + " -> " + owner + "." + key + " (owner known, method missing)");
            }
            return;
        }
        if ((access[0] & Opcodes.ACC_PRIVATE) != 0 && !owner.equals(caller.name)) {
            privateHits.add(caller.name + "." + method.name + method.desc
                    + " -> " + owner + "." + key + " [" + flags(access[0]) + "]");
            privateTargets.add(owner + "." + key);
            privateCallers.add(caller.name);
        }
    }

    private static void checkField(ClassNode caller, MethodNode method, String owner, String name, String desc,
                                   List<String> privateHits, List<String> missingHits,
                                   Set<String> privateTargets, Set<String> privateCallers) {
        if (owner.startsWith("[")) {
            return;
        }
        String key = name + ":" + desc;
        int[] access = resolveField(owner, key);
        if (access == null) {
            if (CLASSES.containsKey(owner) && !"java/lang/Object".equals(owner)) {
                missingHits.add(caller.name + "." + method.name + method.desc
                        + " -> " + owner + "." + key + " (owner known, field missing)");
            }
            return;
        }
        if ((access[0] & Opcodes.ACC_PRIVATE) != 0 && !owner.equals(caller.name)) {
            privateHits.add(caller.name + "." + method.name + method.desc
                    + " -> " + owner + "." + key + " [" + flags(access[0]) + "]");
            privateTargets.add(owner + "." + key);
            privateCallers.add(caller.name);
        }
    }

    private static void checkHandle(ClassNode caller, MethodNode method, Handle handle,
                                    List<String> privateHits, List<String> missingHits,
                                    Set<String> privateTargets, Set<String> privateCallers) {
        if (handle == null || handle.getOwner().startsWith("[")) {
            return;
        }
        switch (handle.getTag()) {
            case Opcodes.H_GETFIELD:
            case Opcodes.H_GETSTATIC:
            case Opcodes.H_PUTFIELD:
            case Opcodes.H_PUTSTATIC:
                checkField(caller, method, handle.getOwner(), handle.getName(), handle.getDesc(),
                        privateHits, missingHits, privateTargets, privateCallers);
                break;
            default:
                checkMethod(caller, method, handle.getOwner(), handle.getName(), handle.getDesc(),
                        privateHits, missingHits, privateTargets, privateCallers);
                break;
        }
    }

    /** @return {@code {accessFlags, 1}} when the method resolves, else {@code null}. */
    private static int[] resolveMethod(String owner, String key) {
        String current = owner;
        for (int depth = 0; depth < 16 && current != null; depth++) {
            Map<String, Integer> methods = METHOD_ACCESS.get(current);
            if (methods != null) {
                Integer access = methods.get(key);
                if (access != null) {
                    return new int[] {access.intValue(), 1};
                }
            }
            ClassNode node = CLASSES.get(current);
            current = node == null ? null : node.superName;
        }
        return null;
    }

    private static int[] resolveField(String owner, String key) {
        String current = owner;
        for (int depth = 0; depth < 16 && current != null; depth++) {
            Map<String, Integer> fields = FIELD_ACCESS.get(current);
            if (fields != null) {
                Integer access = fields.get(key);
                if (access != null) {
                    return new int[] {access.intValue(), 1};
                }
            }
            ClassNode node = CLASSES.get(current);
            current = node == null ? null : node.superName;
        }
        return null;
    }

    private static String flags(int access) {
        StringBuilder b = new StringBuilder();
        if ((access & Opcodes.ACC_PUBLIC) != 0) {
            b.append("public ");
        }
        if ((access & Opcodes.ACC_PRIVATE) != 0) {
            b.append("private ");
        }
        if ((access & Opcodes.ACC_PROTECTED) != 0) {
            b.append("protected ");
        }
        if ((access & Opcodes.ACC_STATIC) != 0) {
            b.append("static ");
        }
        if ((access & Opcodes.ACC_SYNTHETIC) != 0) {
            b.append("synthetic ");
        }
        if (b.length() == 0) {
            b.append("package-private ");
        }
        return b.toString().trim();
    }

    private static ClassNode read(File file) throws Exception {
        InputStream in = new FileInputStream(file);
        try {
            byte[] bytes = new byte[(int) file.length()];
            int offset = 0;
            while (offset < bytes.length) {
                int read = in.read(bytes, offset, bytes.length - offset);
                if (read < 0) {
                    break;
                }
                offset += read;
            }
            ClassNode node = new ClassNode();
            new ClassReader(bytes).accept(node, 0);
            return node;
        } catch (Throwable unreadable) {
            return null;
        } finally {
            in.close();
        }
    }

    private static void collect(File dir, List<File> out) {
        File[] children = dir.listFiles();
        if (children == null) {
            return;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                collect(child, out);
            } else if (child.getName().endsWith(".class")) {
                out.add(child);
            }
        }
    }
}
