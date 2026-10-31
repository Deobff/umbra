import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.jar.JarFile;

/**
 * Diagnostic probe for the Umbra class-encryption runtime (read-only).
 *
 * <p>Loads the packaged artifact with its own injected loader, then reports the
 * facts a stack trace cannot give: which ClassLoader instance defined each
 * payload class, whether two classes share one runtime package, and the access
 * flags of the payload methods. Optionally dumps the decrypted class files so
 * they can be inspected with {@code javap -p}.</p>
 *
 * <p>Usage:
 * {@code java -Dumbra.probe.jar=artifact.jar -cp artifact.jar;. UmbraProbe
 * [--dump DIR] [--dump-all] [--members] [names...]}</p>
 */
public final class UmbraProbe {

    private static Object loader;
    private static Class<?> loaderType;
    private static Method readEntry;
    private static Method payloadKey;
    private static Method loadClassPayload;
    private static Method cryptConstantPool;
    private static boolean constantPoolEncrypted;

    public static void main(String[] args) throws Exception {
        String dumpDir = null;
        boolean dumpAll = false;
        boolean members = false;
        List<String> names = new ArrayList<String>();
        for (int i = 0; i < args.length; i++) {
            if ("--dump".equals(args[i])) {
                dumpDir = args[++i];
            } else if ("--dump-all".equals(args[i])) {
                dumpAll = true;
            } else if ("--members".equals(args[i])) {
                members = true;
            } else {
                names.add(args[i]);
            }
        }

        String loaderName = readMainClass();
        System.out.println("main-class          : " + loaderName);
        loaderType = Class.forName(loaderName);
        System.out.println("loader class        : " + loaderType.getName());
        System.out.println("loader code source  : " + codeSource(loaderType));
        System.out.println("loader's own loader : " + describe(loaderType.getClassLoader()));

        loader = loaderType.newInstance();
        System.out.println("loader instance     : " + describe(loader));
        System.out.println("loader identityHash : " + System.identityHashCode(loader));
        System.out.println("loader parent       : " + describe(((ClassLoader) loader).getParent()));

        readEntry = declared(loaderType, "readEntry", String.class);
        payloadKey = declared(loaderType, "payloadKey", String.class, byte[].class);
        loadClassPayload = declared(loaderType, "loadClassPayload", String.class, String.class);
        cryptConstantPool = loaderType.getDeclaredMethod("cryptConstantPool", byte[].class, byte[].class);
        cryptConstantPool.setAccessible(true);

        Map<?, ?> classEntries = (Map<?, ?>) field("classEntries");
        System.out.println("payload class count : " + classEntries.size());
        System.out.println("entryClass/method   : " + field("entryClass") + " / " + field("entryMethod"));
        constantPoolEncrypted = Boolean.TRUE.equals(field("constantPoolEncrypted"));
        System.out.println("constantPoolEncrypt : " + constantPoolEncrypted);
        System.out.println("integrityEnabled    : " + field("integrityEnabled")
                + " level=" + field("integrityLevel"));
        System.out.println("antiDump            : " + field("antiDump"));
        System.out.println("payloadAlgorithm    : " + field("payloadAlgorithm"));

        File out = null;
        if (dumpDir != null) {
            out = new File(dumpDir);
            if (!out.isDirectory() && !out.mkdirs()) {
                throw new IllegalStateException("cannot create " + out);
            }
        }

        if (out != null) {
            List<String> dumpTargets = dumpAll ? new ArrayList<String>() : new ArrayList<String>(names);
            if (dumpAll) {
                for (Object name : classEntries.keySet()) {
                    dumpTargets.add(String.valueOf(name));
                }
                Collections.sort(dumpTargets);
            }
            int dumped = 0;
            int failed = 0;
            for (String name : dumpTargets) {
                try {
                    if (dump(name, out) != null) {
                        dumped++;
                    } else {
                        failed++;
                    }
                } catch (Throwable t) {
                    failed++;
                    System.out.println("dump FAILED " + name + " : " + t);
                }
            }
            System.out.println("dumped              : " + dumped + " (failed " + failed + ") into " + out);
        }

        if (names.isEmpty()) {
            halt();
            return;
        }

        System.out.println();
        System.out.println("== identity / package ==");
        Class<?> first = null;
        for (String name : names) {
            try {
                Class<?> type = ((ClassLoader) loader).loadClass(name);
                if (first == null) {
                    first = type;
                }
                System.out.println(pad(name) + " loader=" + describe(type.getClassLoader())
                        + " identityHash=" + System.identityHashCode(type.getClassLoader())
                        + " package=" + quote(packageName(type))
                        + " packageIdentity=" + System.identityHashCode(type.getPackage())
                        + " classModifiers=" + Modifier.toString(type.getModifiers())
                        + " super=" + (type.getSuperclass() == null ? "-" : type.getSuperclass().getName()));
                System.out.println(pad(name) + " sameLoaderAsFirst="
                        + (type.getClassLoader() == first.getClassLoader())
                        + " samePackageAsFirst=" + (type.getPackage() == first.getPackage()));
            } catch (Throwable t) {
                System.out.println(pad(name) + " LOAD FAILED : " + t);
            }
        }

        if (members) {
            System.out.println();
            System.out.println("== declared methods ==");
            for (String name : names) {
                try {
                    Class<?> type = ((ClassLoader) loader).loadClass(name);
                    Method[] methods = type.getDeclaredMethods();
                    List<String> shown = new ArrayList<String>();
                    for (Method method : methods) {
                        shown.add(Modifier.toString(method.getModifiers()) + " "
                                + method.getName() + descriptor(method));
                    }
                    Collections.sort(shown);
                    System.out.println(pad(name) + " declared methods: " + methods.length);
                    for (String line : shown) {
                        System.out.println("    " + line);
                    }
                    System.out.println(pad(name) + " declared fields: " + type.getDeclaredFields().length);
                } catch (Throwable t) {
                    System.out.println(pad(name) + " LOAD FAILED : " + t);
                }
            }
        }

        halt();
    }

    private static byte[] dump(String name, File out) throws Exception {
        Map<?, ?> classEntries = (Map<?, ?>) field("classEntries");
        Object entry = classEntries.get(name);
        if (entry == null) {
            System.out.println("no payload entry for " + name);
            return null;
        }
        byte[] sealed = (byte[]) readEntry.invoke(loader, entry);
        byte[] key = (byte[]) payloadKey.invoke(loader, "c:" + name, sealed);
        byte[] plain = (byte[]) loadClassPayload.invoke(loader, name, entry);
        if (constantPoolEncrypted) {
            boolean patched = ((Boolean) cryptConstantPool.invoke(null, plain, key)).booleanValue();
            if (!patched) {
                System.out.println("constant pool patch FAILED for " + name);
            }
        }
        File target = new File(out, name.replace('.', File.separatorChar) + ".class");
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create " + parent);
        }
        FileOutputStream stream = new FileOutputStream(target);
        try {
            stream.write(plain);
        } finally {
            stream.close();
        }
        return plain;
    }

    private static String readMainClass() throws Exception {
        String path = System.getProperty("umbra.probe.jar");
        if (path == null) {
            String[] parts = System.getProperty("java.class.path").split(File.pathSeparator);
            for (int i = 0; i < parts.length; i++) {
                if (parts[i].toLowerCase().endsWith(".jar")) {
                    path = parts[i];
                    break;
                }
            }
        }
        if (path == null) {
            throw new IllegalStateException("no jar on the class path; pass -Dumbra.probe.jar=...");
        }
        JarFile jar = new JarFile(path);
        try {
            String main = jar.getManifest().getMainAttributes().getValue("Main-Class");
            if (main == null) {
                throw new IllegalStateException("jar has no Main-Class: " + path);
            }
            System.out.println("probe jar           : " + new File(path).getAbsolutePath());
            return main.trim();
        } finally {
            jar.close();
        }
    }

    private static Method declared(Class<?> type, String name, Class<?>... parameters) throws Exception {
        Method method = type.getDeclaredMethod(name, parameters);
        method.setAccessible(true);
        return method;
    }

    private static Object field(String name) throws Exception {
        Field f = loaderType.getDeclaredField(name);
        f.setAccessible(true);
        return f.get(loader);
    }

    private static String codeSource(Class<?> type) {
        try {
            return String.valueOf(type.getProtectionDomain().getCodeSource().getLocation());
        } catch (Throwable t) {
            return "n/a";
        }
    }

    private static String packageName(Class<?> type) {
        Package pkg = type.getPackage();
        return pkg == null ? "<none>" : pkg.getName();
    }

    private static String describe(Object owner) {
        if (owner == null) {
            return "<bootstrap>";
        }
        return owner.getClass().getName();
    }

    private static String quote(String value) {
        return "'" + value + "'";
    }

    private static String pad(String name) {
        StringBuilder b = new StringBuilder(name);
        while (b.length() < 20) {
            b.append(' ');
        }
        return b.toString();
    }

    private static String descriptor(Method method) {
        StringBuilder b = new StringBuilder("(");
        Class<?>[] params = method.getParameterTypes();
        for (int i = 0; i < params.length; i++) {
            b.append(typeDescriptor(params[i]));
        }
        b.append(')').append(typeDescriptor(method.getReturnType()));
        return b.toString();
    }

    private static String typeDescriptor(Class<?> type) {
        if (type == Void.TYPE) {
            return "V";
        }
        if (type == Boolean.TYPE) {
            return "Z";
        }
        if (type == Byte.TYPE) {
            return "B";
        }
        if (type == Character.TYPE) {
            return "C";
        }
        if (type == Short.TYPE) {
            return "S";
        }
        if (type == Integer.TYPE) {
            return "I";
        }
        if (type == Long.TYPE) {
            return "J";
        }
        if (type == Float.TYPE) {
            return "F";
        }
        if (type == Double.TYPE) {
            return "D";
        }
        if (type.isArray()) {
            return "[" + typeDescriptor(type.getComponentType());
        }
        return "L" + type.getName().replace('.', '/') + ";";
    }

    private static void halt() {
        System.out.flush();
        Runtime.getRuntime().halt(0);
    }
}
