package qa.mc;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.Type;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Simulated Minecraft mod-loader harness.
 *
 * <p>Loads a protected mod jar with a plain {@link URLClassLoader}, derives the
 * entry point from the mod metadata (Fabric/Quilt JSON), from the {@code @Mod}
 * annotation (Forge/NeoForge), invokes it, captures the marker output and
 * verifies the adaptation invariants:</p>
 *
 * <ul>
 *   <li>entry / mixin / target class names survive;</li>
 *   <li>mixin config, refmap, access widener/transformer and loader metadata are
 *       byte-identical to the input fixture;</li>
 *   <li>no class encryption (every {@code .class} entry still starts with
 *       {@code CAFEBABE}) and no native library entries;</li>
 *   <li>mixin and target method bodies are instruction-for-instruction
 *       unchanged (no flattening / VM / constant rewrites);</li>
 *   <li>the entry point executes and prints the expected marker.</li>
 * </ul>
 *
 * <p>Control modes: {@code no-adapt} asserts the original entry name is NOT
 * loadable after {@code minecraft.enabled=false}; {@code conflict} asserts the
 * protected archive is not loadable as plain classes when
 * {@code minecraft.allowConflicts=true} kept class encryption on.</p>
 *
 * <p>Output is line based ({@code ASSERT ...}, {@code MC-HARNESS ...}) so the
 * PowerShell driver can aggregate it into machine-readable results.</p>
 */
public final class McHarness {

    private static final List<String> PASSES = new ArrayList<String>();
    private static final List<String> FAILURES = new ArrayList<String>();

    private McHarness() {
    }

    public static void main(String[] args) {
        Map<String, String> options = new LinkedHashMap<String, String>();
        for (int i = 0; i < args.length; i++) {
            if (!args[i].startsWith("--")) {
                continue;
            }
            String key = args[i].substring(2);
            String value = "";
            if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                value = args[++i];
            }
            options.put(key, value);
        }
        String jar = options.get("jar");
        String fixture = options.get("fixture");
        String loader = value(options, "loader", "fabric");
        String entryClass = value(options, "entry-class", "");
        String entryMethod = value(options, "entry-method", "");
        String marker = value(options, "marker", "");
        String mode = value(options, "mode", "normal");
        String mixinClass = value(options, "mixin-class", "demo.mc.mixin.TargetMixin");
        String targetClass = value(options, "target-class", "demo.mc.game.Target");
        String expectModId = value(options, "mod-id", "");

        try {
            ZipFile output = new ZipFile(new File(jar));
            ZipFile input = new ZipFile(new File(fixture));
            try {
                if ("no-adapt".equals(mode)) {
                    runNoAdapt(output, entryClass, entryMethod);
                } else if ("conflict".equals(mode)) {
                    runConflict(output, entryClass);
                } else {
                    runNormal(output, input, loader, entryClass, entryMethod, marker,
                            mixinClass, targetClass, expectModId);
                }
            } finally {
                output.close();
                input.close();
            }
        } catch (Throwable failure) {
            fail("harness-crash", String.valueOf(failure));
            failure.printStackTrace(System.out);
        }
        for (String pass : PASSES) {
            System.out.println("ASSERT PASS " + pass);
        }
        for (String failure : FAILURES) {
            System.out.println("ASSERT FAIL " + failure);
        }
        if (FAILURES.isEmpty()) {
            System.out.println("MC-HARNESS RESULT PASS");
            System.out.flush();
            System.exit(0);
        }
        System.out.println("MC-HARNESS RESULT FAIL");
        System.out.flush();
        System.exit(1);
    }

    private static void runNormal(ZipFile output, ZipFile input, String loader,
                                  String expectedEntry, String expectedMethod, String marker,
                                  String mixinClass, String targetClass, String expectedModId)
            throws Exception {
        String[] derived = deriveEntrypoint(output, loader, expectedEntry);
        if (expectedEntry.isEmpty()) {
            expectedEntry = derived[0];
        }
        if (expectedMethod.isEmpty()) {
            expectedMethod = derived[1];
        }
        check("metadata-entrypoint", expectedEntry.equals(derived[0]),
                "derived " + derived[0] + "::" + derived[1] + ", expected " + expectedEntry + "::" + expectedMethod);
        if (derived.length > 3 && !derived[3].isEmpty()) {
            check("metadata-annotation", derived[3].contains(expectedEntry),
                    "@Mod classes found: " + derived[3] + ", expected " + expectedEntry);
        }
        if (!expectedModId.isEmpty() && derived.length > 2) {
            check("metadata-modid", derived[2].contains(expectedModId),
                    "derived mod ids '" + derived[2] + "', expected " + expectedModId);
        }
        // From here on use the names derived from the protected jar's own
        // metadata/annotations, never the caller's expectation: that is what a
        // real loader would do.
        expectedEntry = derived[0];
        expectedMethod = derived[1];

        // --- archive invariants ---------------------------------------------
        boolean allReadable = true;
        int classCount = 0;
        boolean nativeLibrary = false;
        Enumeration<? extends ZipEntry> entries = output.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.endsWith(".dll") || lower.endsWith(".so") || lower.endsWith(".dylib")) {
                nativeLibrary = true;
            }
            if (name.endsWith(".class")) {
                classCount++;
                byte[] bytes = read(output, name);
                if (bytes == null || bytes.length < 4
                        || (bytes[0] & 0xFF) != 0xCA || (bytes[1] & 0xFF) != 0xFE
                        || (bytes[2] & 0xFF) != 0xBA || (bytes[3] & 0xFF) != 0xBE) {
                    allReadable = false;
                }
            }
        }
        check("no-class-encryption", allReadable, "every .class entry is a readable class file");
        check("no-native-library", !nativeLibrary, "no .dll/.so/.dylib resources in archive");
        check("class-count", classCount > 0, "classes in archive: " + classCount);

        check("entry-class-present", output.getEntry(expectedEntry.replace('.', '/') + ".class") != null,
                expectedEntry);
        check("mixin-class-present", output.getEntry(mixinClass.replace('.', '/') + ".class") != null,
                mixinClass);
        check("target-class-present", output.getEntry(targetClass.replace('.', '/') + ".class") != null,
                targetClass);
        for (String resource : resourcesFor(loader)) {
            byte[] before = read(input, resource);
            byte[] after = read(output, resource);
            check("resource-identical:" + resource,
                    before != null && after != null && Arrays.equals(before, after),
                    "before=" + (before == null ? -1 : before.length)
                            + " after=" + (after == null ? -1 : after.length));
        }

        // --- body-shape invariants ------------------------------------------
        byte[] targetBefore = read(input, targetClass.replace('.', '/') + ".class");
        byte[] targetAfter = read(output, targetClass.replace('.', '/') + ".class");
        compareBodies("target", targetBefore, targetAfter);
        if (input.getEntry(mixinClass.replace('.', '/') + ".class") != null) {
            compareBodies("mixin",
                    read(input, mixinClass.replace('.', '/') + ".class"),
                    read(output, mixinClass.replace('.', '/') + ".class"));
        }

        // --- run the entrypoint through a plain URLClassLoader ---------------
        String captured = invoke(output, expectedEntry, expectedMethod);
        if (!marker.isEmpty()) {
            check("entry-marker", captured.contains(marker),
                    "marker '" + marker + "' in captured output");
        }
        check("entry-output", !captured.trim().isEmpty(), "entry produced output");
    }

    private static void runNoAdapt(ZipFile output, String entryClass, String entryMethod) {
        boolean loadable = false;
        String detail = "";
        try {
            URLClassLoader classLoader = new URLClassLoader(
                    new URL[]{new File(output.getName()).getAbsoluteFile().toURI().toURL()},
                    McHarness.class.getClassLoader());
            try {
                Class<?> type = Class.forName(entryClass, false, classLoader);
                loadable = true;
                detail = "entry class loadable as " + type.getName();
                if (!entryMethod.isEmpty()) {
                    detail += ", method " + (findMethod(type, entryMethod) != null ? "present" : "missing");
                }
            } finally {
                classLoader.close();
            }
        } catch (Throwable expected) {
            detail = "entry class not loadable: " + expected;
        }
        if (loadable) {
            fail("no-adapt", detail + " (adaptation disabled but entry kept intact)");
        } else {
            PASSES.add("no-adapt entry renamed/encrypted: " + detail);
            System.out.println("MC-HARNESS NO_ADAPT_CONFIRMED");
        }
    }

    private static void runConflict(ZipFile output, String entryClass) {
        boolean loadable = true;
        String detail = "";
        try {
            URLClassLoader classLoader = new URLClassLoader(
                    new URL[]{new File(output.getName()).getAbsoluteFile().toURI().toURL()},
                    McHarness.class.getClassLoader());
            try {
                Class.forName(entryClass, false, classLoader);
                detail = "entry class loaded from a plain URLClassLoader";
            } finally {
                classLoader.close();
            }
        } catch (Throwable expected) {
            loadable = false;
            detail = "entry class not readable as plain classes: " + expected;
        }
        if (loadable) {
            fail("conflict", "class encryption was disabled despite minecraft.allowConflicts=true; " + detail);
        } else {
            PASSES.add("conflict kept class encryption: " + detail);
            System.out.println("MC-HARNESS CONFLICT_CONFIRMED");
        }
    }

    /** Invokes the entrypoint; returns everything it printed to System.out. */
    private static String invoke(ZipFile output, String entryClass, String entryMethod) throws Exception {
        URLClassLoader classLoader = new URLClassLoader(
                new URL[]{new File(output.getName()).getAbsoluteFile().toURI().toURL()},
                McHarness.class.getClassLoader());
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream realOut = System.out;
        PrintStream tee = new PrintStream(new TeeOutputStream(captured, realOut), true, "UTF-8");
        try {
            Class<?> type = Class.forName(entryClass, true, classLoader);
            System.setOut(tee);
            Object instance = null;
            Constructor<?> constructor = type.getDeclaredConstructor();
            constructor.setAccessible(true);
            instance = constructor.newInstance();
            if (entryMethod != null && !entryMethod.isEmpty()) {
                Method method = findMethod(type, entryMethod);
                if (method == null) {
                    throw new NoSuchMethodException(entryClass + "::" + entryMethod);
                }
                method.setAccessible(true);
                method.invoke(instance);
            }
        } finally {
            System.setOut(realOut);
            tee.flush();
            classLoader.close();
        }
        return captured.toString("UTF-8");
    }

    private static Method findMethod(Class<?> type, String name) {
        for (Method method : type.getDeclaredMethods()) {
            if (method.getName().equals(name) && method.getParameterTypes().length == 0) {
                return method;
            }
        }
        return null;
    }

    /** Derives {@code [class, method, modIds]} from output metadata/annotations. */
    private static String[] deriveEntrypoint(ZipFile output, String loader, String expectedEntry)
            throws Exception {
        if ("fabric".equals(loader)) {
            Map<String, Object> json = parseJson(new String(read(output, "fabric.mod.json"), "UTF-8"));
            Map<String, Object> entrypoints = asMap(json.get("entrypoints"));
            List<Object> main = asList(entrypoints == null ? null : entrypoints.get("main"));
            String value = main == null || main.isEmpty() ? expectedEntry + "::onInitialize" : String.valueOf(main.get(0));
            String[] parts = value.split("::", 2);
            return new String[]{parts[0], parts.length > 1 ? parts[1] : "", String.valueOf(json.get("id")), ""};
        }
        if ("quilt".equals(loader)) {
            Map<String, Object> json = parseJson(new String(read(output, "quilt.mod.json"), "UTF-8"));
            Map<String, Object> quilt = asMap(json.get("quilt_loader"));
            Map<String, Object> entrypoints = asMap(quilt.get("entrypoints"));
            List<Object> main = asList(entrypoints == null ? null : entrypoints.get("main"));
            Object first = main == null || main.isEmpty() ? null : main.get(0);
            String value = "";
            if (first instanceof Map) {
                value = String.valueOf(asMap(first).get("value"));
            } else if (first != null) {
                value = String.valueOf(first);
            }
            if (value.isEmpty()) {
                value = expectedEntry;
            }
            String method = "";
            if (value.contains("::")) {
                String[] parts = value.split("::", 2);
                value = parts[0];
                method = parts[1];
            }
            return new String[]{value, method, String.valueOf(quilt.get("id")), ""};
        }
        // Forge / NeoForge: find the @Mod annotation in the class entries.
        String descriptor = "neo".equals(loader) || "neoforge".equals(loader)
                ? "Lnet/neoforged/fml/common/Mod;" : "Lnet/minecraftforge/fml/common/Mod;";
        String found = null;
        List<String> modClasses = new ArrayList<String>();
        Enumeration<? extends ZipEntry> entries = output.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            if (!entry.getName().endsWith(".class")) {
                continue;
            }
            byte[] bytes = read(output, entry.getName());
            if (bytes != null && indexOf(bytes, descriptor.getBytes(StandardCharsets.UTF_8)) >= 0) {
                String name = entry.getName().substring(0, entry.getName().length() - 6).replace('/', '.');
                modClasses.add(name);
                if (name.equals(expectedEntry)) {
                    found = name;
                } else if (found == null) {
                    found = name;
                }
            }
        }
        if (found == null) {
            found = expectedEntry;
        }
        String modId = found;
        if ("forge-legacy".equals(loader)) {
            byte[] info = read(output, "mcmod.info");
            if (info != null) {
                List<Object> list = asList(parseJsonValue(new String(info, "UTF-8")));
                if (list != null && !list.isEmpty()) {
                    modId = String.valueOf(asMap(list.get(0)).get("modid"));
                }
            }
        } else {
            String toml = readText(output, "neo".equals(loader) || "neoforge".equals(loader)
                    ? "META-INF/neoforge.mods.toml" : "META-INF/mods.toml");
            int at = toml.indexOf("modId = \"");
            if (at < 0) {
                at = toml.indexOf("modId=\"");
            }
            if (at >= 0) {
                int start = toml.indexOf('"', at) + 1;
                int end = toml.indexOf('"', start);
                modId = toml.substring(start, end);
            }
        }
        return new String[]{found, "", modId, joinText(modClasses)};
    }

    // --- body comparison -----------------------------------------------------

    private static void compareBodies(String label, byte[] before, byte[] after) {
        if (before == null || after == null) {
            fail(label + "-body", "class missing (before=" + (before == null) + ", after=" + (after == null) + ")");
            return;
        }
        try {
            List<String> a = dump(before);
            List<String> b = dump(after);
            if (!a.equals(b)) {
                String firstDifference = "";
                for (int i = 0; i < Math.min(a.size(), b.size()); i++) {
                    if (!a.get(i).equals(b.get(i))) {
                        firstDifference = "first difference at " + i + ":\n  before: " + a.get(i)
                                + "\n  after:  " + b.get(i);
                        break;
                    }
                }
                if (firstDifference.isEmpty()) {
                    firstDifference = "instruction list length differs: " + a.size() + " vs " + b.size();
                }
                fail(label + "-body-identical", firstDifference);
            } else {
                PASSES.add(label + "-body-identical (" + a.size() + " methods)");
            }
            String raw = new String(after, StandardCharsets.ISO_8859_1);
            String joinedDump = joinText(a);
            check(label + "-no-vm", raw.indexOf("umbra/runtime") < 0,
                    "no VM helper references in " + label);
            check(label + "-no-switch", joinedDump.indexOf("SWITCH") < 0,
                    "no flattening switch introduced into " + label);
        } catch (Throwable error) {
            fail(label + "-body-identical", "comparison failed: " + error);
        }
    }

    /** Instruction dump: opcodes plus literal/kept-operand details, no labels. */
    private static List<String> dump(byte[] bytes) throws Exception {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        List<String> methods = new ArrayList<String>();
        List<MethodNode> sorted = new ArrayList<MethodNode>(node.methods);
        Collections.sort(sorted, new Comparator<MethodNode>() {
            @Override
            public int compare(MethodNode left, MethodNode right) {
                int byName = left.name.compareTo(right.name);
                return byName != 0 ? byName : left.desc.compareTo(right.desc);
            }
        });
        for (MethodNode method : sorted) {
            StringBuilder line = new StringBuilder();
            line.append(method.name).append(method.desc).append('=');
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                int opcode = insn.getOpcode();
                if (opcode < 0) {
                    continue;
                }
                line.append(opcode).append(';');
                if (insn instanceof LdcInsnNode) {
                    Object constant = ((LdcInsnNode) insn).cst;
                    String text = constant instanceof Type ? ((Type) constant).getDescriptor() : String.valueOf(constant);
                    line.append("ldc:").append(text).append(';');
                } else if (insn instanceof IntInsnNode) {
                    line.append("int:").append(((IntInsnNode) insn).operand).append(';');
                } else if (insn instanceof VarInsnNode) {
                    line.append("var:").append(((VarInsnNode) insn).var).append(';');
                } else if (insn instanceof IincInsnNode) {
                    line.append("iinc:").append(((IincInsnNode) insn).var).append(',')
                            .append(((IincInsnNode) insn).incr).append(';');
                } else if (insn instanceof MethodInsnNode) {
                    MethodInsnNode call = (MethodInsnNode) insn;
                    line.append("m:").append(normalizeOwner(call.owner)).append('#')
                            .append(call.name).append(call.desc).append(';');
                } else if (insn instanceof FieldInsnNode) {
                    FieldInsnNode field = (FieldInsnNode) insn;
                    line.append("f:").append(normalizeOwner(field.owner)).append('#')
                            .append(field.name).append(':').append(field.desc).append(';');
                } else if (insn instanceof TypeInsnNode) {
                    line.append("t:").append(normalizeOwner(((TypeInsnNode) insn).desc)).append(';');
                } else if (insn instanceof org.objectweb.asm.tree.TableSwitchInsnNode
                        || insn instanceof org.objectweb.asm.tree.LookupSwitchInsnNode) {
                    line.append("SWITCH;");
                }
            }
            methods.add(line.toString());
        }
        return methods;
    }

    private static String joinText(List<String> lines) {
        StringBuilder builder = new StringBuilder();
        for (String line : lines) {
            builder.append(line).append('\n');
        }
        return builder.toString();
    }

    private static String normalizeOwner(String owner) {
        if (owner == null) {
            return "?";
        }
        if (owner.startsWith("java/") || owner.startsWith("javax/")) {
            return owner;
        }
        if (owner.startsWith("demo/mc/")) {
            return owner;
        }
        return "X";
    }

    // --- helpers -------------------------------------------------------------

    private static List<String> resourcesFor(String loader) {
        List<String> resources = new ArrayList<String>();
        resources.add("demo.mc.mixins.json");
        resources.add("demo.refmap.json");
        if ("fabric".equals(loader)) {
            resources.add("fabric.mod.json");
            resources.add("demo.accesswidener");
        } else if ("quilt".equals(loader)) {
            resources.add("quilt.mod.json");
            resources.add("demo.accesswidener");
        } else if ("forge-legacy".equals(loader)) {
            resources.add("mcmod.info");
            resources.add("qa_at.cfg");
        } else if ("neo".equals(loader) || "neoforge".equals(loader)) {
            resources.add("META-INF/neoforge.mods.toml");
            resources.add("META-INF/accesstransformer.cfg");
        } else {
            resources.add("META-INF/mods.toml");
            resources.add("META-INF/accesstransformer.cfg");
        }
        return resources;
    }

    private static byte[] read(ZipFile jar, String name) throws Exception {
        ZipEntry entry = jar.getEntry(name);
        if (entry == null) {
            return null;
        }
        InputStream stream = jar.getInputStream(entry);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = stream.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            stream.close();
        }
    }

    private static String readText(ZipFile jar, String name) throws Exception {
        byte[] bytes = read(jar, name);
        return bytes == null ? "" : new String(bytes, StandardCharsets.UTF_8);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static void check(String name, boolean condition, String detail) {
        if (condition) {
            PASSES.add(name + (detail.isEmpty() ? "" : " (" + detail + ")"));
        } else {
            fail(name, detail);
        }
    }

    private static void fail(String name, String detail) {
        FAILURES.add(name + ": " + detail);
    }

    private static String value(Map<String, String> options, String key, String fallback) {
        String value = options.get(key);
        return value == null ? fallback : value;
    }

    // --- tiny JSON parser (objects/arrays/strings/numbers/booleans/null) -----

    static Map<String, Object> parseJson(String text) {
        if (text != null && text.length() > 0 && text.charAt(0) == '\uFEFF') {
            text = text.substring(1);
        }
        Parser parser = new Parser(text);
        Object value = parser.parseValue();
        return asMap(value);
    }

    static Object parseJsonValue(String text) {
        if (text != null && text.length() > 0 && text.charAt(0) == '\uFEFF') {
            text = text.substring(1);
        }
        return new Parser(text).parseValue();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object value) {
        return value instanceof List ? (List<Object>) value : null;
    }

    private static final class Parser {
        private final String text;
        private int index;

        Parser(String text) {
            this.text = text;
        }

        Object parseValue() {
            skipSpace();
            char current = text.charAt(index);
            if (current == '{') {
                return parseObject();
            }
            if (current == '[') {
                return parseArray();
            }
            if (current == '"') {
                return parseString();
            }
            if (current == 't') {
                index += 4;
                return Boolean.TRUE;
            }
            if (current == 'f') {
                index += 5;
                return Boolean.FALSE;
            }
            if (current == 'n') {
                index += 4;
                return null;
            }
            return parseNumber();
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<String, Object>();
            index++;
            skipSpace();
            if (text.charAt(index) == '}') {
                index++;
                return map;
            }
            while (true) {
                skipSpace();
                String key = parseString();
                skipSpace();
                index++; // ':'
                map.put(key, parseValue());
                skipSpace();
                char separator = text.charAt(index++);
                if (separator == '}') {
                    return map;
                }
            }
        }

        private List<Object> parseArray() {
            List<Object> list = new ArrayList<Object>();
            index++;
            skipSpace();
            if (text.charAt(index) == ']') {
                index++;
                return list;
            }
            while (true) {
                list.add(parseValue());
                skipSpace();
                char separator = text.charAt(index++);
                if (separator == ']') {
                    return list;
                }
            }
        }

        private String parseString() {
            StringBuilder builder = new StringBuilder();
            index++;
            while (true) {
                char current = text.charAt(index++);
                if (current == '"') {
                    return builder.toString();
                }
                if (current == '\\') {
                    char escaped = text.charAt(index++);
                    switch (escaped) {
                        case 'n': builder.append('\n'); break;
                        case 't': builder.append('\t'); break;
                        case 'r': builder.append('\r'); break;
                        case 'b': builder.append('\b'); break;
                        case 'f': builder.append('\f'); break;
                        case 'u':
                            builder.append((char) Integer.parseInt(text.substring(index, index + 4), 16));
                            index += 4;
                            break;
                        default: builder.append(escaped);
                    }
                } else {
                    builder.append(current);
                }
            }
        }

        private Object parseNumber() {
            int start = index;
            while (index < text.length() && "-+.eE0123456789".indexOf(text.charAt(index)) >= 0) {
                index++;
            }
            String number = text.substring(start, index);
            if (number.indexOf('.') >= 0 || number.indexOf('e') >= 0 || number.indexOf('E') >= 0) {
                return Double.valueOf(number);
            }
            return Long.valueOf(number);
        }

        private void skipSpace() {
            while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
                index++;
            }
        }
    }

    private static final class TeeOutputStream extends java.io.OutputStream {
        private final ByteArrayOutputStream captured;
        private final PrintStream real;

        TeeOutputStream(ByteArrayOutputStream captured, PrintStream real) {
            this.captured = captured;
            this.real = real;
        }

        @Override
        public void write(int value) {
            captured.write(value);
            real.write(value);
        }

        @Override
        public void write(byte[] bytes, int offset, int length) {
            captured.write(bytes, offset, length);
            real.write(bytes, offset, length);
        }

        @Override
        public void flush() {
            real.flush();
        }
    }
}
