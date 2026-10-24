package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.model.ClassInfo;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.rules.Glob;
import io.umbra.core.rules.RuleSet;
import io.umbra.core.util.MappingWriter;
import io.umbra.core.util.NameGenerator;
import io.umbra.core.util.Jars;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Renames classes, methods and fields and rewrites every reference.
 *
 * <p>Method and field names are mapped globally by {@code name + descriptor},
 * which automatically keeps override families consistent. Names declared in
 * kept classes, library overrides, JNI natives and serialization hooks are
 * pinned. Class renames are hierarchical: inner classes follow their outer
 * class.</p>
 */
public final class RenamePass implements Pass {

    @Override
    public String name() {        return "rename";
    }

    @Override
    public int order() {
        return 50;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().renamer().enabled();
    }

    @Override
    public void run(PassContext context) throws IOException {
        UmbraConfig config = context.config();
        ClassPool pool = context.classes();
        Hierarchy hierarchy = context.hierarchy();
        RuleSet rules = context.rules();
        MappingSet mappings = context.mappings();
        UmbraConfig.RenamerOptions options = config.renamer();

        Map<String, ClassNode> original = new LinkedHashMap<String, ClassNode>(pool.classes());
        List<String> names = new ArrayList<String>(original.keySet());
        Collections.sort(names);

        Set<String> memberRenamable = new HashSet<String>();
        for (String name : names) {
            ClassNode node = original.get(name);
            if (!pool.isFrozen(name) && rules.allowClassRename(node)
                    && (node.access & Opcodes.ACC_ANNOTATION) == 0
                    && (node.access & Opcodes.ACC_RECORD) == 0) {
                // Annotation element names and record component names are part
                // of their binary contract; leaving them untouched is safer.
                memberRenamable.add(name);
            }
        }

        // Java agent entry classes are resolved by exact class name from the
        // manifest after the agent JAR shares the target's class path. Renaming
        // a different app/agent class in the same package to the same
        // obfuscated name makes the app class shadow the agent class (the JVM
        // then looks for premain/agentmain in the wrong class), so agent entry
        // classes keep their original names and members.
        Set<String> agentEntryClasses = agentEntryClasses(pool, original);
        if (!agentEntryClasses.isEmpty()) {
            for (String entry : agentEntryClasses) {
                memberRenamable.remove(entry);
            }
            context.stats().add("rename.agentEntryPinned", agentEntryClasses.size());
            context.log().info("rename: keeping %d java-agent entry class name(s) stable: %s",
                    agentEntryClasses.size(), agentEntryClasses);
        }

        MappingSet previous = null;
        if (!config.mapping().inputFile().trim().isEmpty()) {
            Path previousFile = resolveInputMapping(config);
            if (java.nio.file.Files.exists(previousFile)) {
                previous = io.umbra.core.enterprise.MappingReader.read(previousFile);
                context.log().info("rename: loaded previous mapping %s", previousFile);
            } else {
                context.log().warn("rename: previous mapping not found: %s", previousFile);
            }
        }

        Map<String, String> seededClasses = new LinkedHashMap<String, String>();
        Map<String, String> packageMap = new LinkedHashMap<String, String>();
        Set<String> usedClassNames = new HashSet<String>(names);
        if (previous != null && options.renameClasses()) {
            for (Map.Entry<String, String> e : previous.classes().entrySet()) {
                String from = e.getKey();
                String to = e.getValue();
                if (!original.containsKey(from) || !memberRenamable.contains(from) || from.equals(to)) {
                    continue;
                }
                if (usedClassNames.contains(to)) {
                    context.log().warn("rename: previous class mapping %s -> %s collides; regenerating", from, to);
                    continue;
                }
                seededClasses.put(from, to);
                mappings.mapClass(from, to);
                if (!packageOf(from).equals(packageOf(to))) {
                    packageMap.put(packageOf(from), packageOf(to));
                }
                usedClassNames.add(to);
            }
        }

        Map<String, String> packageOnly = new LinkedHashMap<String, String>();
        Map<String, String> classMap = renameClasses(context, original, names, memberRenamable,
                seededClasses, usedClassNames, packageMap, packageOnly);

        Set<String> pinnedMethods = new HashSet<String>();
        Set<String> pinnedFields = new HashSet<String>();
        if (options.renameMethods() || options.renameFields()) {
            pinMembers(hierarchy, rules, original, names, memberRenamable, pinnedMethods, pinnedFields);
        }

        if (previous != null) {
            seedMemberMappings(context, previous, memberRenamable, pinnedMethods, pinnedFields);
        }

        NameGenerator memberNames = new NameGenerator(context.random(), "",
                options.dictionary(), options.minimumNameLength());
        Set<String> reservedNames = new HashSet<String>();
        for (ClassNode node : original.values()) {
            for (MethodNode method : node.methods) {
                reservedNames.add(method.name);
            }
            for (FieldNode field : node.fields) {
                reservedNames.add(field.name);
            }
        }
        int renamedMethods = 0;
        int renamedFields = 0;
        for (String name : names) {
            if (!memberRenamable.contains(name)) {
                continue;
            }
            ClassNode node = original.get(name);
            if (options.renameMethods()) {
                for (MethodNode method : node.methods) {
                    if (method.name.startsWith("<")) {
                        continue;
                    }
                    String key = method.name + method.desc;
                    if (pinnedMethods.contains(key)) {
                        continue;
                    }
                    String assigned = mappings.mappedMethod(method.name, method.desc);
                    if (assigned.equals(method.name)) {
                        assigned = uniqueMember(memberNames, method.name, reservedNames);
                        reservedNames.add(assigned);
                        mappings.mapMethod(name, method.name, method.desc, assigned);
                        renamedMethods++;
                    } else {
                        mappings.mapMethod(name, method.name, method.desc, assigned);
                    }
                }
            }
            if (options.renameFields()) {
                for (FieldNode field : node.fields) {
                    String key = field.name + ":" + field.desc;
                    if (pinnedFields.contains(key)) {
                        continue;
                    }
                    String assigned = mappings.mappedField(field.name, field.desc);
                    if (assigned.equals(field.name)) {
                        assigned = uniqueMember(memberNames, field.name, reservedNames);
                        reservedNames.add(assigned);
                        mappings.mapField(name, field.name, field.desc, assigned);
                        renamedFields++;
                    } else {
                        mappings.mapField(name, field.name, field.desc, assigned);
                    }
                }
            }
        }

        UmbraRemapper remapper = new UmbraRemapper(hierarchy, mappings, memberRenamable, packageMap,
                context.config().reflection().rewriteClassStrings());
        Map<String, ClassNode> remapped = new LinkedHashMap<String, ClassNode>();
        for (String name : names) {
            ClassNode node = original.get(name);
            if (pool.isFrozen(name)) {
                remapped.put(name, node);
                continue;
            }
            ClassNode out = new ClassNode();
            node.accept(new ClassRemapper(out, remapper));
            remapped.put(name, out);
        }
        pool.applyRenames(classMap, remapped);
        // Package-only renames keep the class bytecode intact; freeze the new
        // names so later passes do not transform framework/script boundaries.
        for (String newName : packageOnly.values()) {
            pool.freeze(newName);
        }
        // Refresh hierarchy entries under their new names for frame computation.
        for (ClassNode node : pool.classes().values()) {
            hierarchy.addInput(node);
        }

        if (config.mapping().enabled()) {
            Path path = mappingPath(config);
            MappingWriter.write(path, mappings);
            context.log().info("rename: mapping written to %s", path.toAbsolutePath());
        }

        context.stats().add("classes.renamed", classMap.size());
        context.stats().add("methods.renamed", renamedMethods);
        context.stats().add("fields.renamed", renamedFields);
        context.log().info("rename: %d classes, %d methods, %d fields renamed",
                classMap.size(), renamedMethods, renamedFields);
    }

    private Map<String, String> renameClasses(PassContext context, Map<String, ClassNode> original,
                                              List<String> names, Set<String> memberRenamable,
                                              Map<String, String> seeded, Set<String> used,
                                              Map<String, String> packageMap,
                                              Map<String, String> packageOnly) {
        UmbraConfig.RenamerOptions options = context.config().renamer();
        Map<String, String> classMap = new LinkedHashMap<String, String>();
        if (!options.renameClasses()) {
            return classMap;
        }
        classMap.putAll(seeded);
        NameGenerator classNames = new NameGenerator(context.random(), options.prefix(),
                options.dictionary(), options.minimumNameLength());
        boolean randomPackages = options.repackage()
                && "*".equals(options.repackagePackage().trim());
        NameGenerator packageNames = new NameGenerator(context.random(), "",
                options.dictionary(), 1);
        Set<String> usedPackages = new HashSet<String>();
        for (String name : names) {
            String pkg = packageOf(name);
            if (!pkg.isEmpty()) {
                usedPackages.add(pkg);
            }
        }
        Map<String, String> randomPackageMap = new LinkedHashMap<String, String>();
        List<String> ordered = new ArrayList<String>(names);
        Collections.sort(ordered, new Comparator<String>() {
            @Override
            public int compare(String a, String b) {
                int da = depth(a);
                int db = depth(b);
                if (da != db) {
                    return da - db;
                }
                return a.compareTo(b);
            }
        });

        if (randomPackages && !options.repackageKept().isEmpty()) {
            List<Glob> globs = new ArrayList<Glob>();
            for (String pattern : options.repackageKept()) {
                if (pattern != null && !pattern.trim().isEmpty()) {
                    globs.add(new Glob(pattern.trim()));
                }
            }
            for (String name : names) {
                if (classMap.containsKey(name) || context.classes().isFrozen(name)) {
                    continue;
                }
                boolean matched = false;
                for (Glob glob : globs) {
                    if (glob.matches(name)) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    continue;
                }
                String pkg = packageOf(name);
                if (pkg.isEmpty()) {
                    continue;
                }
                String mappedPkg = mapPackage(pkg, randomPackageMap, usedPackages, packageNames);
                String simple = name.substring(name.lastIndexOf('/') + 1);
                String newName = mappedPkg + "/" + simple;
                if (used.contains(newName)) {
                    context.log().warn("rename: package-only mapping collision for %s -> %s", name, newName);
                    continue;
                }
                classMap.put(name, newName);
                context.mappings().mapClass(name, newName);
                packageMap.put(pkg, mappedPkg);
                used.add(newName);
                packageOnly.put(name, newName);
            }
        }

        for (String name : ordered) {
            ClassNode node = original.get(name);
            if (!memberRenamable.contains(name) || classMap.containsKey(name)) {
                continue;
            }
            String newName;
            int slash = name.lastIndexOf('/');
            int dollar = name.lastIndexOf('$');
            if (dollar > slash) {
                String outer = name.substring(0, dollar);
                String outerMapped = classMap.get(outer);
                if (outerMapped == null) {
                    continue;
                }
                String suffix = name.substring(dollar + 1);
                if (suffix.matches("\\d+")) {
                    newName = outerMapped + "$" + suffix;
                    while (used.contains(newName)) {
                        newName = outerMapped + "$" + classNames.next();
                    }
                } else {
                    newName = outerMapped + "$" + classNames.next();
                    while (used.contains(newName)) {
                        newName = outerMapped + "$" + classNames.next();
                    }
                }
            } else {
                String pkg = packageOf(name);
                if (randomPackages && !pkg.isEmpty()) {
                    pkg = mapPackage(pkg, randomPackageMap, usedPackages, packageNames);
                } else if (options.repackage()
                        && !NameGenerator.normalizePackage(options.repackagePackage()).isEmpty()) {
                    pkg = NameGenerator.normalizePackage(options.repackagePackage());
                }
                newName = uniqueClass(context.hierarchy(), used, classNames, pkg);
            }
            if (!newName.equals(name)) {
                classMap.put(name, newName);
                context.mappings().mapClass(name, newName);
                if (dollar <= slash && !packageOf(name).equals(packageOf(newName))) {
                    packageMap.put(packageOf(name), packageOf(newName));
                }
                used.add(newName);
            }
        }
        return classMap;
    }

    private void pinMembers(Hierarchy hierarchy, RuleSet rules, Map<String, ClassNode> original,
                            List<String> names, Set<String> memberRenamable,
                            Set<String> pinnedMethods, Set<String> pinnedFields) {
        for (String name : names) {
            ClassNode node = original.get(name);
            boolean renamable = memberRenamable.contains(name);
            for (MethodNode method : node.methods) {
                String key = method.name + method.desc;
                boolean pin = !renamable
                        || (node.access & Opcodes.ACC_INTERFACE) != 0
                        || rules.keepMethod(name, method)
                        || isEnumSynthetic(node, method)
                        || overridesLibrary(hierarchy, node, method);
                if (pin) {
                    pinnedMethods.add(key);
                }
            }
            for (FieldNode field : node.fields) {
                String key = field.name + ":" + field.desc;
                boolean pin = !renamable
                        || rules.keepField(name, field)
                        || isEnumSyntheticField(node, field)
                        || inheritsLibraryField(hierarchy, node, field);
                if (pin) {
                    pinnedFields.add(key);
                }
            }
        }
    }

    private void seedMemberMappings(PassContext context, MappingSet previous,
                                    Set<String> memberRenamable,
                                    Set<String> pinnedMethods, Set<String> pinnedFields) {
        UmbraConfig.RenamerOptions options = context.config().renamer();
        if (options.renameMethods()) {
            for (Map.Entry<String, String> e : previous.methods().entrySet()) {
                String[] parts = e.getKey().split("#", 3);
                if (parts.length != 3) {
                    continue;
                }
                String owner = parts[0];
                String name = parts[1];
                String desc = parts[2];
                if (!memberRenamable.contains(owner) || pinnedMethods.contains(name + desc)) {
                    continue;
                }
                String existing = context.mappings().mappedMethod(name, desc);
                if (existing.equals(name)) {
                    context.mappings().mapMethod(owner, name, desc, e.getValue());
                } else if (!existing.equals(e.getValue())) {
                    context.log().warn("rename: method mapping conflict for %s%s: %s vs %s",
                            name, desc, existing, e.getValue());
                } else {
                    context.mappings().mapMethod(owner, name, desc, e.getValue());
                }
            }
        }
        if (options.renameFields()) {
            for (Map.Entry<String, String> e : previous.fields().entrySet()) {
                String[] parts = e.getKey().split("#", 3);
                if (parts.length != 3) {
                    continue;
                }
                String owner = parts[0];
                String name = parts[1];
                String desc = parts[2];
                if (!memberRenamable.contains(owner) || pinnedFields.contains(name + ":" + desc)) {
                    continue;
                }
                String existing = context.mappings().mappedField(name, desc);
                if (existing.equals(name)) {
                    context.mappings().mapField(owner, name, desc, e.getValue());
                } else if (!existing.equals(e.getValue())) {
                    context.log().warn("rename: field mapping conflict for %s:%s: %s vs %s",
                            name, desc, existing, e.getValue());
                } else {
                    context.mappings().mapField(owner, name, desc, e.getValue());
                }
            }
        }
    }

    private static String mapPackage(String pkg, Map<String, String> map, Set<String> used,
                                     NameGenerator generator) {
        String mapped = map.get(pkg);
        if (mapped == null) {
            do {
                mapped = generator.next();
            } while (mapped.isEmpty() || used.contains(mapped));
            used.add(mapped);
            map.put(pkg, mapped);
        }
        return mapped;
    }

    private static Path resolveInputMapping(UmbraConfig config) {
        Path path = Paths.get(config.mapping().inputFile().trim());
        if (path.isAbsolute()) {
            return path;
        }
        Path parent = config.output().toAbsolutePath().getParent();
        return parent == null ? path : parent.resolve(path);
    }

    private static boolean isEnumSynthetic(ClassNode node, MethodNode method) {
        if ((node.access & Opcodes.ACC_ENUM) == 0) {
            return false;
        }
        return ("values".equals(method.name) && ("()[L" + node.name + ";").equals(method.desc))
                || ("valueOf".equals(method.name) && ("(Ljava/lang/String;)L" + node.name + ";").equals(method.desc))
                || "$values".equals(method.name);
    }

    private static boolean isEnumSyntheticField(ClassNode node, FieldNode field) {
        return (node.access & Opcodes.ACC_ENUM) != 0
                && ("$VALUES".equals(field.name) || (field.access & Opcodes.ACC_ENUM) != 0);
    }

    private static boolean overridesLibrary(Hierarchy hierarchy, ClassNode node, MethodNode method) {
        if ((method.access & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) != 0) {
            return false;
        }
        if (!declaredInKnownHierarchy(hierarchy, node)) {
            return true;
        }
        ClassInfo fromSuper = hierarchy.resolveMethod(node.superName, method.name, method.desc);
        if (fromSuper != null && !fromSuper.isInput()) {
            return true;
        }
        for (String itf : node.interfaces) {
            ClassInfo fromInterface = hierarchy.resolveMethod(itf, method.name, method.desc);
            if (fromInterface != null && !fromInterface.isInput()) {
                return true;
            }
        }
        return false;
    }

    private static boolean inheritsLibraryField(Hierarchy hierarchy, ClassNode node, FieldNode field) {
        ClassInfo fromSuper = hierarchy.resolveField(node.superName, field.name, field.desc);
        if (fromSuper != null && !fromSuper.isInput()) {
            return true;
        }
        for (String itf : node.interfaces) {
            ClassInfo fromInterface = hierarchy.resolveField(itf, field.name, field.desc);
            if (fromInterface != null && !fromInterface.isInput()) {
                return true;
            }
        }
        return false;
    }

    private static boolean declaredInKnownHierarchy(Hierarchy hierarchy, ClassNode node) {
        if (node.superName != null && hierarchy.resolve(node.superName).source() == ClassInfo.Source.UNKNOWN) {
            return false;
        }
        for (String itf : node.interfaces) {
            if (hierarchy.resolve(itf).source() == ClassInfo.Source.UNKNOWN) {
                return false;
            }
        }
        return true;
    }

    private static String uniqueClass(Hierarchy hierarchy, Set<String> used, NameGenerator names, String pkg) {
        for (int i = 0; i < 10000; i++) {
            String simple = names.next();
            String candidate = pkg.isEmpty() ? simple : pkg + "/" + simple;
            if (!used.contains(candidate) && !hierarchy.isKnown(candidate)) {
                used.add(candidate);
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to allocate a unique class name in package " + pkg);
    }

    private static String uniqueMember(NameGenerator names, String original, java.util.Collection<String> taken) {
        for (int i = 0; i < 10000; i++) {
            String candidate = names.next();
            if (!candidate.equals(original) && !taken.contains(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to allocate a unique member name");
    }

    private static String packageOf(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? "" : internalName.substring(0, slash);
    }

    private static int depth(String name) {
        int count = 0;
        int slash = name.lastIndexOf('/');
        for (int i = slash + 1; i < name.length(); i++) {
            if (name.charAt(i) == '$') {
                count++;
            }
        }
        return count;
    }

    private static Path mappingPath(UmbraConfig config) {
        Path path = Paths.get(config.renamer().mappingFile());
        if (path.isAbsolute()) {
            return path;
        }
        Path parent = config.output().toAbsolutePath().getParent();
        return parent == null ? path : parent.resolve(path);
    }

    /** Remapper backed by the global member maps and the hierarchy. */
    static final class UmbraRemapper extends Remapper {
        private final Hierarchy hierarchy;
        private final MappingSet mappings;
        private final Set<String> memberRenamable;
        private final Map<String, String> packageMap;
        private final boolean rewriteClassStrings;

        UmbraRemapper(Hierarchy hierarchy, MappingSet mappings, Set<String> memberRenamable,
                      Map<String, String> packageMap, boolean rewriteClassStrings) {
            this.hierarchy = hierarchy;
            this.mappings = mappings;
            this.memberRenamable = memberRenamable;
            this.packageMap = packageMap;
            this.rewriteClassStrings = rewriteClassStrings;
        }

        @Override
        public String mapPackageName(String name) {
            String mapped = packageMap.get(name);
            return mapped == null ? name : mapped;
        }

        @Override
        public String map(String internalName) {
            return mappings.mappedClass(internalName);
        }

        @Override
        public Object mapValue(Object value) {
            if (rewriteClassStrings && value instanceof String) {
                String text = (String) value;
                String internal = text.replace('.', '/');
                String mapped = mappings.mappedClass(internal);
                if (!mapped.equals(internal)) {
                    return text.indexOf('/') < 0 ? mapped.replace('/', '.') : mapped;
                }
            }
            return super.mapValue(value);
        }

        @Override
        public String mapMethodName(String owner, String name, String descriptor) {
            if (name.startsWith("<")) {
                return name;
            }
            ClassInfo declaring = hierarchy.resolveMethod(owner, name, descriptor);
            if (declaring == null || !memberRenamable.contains(declaring.name())) {
                return name;
            }
            return mappings.mappedMethod(name, descriptor);
        }

        @Override
        public String mapFieldName(String owner, String name, String descriptor) {
            ClassInfo declaring = hierarchy.resolveField(owner, name, descriptor);
            if (declaring == null || !memberRenamable.contains(declaring.name())) {
                return name;
            }
            return mappings.mappedField(name, descriptor);
        }

        @Override
        public String mapInvokeDynamicMethodName(String name, String descriptor) {
            return mappings.mappedMethod(name, descriptor);
        }

        @Override
        public String mapRecordComponentName(String owner, String name, String descriptor) {
            return mapFieldName(owner, name, descriptor);
        }
    }

    /**
     * Returns the classes referenced by Java agent manifest attributes. Their
     * names must stay stable so that a separately protected agent JAR cannot be
     * shadowed by a same-named obfuscated class from the target application.
     */
    private static Set<String> agentEntryClasses(ClassPool pool, Map<String, ClassNode> original) {
        Set<String> entries = new HashSet<String>();
        ClassPool.Resource manifest = pool.resource("META-INF/MANIFEST.MF");
        if (manifest == null) {
            return entries;
        }
        Map<String, String> attributes = Jars.parseManifest(manifest.bytes());
        for (String key : new String[]{"Premain-Class", "Agent-Class", "Launcher-Agent-Class"}) {
            String value = attributes.get(key);
            if (value == null || value.trim().isEmpty()) {
                continue;
            }
            String internal = value.trim().replace('.', '/');
            if (original.containsKey(internal)) {
                entries.add(internal);
            }
        }
        return entries;
    }
}
