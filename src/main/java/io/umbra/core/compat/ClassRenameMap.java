package io.umbra.core.compat;

import org.objectweb.asm.commons.Remapper;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Immutable view of the renamer's mapping, used by the archive-layout layer.
 *
 * <p>The renamer produces three global maps that are sufficient to rewrite
 * classes and resources at write time:</p>
 *
 * <ul>
 *   <li>internal class names ({@code a/b/C} to {@code x/y/Z}),</li>
 *   <li>method names keyed by {@code name + descriptor},</li>
 *   <li>field names keyed by {@code name + ":" + descriptor}.</li>
 * </ul>
 *
 * <p>Package moves are derived from the class map (consistent moves only). This
 * is what makes OSGi manifest headers and module descriptors rewritable.</p>
 */
public final class ClassRenameMap {

    /** No-op mapping. */
    public static final ClassRenameMap EMPTY = new ClassRenameMap(
            Collections.<String, String>emptyMap(),
            Collections.<String, String>emptyMap(),
            Collections.<String, String>emptyMap());

    private final Map<String, String> classes;
    private final Map<String, String> methods;
    private final Map<String, String> fields;
    private final Map<String, String> packages = new LinkedHashMap<String, String>();
    private final Set<String> packageConflicts = new LinkedHashSet<String>();
    private final Set<String> movedOutPackages = new LinkedHashSet<String>();

    private ClassRenameMap(Map<String, String> classes, Map<String, String> methods,
                           Map<String, String> fields) {
        this.classes = classes;
        this.methods = methods;
        this.fields = fields;
        derivePackages();
    }

    private void derivePackages() {
        for (Map.Entry<String, String> entry : classes.entrySet()) {
            String from = entry.getKey();
            String to = entry.getValue();
            if (from == null || to == null || from.equals(to)) {
                continue;
            }
            String fromPackage = packageOf(from);
            String toPackage = packageOf(to);
            if (fromPackage.equals(toPackage)) {
                continue;
            }
            movedOutPackages.add(fromPackage);
            String existing = packages.get(fromPackage);
            if (existing == null) {
                packages.put(fromPackage, toPackage);
            } else if (!existing.equals(toPackage)) {
                packageConflicts.add(fromPackage);
            }
        }
        for (String conflict : packageConflicts) {
            packages.remove(conflict);
        }
    }

    /** Builds a map from the renamer output; any argument may be {@code null}. */
    public static ClassRenameMap of(Map<String, String> classes, Map<String, String> methods,
                                    Map<String, String> fields) {
        boolean emptyClasses = classes == null || classes.isEmpty();
        boolean emptyMethods = methods == null || methods.isEmpty();
        boolean emptyFields = fields == null || fields.isEmpty();
        if (emptyClasses && emptyMethods && emptyFields) {
            return EMPTY;
        }
        return new ClassRenameMap(copy(classes), copy(methods), copy(fields));
    }

    /** Builds a class-only map (useful for tests and tooling). */
    public static ClassRenameMap ofClasses(Map<String, String> classes) {
        return of(classes, null, null);
    }

    private static Map<String, String> copy(Map<String, String> source) {
        if (source == null || source.isEmpty()) {
            return Collections.emptyMap();
        }
        return Collections.unmodifiableMap(new LinkedHashMap<String, String>(source));
    }

    public boolean isEmpty() {
        return classes.isEmpty() && methods.isEmpty() && fields.isEmpty();
    }

    public boolean hasClassMapping() {
        return !classes.isEmpty();
    }

    /** Maps an internal class name; returns the input when unmapped. */
    public String mapClass(String internalName) {
        if (internalName == null) {
            return null;
        }
        String mapped = classes.get(internalName);
        return mapped == null ? internalName : mapped;
    }

    /** Maps a dotted binary class name; returns the input when unmapped. */
    public String mapDotted(String dottedName) {
        if (dottedName == null || dottedName.isEmpty()) {
            return dottedName;
        }
        String mapped = classes.get(dottedName.replace('.', '/'));
        return mapped == null ? dottedName : mapped.replace('/', '.');
    }

    /** Maps a global method name; returns the input when unmapped. */
    public String mapMethodName(String name, String descriptor) {
        if (name == null) {
            return null;
        }
        String mapped = methods.get(name + descriptor);
        return mapped == null ? name : mapped;
    }

    /** Maps a global field name; returns the input when unmapped. */
    public String mapFieldName(String name, String descriptor) {
        if (name == null) {
            return null;
        }
        String mapped = fields.get(name + ":" + descriptor);
        return mapped == null ? name : mapped;
    }

    /** Maps an internal package name ({@code a/b}); returns the input when unmapped. */
    public String mapPackageInternal(String internalPackage) {
        if (internalPackage == null) {
            return null;
        }
        String mapped = packages.get(internalPackage);
        return mapped == null ? internalPackage : mapped;
    }

    /** Maps a dotted package name ({@code a.b}); returns the input when unmapped. */
    public String mapPackageDotted(String dottedPackage) {
        if (dottedPackage == null || dottedPackage.isEmpty()) {
            return dottedPackage;
        }
        String mapped = packages.get(dottedPackage.replace('.', '/'));
        return mapped == null ? dottedPackage : mapped.replace('/', '.');
    }

    /** True when the package itself has a consistent mapping. */
    public boolean hasPackageMapping(String internalPackage) {
        return packages.containsKey(internalPackage);
    }

    /** True when at least one class left this package for a different package. */
    public boolean hasClassMovedOut(String internalPackage) {
        return movedOutPackages.contains(internalPackage);
    }

    /** Packages whose classes moved inconsistently; they cannot be mapped safely. */
    public Set<String> packageConflicts() {
        return Collections.unmodifiableSet(packageConflicts);
    }

    /** Consistent package mappings (internal form). */
    public Map<String, String> packageMap() {
        return Collections.unmodifiableMap(packages);
    }

    /**
     * Rewrites dotted class names inside an arbitrary text blob.
     *
     * <p>Tokens are scanned as Java-identifier runs including {@code '.'} and
     * {@code '$'}; only exact mapped class names are replaced, so file formats
     * such as {@code spring.factories}, {@code .imports} lists and
     * {@code META-INF/native-image} JSON stay structurally intact.</p>
     */
    public String rewriteDottedNames(String text) {
        if (text == null || text.isEmpty() || classes.isEmpty()) {
            return text;
        }
        StringBuilder out = new StringBuilder(text.length() + 16);
        int index = 0;
        int length = text.length();
        while (index < length) {
            char c = text.charAt(index);
            if (Character.isJavaIdentifierStart(c)) {
                int end = index + 1;
                while (end < length) {
                    char next = text.charAt(end);
                    if (Character.isJavaIdentifierPart(next) || next == '.') {
                        end++;
                    } else {
                        break;
                    }
                }
                String token = text.substring(index, end);
                String mapped = mapDotted(token);
                out.append(mapped);
                index = end;
            } else {
                out.append(c);
                index++;
            }
        }
        return out.toString();
    }

    /** ASM remapper backed by this mapping (class/method/field/package aware). */
    public Remapper remapper() {
        final ClassRenameMap mapping = this;
        return new Remapper() {
            @Override
            public String map(String internalName) {
                return mapping.mapClass(internalName);
            }

            @Override
            public String mapMethodName(String owner, String name, String descriptor) {
                return mapping.mapMethodName(name, descriptor);
            }

            @Override
            public String mapInvokeDynamicMethodName(String name, String descriptor) {
                return mapping.mapMethodName(name, descriptor);
            }

            @Override
            public String mapFieldName(String owner, String name, String descriptor) {
                return mapping.mapFieldName(name, descriptor);
            }

            @Override
            public String mapPackageName(String name) {
                // ASM passes the internal form (as stored in the Module attribute).
                return mapping.mapPackageInternal(name);
            }

            @Override
            public String mapModuleName(String name) {
                return name;
            }
        };
    }

    private static String packageOf(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? "" : internalName.substring(0, slash);
    }

    @Override
    public String toString() {
        return "ClassRenameMap{classes=" + classes.size() + ", methods=" + methods.size()
                + ", fields=" + fields.size() + ", packages=" + packages.size() + '}';
    }
}
