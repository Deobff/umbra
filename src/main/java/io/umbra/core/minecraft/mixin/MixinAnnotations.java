package io.umbra.core.minecraft.mixin;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;

import java.util.ArrayList;
import java.util.List;

/**
 * Annotation descriptors and value readers for the SpongePowered Mixin family.
 *
 * <p>Read-only helpers over ASM tree nodes. Every reader tolerates missing,
 * {@code null} or malformed annotation elements: it skips what it cannot
 * understand and records a short note through {@link MixinCollector} instead of
 * throwing. Both the visible and the invisible annotation lists are searched
 * because Mixin annotations are not {@code @Retention(RUNTIME)}.</p>
 */
public final class MixinAnnotations {

    /** References a target class annotated on the mixin class. */
    public static final String MIXIN = "Lorg/spongepowered/asm/mixin/Mixin;";
    /** Marks a mixin member that shadows a target member. */
    public static final String SHADOW = "Lorg/spongepowered/asm/mixin/Shadow;";
    /** Replaces a target method with the annotated mixin method. */
    public static final String OVERWRITE = "Lorg/spongepowered/asm/mixin/Overwrite;";
    /** Generated field getter/setter; the value names the target field. */
    public static final String ACCESSOR = "Lorg/spongepowered/asm/mixin/gen/Accessor;";
    /** Generated proxy method; the value names the target method. */
    public static final String INVOKER = "Lorg/spongepowered/asm/mixin/gen/Invoker;";

    /**
     * Injection annotations whose {@code method} element references a target
     * member. The MixinExtras annotations are listed under their own package and
     * (defensively) under the Mixin package as well; comparing descriptors is
     * free, so an extra entry only makes the scan more forgiving.
     */
    public static final String[] INJECTIONS = {
            "Lorg/spongepowered/asm/mixin/injection/Inject;",
            "Lorg/spongepowered/asm/mixin/injection/Redirect;",
            "Lorg/spongepowered/asm/mixin/injection/ModifyArg;",
            "Lorg/spongepowered/asm/mixin/injection/ModifyArgs;",
            "Lorg/spongepowered/asm/mixin/injection/ModifyVariable;",
            "Lorg/spongepowered/asm/mixin/injection/ModifyConstant;",
            "Lcom/llamalad7/mixinextras/injector/ModifyExpressionValue;",
            "Lcom/llamalad7/mixinextras/injector/ModifyReturnValue;",
            "Lcom/llamalad7/mixinextras/injector/ModifyReceiver;",
            "Lcom/llamalad7/mixinextras/injector/WrapOperation;",
            "Lcom/llamalad7/mixinextras/injector/WrapWithCondition;",
            "Lorg/spongepowered/asm/mixin/injection/ModifyExpressionValue;",
            "Lorg/spongepowered/asm/mixin/injection/ModifyReturnValue;",
            "Lorg/spongepowered/asm/mixin/injection/ModifyReceiver;",
            "Lorg/spongepowered/asm/mixin/injection/WrapOperation;",
            "Lorg/spongepowered/asm/mixin/injection/WrapWithCondition;"
    };

    private MixinAnnotations() {
    }

    /** Finds an annotation by descriptor in the visible or invisible list. */
    public static AnnotationNode find(List<AnnotationNode> visible, List<AnnotationNode> invisible,
                                      String desc) {
        AnnotationNode found = findIn(visible, desc);
        return found != null ? found : findIn(invisible, desc);
    }

    public static boolean has(List<AnnotationNode> visible, List<AnnotationNode> invisible,
                              String desc) {
        return find(visible, invisible, desc) != null;
    }

    private static AnnotationNode findIn(List<AnnotationNode> annotations, String desc) {
        if (annotations == null || desc == null) {
            return null;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation != null && desc.equals(annotation.desc)) {
                return annotation;
            }
        }
        return null;
    }

    /** Returns the raw value of an annotation element, or {@code null}. */
    public static Object value(AnnotationNode annotation, String key) {
        if (annotation == null || annotation.values == null || key == null) {
            return null;
        }
        List<Object> values = annotation.values;
        for (int i = 0; i + 1 < values.size(); i += 2) {
            Object name = values.get(i);
            if (key.equals(name)) {
                return values.get(i + 1);
            }
        }
        return null;
    }

    /**
     * Reads a class-valued annotation element ({@code Type[]} for {@code @Mixin}
     * {@code value}) and returns internal names.
     */
    public static List<String> classNames(AnnotationNode annotation, String key,
                                          MixinCollector collector, String where) {
        List<String> out = new ArrayList<String>();
        collectClassNames(value(annotation, key), out, collector, where + '.' + key);
        return out;
    }

    private static void collectClassNames(Object raw, List<String> out,
                                          MixinCollector collector, String where) {
        if (raw == null) {
            return;
        }
        if (raw instanceof Type) {
            String internal = internalName((Type) raw);
            if (internal != null) {
                out.add(internal);
            } else {
                note(collector, "ignored non-class @Mixin target type '" + raw + "' in " + where);
            }
            return;
        }
        if (raw instanceof String) {
            String internal = normalizeClassName((String) raw);
            if (internal != null) {
                out.add(internal);
            } else {
                note(collector, "ignored empty @Mixin target in " + where);
            }
            return;
        }
        if (raw instanceof List) {
            for (Object item : (List<?>) raw) {
                collectClassNames(item, out, collector, where);
            }
            return;
        }
        if (raw instanceof Object[]) {
            for (Object item : (Object[]) raw) {
                collectClassNames(item, out, collector, where);
            }
            return;
        }
        note(collector, "ignored @Mixin target of unsupported type "
                + raw.getClass().getSimpleName() + " in " + where);
    }

    /**
     * Reads a string-valued annotation element. Handles a single string, an
     * array ({@code List} in the ASM tree) and nested arrays; empty entries are
     * dropped.
     */
    public static List<String> strings(AnnotationNode annotation, String key) {
        List<String> out = new ArrayList<String>();
        collectStrings(value(annotation, key), out);
        return out;
    }

    private static void collectStrings(Object raw, List<String> out) {
        if (raw == null) {
            return;
        }
        if (raw instanceof String) {
            String text = ((String) raw).trim();
            if (!text.isEmpty()) {
                out.add(text);
            }
            return;
        }
        if (raw instanceof List) {
            for (Object item : (List<?>) raw) {
                collectStrings(item, out);
            }
            return;
        }
        if (raw instanceof Object[]) {
            for (Object item : (Object[]) raw) {
                collectStrings(item, out);
            }
        }
    }

    private static String internalName(Type type) {
        if (type == null || type.getSort() != Type.OBJECT) {
            return null;
        }
        String name = type.getInternalName();
        return name != null && !name.isEmpty() ? name : null;
    }

    /**
     * Normalizes a class name from an annotation into an internal name.
     * Accepts binary names ({@code net.minecraft.Foo}), internal names
     * ({@code net/minecraft/Foo}), descriptors ({@code Lnet/minecraft/Foo;}) and
     * array descriptors ({@code [Lnet/minecraft/Foo;}).
     */
    public static String normalizeClassName(String raw) {
        if (raw == null) {
            return null;
        }
        String name = raw.trim();
        if (name.isEmpty()) {
            return null;
        }
        int start = 0;
        while (start < name.length() && name.charAt(start) == '[') {
            start++;
        }
        name = name.substring(start);
        if (name.length() > 2 && name.charAt(0) == 'L' && name.charAt(name.length() - 1) == ';') {
            name = name.substring(1, name.length() - 1);
        }
        name = name.replace('.', '/');
        if (name.isEmpty() || name.indexOf(';') >= 0 || name.indexOf(' ') >= 0
                || name.indexOf('(') >= 0 || name.indexOf(')') >= 0) {
            return null;
        }
        return name;
    }

    private static void note(MixinCollector collector, String note) {
        if (collector != null) {
            collector.note(note);
        }
    }
}
