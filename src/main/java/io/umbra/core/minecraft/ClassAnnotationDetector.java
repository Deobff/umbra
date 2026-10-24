package io.umbra.core.minecraft;

import io.umbra.core.model.ClassPool;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import java.util.List;

/**
 * Scans class-level annotations for mod-loader, Mixin and coremod markers.
 *
 * <p>Any class carrying an annotation from a known loader/Mixin namespace is
 * kept by name, because the loader or the Mixin runtime discovers it
 * reflectively or from metadata. {@code @Mixin} classes additionally become
 * body-transform exempt together with their declared target classes. Classes
 * implementing {@code IFMLLoadingPlugin}/{@code ICoreMod} are frozen like
 * manifest-declared coremods.</p>
 */
final class ClassAnnotationDetector {

    private static final String MIXIN_ANNOTATION = "Lorg/spongepowered/asm/mixin/Mixin;";
    private static final String MIXIN_PREFIX = "Lorg/spongepowered/asm/mixin/";
    private static final String FORGE_PREFIX = "Lnet/minecraftforge/";
    private static final String LEGACY_FORGE_PREFIX = "Lcpw/mods/fml/";
    private static final String NEOFORGE_PREFIX = "Lnet/neoforged/";
    private static final String FABRIC_PREFIX = "Lnet/fabricmc/";
    private static final String QUILT_PREFIX = "Lorg/quiltmc/";

    private ClassAnnotationDetector() {
    }

    static void scan(ClassPool pool, MinecraftScan scan) {
        for (ClassNode node : pool.classes().values()) {
            if (node == null || node.name == null) {
                continue;
            }
            scanCoremodInterfaces(node, scan);
            int[] counts = new int[5];
            add(counts, scanAnnotationList(node.visibleAnnotations, node, scan));
            add(counts, scanAnnotationList(node.invisibleAnnotations, node, scan));
            if (counts[0] > 0) {
                scan.loaderForge();
            }
            if (counts[1] > 0) {
                scan.loaderNeoForge();
            }
            if (counts[2] > 0) {
                scan.loaderFabric();
            }
            if (counts[3] > 0) {
                scan.loaderQuilt();
            }
            if (counts[4] > 0) {
                scan.loaderMixin();
            }
        }
    }

    private static void add(int[] target, int[] values) {
        for (int i = 0; i < target.length && i < values.length; i++) {
            target[i] += values[i];
        }
    }

    /** Returns counts for [forge, neoforge, fabric, quilt, mixin]. */
    private static int[] scanAnnotationList(List<AnnotationNode> annotations, ClassNode node,
                                            MinecraftScan scan) {
        int[] counts = new int[5];
        if (annotations == null) {
            return counts;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation == null || annotation.desc == null) {
                continue;
            }
            String desc = annotation.desc;
            if (MIXIN_ANNOTATION.equals(desc)) {
                scan.mixinClass(node.name);
                scan.evidence("mixin-annotation:" + node.name,
                        "@Mixin " + node.name.replace('/', '.'));
                scanMixinTargets(annotation, scan);
                counts[4]++;
                continue;
            }
            if (desc.startsWith(MIXIN_PREFIX)) {
                scan.keepClass(node.name);
                scan.evidence("mixin-annotation:" + node.name + ":" + desc,
                        desc + " on " + node.name.replace('/', '.'));
                counts[4]++;
                continue;
            }
            if (desc.startsWith(FORGE_PREFIX) || desc.startsWith(LEGACY_FORGE_PREFIX)) {
                scan.keepClass(node.name);
                scan.evidence("forge-annotation:" + node.name + ":" + desc,
                        desc + " on " + node.name.replace('/', '.'));
                counts[0]++;
                continue;
            }
            if (desc.startsWith(NEOFORGE_PREFIX)) {
                scan.keepClass(node.name);
                scan.evidence("neoforge-annotation:" + node.name + ":" + desc,
                        desc + " on " + node.name.replace('/', '.'));
                counts[1]++;
                continue;
            }
            if (desc.startsWith(FABRIC_PREFIX)) {
                scan.keepClass(node.name);
                scan.evidence("fabric-annotation:" + node.name + ":" + desc,
                        desc + " on " + node.name.replace('/', '.'));
                counts[2]++;
                continue;
            }
            if (desc.startsWith(QUILT_PREFIX)) {
                scan.keepClass(node.name);
                scan.evidence("quilt-annotation:" + node.name + ":" + desc,
                        desc + " on " + node.name.replace('/', '.'));
                counts[3]++;
            }
        }
        return counts;
    }

    private static void scanMixinTargets(AnnotationNode annotation, MinecraftScan scan) {
        List<Object> values = annotation.values;
        if (values == null) {
            return;
        }
        for (int i = 0; i + 1 < values.size(); i += 2) {
            Object key = values.get(i);
            if (!(key instanceof String)) {
                continue;
            }
            String name = (String) key;
            if (!"value".equals(name) && !"targets".equals(name)) {
                continue;
            }
            collectTargets(values.get(i + 1), scan);
        }
    }

    private static void collectTargets(Object value, MinecraftScan scan) {
        if (value == null) {
            return;
        }
        if (value instanceof Type) {
            Type type = (Type) value;
            if (type.getSort() == Type.OBJECT) {
                scan.targetClass(type.getInternalName());
            }
            return;
        }
        if (value instanceof String) {
            String text = ((String) value).trim();
            if (text.startsWith("L") && text.endsWith(";") && text.length() > 2) {
                text = text.substring(1, text.length() - 1);
            }
            scan.targetClass(text);
            return;
        }
        List<Object> list = MinecraftJson.asList(value);
        if (list != null) {
            for (Object item : list) {
                collectTargets(item, scan);
            }
        }
    }

    private static void scanCoremodInterfaces(ClassNode node, MinecraftScan scan) {
        if (node.interfaces == null) {
            return;
        }
        for (String iface : node.interfaces) {
            if (iface == null) {
                continue;
            }
            if (iface.indexOf("IFMLLoadingPlugin") >= 0 || iface.indexOf("ICoreMod") >= 0) {
                scan.freezeClass(node.name);
                boolean neo = iface.startsWith("net/neoforged/");
                if (neo) {
                    scan.loaderNeoForge();
                } else {
                    scan.loaderForge();
                }
                scan.evidence("coremod-interface:" + node.name,
                        iface.replace('/', '.') + " implemented by " + node.name.replace('/', '.'));
                return;
            }
        }
    }
}
