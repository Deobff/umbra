package io.umbra.tests;

import io.umbra.core.minecraft.MixinAnalysis;
import io.umbra.core.minecraft.MixinAnalyzer;
import io.umbra.core.model.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

/**
 * Plain-main tests for {@link MixinAnalyzer}.
 *
 * <p>Synthetic {@code ClassNode}s are built with the ASM tree API; no Minecraft
 * or Mixin dependency is needed because the analyzer only reads annotation
 * descriptors. Arrays are represented as {@code List} values, exactly like
 * {@code ClassReader} produces them, so the test exercises the same shape the
 * production scan sees.</p>
 */
public final class MixinAnalyzerTest {

    private static final String MIXIN = "Lorg/spongepowered/asm/mixin/Mixin;";
    private static final String SHADOW = "Lorg/spongepowered/asm/mixin/Shadow;";
    private static final String OVERWRITE = "Lorg/spongepowered/asm/mixin/Overwrite;";
    private static final String ACCESSOR = "Lorg/spongepowered/asm/mixin/gen/Accessor;";
    private static final String INVOKER = "Lorg/spongepowered/asm/mixin/gen/Invoker;";
    private static final String INJECT = "Lorg/spongepowered/asm/mixin/injection/Inject;";
    private static final String REDIRECT = "Lorg/spongepowered/asm/mixin/injection/Redirect;";
    private static final String MODIFY_ARG = "Lorg/spongepowered/asm/mixin/injection/ModifyArg;";
    private static final String MODIFY_ARGS = "Lorg/spongepowered/asm/mixin/injection/ModifyArgs;";
    private static final String MODIFY_VARIABLE = "Lorg/spongepowered/asm/mixin/injection/ModifyVariable;";
    private static final String MODIFY_CONSTANT = "Lorg/spongepowered/asm/mixin/injection/ModifyConstant;";
    private static final String WRAP_OPERATION = "Lcom/llamalad7/mixinextras/injector/WrapOperation;";
    private static final String INJECTION_AT = "Lorg/spongepowered/asm/mixin/injection/At;";
    private static final String REFMAP_RESOURCE = "examplemod-refmap.json";
    private static final String REFMAP_JSON = lines(
            "{",
            "  \"mappings\": {",
            "    \"com.example.mod.target.BlockTicker\": {",
            "      \"tick(I)V\": \"func_1234_a\",",
            "      \"counter\": \"field_5678_b\",",
            "      \"overwriteThing(J)Ljava/lang/String;\": \"func_9999_z\",",
            "      \"compute\": \"func_7777_c\",",
            "      \"unusedName\": \"func_0000_x\"",
            "    },",
            "    \"com/example/mod/target/Helper\": {",
            "      \"helper ()V\": \"func_4242_h\"",
            "    }",
            "  },",
            "  \"data\": {",
            "    \"searge\": {",
            "      \"com.example.mod.target.BlockTicker\": \"com.example.mod.target.BlockTicker\",",
            "      \"com/example/mod/target/Helper\": \"com/example/mod/target/Helper\"",
            "    }",
            "  }",
            "}");


    private static int checks;

    private MixinAnalyzerTest() {
    }

    public static void main(String[] args) {
        testMixinTargets();
        testShadowMembers();
        testAccessorAndInvoker();
        testInjectionForms();
        testDedupeAndDeterminism();
        testMalformedValuesTolerated();
        testRefmapMapping();
        testRefmapRemapFlags();
        testRefmapClassAlias();
        testRefmapDeclaredByConfig();
        testRefmapMalformedTolerated();
        testRefmapDisabled();
        System.out.println("MixinAnalyzerTest: " + checks + " checks passed");
    }

    private static void testMixinTargets() {
        ClassNode mixinA = newClass("mod/mixins/MixinA");
        addClassAnnotation(mixinA, true, annotation(MIXIN,
                "value", Arrays.asList(
                        Type.getObjectType("net/minecraft/entity/Entity"),
                        Type.getObjectType("net/minecraft/entity/Entity$1")),
                "targets", Arrays.asList("net.minecraft.world.World", ""),
                "remap", Boolean.FALSE));

        ClassNode mixinB = newClass("mod/mixins/MixinB");
        addClassAnnotation(mixinB, false, annotation(MIXIN,
                "targets", Arrays.asList("com.example.Dotted")));

        ClassNode plainClass = newClass("mod/Plain");
        addField(plainClass, field("value", "I"));

        MixinAnalysis analysis = MixinAnalyzer.analyze(poolOf(mixinA, mixinB, plainClass));

        check(analysis.mixinClasses().equals(Arrays.asList(
                "mod/mixins/MixinA", "mod/mixins/MixinB")),
                "mixinClasses lists only @Mixin classes");
        check(analysis.targetClasses().equals(Arrays.asList(
                "com/example/Dotted",
                "net/minecraft/entity/Entity",
                "net/minecraft/entity/Entity$1",
                "net/minecraft/world/World")),
                "targetClasses from value Type[] and targets String[]");
        checkContains(analysis.keepRules(), "mod/mixins/MixinA", "mixin class keep glob");
        checkContains(analysis.keepRules(), "net/minecraft/entity/Entity$1", "nested target keep glob");
        checkContains(analysis.bodySkipGlobs(), "mod/mixins/MixinB", "invisible @Mixin body skip");
        checkContains(analysis.bodySkipGlobs(), "com/example/Dotted", "dotted target body skip");
        checkContains(analysis.bodySkipGlobs(), "net/minecraft/world/World", "target body skip");
        checkMissing(analysis.keepRules(), "mod/Plain", "non-mixin class is not kept");
        checkMissing(analysis.bodySkipGlobs(), "mod/Plain", "non-mixin class body is not exempt");
        checkContains(analysis.notes(), "ignored empty @Mixin target in @Mixin(mod/mixins/MixinA).targets",
                "empty target entry produces a note");
        checkUniqueAndSorted(analysis);
    }

    private static void testShadowMembers() {
        ClassNode mixin = newClass("mod/mixins/ShadowMixin");
        addClassAnnotation(mixin, true, annotation(MIXIN,
                "targets", Arrays.asList(
                        "net/minecraft/world/level/Level",
                        "net/minecraft/world/level/LevelAccessor")));

        addField(mixin, field("value", "I"), annotation(SHADOW));
        addInvisibleField(mixin, field("shadow$hidden", "J"), annotation(SHADOW));
        addField(mixin, field("notShadowed", "I"));

        addMethod(mixin, "tick", "(I)V", annotation(SHADOW));
        addInvisibleMethod(mixin, "shadow$helper", "()V", annotation(SHADOW));
        addMethod(mixin, "shadowedInject", "()V",
                annotation(SHADOW), annotation(INJECT, "method", "injected()V"));
        addMethod(mixin, "plain", "()V");

        MixinAnalysis analysis = MixinAnalyzer.analyze(poolOf(mixin));

        for (String owner : new String[] { "net/minecraft/world/level/Level",
                "net/minecraft/world/level/LevelAccessor" }) {
            checkContains(analysis.keepRules(), owner + "#value", "shadow field keep");
            checkMissing(analysis.keepRules(), owner + "#value:I",
                    "field names are kept without a descriptor (rule grammar has none)");
            checkContains(analysis.keepRules(), owner + "#hidden", "shadow$ field alias keep");
            checkContains(analysis.keepRules(), owner + "#shadow$hidden",
                    "prefixed shadow field name kept conservatively as well");
            checkContains(analysis.keepRules(), owner + "#tick(I)V", "shadow method keep");
            checkContains(analysis.keepRules(), owner + "#helper()V", "shadow$ method alias keep");
            checkContains(analysis.keepRules(), owner + "#shadowedInject()V",
                    "@Shadow member with an injector still keeps own target member");
            checkContains(analysis.keepRules(), owner + "#injected()V",
                    "@Shadow + @Inject also keeps the injected method");
            checkMissing(analysis.keepRules(), owner + "#notShadowed", "plain field not kept");
            checkMissing(analysis.keepRules(), owner + "#plain()V", "plain method not kept");
        }
        checkContains(analysis.notes(),
                "shadow$ prefix treated as shadow alias in: mod/mixins/ShadowMixin",
                "shadow$ usage is noted");
        checkUniqueAndSorted(analysis);
    }

    private static void testAccessorAndInvoker() {
        ClassNode mixin = newClass("mod/mixins/AccessorMixin");
        addClassAnnotation(mixin, true, annotation(MIXIN,
                "value", Arrays.asList(Type.getObjectType("net/minecraft/world/Container"))));

        addMethod(mixin, "getItems", "()Ljava/util/List;", annotation(ACCESSOR, "value", "items"));
        addMethod(mixin, "setSize", "(I)V", annotation(ACCESSOR, "value", "size"));
        addInvisibleMethod(mixin, "callSetItem", "(ILjava/lang/Object;)V",
                annotation(INVOKER, "value", "setItem"));
        addMethod(mixin, "getDerived", "()I", annotation(ACCESSOR));
        addMethod(mixin, "callHidden", "()V", annotation(INVOKER));

        MixinAnalysis analysis = MixinAnalyzer.analyze(poolOf(mixin));
        String owner = "net/minecraft/world/Container";

        checkContains(analysis.keepRules(), owner + "#items", "@Accessor value keep (desc-less)");
        checkContains(analysis.keepRules(), owner + "#size", "@Accessor value keep");
        checkContains(analysis.keepRules(), owner + "#setItem", "@Invoker value keep");
        checkMissing(analysis.keepRules(), owner + "#getItems()Ljava/util/List;",
                "accessor keeps the target field name, not the accessor method");
        checkContains(analysis.keepRules(), owner + "#derived", "@Accessor target derived from name");
        checkContains(analysis.keepRules(), owner + "#hidden", "@Invoker call-prefix target derived");
        checkContains(analysis.notes(), "@Accessor target derived from method name: "
                + "mod/mixins/AccessorMixin#getDerived -> derived", "@Accessor derivation noted");
        checkUniqueAndSorted(analysis);
    }

    private static void testInjectionForms() {
        ClassNode mixin = newClass("mod/mixins/InjectMixin");
        addClassAnnotation(mixin, true, annotation(MIXIN,
                "value", Arrays.asList(
                        Type.getObjectType("net/minecraft/entity/Entity"),
                        Type.getObjectType("net/minecraft/entity/Player"))));

        addMethod(mixin, "injectSimple", "()V",
                annotation(INJECT, "method", "foo(I)V"));
        addMethod(mixin, "injectArray", "()V",
                annotation(INJECT, "method", Arrays.asList("a()V", "b(I)I")));
        addMethod(mixin, "redirectInternalOwner", "()V",
                annotation(REDIRECT, "method", "Lfoo/Bar;baz(Ljava/lang/String;)V"));
        addMethod(mixin, "redirectDottedOwner", "()V",
                annotation(REDIRECT, "method", "net.minecraft.util.Thing.pop()V"));
        addMethod(mixin, "modifyVariable", "()V",
                annotation(MODIFY_VARIABLE, "method", "tick()V", "ordinal", Integer.valueOf(0)));
        addInvisibleMethod(mixin, "modifyConstant", "()V",
                annotation(MODIFY_CONSTANT, "method", Arrays.asList("constants()V")));
        addMethod(mixin, "wrapOperation", "()V",
                annotation(WRAP_OPERATION, "method", "wrapped()V"));
        addMethod(mixin, "modifyArgPlain", "()V",
                annotation(MODIFY_ARG, "method", "doThing"));
        addMethod(mixin, "modifyArgsNested", "()V",
                annotation(MODIFY_ARGS, "method", Arrays.asList(
                        Arrays.asList("nested()V", "other()V"))));
        addMethod(mixin, "overwriteMe", "(J)Ljava/lang/String;", annotation(OVERWRITE));
        addMethod(mixin, "injectCtor", "()V",
                annotation(INJECT, "method", "<init>()V"));
        addMethod(mixin, "injectBroken", "()V",
                annotation(INJECT, "method", "Lfoo/Bar;"));

        MixinAnalysis analysis = MixinAnalyzer.analyze(poolOf(mixin));
        String[] targets = { "net/minecraft/entity/Entity", "net/minecraft/entity/Player" };

        for (String owner : targets) {
            checkContains(analysis.keepRules(), owner + "#foo(I)V",
                    "@Inject name(desc) resolved against every target");
            checkContains(analysis.keepRules(), owner + "#a()V", "@Inject string array form");
            checkContains(analysis.keepRules(), owner + "#b(I)I", "@Inject string array form");
            checkContains(analysis.keepRules(), owner + "#tick()V", "@ModifyVariable method");
            checkContains(analysis.keepRules(), owner + "#doThing", "plain name keeps any descriptor");
            checkContains(analysis.keepRules(), owner + "#nested()V", "nested array form");
            checkContains(analysis.keepRules(), owner + "#other()V", "nested array form");
            checkContains(analysis.keepRules(), owner + "#constants()V",
                    "invisible @ModifyConstant method target");
            checkContains(analysis.keepRules(), owner + "#wrapped()V",
                    "MixinExtras @WrapOperation method target");
            checkContains(analysis.keepRules(), owner + "#overwriteMe(J)Ljava/lang/String;",
                    "@Overwrite keeps the annotated member on the target");
        }

        checkContains(analysis.keepRules(), "foo/Bar#baz(Ljava/lang/String;)V",
                "Lowner;name(desc) explicit owner rule");
        checkContains(analysis.keepRules(), "foo/Bar", "explicit injection owner class kept");
        checkContains(analysis.bodySkipGlobs(), "foo/Bar",
                "explicit injection owner body skipped");
        checkContains(analysis.keepRules(), "net/minecraft/util/Thing#pop()V",
                "dotted owner.name(desc) explicit owner rule");
        checkContains(analysis.notes(),
                "kept explicit injection owner outside @Mixin targets: foo/Bar",
                "explicit owner noted");
        checkMissing(analysis.keepRules(), "net/minecraft/entity/Entity#<init>()V",
                "constructor target skipped");
        checkMissing(analysis.keepRules(), "net/minecraft/entity/Entity#<clinit>()V",
                "initializer target skipped");
        checkContains(analysis.notes(), "skipped constructor/initializer target '<init>()V' in "
                + "@Inject on mod/mixins/InjectMixin#injectCtor", "constructor skip noted");
        checkUniqueAndSorted(analysis);
    }

    private static void testDedupeAndDeterminism() {
        ClassNode mixinX = newClass("mod/mixins/DupeX");
        addClassAnnotation(mixinX, true, annotation(MIXIN, "targets", Arrays.asList("net/minecraft/Foo")));
        addField(mixinX, field("bar", "I"), annotation(SHADOW));
        addMethod(mixinX, "inject", "(I)V", annotation(INJECT, "method", "baz()V"));

        ClassNode mixinY = newClass("mod/mixins/DupeY");
        addClassAnnotation(mixinY, true, annotation(MIXIN, "value",
                Arrays.asList(Type.getObjectType("net/minecraft/Foo"))));
        addField(mixinY, field("bar", "I"), annotation(SHADOW));
        addMethod(mixinY, "inject", "(I)V", annotation(INJECT, "method", "baz()V"));

        MixinAnalysis first = MixinAnalyzer.analyze(poolOf(mixinX, mixinY));
        MixinAnalysis second = MixinAnalyzer.analyze(poolOf(mixinY, mixinX));

        check(first.targetClasses().size() == 1, "duplicate targets collapse to one class");
        check(first.targetClasses().get(0).equals("net/minecraft/Foo"), "unique target name");
        check(countOccurrences(first.keepRules(), "net/minecraft/Foo#bar") == 1,
                "shadow rule emitted once");
        check(countOccurrences(first.keepRules(), "net/minecraft/Foo#baz()V") == 1,
                "inject rule emitted once");
        check(first.mixinClasses().size() == 2, "both mixin classes reported once each");
        check(first.keepRules().equals(second.keepRules()), "rule order is input-order independent");
        check(first.bodySkipGlobs().equals(second.bodySkipGlobs()), "body skip order is stable");
        check(first.notes().equals(second.notes()), "notes are stable");
        checkUniqueAndSorted(first);
    }

    private static void testMalformedValuesTolerated() {
        ClassNode broken = newClass("mod/BrokenMixin");
        addClassAnnotation(broken, true, annotation(MIXIN,
                "value", Integer.valueOf(42),
                "targets", Arrays.asList(Integer.valueOf(7), null, "")));
        addField(broken, field("orphan", "I"), annotation(SHADOW));
        addMethod(broken, "badInject", "()V", annotation(INJECT, "method", Integer.valueOf(3)));
        addMethod(broken, "emptyInject", "()V", annotation(INJECT, "method", ""));
        addMethod(broken, "nullInject", "()V", annotation(INJECT, "method", null));
        addMethod(broken, "nullValues", "()V", new AnnotationNode(INJECT));

        ClassNode noValues = newClass("mod/NoValuesMixin");
        AnnotationNode bareMixin = new AnnotationNode(MIXIN);
        addClassAnnotation(noValues, true, bareMixin);

        MixinAnalysis analysis;
        try {
            analysis = MixinAnalyzer.analyze(poolOf(broken, noValues));
        } catch (RuntimeException e) {
            throw new AssertionError("malformed annotations must not throw: " + e);
        }
        checks++;
        check(analysis.mixinClasses().contains("mod/BrokenMixin"), "broken mixin class still reported");
        check(analysis.mixinClasses().contains("mod/NoValuesMixin"), "target-less mixin still reported");
        checkContains(analysis.bodySkipGlobs(), "mod/BrokenMixin", "broken mixin body skipped");
        checkContains(analysis.notes(), "@Mixin without resolvable targets: mod/BrokenMixin",
                "target-less @Mixin noted");
        checkContains(analysis.notes(), "@Mixin without resolvable targets: mod/NoValuesMixin",
                "annotation without values noted");
        checkContains(analysis.notes(), "@Shadow field without resolvable @Mixin targets: "
                + "mod/BrokenMixin#orphan", "orphan shadow noted");
        checkMissing(analysis.keepRules(), "mod/BrokenMixin#orphan",
                "orphan shadow emits no member rule");
        for (String rule : analysis.keepRules()) {
            check(rule.indexOf("42") < 0 && rule.indexOf("null") < 0 && rule.indexOf("Integer") < 0,
                    "malformed value never reaches a keep rule: " + rule);
        }

        MixinAnalysis empty = MixinAnalyzer.analyze(null);
        check(empty.mixinClasses().isEmpty() && empty.targetClasses().isEmpty()
                        && empty.keepRules().isEmpty() && empty.bodySkipGlobs().isEmpty(),
                "null pool yields EMPTY");
        MixinAnalysis emptyPool = MixinAnalyzer.analyze(new ClassPool());
        check(emptyPool.mixinClasses().isEmpty() && emptyPool.keepRules().isEmpty(),
                "empty pool yields no rules");

        ClassNode nullDesc = newClass("mod/NullDesc");
        AnnotationNode weird = new AnnotationNode((String) null);
        if (nullDesc.visibleAnnotations == null) {
            nullDesc.visibleAnnotations = new ArrayList<AnnotationNode>();
        }
        nullDesc.visibleAnnotations.add(weird);
        MixinAnalysis stillFine = MixinAnalyzer.analyze(poolOf(nullDesc));
        check(stillFine.mixinClasses().isEmpty(), "annotation with null descriptor ignored");
        checkUniqueAndSorted(analysis);
    }


    /**
     * Forge 1.12-1.16 mixins write the target member in the pre-obfuscation
     * namespace and rely on the refmap to reach the production name, so the
     * production name has to survive renaming as well.
     */
    private static void testRefmapMapping() {
        ClassNode mixin = newClass("mod/mixins/RefmapMixin");
        addClassAnnotation(mixin, true, annotation(MIXIN,
                "targets", Arrays.asList("com.example.mod.target.BlockTicker")));
        addMethod(mixin, "injectTick", "()V", annotation(INJECT, "method", "tick(I)V"));
        addField(mixin, field("counter", "I"), annotation(SHADOW));
        addMethod(mixin, "overwriteThing", "(J)Ljava/lang/String;", annotation(OVERWRITE));
        addMethod(mixin, "callCompute", "()V", annotation(INVOKER, "value", "compute"));
        addMethod(mixin, "injectAt", "()V", annotation(INJECT, "method", "tick(I)V",
                "at", annotation(INJECTION_AT, "target",
                        "Lcom/example/mod/target/Helper;helper()V")));
        addMethod(mixin, "injectUnknown", "()V", annotation(INJECT, "method", "unknownThing()V"));

        ClassPool pool = poolOf(mixin);
        resource(pool, REFMAP_RESOURCE, REFMAP_JSON);

        MixinAnalysis analysis = MixinAnalyzer.analyze(pool);
        String owner = "com/example/mod/target/BlockTicker";
        checkContains(analysis.keepRules(), owner + "#tick(I)V", "literal @Inject reference kept");
        checkContains(analysis.keepRules(), owner + "#func_1234_a",
                "refmap production name kept for @Inject");
        checkMissing(analysis.keepRules(), owner + "#func_1234_a(I)V",
                "refmap-derived rule is descriptor-less");
        checkContains(analysis.keepRules(), owner + "#counter", "literal @Shadow field kept");
        checkContains(analysis.keepRules(), owner + "#field_5678_b",
                "@Shadow field production name kept");
        checkContains(analysis.keepRules(), owner + "#overwriteThing(J)Ljava/lang/String;",
                "literal @Overwrite kept");
        checkContains(analysis.keepRules(), owner + "#func_9999_z",
                "@Overwrite production name kept");
        checkContains(analysis.keepRules(), owner + "#compute", "literal @Invoker value kept");
        checkContains(analysis.keepRules(), owner + "#func_7777_c",
                "@Invoker production name kept");
        checkContains(analysis.keepRules(), "com/example/mod/target/Helper#helper()V",
                "literal @At target kept");
        checkContains(analysis.keepRules(), "com/example/mod/target/Helper#func_4242_h",
                "@At target production name kept");
        checkMissing(analysis.keepRules(), owner + "#func_0000_x",
                "an unreferenced refmap entry is not kept");
        checkMissing(analysis.keepRules(), owner + "#unknownThing",
                "a reference without a refmap entry keeps only its literal rule");
        check(analysis.refmapFiles().equals(Collections.singletonList(REFMAP_RESOURCE)),
                "refmap file reported: " + analysis.refmapFiles());
        checkContains(analysis.refmapHits(), owner + "#tick->func_1234_a", "refmap hit recorded");
        checkContains(analysis.refmapHits(), owner + "#counter->field_5678_b",
                "refmap field hit recorded");
        check(analysis.refmapHits().size() == 5,
                "one hit per translated reference: " + analysis.refmapHits());
        checkContains(analysis.notes(), "mixin refmap: 6 member mapping(s) for 2 class(es) "
                        + "in 1 refmap file(s), 5 reference(s) kept under their production name",
                "refmap summary note");
        checkUniqueAndSorted(analysis);
    }

    private static void testRefmapRemapFlags() {
        ClassNode classLevel = newClass("mod/mixins/NoRemapMixin");
        addClassAnnotation(classLevel, true, annotation(MIXIN,
                "targets", Arrays.asList("com.example.mod.target.BlockTicker"),
                "remap", Boolean.FALSE));
        addMethod(classLevel, "injectTick", "()V", annotation(INJECT, "method", "tick(I)V"));

        ClassNode annotationLevel = newClass("mod/mixins/AnnotationNoRemapMixin");
        addClassAnnotation(annotationLevel, true, annotation(MIXIN,
                "targets", Arrays.asList("com.example.mod.target.BlockTicker")));
        addMethod(annotationLevel, "injectTick", "()V",
                annotation(INJECT, "method", "tick(I)V", "remap", Boolean.FALSE));

        ClassPool pool = poolOf(classLevel, annotationLevel);
        resource(pool, REFMAP_RESOURCE, REFMAP_JSON);

        MixinAnalysis analysis = MixinAnalyzer.analyze(pool);
        String owner = "com/example/mod/target/BlockTicker";
        checkContains(analysis.keepRules(), owner + "#tick(I)V",
                "literal rule is kept even when remapping is off");
        checkMissing(analysis.keepRules(), owner + "#func_1234_a",
                "@Mixin(remap=false) and annotation remap=false suppress the translation");
        check(analysis.refmapHits().isEmpty(),
                "no refmap hit when remapping is off: " + analysis.refmapHits());
    }

    private static void testRefmapClassAlias() {
        ClassNode mixin = newClass("mod/mixins/AliasMixin");
        addClassAnnotation(mixin, true, annotation(MIXIN,
                "targets", Arrays.asList("com.example.mod.target.OldName")));
        addMethod(mixin, "injectTick", "()V", annotation(INJECT, "method", "tick()V"));

        ClassPool pool = poolOf(mixin);
        resource(pool, "alias-refmap.json", lines(
                "{",
                "  \"mappings\": {",
                "    \"com.example.mod.target.NewName\": {",
                "      \"tick\": \"a\"",
                "    }",
                "  },",
                "  \"data\": {",
                "    \"searge\": {",
                "      \"com.example.mod.target.OldName\": \"com.example.mod.target.NewName\"",
                "    }",
                "  }",
                "}"));

        MixinAnalysis analysis = MixinAnalyzer.analyze(pool);
        checkContains(analysis.keepRules(), "com/example/mod/target/NewName#a",
                "production member kept on the refmap-aliased owner");
        checkContains(analysis.keepRules(), "com/example/mod/target/NewName",
                "aliased owner class kept");
        checkContains(analysis.bodySkipGlobs(), "com/example/mod/target/NewName",
                "aliased owner body skipped");
        checkContains(analysis.targetClasses(), "com/example/mod/target/NewName",
                "aliased owner reported as a target");
        checkContains(analysis.refmapHits(), "com/example/mod/target/NewName#tick->a",
                "alias hit recorded");
        checkContains(analysis.notes(),
                "mixin target com/example/mod/target/OldName is aliased to "
                        + "com/example/mod/target/NewName by the refmap data section",
                "alias noted");
    }

    private static void testRefmapDeclaredByConfig() {
        ClassNode mixin = newClass("mod/mixins/DeclaredMixin");
        addClassAnnotation(mixin, true, annotation(MIXIN,
                "targets", Arrays.asList("com.example.Declared")));
        addMethod(mixin, "inject", "()V", annotation(INJECT, "method", "go()V"));

        ClassPool pool = poolOf(mixin);
        resource(pool, "declared.mixins.json", lines(
                "{",
                "  \"package\": \"mod.mixins\",",
                "  \"refmap\": \"names.json\",",
                "  \"mixins\": [\"DeclaredMixin\"]",
                "}"));
        resource(pool, "names.json", lines(
                "{",
                "  \"mappings\": {",
                "    \"com.example.Declared\": {",
                "      \"go\": \"func_5_a\"",
                "    }",
                "  }",
                "}"));

        MixinAnalysis analysis = MixinAnalyzer.analyze(pool);
        checkContains(analysis.keepRules(), "com/example/Declared#func_5_a",
                "a refmap whose file name does not mention refmap is read via the config");
        checkContains(analysis.refmapFiles(), "names.json",
                "declared refmap file reported: " + analysis.refmapFiles());
    }

    private static void testRefmapMalformedTolerated() {
        ClassNode mixin = newClass("mod/mixins/BrokenRefmapMixin");
        addClassAnnotation(mixin, true, annotation(MIXIN,
                "targets", Arrays.asList("net/minecraft/Foo")));
        addMethod(mixin, "inject", "()V", annotation(INJECT, "method", "bar()V"));

        ClassPool pool = poolOf(mixin);
        resource(pool, "broken-refmap.json", "{\"mappings\": {\"net/minecraft/Foo\": {");

        MixinAnalysis analysis;
        try {
            analysis = MixinAnalyzer.analyze(pool);
        } catch (RuntimeException e) {
            throw new AssertionError("malformed refmap must not throw: " + e);
        }
        checks++;
        check(anyContains(analysis.notes(), "mixin refmap broken-refmap.json could not be parsed"),
                "malformed refmap noted: " + analysis.notes());
        checkContains(analysis.keepRules(), "net/minecraft/Foo#bar()V",
                "literal rule survives a broken refmap");
        check(analysis.refmapHits().isEmpty(), "broken refmap produces no hits");
        check(analysis.refmapFiles().isEmpty(), "broken refmap is not reported as used");
    }

    private static void testRefmapDisabled() {
        ClassNode mixin = newClass("mod/mixins/DisabledRefmapMixin");
        addClassAnnotation(mixin, true, annotation(MIXIN,
                "targets", Arrays.asList("com.example.mod.target.BlockTicker")));
        addMethod(mixin, "injectTick", "()V", annotation(INJECT, "method", "tick(I)V"));

        ClassPool pool = poolOf(mixin);
        resource(pool, REFMAP_RESOURCE, REFMAP_JSON);

        MixinAnalysis off = MixinAnalyzer.analyze(pool, false);
        checkContains(off.keepRules(), "com/example/mod/target/BlockTicker#tick(I)V",
                "literal rule kept when the refmap is disabled");
        checkMissing(off.keepRules(), "com/example/mod/target/BlockTicker#func_1234_a",
                "no translated rule when the refmap is disabled");
        checkContains(off.notes(), "mixin refmap mapping disabled by minecraft.refmap=false",
                "disabled note recorded");
        check(off.refmapHits().isEmpty(), "no hits when the refmap is disabled");
        check(off.refmapFiles().isEmpty(), "no refmap files reported when disabled");

        MixinAnalysis on = MixinAnalyzer.analyze(pool, true);
        check(on.refmapHits().size() == 1, "enabled run records the hit: " + on.refmapHits());
        MixinAnalysis repeat = MixinAnalyzer.analyze(pool, true);
        check(repeat.refmapHits().equals(on.refmapHits()), "refmap hits are deterministic");
        check(repeat.keepRules().equals(on.keepRules()), "refmap rules are deterministic");
    }

    private static ClassNode newClass(String name) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC;
        node.name = name;
        node.superName = "java/lang/Object";
        return node;
    }

    private static AnnotationNode annotation(String desc, Object... pairs) {
        AnnotationNode node = new AnnotationNode(desc);
        node.values = new ArrayList<Object>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            node.values.add(pairs[i]);
            node.values.add(pairs[i + 1]);
        }
        return node;
    }

    private static void addClassAnnotation(ClassNode node, boolean visible, AnnotationNode annotation) {
        List<AnnotationNode> list = visible ? node.visibleAnnotations : node.invisibleAnnotations;
        if (list == null) {
            list = new ArrayList<AnnotationNode>();
            if (visible) {
                node.visibleAnnotations = list;
            } else {
                node.invisibleAnnotations = list;
            }
        }
        list.add(annotation);
    }

    private static FieldNode field(String name, String desc) {
        return new FieldNode(Opcodes.ACC_PRIVATE, name, desc, null, null);
    }

    private static void addField(ClassNode node, FieldNode field, AnnotationNode... annotations) {
        addFieldAnnotations(field, true, annotations);
        node.fields.add(field);
    }

    private static void addInvisibleField(ClassNode node, FieldNode field,
                                          AnnotationNode... annotations) {
        addFieldAnnotations(field, false, annotations);
        node.fields.add(field);
    }

    private static void addFieldAnnotations(FieldNode field, boolean visible,
                                            AnnotationNode... annotations) {
        for (AnnotationNode annotation : annotations) {
            if (visible) {
                if (field.visibleAnnotations == null) {
                    field.visibleAnnotations = new ArrayList<AnnotationNode>();
                }
                field.visibleAnnotations.add(annotation);
            } else {
                if (field.invisibleAnnotations == null) {
                    field.invisibleAnnotations = new ArrayList<AnnotationNode>();
                }
                field.invisibleAnnotations.add(annotation);
            }
        }
    }

    private static MethodNode addMethod(ClassNode node, String name, String desc,
                                        AnnotationNode... annotations) {
        return addMethod(node, name, desc, true, annotations);
    }

    private static MethodNode addInvisibleMethod(ClassNode node, String name, String desc,
                                                 AnnotationNode... annotations) {
        return addMethod(node, name, desc, false, annotations);
    }

    private static MethodNode addMethod(ClassNode node, String name, String desc, boolean visible,
                                        AnnotationNode... annotations) {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, name, desc, null, null);
        for (AnnotationNode annotation : annotations) {
            if (visible) {
                if (method.visibleAnnotations == null) {
                    method.visibleAnnotations = new ArrayList<AnnotationNode>();
                }
                method.visibleAnnotations.add(annotation);
            } else {
                if (method.invisibleAnnotations == null) {
                    method.invisibleAnnotations = new ArrayList<AnnotationNode>();
                }
                method.invisibleAnnotations.add(annotation);
            }
        }
        node.methods.add(method);
        return method;
    }

    private static ClassPool poolOf(ClassNode... nodes) {
        ClassPool pool = new ClassPool();
        for (ClassNode node : nodes) {
            pool.putClass(node.name + ".class", new byte[0], node);
        }
        return pool;
    }

    private static void resource(ClassPool pool, String name, String text) {
        pool.putResource(name, text.getBytes(StandardCharsets.UTF_8), 0L, 0);
    }

    private static String lines(String... lines) {
        return String.join("\n", lines);
    }

    private static boolean anyContains(List<String> values, String fragment) {
        for (String value : values) {
            if (value != null && value.contains(fragment)) {
                return true;
            }
        }
        return false;
    }

    private static void check(boolean condition, String what) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + what);
        }
    }

    private static void checkContains(List<String> values, String expected, String what) {
        check(values.contains(expected), what + " (missing '" + expected + "' in " + values + ")");
    }

    private static void checkMissing(List<String> values, String unexpected, String what) {
        check(!values.contains(unexpected), what + " (unexpected '" + unexpected + "')");
    }

    private static int countOccurrences(List<String> values, String expected) {
        int count = 0;
        for (String value : values) {
            if (expected.equals(value)) {
                count++;
            }
        }
        return count;
    }

    private static void checkUniqueAndSorted(MixinAnalysis analysis) {
        checkSorted(analysis.mixinClasses(), "mixinClasses");
        checkSorted(analysis.targetClasses(), "targetClasses");
        checkSorted(analysis.keepRules(), "keepRules");
        checkSorted(analysis.bodySkipGlobs(), "bodySkipGlobs");
        checkSorted(analysis.notes(), "notes");
        checkSorted(analysis.refmapFiles(), "refmapFiles");
        checkSorted(analysis.refmapHits(), "refmapHits");
        checkUnique(analysis.mixinClasses(), "mixinClasses");
        checkUnique(analysis.targetClasses(), "targetClasses");
        checkUnique(analysis.keepRules(), "keepRules");
        checkUnique(analysis.bodySkipGlobs(), "bodySkipGlobs");
        checkUnique(analysis.notes(), "notes");
        checkUnique(analysis.refmapFiles(), "refmapFiles");
        checkUnique(analysis.refmapHits(), "refmapHits");
    }

    private static void checkSorted(List<String> values, String what) {
        List<String> copy = new ArrayList<String>(values);
        Collections.sort(copy);
        check(copy.equals(values), what + " is sorted");
    }

    private static void checkUnique(List<String> values, String what) {
        check(new HashSet<String>(values).size() == values.size(), what + " has no duplicates");
    }
}
