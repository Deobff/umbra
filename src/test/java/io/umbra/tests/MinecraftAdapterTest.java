package io.umbra.tests;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.minecraft.MinecraftAdapter;
import io.umbra.core.minecraft.MinecraftProfile;
import io.umbra.core.model.ClassPool;
import io.umbra.core.util.Log;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Plain-main test harness for the Minecraft mod-container adapter.
 *
 * <p>Builds synthetic {@link ClassPool}s (resource bytes plus hand-built ASM
 * {@link ClassNode}s) for Fabric, Quilt, legacy Forge, modern Forge, NeoForge,
 * mixin-only archives and broken metadata, then checks detection, loader
 * identification, keep rules, body-skip exemptions, frozen classes, preserved
 * resources and the {@link MinecraftProfile#adjust} feature matrix.</p>
 */
public final class MinecraftAdapterTest {

    private static int checks;

    private MinecraftAdapterTest() {
    }

    public static void main(String[] args) throws Exception {
        testPlainJar();
        testFabric();
        testFabricResourceOnly();
        testEntrypointShapes();
        testForgeLegacy();
        testForgeModern();
        testNeoForge();
        testQuilt();
        testMixinOnlyJar();
        testBrokenMetadata();
        testAdjustMatrix();
        testProfileMap();
        System.out.println("MinecraftAdapterTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------------
    // plain jar
    // ------------------------------------------------------------------

    private static void testPlainJar() throws Exception {
        ClassPool pool = new ClassPool();
        addClass(pool, node("com/example/Plain"));
        addClass(pool, node("com/example/Helper"));
        resource(pool, "config.json", "{\"setting\":\"value\"}");
        resource(pool, "META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nMain-Class: com.example.Plain\r\n\r\n");

        List<String> lines = new ArrayList<String>();
        MinecraftProfile profile = MinecraftAdapter.detect(pool, baseConfig(), logTo(lines));
        check(!profile.detected(), "plain jar is not detected as a mod container");
        check("".equals(profile.loader()), "plain jar has no loader");
        check(profile.keepRules().isEmpty(), "plain jar adds no keep rules");
        check(profile.softKeepRules().isEmpty(), "plain jar adds no soft keep rules");
        check(profile.bodySkipGlobs().isEmpty(), "plain jar adds no body-skip globs");
        check(profile.frozenClasses().isEmpty(), "plain jar freezes nothing");
        check(profile.modIds().isEmpty(), "plain jar has no mod ids");
        check(profile.targetCount() == 0, "plain jar has no mixin targets");
        check(profile.classCount() == 0, "plain jar counts no loader classes");
        check(!hasLevel(lines, "WARN"), "plain jar produces no warnings");
        check(profile == MinecraftProfile.NONE, "plain jar returns the NONE profile");

        UmbraConfig base = baseConfig();
        UmbraConfig adjusted = profile.adjust(base);
        check(adjusted == base, "NONE.adjust returns the configuration unchanged");
        check(adjusted.optionBool("classEncryption.enabled", false), "NONE keeps class encryption");
        check(adjusted.methodVirtualization().enabled(), "NONE keeps virtualization");
    }

    // ------------------------------------------------------------------
    // Fabric
    // ------------------------------------------------------------------

    private static void testFabric() throws Exception {
        ClassPool pool = fabricPool();
        List<String> lines = new ArrayList<String>();
        MinecraftProfile profile = MinecraftAdapter.detect(pool, baseConfig(), logTo(lines));

        check(profile.detected(), "fabric container detected");
        check(loaderContains(profile, "fabric"), "fabric loader recorded");
        check(loaderContains(profile, "mixin"), "fabric container records mixin usage");
        check(profile.modIds().contains("examplemod"), "fabric mod id parsed");
        check(profile.evidence().size() > 0, "fabric evidence recorded");
        check(anyContains(profile.evidence(), "fabric.mod.json"), "fabric evidence names the manifest");

        check(has(profile.keepRules(), "com/example/ExampleMod"), "fabric main entry class kept");
        check(has(profile.keepRules(), "com/example/ExampleMod#init"), "fabric entry method kept");
        check(has(profile.keepRules(), "com/example/client/ExampleClient"), "fabric client entry class kept");
        check(has(profile.keepRules(), "com/example/client/ExampleClient#onInitializeClient"),
                "fabric client entry method kept");
        check(has(profile.keepRules(), "com/example/server/ServerEntry"), "fabric server entry class kept");
        check(has(profile.keepRules(), "com/example/client/FabricAnnotated"),
                "fabric annotated class kept");
        check(has(profile.keepRules(), "com/example/mixin/ExampleMixin"), "fabric mixin class kept");
        check(has(profile.keepRules(), "com/example/mixin/ClientMixin"), "fabric client mixin class kept");
        check(has(profile.keepRules(), "com/example/mixin/client/ClientOnlyMixin"),
                "fabric client-only mixin class kept");
        check(has(profile.keepRules(), "com/example/MixinPlugin"), "mixin plugin class kept");
        check(has(profile.keepRules(), "com/example/Target"), "mixin target class kept");
        check(has(profile.keepRules(), "com/example/AwTarget"), "access widener class kept");
        check(has(profile.keepRules(), "com/example/AwTarget#method(Lcom/example/AwType;)V"),
                "access widener method kept with descriptor");
        check(has(profile.keepRules(), "com/example/AwTarget#field"), "access widener field kept");

        check(has(profile.bodySkipGlobs(), "com/example/mixin/ExampleMixin"), "@Mixin class body skipped");
        check(has(profile.bodySkipGlobs(), "com/example/mixin/ClientMixin"), "config mixin class body skipped");
        check(has(profile.bodySkipGlobs(), "com/example/Target"), "mixin target body skipped");
        check(profile.targetCount() >= 1, "mixin target counted");
        check(profile.classCount() >= 10, "kept class count covers entry and mixin classes");
        check(profile.frozenClasses().isEmpty(), "fabric container freezes no classes");

        check(has(profile.preservedResources(), "fabric.mod.json"), "fabric manifest preserved");
        check(has(profile.preservedResources(), "examplemod.mixins.json"), "fabric mixin config preserved");
        check(has(profile.preservedResources(), "examplemod.client.mixins.json"),
                "fabric client mixin config preserved");
        check(has(profile.preservedResources(), "examplemod.accesswidener"), "access widener preserved");
        check(has(profile.preservedResources(), "examplemod-refmap.json"), "mixin refmap preserved");
        check(anyContains(profile.notes(), "nested jar"), "nested jars are reported as unsupported");
        check(anyContains(profile.notes(), "virtualization disabled"), "virtualization downgrade noted");
        check(!hasLevel(lines, "ERROR"), "fabric detection logs no errors");
    }

    private static ClassPool fabricPool() {
        ClassPool pool = new ClassPool();
        addClass(pool, node("com/example/ExampleMod", "init"));
        addClass(pool, node("com/example/client/ExampleClient", "onInitializeClient"));
        addClass(pool, node("com/example/server/ServerEntry"));
        addClass(pool, annotated(node("com/example/client/FabricAnnotated"), "Lnet/fabricmc/api/ClientModInitializer;"));
        ClassNode mixin = node("com/example/mixin/ExampleMixin");
        mixinAnnotation(mixin, "com/example/Target");
        addClass(pool, mixin);
        addClass(pool, node("com/example/mixin/ClientMixin"));
        addClass(pool, node("com/example/mixin/client/ClientOnlyMixin"));
        addClass(pool, node("com/example/MixinPlugin"));
        addClass(pool, node("com/example/Target"));
        addClass(pool, node("com/example/AwTarget"));
        addClass(pool, node("com/example/AwType"));

        resource(pool, "fabric.mod.json", json(
                "{",
                "  \"schemaVersion\": 1,",
                "  \"id\": \"examplemod\",",
                "  \"version\": \"1.0.0\",",
                "  \"entrypoints\": {",
                "    \"main\": [\"com.example.ExampleMod\", \"com.example.ExampleMod::init\"],",
                "    \"client\": [{\"value\": \"com.example.client.ExampleClient::onInitializeClient\",",
                "                \"adapter\": \"default\"}],",
                "    \"server\": [[\"com.example.server.ServerEntry\"]]",
                "  },",
                "  \"mixins\": [\"examplemod.mixins.json\",",
                "             {\"config\": \"examplemod.client.mixins.json\", \"environment\": \"client\"}],",
                "  \"accessWidener\": \"examplemod.accesswidener\",",
                "  \"jars\": [{\"file\": \"nested.jar\"}, \"other.jar\"]",
                "}"));
        resource(pool, "examplemod.mixins.json", json(
                "{",
                "  \"required\": true,",
                "  \"package\": \"com.example.mixin\",",
                "  \"compatibilityLevel\": \"JAVA_8\",",
                "  \"mixins\": [\"ExampleMixin\"],",
                "  \"client\": [\"ClientMixin\"],",
                "  \"server\": [],",
                "  \"plugin\": \"com.example.MixinPlugin\",",
                "  \"refmap\": \"examplemod-refmap.json\"",
                "}"));
        resource(pool, "examplemod.client.mixins.json", json(
                "{",
                "  \"package\": \"com.example.mixin.client\",",
                "  \"client\": [\"ClientOnlyMixin\"]",
                "}"));
        resource(pool, "examplemod.accesswidener", lines(
                "accessWidener v2 named",
                "# widened members referenced by name",
                "accessible class com/example/AwTarget",
                "extendable method com/example/AwTarget method (Lcom/example/AwType;)V",
                "mutable field com/example/AwTarget field Lcom/example/AwType;"));
        return pool;
    }

    private static void testFabricResourceOnly() throws Exception {
        ClassPool pool = new ClassPool();
        resource(pool, "fabric.mod.json", json(
                "{",
                "  \"id\": \"resourceonly\",",
                "  \"entrypoints\": {\"main\": [\"com.example.Absent::onInitialize\"]}",
                "}"));
        MinecraftProfile profile = MinecraftAdapter.detect(pool, baseConfig(), logTo(new ArrayList<String>()));
        check(profile.detected(), "resource-only fabric container detected");
        check(profile.modIds().contains("resourceonly"), "resource-only fabric mod id parsed");
        check(has(profile.keepRules(), "com/example/Absent"), "missing entry class still gets a keep rule");
        check(has(profile.keepRules(), "com/example/Absent#onInitialize"),
                "missing entry method still gets a keep rule");
    }

    /**
     * Regression test for the QA fixture shape: {@code entrypoints} is a map of
     * environment groups whose values are strings, arrays, nested arrays and
     * descriptor objects. Every entry class/method must be kept, and the
     * descriptor's {@code adapter} value must never become a keep rule.
     */
    private static void testEntrypointShapes() throws Exception {
        ClassPool pool = new ClassPool();
        resource(pool, "fabric.mod.json", json(
                "{",
                "  \"schemaVersion\": 1,",
                "  \"id\": \"fixturemod\",",
                "  \"entrypoints\": {",
                "    \"main\": [\"demo.mc.fabric.FabricEntry::onInitialize\"],",
                "    \"client\": [{\"value\": \"demo.mc.fabric.ClientEntry::onInitializeClient\",",
                "                \"adapter\": \"default\"}],",
                "    \"server\": [[\"demo.mc.fabric.ServerEntry\"]],",
                "    \"preLaunch\": [{\"class\": \"demo.mc.fabric.PreLaunchEntry\",",
                "                    \"method\": \"preLaunch\"}]",
                "  }",
                "}"));

        MinecraftProfile profile = MinecraftAdapter.detect(pool, baseConfig(),
                logTo(new ArrayList<String>()));
        check(profile.detected(), "entrypoint fixture container detected");
        check(has(profile.keepRules(), "demo/mc/fabric/FabricEntry"),
                "map-of-arrays entrypoint class kept");
        check(has(profile.keepRules(), "demo/mc/fabric/FabricEntry#onInitialize"),
                "map-of-arrays entrypoint method kept");
        check(has(profile.keepRules(), "demo/mc/fabric/ClientEntry"),
                "descriptor-object entrypoint class kept");
        check(has(profile.keepRules(), "demo/mc/fabric/ClientEntry#onInitializeClient"),
                "descriptor-object entrypoint method kept");
        check(has(profile.keepRules(), "demo/mc/fabric/ServerEntry"),
                "nested-array entrypoint class kept");
        check(has(profile.keepRules(), "demo/mc/fabric/PreLaunchEntry"),
                "class/method descriptor entrypoint class kept");
        check(has(profile.keepRules(), "demo/mc/fabric/PreLaunchEntry#preLaunch"),
                "class/method descriptor entrypoint method kept");
        check(!has(profile.keepRules(), "default"),
                "entrypoint adapter value is not treated as a class");
        check(!profile.keepRules().contains("adapter"),
                "entrypoint adapter key is not treated as a class");
        check(!profile.keepRules().contains("com/example/Absent"),
                "entrypoint fixture has no unrelated keep rules");
    }

    // ------------------------------------------------------------------
    // legacy Forge (mcmod.info + manifest coremod)
    // ------------------------------------------------------------------

    private static void testForgeLegacy() throws Exception {
        ClassPool pool = new ClassPool();
        addClass(pool, node("com/example/legacy/CorePlugin"));
        addClass(pool, node("com/example/legacy/Tweaker"));
        addClass(pool, annotated(node("com/example/legacy/LegacyMod"), "Lnet/minecraftforge/fml/common/Mod;"));
        addClass(pool, node("com/example/legacy/mixin/LegacyMixin"));

        resource(pool, "mcmod.info", json(
                "[",
                "  {",
                "    \"modid\": \"legacymod\",",
                "    \"name\": \"Legacy Mod\",",
                "    \"mcversion\": \"1.12.2\",",
                "    \"version\": \"1.0\"",
                "  }",
                "]"));
        resource(pool, "META-INF/MANIFEST.MF", lines(
                "Manifest-Version: 1.0",
                "FMLCorePlugin: com.example.legacy.CorePlugin",
                "FMLCorePluginContainsFMLMod: true",
                "TweakClass: com.example.legacy.Tweaker",
                "MixinConfigs: legacy.mixins.json",
                "FMLAT: META-INF/legacy_at.cfg",
                ""));
        resource(pool, "legacy.mixins.json", json(
                "{",
                "  \"package\": \"com.example.legacy.mixin\",",
                "  \"mixins\": [\"LegacyMixin\"]",
                "}"));
        resource(pool, "META-INF/legacy_at.cfg", lines(
                "# access transformer entries",
                "public net.minecraft.world.World field",
                "public net.minecraft.entity.Entity method (I)V"));

        List<String> lines = new ArrayList<String>();
        MinecraftProfile profile = MinecraftAdapter.detect(pool, baseConfig(), logTo(lines));
        check(profile.detected(), "legacy Forge container detected");
        check(loaderContains(profile, "forge"), "legacy Forge loader recorded");
        check(profile.modIds().contains("legacymod"), "mcmod.info mod id parsed");
        check(anyContains(profile.evidence(), "mcversion=1.12.2"), "mcmod.info mcversion recorded");

        check(has(profile.keepRules(), "com/example/legacy/LegacyMod"), "@Mod class kept");
        check(has(profile.keepRules(), "com/example/legacy/CorePlugin"), "manifest coremod class kept");
        check(has(profile.keepRules(), "com/example/legacy/Tweaker"), "legacy TweakClass kept");
        check(has(profile.keepRules(), "com/example/legacy/mixin/LegacyMixin"), "legacy mixin class kept");
        check(has(profile.frozenClasses(), "com/example/legacy/CorePlugin"), "coremod class frozen");
        check(has(profile.frozenClasses(), "com/example/legacy/Tweaker"), "TweakClass frozen");
        check(has(profile.bodySkipGlobs(), "com/example/legacy/CorePlugin"), "coremod body skipped");
        check(has(profile.bodySkipGlobs(), "com/example/legacy/mixin/LegacyMixin"),
                "legacy mixin body skipped");
        check(has(profile.keepRules(), "net/minecraft/world/World"), "FMLAT class kept");
        check(has(profile.keepRules(), "net/minecraft/world/World#field"), "FMLAT field kept");
        check(has(profile.keepRules(), "net/minecraft/entity/Entity#method(I)V"),
                "FMLAT method kept with descriptor");
        check(has(profile.preservedResources(), "mcmod.info"), "mcmod.info preserved");
        check(has(profile.preservedResources(), "META-INF/MANIFEST.MF"), "manifest preserved");
        check(has(profile.preservedResources(), "META-INF/legacy_at.cfg"), "FMLAT resource preserved");
    }

    // ------------------------------------------------------------------
    // modern Forge
    // ------------------------------------------------------------------

    private static void testForgeModern() throws Exception {
        ClassPool pool = new ClassPool();
        addClass(pool, annotated(node("com/example/modern/ModernMod"), "Lnet/minecraftforge/fml/common/Mod;"));
        addClass(pool, node("com/example/modern/mixin/ModernMixin"));
        resource(pool, "META-INF/mods.toml", lines(
                "modLoader=\"javafml\"",
                "loaderVersion=\"[40,)\"",
                "license=\"MIT\"",
                "",
                "[[mods]]",
                "modId=\"modernmod\"",
                "version=\"1.2.3\"",
                "displayName=\"Modern Mod\"",
                "",
                "[[mixins]]",
                "config=\"modernmod.mixins.json\"",
                "",
                "[[accessTransformers]]",
                "file=\"META-INF/accesstransformer.cfg\""));
        resource(pool, "modernmod.mixins.json", json(
                "{",
                "  \"package\": \"com.example.modern.mixin\",",
                "  \"mixins\": [\"ModernMixin\"]",
                "}"));
        resource(pool, "META-INF/accesstransformer.cfg", lines(
                "public net.minecraft.core.BlockPos field"));

        List<String> lines = new ArrayList<String>();
        MinecraftProfile profile = MinecraftAdapter.detect(pool, baseConfig(), logTo(lines));
        check(profile.detected(), "modern Forge container detected");
        check(loaderContains(profile, "forge"), "modern Forge loader recorded");
        check(profile.modIds().contains("modernmod"), "mods.toml mod id parsed");
        check(anyContains(profile.evidence(), "modLoader=javafml"), "mods.toml modLoader evidence recorded");
        check(has(profile.keepRules(), "com/example/modern/ModernMod"), "modern @Mod class kept");
        check(has(profile.keepRules(), "com/example/modern/mixin/ModernMixin"), "modern mixin class kept");
        check(has(profile.bodySkipGlobs(), "com/example/modern/mixin/ModernMixin"),
                "modern mixin body skipped");
        check(has(profile.preservedResources(), "META-INF/mods.toml"), "mods.toml preserved");
        check(has(profile.preservedResources(), "modernmod.mixins.json"), "toml mixin config preserved");
        check(has(profile.preservedResources(), "META-INF/accesstransformer.cfg"),
                "access transformer preserved");
        check(has(profile.keepRules(), "net/minecraft/core/BlockPos#field"),
                "mods.toml access transformer member kept");
    }

    // ------------------------------------------------------------------
    // NeoForge
    // ------------------------------------------------------------------

    private static void testNeoForge() throws Exception {
        ClassPool pool = new ClassPool();
        addClass(pool, annotated(node("com/example/neo/NeoMod"), "Lnet/neoforged/fml/common/Mod;"));
        addClass(pool, annotated(node("com/example/neo/NeoSubscriber"), "Lnet/neoforged/fml/common/EventBusSubscriber;"));
        addClass(pool, node("com/example/neo/mixin/NeoMixin"));
        resource(pool, "META-INF/neoforge.mods.toml", lines(
                "modLoader=\"javafml\"",
                "loaderVersion=\"[1,)\"",
                "",
                "[[mods]]",
                "modId=\"neomod\"",
                "version=\"2.0.0\"",
                "",
                "[[mixins]]",
                "config=\"neomod.mixins.json\""));
        resource(pool, "neomod.mixins.json", json(
                "{",
                "  \"package\": \"com.example.neo.mixin\",",
                "  \"mixins\": [\"NeoMixin\"]",
                "}"));

        MinecraftProfile profile = MinecraftAdapter.detect(pool, baseConfig(), logTo(new ArrayList<String>()));
        check(profile.detected(), "NeoForge container detected");
        check(loaderContains(profile, "neoforge"), "NeoForge loader recorded");
        check(profile.modIds().contains("neomod"), "neoforge.mods.toml mod id parsed");
        check(has(profile.keepRules(), "com/example/neo/NeoMod"), "NeoForge @Mod class kept");
        check(has(profile.keepRules(), "com/example/neo/NeoSubscriber"),
                "NeoForge EventBusSubscriber class kept");
        check(has(profile.keepRules(), "com/example/neo/mixin/NeoMixin"), "NeoForge mixin class kept");
        check(has(profile.preservedResources(), "META-INF/neoforge.mods.toml"),
                "neoforge.mods.toml preserved");
    }

    // ------------------------------------------------------------------
    // Quilt
    // ------------------------------------------------------------------

    private static void testQuilt() throws Exception {
        ClassPool pool = new ClassPool();
        addClass(pool, node("com/example/quilt/QuiltMod", "init"));
        addClass(pool, node("com/example/quilt/QuiltClient"));
        addClass(pool, node("com/example/quilt/mixin/QuiltMixin"));
        addClass(pool, node("com/example/quilt/QuiltTarget"));
        resource(pool, "quilt.mod.json", json(
                "{",
                "  \"schema_version\": 1,",
                "  \"quilt_loader\": {",
                "    \"group\": \"com.example\",",
                "    \"id\": \"quiltmod\",",
                "    \"version\": \"1.0.0\",",
                "    \"entrypoints\": {",
                "      \"init\": [\"com.example.quilt.QuiltMod::init\"],",
                "      \"client_init\": [\"com.example.quilt.QuiltClient\"]",
                "    }",
                "  },",
                "  \"mixin\": \"quiltmod.mixins.json\",",
                "  \"access_widener\": \"quiltmod.accesswidener\"",
                "}"));
        resource(pool, "quiltmod.mixins.json", json(
                "{",
                "  \"package\": \"com.example.quilt.mixin\",",
                "  \"mixins\": [\"QuiltMixin\"]",
                "}"));
        resource(pool, "quiltmod.accesswidener", lines(
                "accessWidener v1 named",
                "accessible class com/example/quilt/QuiltTarget"));

        MinecraftProfile profile = MinecraftAdapter.detect(pool, baseConfig(), logTo(new ArrayList<String>()));
        check(profile.detected(), "Quilt container detected");
        check(loaderContains(profile, "quilt"), "Quilt loader recorded");
        check(profile.modIds().contains("quiltmod"), "quilt_loader id parsed");
        check(has(profile.keepRules(), "com/example/quilt/QuiltMod"), "Quilt entry class kept");
        check(has(profile.keepRules(), "com/example/quilt/QuiltMod#init"), "Quilt entry method kept");
        check(has(profile.keepRules(), "com/example/quilt/QuiltClient"), "Quilt client entry class kept");
        check(has(profile.keepRules(), "com/example/quilt/mixin/QuiltMixin"), "Quilt mixin class kept");
        check(has(profile.keepRules(), "com/example/quilt/QuiltTarget"), "Quilt access widener class kept");
        check(has(profile.preservedResources(), "quilt.mod.json"), "quilt.mod.json preserved");
        check(has(profile.preservedResources(), "quiltmod.accesswidener"), "Quilt access widener preserved");
    }

    // ------------------------------------------------------------------
    // mixin-only archive
    // ------------------------------------------------------------------

    private static void testMixinOnlyJar() throws Exception {
        ClassPool pool = new ClassPool();
        ClassNode mixin = node("com/example/mixinlib/LibraryMixin");
        mixinAnnotation(mixin, "com/example/mixinlib/InjectedTarget");
        addClass(pool, mixin);
        addClass(pool, node("com/example/mixinlib/InjectedTarget"));
        resource(pool, "mixinlib.mixins.json", json(
                "{",
                "  \"package\": \"com.example.mixinlib\",",
                "  \"mixins\": [\"LibraryMixin\"],",
                "  \"plugin\": \"com.example.mixinlib.LibraryPlugin\"",
                "}"));

        MinecraftProfile profile = MinecraftAdapter.detect(pool, baseConfig(), logTo(new ArrayList<String>()));
        check(profile.detected(), "mixin-only archive detected");
        check("mixin".equals(profile.loader()), "mixin-only archive loader is 'mixin'");
        check(has(profile.keepRules(), "com/example/mixinlib/LibraryMixin"), "mixin-only class kept");
        check(has(profile.keepRules(), "com/example/mixinlib/LibraryPlugin"), "mixin-only plugin kept");
        check(has(profile.bodySkipGlobs(), "com/example/mixinlib/LibraryMixin"), "mixin-only body skipped");
        check(has(profile.bodySkipGlobs(), "com/example/mixinlib/InjectedTarget"),
                "mixin-only target body skipped");
        check(profile.targetCount() >= 1, "mixin-only target counted");
        check(has(profile.preservedResources(), "mixinlib.mixins.json"), "mixin-only config preserved");
    }

    // ------------------------------------------------------------------
    // broken metadata
    // ------------------------------------------------------------------

    private static void testBrokenMetadata() throws Exception {
        ClassPool pool = new ClassPool();
        addClass(pool, node("com/example/broken/BrokenMod"));
        resource(pool, "fabric.mod.json", "{\"id\": \"brokenmod\", \"entrypoints\": {");
        resource(pool, "META-INF/mods.toml", lines(
                "modLoader = \"javafml\"",
                "[[mods]]",
                "modId = \"brokenmod\"",
                "[[mixins]",
                "config = \"broken.mixins.json\""));
        resource(pool, "broken.mixins.json", "{\"package\": \"com.example.broken\", \"mixins\": [}");
        resource(pool, "broken.accesswidener", lines(
                "accessWidener v2 named",
                "accessible class"));
        resource(pool, "META-INF/accesstransformer.cfg", "public");

        List<String> lines = new ArrayList<String>();
        MinecraftProfile profile = null;
        try {
            profile = MinecraftAdapter.detect(pool, baseConfig(), logTo(lines));
        } catch (RuntimeException e) {
            check(false, "broken metadata must never throw: " + e);
        }
        check(profile != null && profile.detected(), "broken metadata still detects the container");
        check(loaderContains(profile, "fabric"), "broken fabric metadata keeps the fabric loader");
        check(loaderContains(profile, "forge"), "broken TOML metadata keeps the forge loader");
        check(profile.modIds().contains("brokenmod"),
                "broken mods.toml still recovers the mod id via the fallback");
        check(has(profile.preservedResources(), "fabric.mod.json"), "broken fabric manifest preserved");
        check(has(profile.preservedResources(), "broken.mixins.json"), "broken mixin config preserved");
        check(hasLevel(lines, "WARN"), "broken metadata produces warnings");
        check(anyContains(lines, "malformed"), "broken metadata warning names the failure");
        check(profile.keepRules().isEmpty() || !profile.keepRules().isEmpty(),
                "broken metadata returns a consistent profile");

        UmbraConfig base = baseConfig();
        UmbraConfig adjusted = profile.adjust(base);
        check(!adjusted.optionBool("classEncryption.enabled", true),
                "broken metadata still applies the feature downgrade");
    }

    // ------------------------------------------------------------------
    // adjust() feature matrix
    // ------------------------------------------------------------------

    private static void testAdjustMatrix() throws Exception {
        ClassPool pool = fabricPool();
        MinecraftProfile profile = MinecraftAdapter.detect(pool, baseConfig(), logTo(new ArrayList<String>()));
        check(profile.detected(), "adjust matrix uses a detected profile");

        UmbraConfig base = baseConfig();
        check(base.optionBool("classEncryption.enabled", false), "test base enables class encryption");
        check(base.methodVirtualization().enabled(), "test base enables virtualization");
        check(base.reflection().enabled(), "test base leaves reflection analysis enabled");

        UmbraConfig adjusted = profile.adjust(base);
        check(!adjusted.optionBool("classEncryption.enabled", true), "class encryption disabled");
        check(!adjusted.optionBool("integrity.enabled", true), "integrity guard disabled");
        check(!adjusted.optionBool("native.enabled", true), "native code disabled");
        check(!adjusted.optionBool("vm2.enabled", true), "VM2 engine disabled");
        check(!adjusted.referenceObfuscation().enabled(), "reference obfuscation disabled");
        check(!adjusted.resources().rewriteContent(), "resource content rewriting disabled");
        check(!adjusted.resources().obfuscatePaths(), "resource path obfuscation disabled");
        check(!adjusted.trim().enabled(), "member trimming disabled");
        check(!adjusted.methodVirtualization().enabled(), "virtualization disabled");
        check(adjusted.optionBool("minecraft.detected", false), "minecraft.detected option recorded");
        check(loaderContains(adjusted.option("minecraft.loader", ""), "fabric"),
                "minecraft.loader option recorded");

        check(adjusted.renamer().enabled(), "renaming kept on non-exempt classes");
        check(adjusted.stringEncryption().enabled(), "string encryption kept");
        check(adjusted.integerEncryption().enabled(), "integer encryption kept");
        check(adjusted.flow().enabled(), "control flow obfuscation kept");
        check(adjusted.antiLlm().enabled(), "anti-LLM protection kept");
        check(adjusted.watermark().enabled(), "watermark kept");
        check(adjusted.junk().enabled(), "junk members kept for non-exempt classes");
        check(adjusted.debug().enabled(), "debug info cleanup kept");

        // minecraft.forceVmp keeps the virtualization engine while other
        // conflicting features stay disabled.
        MinecraftProfile forced = MinecraftAdapter.detect(fabricPool(),
                baseConfig("minecraft.forceVmp", "true"), logTo(new ArrayList<String>()));
        UmbraConfig forcedBase = baseConfig("minecraft.forceVmp", "true");
        UmbraConfig forcedAdjusted = forced.adjust(forcedBase);
        check(forcedAdjusted.methodVirtualization().enabled(), "forceVmp keeps virtualization");
        check(forcedAdjusted.optionBool("vm2.enabled", false), "forceVmp keeps VM2");
        check(!forcedAdjusted.optionBool("classEncryption.enabled", true),
                "forceVmp still disables class encryption");
        check(anyContains(forced.notes(), "forceVmp"), "forceVmp policy noted");

        // minecraft.allowConflicts skips the downgrade entirely.
        MinecraftProfile conflicts = MinecraftAdapter.detect(fabricPool(),
                baseConfig("minecraft.allowConflicts", "true"), logTo(new ArrayList<String>()));
        UmbraConfig conflictBase = baseConfig("minecraft.allowConflicts", "true");
        UmbraConfig conflictAdjusted = conflicts.adjust(conflictBase);
        check(conflictAdjusted.optionBool("classEncryption.enabled", false),
                "allowConflicts keeps class encryption");
        check(conflictAdjusted.methodVirtualization().enabled(), "allowConflicts keeps virtualization");
        check(conflictAdjusted.trim().enabled(), "allowConflicts keeps trimming");
        check(conflictAdjusted.referenceObfuscation().enabled(), "allowConflicts keeps reference obfuscation");
        check(conflictAdjusted.resources().rewriteContent(), "allowConflicts keeps resource rewriting");
        check(anyContains(conflicts.notes(), "allowConflicts"), "allowConflicts policy noted");
    }

    // ------------------------------------------------------------------
    // asMap
    // ------------------------------------------------------------------

    private static void testProfileMap() throws Exception {
        MinecraftProfile profile = MinecraftAdapter.detect(fabricPool(), baseConfig(),
                logTo(new ArrayList<String>()));
        Map<String, Object> map = profile.asMap();
        check(Boolean.TRUE.equals(map.get("detected")), "asMap detected flag");
        check(map.get("loader") instanceof String, "asMap loader is a string");
        check(((Integer) map.get("keepRules")).intValue() == profile.keepRules().size(),
                "asMap keep rule count matches");
        check(((Integer) map.get("bodySkipGlobs")).intValue() == profile.bodySkipGlobs().size(),
                "asMap body-skip count matches");
        check(((Integer) map.get("targets")).intValue() == profile.targetCount(),
                "asMap target count matches");
        check(((Integer) map.get("classCount")).intValue() == profile.classCount(),
                "asMap class count matches");
        check(map.get("preservedResources") instanceof List, "asMap lists preserved resources");
        check(map.get("disabledFeatures") instanceof Map, "asMap lists disabled features");
        Map<?, ?> disabled = (Map<?, ?>) map.get("disabledFeatures");
        check(Boolean.FALSE.equals(disabled.get("classEncryption")), "asMap disables class encryption");
        check(Boolean.FALSE.equals(disabled.get("native")), "asMap disables native code");
    }

    // ------------------------------------------------------------------
    // configuration helpers
    // ------------------------------------------------------------------

    private static UmbraConfig baseConfig(String... options) throws Exception {
        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(Paths.get("in.jar"))
                .output(Paths.get("out.jar"))
                .methodVirtualization(new UmbraConfig.VirtualizationOptions(true, 2000, 0))
                .trim(new UmbraConfig.TrimOptions(true, true, true))
                .referenceObfuscation(new UmbraConfig.ReferenceOptions(true))
                .resources(new UmbraConfig.ResourceOptions(true, true,
                        Collections.<String>emptyList()))
                .antiLlm(new UmbraConfig.AntiLlmOptions(true, 2, 2, 1, 12, true))
                .option("classEncryption.enabled", "true")
                .option("integrity.enabled", "true")
                .option("native.enabled", "true")
                .option("vm2.enabled", "true");
        for (int i = 0; i + 1 < options.length; i += 2) {
            builder.option(options[i], options[i + 1]);
        }
        return builder.build();
    }

    private static Log logTo(final List<String> lines) {
        return new Log(new Log.Sink() {
            @Override
            public void line(String level, String message) {
                lines.add(level + ": " + message);
            }
        }, true);
    }

    private static boolean hasLevel(List<String> lines, String level) {
        for (String line : lines) {
            if (line.startsWith(level + ":")) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    // pool helpers
    // ------------------------------------------------------------------

    private static ClassNode node(String internalName, String... methods) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC;
        node.name = internalName;
        node.superName = "java/lang/Object";
        node.methods = new ArrayList<org.objectweb.asm.tree.MethodNode>();
        node.fields = new ArrayList<org.objectweb.asm.tree.FieldNode>();
        node.interfaces = new ArrayList<String>();
        for (String method : methods) {
            org.objectweb.asm.tree.MethodNode methodNode =
                    new org.objectweb.asm.tree.MethodNode(Opcodes.ACC_PUBLIC, method, "()V", null, null);
            methodNode.instructions = new org.objectweb.asm.tree.InsnList();
            methodNode.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
            node.methods.add(methodNode);
        }
        return node;
    }

    private static void addClass(ClassPool pool, ClassNode node) {
        pool.putClass(node.name + ".class", new byte[0], node);
    }

    private static ClassNode annotated(ClassNode node, String descriptor) {
        return annotated(node, new AnnotationNode(descriptor));
    }

    private static ClassNode annotated(ClassNode node, AnnotationNode annotation) {
        if (node.visibleAnnotations == null) {
            node.visibleAnnotations = new ArrayList<AnnotationNode>();
        }
        node.visibleAnnotations.add(annotation);
        return node;
    }

    private static void mixinAnnotation(ClassNode node, String... targets) {
        AnnotationNode annotation = new AnnotationNode("Lorg/spongepowered/asm/mixin/Mixin;");
        annotation.values = new ArrayList<Object>();
        annotation.values.add("value");
        List<Object> types = new ArrayList<Object>();
        for (String target : targets) {
            types.add(Type.getObjectType(target));
        }
        annotation.values.add(types);
        annotated(node, annotation);
    }

    private static void resource(ClassPool pool, String name, String text) {
        pool.putResource(name, text.getBytes(StandardCharsets.UTF_8), 0L, 0);
    }

    // ------------------------------------------------------------------
    // assertions
    // ------------------------------------------------------------------

    private static boolean has(List<String> values, String expected) {
        return values.contains(expected);
    }

    private static boolean anyContains(List<String> values, String fragment) {
        for (String value : values) {
            if (value != null && value.contains(fragment)) {
                return true;
            }
        }
        return false;
    }

    private static boolean loaderContains(MinecraftProfile profile, String loader) {
        if (profile == null) {
            return false;
        }
        return loaderContains(profile.loader(), loader);
    }

    private static boolean loaderContains(String loaderList, String loader) {
        if (loaderList == null) {
            return false;
        }
        return Arrays.asList(loaderList.split(",")).contains(loader);
    }

    private static String json(String... lines) {
        return String.join("\n", lines);
    }

    private static String lines(String... lines) {
        return String.join("\n", lines);
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}
