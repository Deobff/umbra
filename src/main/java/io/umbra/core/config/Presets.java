package io.umbra.core.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Built-in policy presets.
 *
 * <p>Presets only add keep rules or relax transform defaults; explicit user
 * configuration still wins for scalar settings because presets are applied
 * after parsing and never remove user keep rules.</p>
 */
public final class Presets {

    private Presets() {
    }

    public static UmbraConfig apply(UmbraConfig base) throws ConfigException {
        return apply(base, true);
    }

    /**
     * Applies the preset named in the configuration, optionally tolerating a
     * configuration without {@code input}/{@code output} (CLI override loading).
     */
    public static UmbraConfig apply(UmbraConfig base, boolean requirePaths) throws ConfigException {
        if (base.preset() == null || base.preset().trim().isEmpty()) {
            return base;
        }
        return apply(base, base.preset(), requirePaths);
    }

    public static UmbraConfig apply(UmbraConfig base, String preset) throws ConfigException {
        return apply(base, preset, true);
    }

    public static UmbraConfig apply(UmbraConfig base, String preset, boolean requirePaths)
            throws ConfigException {
        String name = preset == null ? "" : preset.trim().toLowerCase(Locale.ROOT);
        if (name.isEmpty() || "default".equals(name) || "none".equals(name)) {
            return base;
        }
        UmbraConfig.Builder b = base.toBuilder();
        if ("library".equals(name)) {
            // Preserve public API names while still allowing string/constant/flow transforms.
            b.softKeepPublicApi(true);
            b.keep(merge(base.keep(), "@io.umbra.annotations.Keep"));
        } else if ("spring".equals(name) || "spring-boot".equals(name)) {
            b.softKeepPublicApi(true);
            List<String> keep = new ArrayList<String>(base.keep());
            keep.addAll(Arrays.asList(
                    "**Application",
                    "**Controller",
                    "**RestController",
                    "**Service",
                    "**Repository",
                    "**Configuration",
                    "**Properties",
                    "**AutoConfiguration",
                    "**WebMvcConfigurer",
                    "**Filter",
                    "**Interceptor",
                    "**Aspect",
                    "**Advice",
                    "**Listener",
                    "@org.springframework.**",
                    "@javax.annotation.**",
                    "@jakarta.annotation.**"));
            b.keep(dedupe(keep));
        } else if ("jackson".equals(name) || "persistence".equals(name)) {
            b.softKeepPublicApi(true);
            List<String> keep = new ArrayList<String>(base.keep());
            keep.addAll(Arrays.asList(
                    "@com.fasterxml.jackson.**",
                    "@javax.persistence.**",
                    "@jakarta.persistence.**",
                    "@javax.xml.bind.annotation.**",
                    "@jakarta.xml.bind.annotation.**",
                    "@org.hibernate.**",
                    "@org.hibernate.validator.**"));
            b.keep(dedupe(keep));
        } else if ("service-loader".equals(name) || "serviceloader".equals(name)) {
            b.softKeepPublicApi(true);
        } else if ("micronaut".equals(name)) {
            b.softKeepPublicApi(true);
            List<String> keep = new ArrayList<String>(base.keep());
            keep.addAll(Arrays.asList("**Controller", "**Factory", "**Configuration", "@io.micronaut.**"));
            b.keep(dedupe(keep));
        } else if ("aggressive".equals(name)) {
            b.keepPublicApi(false);
            b.flow(new UmbraConfig.FlowOptions(true, "normal",
                    base.flow().maxInstructions(), true));
            b.invokeWrapper(new UmbraConfig.WrapperOptions(true, base.invokeWrapper().maxPerClass()));
            b.junk(new UmbraConfig.JunkOptions(true, 4, 4));
            b.option("string.engine", "auto");
            b.option("string.stackTraceHide", "true");
            b.option("string.wipe", "true");
            b.option("string.otpEngines", "true");
            b.option("string.otpMaxSites", "32");
            b.option("flow.aggressive", "true");
            b.option("flow.reorder", "true");
            b.option("otp.enabled", "true");
            b.option("vm2.fusion", "true");
            b.option("typeConfusion.enabled", "true");
            b.option("typeConfusion.level", "1");
            b.option("native.antiDump", "true");
            b.option("layout.springBoot", "true");
            b.option("layout.war", "true");
            b.option("layout.multiRelease", "preserve");
            b.option("layout.moduleInfo", "auto");
        } else if ("nocturne".equals(name)) {
            // Nocturne is an exclusive body engine: the engine turns the other
            // body transforms off when this option is active.
            b.option("nocturne.enabled", "true");
            b.option("nocturne.variants", "3");
            b.option("string.strength", "3");
            b.option("decompilerNoise.level", "3");
            b.option("classEncryption.enabled", "true");
            b.option("antiDebug.level", "2");
            b.option("antiDebug.nativeGuard", "true");
            b.antiDebug(true);
            b.stringEncryption(new UmbraConfig.StringEncryptionOptions(true, 1));
        } else if ("light".equals(name) || "balanced".equals(name) || "maximum".equals(name)
                || "max".equals(name)) {
            applyStrength(b, base, name);
        } else {
            throw new ConfigException("Unknown preset: " + preset
                    + " (expected library, spring-boot, jackson, service-loader, micronaut, aggressive, light, balanced, maximum or nocturne)");
        }
        b.preset(name);
        return b.build(requirePaths);
    }

    private static List<String> dedupe(List<String> values) {
        return new ArrayList<String>(new java.util.LinkedHashSet<String>(values));
    }

    /**
     * Applies the strength ladder used by the GUI, QA matrix and documentation.
     *
     * <p>All three presets keep the project buildable with the stock toolchain:
     * native code generation stays opt-in because it needs a C compiler.</p>
     *
     * <p>The instruction ceilings scale with the tier as well. They are
     * eligibility thresholds ("do not transform a method body larger than this"),
     * and a single shared value made {@code light} as expensive per method as
     * {@code maximum} on the platform's larger methods. Scaling them keeps the
     * promise of each tier: {@code light} stays cheap, {@code maximum} also covers
     * the big methods.</p>
     */
    private static void applyStrength(UmbraConfig.Builder b, UmbraConfig base, String name) {
        boolean maximum = "maximum".equals(name) || "max".equals(name);
        boolean balanced = maximum || "balanced".equals(name);

        // Per-tier instruction ceilings: light < balanced < maximum.
        int flowLimit = maximum ? 8000 : (balanced ? 4000 : 2000);
        int virtualizationLimit = maximum ? 4000 : (balanced ? 2000 : 1000);
        int vmLimit = maximum ? 4000 : 2000;
        int nativeLimit = maximum ? 1600 : (balanced ? 800 : 400);

        b.flow(new UmbraConfig.FlowOptions(true, maximum ? "normal" : "light", flowLimit, balanced));
        b.exceptionObfuscation(new UmbraConfig.ExceptionOptions(balanced));
                // Virtualization runs before flow obfuscation and used to take every
        // eligible method, which left the flow pass almost nothing to transform
        // (8 of 26 classes on a real jar). Capping the per-class VM quota keeps
        // both layers active: VM hides the hot methods, flow obfuscates the rest.
        int vmMaxMethods = maximum ? 16 : 0;
        b.methodVirtualization(
                new UmbraConfig.VirtualizationOptions(true, virtualizationLimit, vmMaxMethods));
        b.antiLlm(new UmbraConfig.AntiLlmOptions(balanced, maximum ? 3 : 2, 2, maximum ? 2 : 1, 12, true));
        b.junk(new UmbraConfig.JunkOptions(true, maximum ? 4 : 2, maximum ? 4 : 2));
        b.stringEncryption(new UmbraConfig.StringEncryptionOptions(true, 2));
        b.integerEncryption(new UmbraConfig.IntegerEncryptionOptions(true, true));
        // Generic signatures are kept by default: framework code (Gson
        // TypeToken, reflection libraries, DI containers) depends on the
        // Signature attribute, and stripping it breaks otherwise valid input
        // JARs. Users can opt in to signature erasure via a YAML config.
        b.debug(new UmbraConfig.DebugOptions(true, true, true, true, false, false, true));
        b.reflection(new UmbraConfig.ReflectionOptions(true, maximum));
        // Business classes join one random package at the strongest tiers, so the
        // archive shows no original package tree (Zelix KlassMaster renames
        // everything into the default package for the same reason). Explicit
        // keep rules still win: frozen classes are never repackaged.
        if (maximum || "aggressive".equals(name)) {
            // Flatten every renamed class into the default package (the layout
            // Zelix KlassMaster produces) and keep the generated helpers there
            // too, so a directory listing shows neither the original module tree
            // nor a suspicious foreign package.
            UmbraConfig.RenamerOptions target = base.renamer();
            b.renamer(new UmbraConfig.RenamerOptions(target.enabled(), target.prefix(),
                    true, "", target.renameClasses(), target.renameMethods(), target.renameFields(),
                    target.mappingFile(), target.dictionary(), target.minimumNameLength(),
                    target.repackageKept()));
            b.option("runtime.package", "flat");
        }
        b.option("string.strength", maximum ? "3" : (balanced ? "2" : "1"));
        // Per-call string re-keying (P0-2-c): the selected sites carry two ciphertexts
        // under different engines and the injected one-time state picks between them
        // on every call, so a single captured decryption does not describe the next.
        b.option("string.otpEngines", String.valueOf(balanced));
        b.option("string.otpMaxSites", maximum ? "32" : "16");
        b.option("string.engine", "auto");
        b.option("string.stackTraceHide", String.valueOf(balanced));
        b.option("string.wipe", String.valueOf(balanced));
        b.option("flow.aggressive", String.valueOf(maximum));
        // Method-level block scheduling (the ZKM MethodFlowAnalyzer idea): moves
        // independent blocks and repairs the fall-through edges, so the emitted
        // layout no longer matches the control-flow graph a decompiler rebuilds.
        b.option("flow.reorder", String.valueOf(balanced));
        // One-time-program state: the guarded entry path changes on every call.
        // Opt-in on light so the cheapest tier keeps its "smallest output" promise.
        b.option("otp.enabled", String.valueOf(balanced));
        b.option("vm2.fusion", String.valueOf(balanced));
        b.option("vm2.enabled", String.valueOf(balanced));
        b.option("vm2.encryptPayload", "true");
        b.option("vm2.opcodeMap", String.valueOf(balanced));
        b.option("vm2.trys", String.valueOf(balanced));
        b.option("vm2.nested", String.valueOf(balanced));
        b.option("vm2.maxInstructions", String.valueOf(vmLimit));
        b.option("native.maxInstructions", String.valueOf(nativeLimit));
        b.option("mba.enabled", String.valueOf(maximum));
        b.option("mba.depth", maximum ? "2" : "1");
        b.option("classEncryption.enabled", String.valueOf(balanced));
        b.option("classEncryption.integrity", String.valueOf(balanced));
        b.option("integrity.enabled", String.valueOf(maximum));
        b.option("integrity.level", maximum ? "2" : "1");
        b.option("antiDebug.level", maximum ? "2" : "0");
        b.option("native.antiDump", "true");
        b.option("native.antiBackfill", "true");
        b.option("layout.springBoot", "true");
        b.option("layout.war", "true");
        b.option("layout.multiRelease", "preserve");
        b.option("layout.moduleInfo", "auto");
        if (maximum) {
            b.antiDebug(true);
            b.invokeWrapper(new UmbraConfig.WrapperOptions(true, 200));
            b.referenceObfuscation(new UmbraConfig.ReferenceOptions(true, true, true, false, false));
            b.option("typeConfusion.enabled", "true");
            b.option("typeConfusion.level", "1");
            b.option("typeConfusion.maxPerMethod", "24");
        }
        b.preset(name);
    }

    private static List<String> merge(List<String> existing, String... extra) {
        List<String> out = new ArrayList<String>(existing);
        for (String value : extra) {
            if (!out.contains(value)) {
                out.add(value);
            }
        }
        return out;
    }
}
