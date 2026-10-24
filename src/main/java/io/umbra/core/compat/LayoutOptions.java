package io.umbra.core.compat;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Archive-layout options, read from the advanced option map.
 *
 * <p>Supported keys (all optional):</p>
 *
 * <pre>
 * layout.enabled        true|false           master switch; false = legacy flat handling
 * layout.springBoot     true|false           detect/handle Spring Boot fat JAR and WAR layouts
 * layout.war            true|false           detect/handle WAR layouts
 * layout.multiRelease   preserve|flatten     keep META-INF/versions/N (default) or flatten it
 * layout.moduleInfo     auto|keep|drop       remap module-info.class, or drop it
 * </pre>
 *
 * <p>Invalid values fall back to the documented default and are reported through
 * {@link #warnings()} so the caller can log them. The options object is immutable
 * and safe to share.</p>
 */
public final class LayoutOptions {

    /** How {@code META-INF/versions/N/} entries are handled. */
    public enum MultiReleaseMode {
        /** Keep the multi-release layout and remap every version consistently. */
        PRESERVE,
        /** Promote versioned classes to base paths and emit a plain JAR. */
        FLATTEN
    }

    /** How {@code module-info.class} is handled. */
    public enum ModuleInfoMode {
        /** Remap the descriptor; drop it with a warning when remapping would be invalid. */
        AUTO,
        /** Always keep the descriptor (remapped on a best-effort basis). */
        KEEP,
        /** Always drop the descriptor. */
        DROP
    }

    public static final String KEY_ENABLED = "layout.enabled";
    public static final String KEY_SPRING_BOOT = "layout.springBoot";
    public static final String KEY_WAR = "layout.war";
    public static final String KEY_MULTI_RELEASE = "layout.multiRelease";
    public static final String KEY_MODULE_INFO = "layout.moduleInfo";

    private static final LayoutOptions DEFAULTS = new LayoutOptions(true, true, true,
            MultiReleaseMode.PRESERVE, ModuleInfoMode.AUTO, Collections.<String>emptyList());

    private final boolean enabled;
    private final boolean springBoot;
    private final boolean war;
    private final MultiReleaseMode multiRelease;
    private final ModuleInfoMode moduleInfo;
    private final List<String> warnings;

    private LayoutOptions(boolean enabled, boolean springBoot, boolean war,
                          MultiReleaseMode multiRelease, ModuleInfoMode moduleInfo,
                          List<String> warnings) {
        this.enabled = enabled;
        this.springBoot = springBoot;
        this.war = war;
        this.multiRelease = multiRelease;
        this.moduleInfo = moduleInfo;
        this.warnings = warnings;
    }

    /** Documented defaults: everything detected and preserved. */
    public static LayoutOptions defaults() {
        return DEFAULTS;
    }

    /** Parses the advanced option map; never returns {@code null}. */
    public static LayoutOptions from(Map<String, String> options) {
        if (options == null || options.isEmpty()) {
            return DEFAULTS;
        }
        List<String> warnings = new ArrayList<String>();
        boolean enabled = bool(options, KEY_ENABLED, true, warnings);
        boolean springBoot = bool(options, KEY_SPRING_BOOT, true, warnings);
        boolean war = bool(options, KEY_WAR, true, warnings);
        MultiReleaseMode multiRelease = multiRelease(options, warnings);
        ModuleInfoMode moduleInfo = moduleInfo(options, warnings);
        if (warnings.isEmpty()) {
            return new LayoutOptions(enabled, springBoot, war, multiRelease, moduleInfo,
                    Collections.<String>emptyList());
        }
        return new LayoutOptions(enabled, springBoot, war, multiRelease, moduleInfo,
                Collections.unmodifiableList(warnings));
    }

    public boolean enabled() {
        return enabled;
    }

    /** True when Spring Boot fat JAR/WAR layouts are handled. */
    public boolean springBoot() {
        return springBoot;
    }

    /** True when WAR layouts are handled. */
    public boolean war() {
        return war;
    }

    public MultiReleaseMode multiRelease() {
        return multiRelease;
    }

    public ModuleInfoMode moduleInfo() {
        return moduleInfo;
    }

    /** Option values that were invalid and replaced by their default. */
    public List<String> warnings() {
        return warnings;
    }

    private static boolean bool(Map<String, String> options, String key, boolean fallback,
                                List<String> warnings) {
        String raw = options.get(key);
        if (raw == null) {
            return fallback;
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if ("true".equals(value) || "1".equals(value) || "yes".equals(value) || "on".equals(value)) {
            return true;
        }
        if ("false".equals(value) || "0".equals(value) || "no".equals(value) || "off".equals(value)) {
            return false;
        }
        warnings.add(key + "=\"" + raw + "\" is not a boolean; using " + fallback);
        return fallback;
    }

    private static MultiReleaseMode multiRelease(Map<String, String> options, List<String> warnings) {
        String raw = options.get(KEY_MULTI_RELEASE);
        if (raw == null) {
            return MultiReleaseMode.PRESERVE;
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if ("preserve".equals(value)) {
            return MultiReleaseMode.PRESERVE;
        }
        if ("flatten".equals(value)) {
            return MultiReleaseMode.FLATTEN;
        }
        warnings.add(KEY_MULTI_RELEASE + "=\"" + raw + "\" is not one of preserve|flatten; using preserve");
        return MultiReleaseMode.PRESERVE;
    }

    private static ModuleInfoMode moduleInfo(Map<String, String> options, List<String> warnings) {
        String raw = options.get(KEY_MODULE_INFO);
        if (raw == null) {
            return ModuleInfoMode.AUTO;
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if ("auto".equals(value)) {
            return ModuleInfoMode.AUTO;
        }
        if ("keep".equals(value)) {
            return ModuleInfoMode.KEEP;
        }
        if ("drop".equals(value)) {
            return ModuleInfoMode.DROP;
        }
        warnings.add(KEY_MODULE_INFO + "=\"" + raw + "\" is not one of auto|keep|drop; using auto");
        return ModuleInfoMode.AUTO;
    }

    @Override
    public String toString() {
        return "LayoutOptions{enabled=" + enabled + ", springBoot=" + springBoot + ", war=" + war
                + ", multiRelease=" + multiRelease + ", moduleInfo=" + moduleInfo + '}';
    }
}
