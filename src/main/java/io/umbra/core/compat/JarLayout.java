package io.umbra.core.compat;

/**
 * Detected archive layout. Immutable; created by {@link LayoutDetector}.
 *
 * <p>A layout describes where the runtime classpath roots are and which parts of
 * the archive must be copied byte-identically. Multi-release and module-info are
 * properties that can be combined with any layout, mirroring the fact that a
 * Spring Boot fat JAR or a plain JAR can both be multi-release/modular.</p>
 */
public final class JarLayout {

    /** Primary layout family. */
    public enum Kind {
        /** Classes live at the archive root (or the layout is disabled). */
        FLAT,
        /** Spring Boot fat JAR: classes in {@code BOOT-INF/classes/}, libs in {@code BOOT-INF/lib/}. */
        SPRING_BOOT,
        /** Spring Boot executable WAR: classes in {@code WEB-INF/classes/}, loader at the root. */
        SPRING_BOOT_WAR,
        /** Plain WAR: classes in {@code WEB-INF/classes/}, libs in {@code WEB-INF/lib/}. */
        WAR
    }

    /** Class root prefix for a Spring Boot fat JAR. */
    public static final String BOOT_CLASSES = "BOOT-INF/classes/";
    /** Nested library prefix for a Spring Boot fat JAR. */
    public static final String BOOT_LIB = "BOOT-INF/lib/";
    /** Class root prefix for a WAR. */
    public static final String WAR_CLASSES = "WEB-INF/classes/";
    /** Nested library prefix for a WAR. */
    public static final String WAR_LIB = "WEB-INF/lib/";

    private final Kind kind;
    private final String classPrefix;
    private final boolean multiRelease;
    private final boolean multiReleaseAttribute;
    private final boolean moduleInfo;
    private final int maxVersion;
    private final String mainClass;
    private final String startClass;
    private final int nestedLibraries;

    private JarLayout(Kind kind, String classPrefix, boolean multiRelease,
                      boolean multiReleaseAttribute, boolean moduleInfo, int maxVersion,
                      String mainClass, String startClass, int nestedLibraries) {
        this.kind = kind;
        this.classPrefix = classPrefix;
        this.multiRelease = multiRelease;
        this.multiReleaseAttribute = multiReleaseAttribute;
        this.moduleInfo = moduleInfo;
        this.maxVersion = maxVersion;
        this.mainClass = mainClass;
        this.startClass = startClass;
        this.nestedLibraries = nestedLibraries;
    }

    /** A plain flat JAR with no compatibility features detected. */
    public static JarLayout flat() {
        return new JarLayout(Kind.FLAT, "", false, false, false, 0, null, null, 0);
    }

    public static JarLayout of(Kind kind, String classPrefix, boolean multiRelease,
                               boolean multiReleaseAttribute, boolean moduleInfo, int maxVersion,
                               String mainClass, String startClass, int nestedLibraries) {
        return new JarLayout(kind, classPrefix == null ? "" : classPrefix, multiRelease,
                multiReleaseAttribute, moduleInfo, maxVersion, mainClass, startClass, nestedLibraries);
    }

    public Kind kind() {
        return kind;
    }

    /** True when classes are read from and written to the archive root. */
    public boolean isFlat() {
        return kind == Kind.FLAT;
    }

    /** Entry prefix that classes live under; empty for a flat JAR. */
    public String classPrefix() {
        return classPrefix;
    }

    /** True when versioned entries or a {@code Multi-Release: true} attribute were detected. */
    public boolean multiRelease() {
        return multiRelease;
    }

    /** True when the manifest itself declared {@code Multi-Release: true}. */
    public boolean multiReleaseAttribute() {
        return multiReleaseAttribute;
    }

    /** True when a (base or versioned) {@code module-info.class} entry was detected. */
    public boolean moduleInfo() {
        return moduleInfo;
    }

    /** Highest {@code N} found under {@code META-INF/versions/N/}, or 0. */
    public int maxVersion() {
        return maxVersion;
    }

    /** Raw manifest {@code Main-Class} value (dotted), or {@code null}. */
    public String mainClass() {
        return mainClass;
    }

    /** Raw manifest {@code Start-Class} value (dotted), or {@code null}. */
    public String startClass() {
        return startClass;
    }

    /** Number of nested library archives detected under a preserved lib prefix. */
    public int nestedLibraries() {
        return nestedLibraries;
    }

    /**
     * Stable layout id used in logs, stats and compatibility reports.
     *
     * <p>Values: {@code flat}, {@code spring-boot}, {@code spring-boot-war},
     * {@code war}, {@code multi-release} (only when no container layout applies).</p>
     */
    public String kindId() {
        switch (kind) {
            case SPRING_BOOT:
                return "spring-boot";
            case SPRING_BOOT_WAR:
                return "spring-boot-war";
            case WAR:
                return "war";
            default:
                return multiRelease ? "multi-release" : "flat";
        }
    }

    /** Human readable one-line description for logs. */
    public String describe() {
        StringBuilder sb = new StringBuilder(kindId());
        if (!classPrefix.isEmpty()) {
            sb.append(" (classes=").append(classPrefix);
            if (nestedLibraries > 0) {
                sb.append(", nested libs=").append(nestedLibraries);
            }
            sb.append(')');
        }
        if (multiRelease) {
            sb.append(" multi-release");
            if (maxVersion > 0) {
                sb.append(" up to version ").append(maxVersion);
            }
        }
        if (moduleInfo) {
            sb.append(" module-info");
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return describe();
    }
}
