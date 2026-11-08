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

    public enum Kind {

        FLAT,

        SPRING_BOOT,

        SPRING_BOOT_WAR,

        WAR
    }

    public static final String BOOT_CLASSES = "BOOT-INF/classes/";

    public static final String BOOT_LIB = "BOOT-INF/lib/";

    public static final String WAR_CLASSES = "WEB-INF/classes/";

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

    public boolean isFlat() {
        return kind == Kind.FLAT;
    }

    public String classPrefix() {
        return classPrefix;
    }

    public boolean multiRelease() {
        return multiRelease;
    }

    public boolean multiReleaseAttribute() {
        return multiReleaseAttribute;
    }

    public boolean moduleInfo() {
        return moduleInfo;
    }

    public int maxVersion() {
        return maxVersion;
    }

    public String mainClass() {
        return mainClass;
    }

    public String startClass() {
        return startClass;
    }

    public int nestedLibraries() {
        return nestedLibraries;
    }

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
