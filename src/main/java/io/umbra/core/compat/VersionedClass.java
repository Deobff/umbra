package io.umbra.core.compat;

/**
 * One versioned class copy found under {@code META-INF/versions/N/}.
 *
 * <p>Instances are recorded by {@link io.umbra.core.util.Jars} when a
 * multi-release archive is read in preserve mode. The class pool can only hold
 * one {@code ClassNode} per internal name, so the versioned copies stay as raw
 * archive entries and are remapped at write time with the same class/member
 * mapping as the base classes.</p>
 */
public final class VersionedClass {

    private final String entryName;
    private final String versionDirectory;
    private final String relativePath;
    private final String classPrefix;
    private final String internalName;
    private final int version;
    private final boolean moduleInfo;
    private final long time;
    private final int method;

    public VersionedClass(String entryName, String versionDirectory, String relativePath,
                          String classPrefix, String internalName, int version,
                          boolean moduleInfo, long time, int method) {
        this.entryName = entryName;
        this.versionDirectory = versionDirectory;
        this.relativePath = relativePath;
        this.classPrefix = classPrefix == null ? "" : classPrefix;
        this.internalName = internalName;
        this.version = version;
        this.moduleInfo = moduleInfo;
        this.time = time;
        this.method = method;
    }

    /** Full original entry name, used as the key of the retained resource bytes. */
    public String entryName() {
        return entryName;
    }

    /** Prefix up to and including the version directory, e.g. {@code META-INF/versions/9/}. */
    public String versionDirectory() {
        return versionDirectory;
    }

    /** Entry path after the version directory, e.g. {@code com/foo/Bar.class}. */
    public String relativePath() {
        return relativePath;
    }

    /** Class root prefix of the layout this copy belongs to (empty for flat JARs). */
    public String classPrefix() {
        return classPrefix;
    }

    /** Internal class name read from the class file itself; {@code null} for module-info. */
    public String internalName() {
        return internalName;
    }

    public int version() {
        return version;
    }

    /** True when this versioned entry is a {@code module-info.class} descriptor. */
    public boolean moduleInfo() {
        return moduleInfo;
    }

    public long time() {
        return time;
    }

    public int method() {
        return method;
    }

    /**
     * Computes the write path for a (possibly renamed) class.
     *
     * <p>The original relative path is preserved; only the class-name suffix is
     * replaced so that nested layout prefixes and unusual paths survive.</p>
     */
    public String outputEntryName(String newInternalName) {
        if (moduleInfo || internalName == null || newInternalName == null
                || internalName.equals(newInternalName)) {
            return entryName;
        }
        String oldSuffix = internalName + ".class";
        if (relativePath.endsWith(oldSuffix)) {
            return versionDirectory + relativePath.substring(0, relativePath.length() - oldSuffix.length())
                    + newInternalName + ".class";
        }
        return versionDirectory + classPrefix + newInternalName + ".class";
    }

    @Override
    public String toString() {
        return entryName + (internalName == null ? "" : " (" + internalName + ')');
    }
}
