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

    public String entryName() {
        return entryName;
    }

    public String versionDirectory() {
        return versionDirectory;
    }

    public String relativePath() {
        return relativePath;
    }

    public String classPrefix() {
        return classPrefix;
    }

    public String internalName() {
        return internalName;
    }

    public int version() {
        return version;
    }

    public boolean moduleInfo() {
        return moduleInfo;
    }

    public long time() {
        return time;
    }

    public int method() {
        return method;
    }

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
