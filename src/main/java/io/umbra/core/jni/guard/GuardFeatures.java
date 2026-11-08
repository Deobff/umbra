package io.umbra.core.jni.guard;

/**
 * Feature set of the generated native guard.
 *
 * <p>{@code antiDebug.level} selects a safe default profile, individual
 * {@code antiDebug.*} knobs can override every check, and expensive deep checks
 * (thread/module/memory enumeration, external handle scan) are only run from the
 * startup check and the periodic watchdog pass, never from the per-native-method
 * tick. Level 1 keeps the cheap classic checks only; level 2 enables the dynamic
 * protection set; level 3 adds the opt-in handle/dump scan.</p>
 */
public final class GuardFeatures {

    public final int level;
    public final boolean frida;
    public final boolean hash;

    public final boolean remoteThread;

    public final boolean execMemoryScan;

    public final boolean imageBreakpoints;

    public final boolean codeSampling;

    public final boolean moduleIntegrity;

    public final boolean timing;

    public final boolean handleDump;

    public final boolean codeCrc;

    public final boolean pageGuard;

    public final boolean textGuard;

    public final boolean guardProbe;

    public final String execWhitelist;

    public final boolean linuxChecks;

    public final long watchdogMs;

    public final boolean testHooks;

    public final String testHookClass;

    private GuardFeatures(Builder builder) {
        this.level = builder.level;
        this.frida = builder.frida;
        this.hash = builder.hash;
        this.remoteThread = builder.remoteThread;
        this.execMemoryScan = builder.execMemoryScan;
        this.imageBreakpoints = builder.imageBreakpoints;
        this.codeSampling = builder.codeSampling;
        this.moduleIntegrity = builder.moduleIntegrity;
        this.timing = builder.timing;
        this.handleDump = builder.handleDump;
        this.codeCrc = builder.codeCrc;
        this.pageGuard = builder.pageGuard;
        this.textGuard = builder.textGuard;
        this.guardProbe = builder.guardProbe;
        this.execWhitelist = builder.execWhitelist;
        this.linuxChecks = builder.linuxChecks;
        this.watchdogMs = builder.watchdogMs;
        this.testHooks = builder.testHooks;
        this.testHookClass = builder.testHookClass;
    }

    public static GuardFeatures legacy(boolean frida, boolean hash) {
        return builder(1).frida(frida).hash(hash).build();
    }

    public static Builder forLevel(int level) {
        int normalized = Math.max(1, Math.min(3, level));
        Builder builder = builder(normalized);
        if (normalized >= 2) {
            builder.remoteThread(true)

                    .execMemoryScan(false)
                    .imageBreakpoints(true)
                    .codeSampling(true)
                    .moduleIntegrity(true)
                    .timing(true)
                    .codeCrc(true)
                    .pageGuard(true)
                    .textGuard(true)
                    .guardProbe(true)
                    .linuxChecks(true);
        }
        if (normalized >= 3) {
            builder.execMemoryScan(true).handleDump(true);
        }
        return builder;
    }

    private static Builder builder(int level) {
        Builder builder = new Builder();
        builder.level = level;
        return builder;
    }

    public int enabledChecks() {
        int count = 0;
        if (frida) {
            count++;
        }
        if (hash) {
            count++;
        }
        if (remoteThread) {
            count++;
        }
        if (execMemoryScan) {
            count++;
        }
        if (imageBreakpoints) {
            count++;
        }
        if (codeSampling) {
            count++;
        }
        if (moduleIntegrity) {
            count++;
        }
        if (timing) {
            count++;
        }
        if (handleDump) {
            count++;
        }
        if (codeCrc) {
            count++;
        }
        if (pageGuard) {
            count++;
        }
        if (textGuard) {
            count++;
        }
        if (guardProbe) {
            count++;
        }
        if (linuxChecks) {
            count++;
        }
        return count;
    }

    public String describe() {
        return "level=" + level
                + ", frida=" + frida
                + ", hash=" + hash
                + ", remoteThread=" + remoteThread
                + ", execMemoryScan=" + execMemoryScan
                + ", imageBreakpoints=" + imageBreakpoints
                + ", codeSampling=" + codeSampling
                + ", moduleIntegrity=" + moduleIntegrity
                + ", timing=" + timing
                + ", handleDump=" + handleDump
                + ", codeCrc=" + codeCrc
                + ", pageGuard=" + pageGuard
                + ", textGuard=" + textGuard
                + ", guardProbe=" + guardProbe
                + ", execWhitelist=" + execWhitelist
                + ", linuxChecks=" + linuxChecks
                + ", watchdogMs=" + watchdogMs;
    }

    public static final class Builder {
        private int level = 1;
        private boolean frida = true;
        private boolean hash = true;
        private boolean remoteThread;
        private boolean execMemoryScan;
        private boolean imageBreakpoints;
        private boolean codeSampling;
        private boolean moduleIntegrity;
        private boolean timing;
        private boolean handleDump;
        private boolean codeCrc;
        private boolean pageGuard;
        private boolean textGuard;
        private boolean guardProbe;
        private String execWhitelist = GuardOptions.DEFAULT_EXEC_WHITELIST;
        private boolean linuxChecks;
        private long watchdogMs = 4000L;
        private boolean testHooks;
        private String testHookClass;

        public Builder level(int value) {
            this.level = Math.max(1, Math.min(3, value));
            return this;
        }

        public Builder frida(boolean value) {
            this.frida = value;
            return this;
        }

        public Builder hash(boolean value) {
            this.hash = value;
            return this;
        }

        public Builder remoteThread(boolean value) {
            this.remoteThread = value;
            return this;
        }

        public Builder execMemoryScan(boolean value) {
            this.execMemoryScan = value;
            return this;
        }

        public Builder imageBreakpoints(boolean value) {
            this.imageBreakpoints = value;
            return this;
        }

        public Builder codeSampling(boolean value) {
            this.codeSampling = value;
            return this;
        }

        public Builder moduleIntegrity(boolean value) {
            this.moduleIntegrity = value;
            return this;
        }

        public Builder timing(boolean value) {
            this.timing = value;
            return this;
        }

        public Builder handleDump(boolean value) {
            this.handleDump = value;
            return this;
        }

        public Builder codeCrc(boolean value) {
            this.codeCrc = value;
            return this;
        }

        public Builder pageGuard(boolean value) {
            this.pageGuard = value;
            return this;
        }

        public Builder textGuard(boolean value) {
            this.textGuard = value;
            return this;
        }

        public Builder guardProbe(boolean value) {
            this.guardProbe = value;
            return this;
        }

        public Builder execWhitelist(String value) {
            this.execWhitelist = GuardOptions.execWhitelist(value);
            return this;
        }

        public Builder linuxChecks(boolean value) {
            this.linuxChecks = value;
            return this;
        }

        public Builder watchdogMs(long value) {
            this.watchdogMs = Math.max(0L, value);
            return this;
        }

        public Builder testHooks(String hookClass) {
            this.testHooks = hookClass != null && !hookClass.isEmpty();
            this.testHookClass = hookClass;
            return this;
        }

        public GuardFeatures build() {
            return new GuardFeatures(this);
        }
    }
}
