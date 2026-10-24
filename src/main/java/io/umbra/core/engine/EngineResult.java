package io.umbra.core.engine;

import io.umbra.core.enterprise.LicenseInfo;
import io.umbra.core.enterprise.RiskReport;

import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Result of one Umbra run. */
public final class EngineResult {

    private final Path output;
    private final int classes;
    private final int resources;
    private final long millis;
    private final boolean dryRun;
    private final Map<String, Long> passTimes;
    private final Stats stats;
    private final RiskReport risk;
    private final LicenseInfo license;
    private final Path reportHtml;
    private final Path reportJson;

    public EngineResult(Path output, int classes, int resources, long millis,
                        boolean dryRun, Map<String, Long> passTimes,
                        Stats stats, RiskReport risk, LicenseInfo license,
                        Path reportHtml, Path reportJson) {
        this.output = output;
        this.classes = classes;
        this.resources = resources;
        this.millis = millis;
        this.dryRun = dryRun;
        this.passTimes = Collections.unmodifiableMap(new LinkedHashMap<String, Long>(passTimes));
        this.stats = stats;
        this.risk = risk;
        this.license = license;
        this.reportHtml = reportHtml;
        this.reportJson = reportJson;
    }

    public Path output() { return output; }
    public int classes() { return classes; }
    public int resources() { return resources; }
    public long millis() { return millis; }
    public boolean dryRun() { return dryRun; }
    public Map<String, Long> passTimes() { return passTimes; }
    public Stats stats() { return stats; }
    public RiskReport risk() { return risk; }
    public LicenseInfo license() { return license; }
    public Path reportHtml() { return reportHtml; }
    public Path reportJson() { return reportJson; }

    @Override
    public String toString() {
        return "EngineResult{classes=" + classes + ", resources=" + resources
                + ", millis=" + millis + ", dryRun=" + dryRun + '}';
    }
}
