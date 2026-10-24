package io.umbra.core.enterprise;

import java.util.Collections;
import java.util.List;

/** Validated (or rejected) enterprise license. */
public final class LicenseInfo {

    private final String id;
    private final String licensee;
    private final String edition;
    private final String expires;
    private final List<String> features;
    private final boolean valid;
    private final boolean signatureVerified;
    private final String error;

    public LicenseInfo(String licensee, String edition, String expires, List<String> features,
                       boolean valid, boolean signatureVerified, String error) {
        this("", licensee, edition, expires, features, valid, signatureVerified, error);
    }

    public LicenseInfo(String id, String licensee, String edition, String expires, List<String> features,
                       boolean valid, boolean signatureVerified, String error) {
        this.id = id == null ? "" : id;
        this.licensee = licensee;
        this.edition = edition;
        this.expires = expires;
        this.features = Collections.unmodifiableList(features);
        this.valid = valid;
        this.signatureVerified = signatureVerified;
        this.error = error;
    }

    public String id() { return id; }
    public String licensee() { return licensee; }
    public String edition() { return edition; }
    public String expires() { return expires; }
    public List<String> features() { return features; }
    public boolean isValid() { return valid; }
    public boolean isSignatureVerified() { return signatureVerified; }
    public String error() { return error; }

    public boolean hasFeature(String feature) {
        return features.contains(feature) || features.contains("*");
    }

    @Override
    public String toString() {
        if (valid) {
            return "license{id='" + id + "', licensee='" + licensee + "', edition='" + edition
                    + "', expires='" + expires + "', features=" + features + '}';
        }
        return "license{INVALID: " + error + '}';
    }
}
