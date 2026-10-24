package io.umbra.core.enterprise;

import io.umbra.core.config.YamlParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Validates RSA-SHA256 signed licenses.
 *
 * <pre>
 * id: lic-123
 * licensee: Acme Corp
 * edition: enterprise
 * expires: 2027-12-31
 * features:
 *   - audit
 * signature: BASE64(RSA-SHA256(canonical))
 * </pre>
 *
 * <p>Canonical payload: {@code id|licensee|edition|expires|sorted,features}
 * when an id is present, otherwise the legacy
 * {@code licensee|edition|expires|sorted,features}. Without a public key the
 * license is parsed but never considered valid.</p>
 */
public final class LicenseValidator {

    private LicenseValidator() {
    }

    public static LicenseInfo validate(Path licenseFile) throws IOException {
        return validate(licenseFile, null);
    }

    public static LicenseInfo validate(Path licenseFile, Path publicKeyFile) throws IOException {
        String text = new String(Files.readAllBytes(licenseFile), StandardCharsets.UTF_8);
        return validateText(text, publicKeyFile);
    }

    public static LicenseInfo validateText(String text, Path publicKeyFile) {
        PublicKey key = null;
        if (publicKeyFile != null) {
            try {
                key = readPublicKey(publicKeyFile);
            } catch (Exception e) {
                return invalid("", "", "", "", Collections.<String>emptyList(),
                        "Unable to read public key: " + e.getMessage());
            }
        }
        return validateText(text, key);
    }

    public static LicenseInfo validateText(String text, PublicKey publicKey) {
        Map<String, Object> root;
        try {
            root = YamlParser.parse(text);
        } catch (Exception e) {
            return invalid("", "", "", "", Collections.<String>emptyList(),
                    "Malformed license: " + e.getMessage());
        }
        String id = str(root.get("id"));
        String licensee = str(root.get("licensee"));
        String edition = str(root.get("edition"));
        String expires = str(root.get("expires"));
        String signature = str(root.get("signature"));
        List<String> features = list(root.get("features"));

        if (licensee.isEmpty() || edition.isEmpty() || expires.isEmpty()) {
            return invalid(id, licensee, edition, expires, features,
                    "Missing licensee, edition or expires");
        }
        if (signature.isEmpty()) {
            return invalid(id, licensee, edition, expires, features, "Missing signature");
        }
        if (isExpired(expires)) {
            return invalid(id, licensee, edition, expires, features, "License expired on " + expires);
        }
        if (publicKey == null) {
            return new LicenseInfo(id, licensee, edition, expires, features, false, false,
                    "Public key not provided; signature cannot be verified");
        }
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(canonical(id, licensee, edition, expires, features)
                    .getBytes(StandardCharsets.UTF_8));
            boolean ok = verifier.verify(Base64.getDecoder().decode(signature));
            if (!ok) {
                return new LicenseInfo(id, licensee, edition, expires, features, false, true,
                        "Signature verification failed");
            }
        } catch (Exception e) {
            return new LicenseInfo(id, licensee, edition, expires, features, false, false,
                    "Signature verification error: " + e.getMessage());
        }
        return new LicenseInfo(id, licensee, edition, expires, features, true, true, "");
    }

    /** Legacy canonical payload (no id). */
    public static String canonical(String licensee, String edition, String expires, List<String> features) {
        return canonical("", licensee, edition, expires, features);
    }

    /** Canonical payload shared by the signer and verifier. */
    public static String canonical(String id, String licensee, String edition, String expires,
                                   List<String> features) {
        List<String> sorted = new ArrayList<String>(features);
        Collections.sort(sorted);
        StringBuilder base = new StringBuilder();
        base.append(licensee).append('|').append(edition).append('|').append(expires).append('|');
        for (int i = 0; i < sorted.size(); i++) {
            if (i > 0) {
                base.append(',');
            }
            base.append(sorted.get(i));
        }
        return id == null || id.isEmpty() ? base.toString() : id + "|" + base;
    }

    public static PublicKey readPublicKey(Path file) throws Exception {
        String pem = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        String base64 = pem.replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    private static boolean isExpired(String expires) {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
        format.setLenient(false);
        try {
            Date date = format.parse(expires);
            return date.before(new Date());
        } catch (ParseException e) {
            return true;
        }
    }

    private static LicenseInfo invalid(String id, String licensee, String edition, String expires,
                                       List<String> features, String error) {
        return new LicenseInfo(id, licensee, edition, expires, features, false, false, error);
    }

    private static String str(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    @SuppressWarnings("unchecked")
    private static List<String> list(Object value) {
        List<String> out = new ArrayList<String>();
        if (value instanceof List) {
            for (Object item : (List<Object>) value) {
                if (item != null) {
                    out.add(String.valueOf(item).trim());
                }
            }
        } else if (value != null && !String.valueOf(value).trim().isEmpty()) {
            out.add(String.valueOf(value).trim());
        }
        return out;
    }
}
