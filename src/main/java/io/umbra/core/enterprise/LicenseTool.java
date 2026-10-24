package io.umbra.core.enterprise;

import io.umbra.core.config.YamlParser;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Vendor-side utility for generating RSA key pairs and signing licenses.
 *
 * <pre>
 * java -cp umbra.jar io.umbra.core.enterprise.LicenseTool generate keys/
 * java -cp umbra.jar io.umbra.core.enterprise.LicenseTool sign license.yml keys/private.pem license-signed.yml
 * java -cp umbra.jar io.umbra.core.enterprise.LicenseTool verify license-signed.yml keys/public.pem
 * </pre>
 *
 * <p>Keep the private key outside the repository and outside build artifacts.</p>
 */
public final class LicenseTool {

    private LicenseTool() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || "help".equals(args[0]) || "--help".equals(args[0])) {
            usage();
            return;
        }
        if ("generate".equals(args[0])) {
            if (args.length < 2) {
                usage();
                return;
            }
            Path dir = Paths.get(args[1]);
            Files.createDirectories(dir);
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            Files.write(dir.resolve("private.pem"), pem("PRIVATE KEY", pair.getPrivate().getEncoded()));
            Files.write(dir.resolve("public.pem"), pem("PUBLIC KEY", pair.getPublic().getEncoded()));
            System.out.println("Wrote " + dir.resolve("private.pem") + " and " + dir.resolve("public.pem"));
        } else if ("sign".equals(args[0])) {
            if (args.length < 4) {
                usage();
                return;
            }
            sign(Paths.get(args[1]), Paths.get(args[2]), Paths.get(args[3]));
        } else if ("verify".equals(args[0])) {
            if (args.length < 3) {
                usage();
                return;
            }
            LicenseInfo info = LicenseValidator.validate(Paths.get(args[1]), Paths.get(args[2]));
            System.out.println(info.toString());
            if (!info.isValid()) {
                System.exit(1);
            }
        } else {
            usage();
        }
    }

    public static void sign(Path licenseFile, Path privateKeyFile, Path output) throws Exception {
        Map<String, Object> root = YamlParser.parse(new String(Files.readAllBytes(licenseFile), StandardCharsets.UTF_8));
        String id = str(root.get("id"));
        String licensee = str(root.get("licensee"));
        String edition = str(root.get("edition"));
        String expires = str(root.get("expires"));
        List<String> features = list(root.get("features"));
        String payload = LicenseValidator.canonical(id, licensee, edition, expires, features);

        PrivateKey privateKey = readPrivateKey(privateKeyFile);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(payload.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getEncoder().encodeToString(signer.sign());

        StringBuilder out = new StringBuilder();
        if (!id.isEmpty()) {
            out.append("id: ").append(quote(id)).append('\n');
        }
        out.append("licensee: ").append(quote(licensee)).append('\n');
        out.append("edition: ").append(quote(edition)).append('\n');
        out.append("expires: ").append(quote(expires)).append('\n');
        out.append("features:\n");
        for (String feature : features) {
            out.append("  - ").append(quote(feature)).append('\n');
        }
        out.append("signature: ").append(quote(signature)).append('\n');
        if (output.toAbsolutePath().getParent() != null) {
            Files.createDirectories(output.toAbsolutePath().getParent());
        }
        Files.write(output, out.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("Signed license written to " + output);
    }

    public static PrivateKey readPrivateKey(Path file) throws Exception {
        String pem = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        String base64 = pem.replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    public static byte[] pem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der);
        return ("-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static void usage() {
        System.out.println("Umbra license tool");
        System.out.println("  generate <dir>");
        System.out.println("  sign <license.yml> <private.pem> <out.yml>");
        System.out.println("  verify <license.yml> <public.pem>");
        System.out.println();
        System.out.println("license.yml fields: licensee, edition, expires (yyyy-MM-dd), features");
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
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
        }
        return out;
    }
}
