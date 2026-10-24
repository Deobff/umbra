package demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Resource coverage: reads a UTF-8 text file bundled inside the jar with
 * {@code getResourceAsStream}. A repackaging or archive-level transform has to
 * keep the resource entry and its path intact.
 */
public final class ResourceSuite {

    public static final String RESOURCE = "/demo/assets/data.txt";

    private ResourceSuite() {
    }

    public static void run() throws DemoException, IOException {
        InputStream stream = ResourceSuite.class.getResourceAsStream(RESOURCE);
        Checks.notNull(stream, "resource " + RESOURCE + " is on the classpath");
        Map<String, String> values = new LinkedHashMap<String, String>();
        List<String> lines = new ArrayList<String>();
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(stream, Charset.forName("UTF-8")));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
                int separator = line.indexOf('=');
                if (separator > 0) {
                    values.put(line.substring(0, separator), line.substring(separator + 1));
                }
            }
        } finally {
            reader.close();
        }

        Checks.eq(lines.size(), 6, "resource line count");
        Checks.eq(lines.get(0), "umbra-demo-resource", "resource header");
        Checks.eq(values.get("alpha"), "17", "resource alpha");
        Checks.eq(values.get("beta"), "42", "resource beta");
        Checks.eq(values.get("gamma"), "\u4f60\u597d", "resource unicode value");
        Checks.eq(values.get("delta"), "3.5", "resource delta");
        Checks.eq(values.get("sentinel"), "resource-ok", "resource sentinel");
    }
}
