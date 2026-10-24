package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.model.ClassPool;
import io.umbra.core.util.Jars;
import org.objectweb.asm.Opcodes;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** Embeds a deterministic watermark in a synthetic field and the manifest. */
public final class WatermarkPass implements Pass {

    @Override
    public String name() {
        return "watermark";
    }

    @Override
    public int order() {
        return 110;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().watermark().enabled();
    }

    @Override
    public void run(PassContext context) {
        String payload = "UMBRA|" + context.config().watermark().id()
                + "|1.0.0|seed=" + Long.toHexString(context.config().seed());
        String location = context.runtime().embedWatermark(context.classes(), payload);

        ClassPool pool = context.classes();
        ClassPool.Resource manifest = pool.resource("META-INF/MANIFEST.MF");
        Map<String, String> attributes;
        long time = 0L;
        int method = Opcodes.ACC_PUBLIC;
        if (manifest != null) {
            attributes = new LinkedHashMap<String, String>(Jars.parseManifest(manifest.bytes()));
            time = manifest.time();
            method = manifest.method();
        } else {
            attributes = new LinkedHashMap<String, String>();
            attributes.put("Manifest-Version", "1.0");
            attributes.put("Created-By", "Umbra 1.0.0");
        }
        attributes.put("Umbra-Watermark", payload);
        attributes.put("Umbra-Version", "1.0.0");
        byte[] bytes = Jars.writeManifest(attributes);
        pool.putResource("META-INF/MANIFEST.MF", bytes, time, method);

        context.stats().add("watermark.embedded", 1);
        context.log().info("watermark: embedded in %s and manifest", location == null ? "manifest only" : location);
    }
}
