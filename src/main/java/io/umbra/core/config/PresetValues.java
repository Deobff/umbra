package io.umbra.core.config;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Effective option values of a preset, in the documented {@code key=value} form.
 *
 * <p>A front-end needs this because explicit {@code --set} values win over the
 * preset: when the UI sends its own defaults for every control, the preset is
 * silently neutralised. With this dump the UI can load the preset values into
 * its controls, so picking a preset really changes the result.</p>
 */
public final class PresetValues {

    private PresetValues() {
    }

    /** Resolves {@code preset} against {@code base} and returns every value it sets. */
    public static Map<String, String> describe(String preset, UmbraConfig base) throws ConfigException {
        Map<String, String> values = new LinkedHashMap<String, String>();
        UmbraConfig config = Presets.apply(base, preset, false);
        values.putAll(config.options());

        UmbraConfig.RenamerOptions renamer = config.renamer();
        values.put("renamer.enabled", String.valueOf(renamer.enabled()));
        values.put("renamer.prefix", renamer.prefix());
        values.put("renamer.repackage", String.valueOf(renamer.repackage()));
        values.put("renamer.repackagePackage", renamer.repackagePackage());
        values.put("renamer.renameClasses", String.valueOf(renamer.renameClasses()));
        values.put("renamer.renameMethods", String.valueOf(renamer.renameMethods()));
        values.put("renamer.renameFields", String.valueOf(renamer.renameFields()));
        values.put("renamer.dictionary", renamer.dictionary());
        values.put("renamer.minimumNameLength", String.valueOf(renamer.minimumNameLength()));

        values.put("stringEncryption.enabled", String.valueOf(config.stringEncryption().enabled()));
        values.put("stringEncryption.minLength", String.valueOf(config.stringEncryption().minLength()));
        values.put("integerEncryption.enabled", String.valueOf(config.integerEncryption().enabled()));
        values.put("integerEncryption.includeLong", String.valueOf(config.integerEncryption().includeLong()));

        values.put("flowObfuscation.enabled", String.valueOf(config.flow().enabled()));
        values.put("flowObfuscation.level", config.flow().level());
        values.put("flowObfuscation.maxInstructions", String.valueOf(config.flow().maxInstructions()));
        values.put("flowObfuscation.flattening", String.valueOf(config.flow().flattening()));
        values.put("exceptionObfuscation.enabled", String.valueOf(config.exceptionObfuscation().enabled()));
        values.put("methodVirtualization.enabled", String.valueOf(config.methodVirtualization().enabled()));
        values.put("methodVirtualization.maxInstructions",
                String.valueOf(config.methodVirtualization().maxInstructions()));

        values.put("antiLlm.enabled", String.valueOf(config.antiLlm().enabled()));
        values.put("antiLlm.decoyMethodsPerClass", String.valueOf(config.antiLlm().decoyMethodsPerClass()));
        values.put("antiLlm.wrapperLayers", String.valueOf(config.antiLlm().wrapperLayers()));
        values.put("antiLlm.maxWrappedMethodsPerClass",
                String.valueOf(config.antiLlm().maxWrappedMethodsPerClass()));

        values.put("junkMembers.enabled", String.valueOf(config.junk().enabled()));
        values.put("junkMembers.methods", String.valueOf(config.junk().methods()));
        values.put("junkMembers.fields", String.valueOf(config.junk().fields()));

        values.put("debugInfo.enabled", String.valueOf(config.debug().enabled()));
        values.put("debugInfo.removeSourceFile", String.valueOf(config.debug().removeSourceFile()));
        values.put("debugInfo.removeLineNumbers", String.valueOf(config.debug().removeLineNumbers()));
        values.put("debugInfo.removeLocalVariables", String.valueOf(config.debug().removeLocalVariables()));
        values.put("debugInfo.removeSignatures", String.valueOf(config.debug().removeSignatures()));
        values.put("reflection.enabled", String.valueOf(config.reflection().enabled()));
        return values;
    }

    /** Renders the map as tab separated {@code key<TAB>value} lines. */
    public static String dump(String preset, UmbraConfig base) throws ConfigException {
        StringBuilder out = new StringBuilder(4096);
        for (Map.Entry<String, String> entry : describe(preset, base).entrySet()) {
            String value = entry.getValue() == null ? "" : entry.getValue();
            out.append(entry.getKey()).append('\t').append(value.replace('\t', ' ')).append('\n');
        }
        return out.toString();
    }
}
