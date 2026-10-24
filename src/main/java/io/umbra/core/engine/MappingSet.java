package io.umbra.core.engine;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Bidirectional naming information produced by the renamer. */
public final class MappingSet {

    private final Map<String, String> classes = new LinkedHashMap<String, String>();
    private final Map<String, String> reverseClasses = new LinkedHashMap<String, String>();
    private final Map<String, String> methods = new LinkedHashMap<String, String>();
    private final Map<String, String> fields = new LinkedHashMap<String, String>();

    /** Global method map keyed by {@code name + desc}; preserves override families. */
    private final Map<String, String> globalMethods = new LinkedHashMap<String, String>();
    /** Global field map keyed by {@code name + ":" + desc}. */
    private final Map<String, String> globalFields = new LinkedHashMap<String, String>();

    public void mapClass(String from, String to) {
        classes.put(from, to);
        reverseClasses.put(to, from);
    }

    /** Records a method mapping keyed by {@code owner#name#desc}. */
    public void mapMethod(String owner, String name, String desc, String to) {
        methods.put(owner + "#" + name + "#" + desc, to);
        globalMethods.put(name + desc, to);
    }

    /** Records a field mapping keyed by {@code owner#name#desc}. */
    public void mapField(String owner, String name, String desc, String to) {
        fields.put(owner + "#" + name + "#" + desc, to);
        globalFields.put(name + ":" + desc, to);
    }

    public boolean isEmpty() {
        return classes.isEmpty() && methods.isEmpty() && fields.isEmpty();
    }

    public Map<String, String> classes() {
        return Collections.unmodifiableMap(classes);
    }

    public Map<String, String> reverseClasses() {
        return Collections.unmodifiableMap(reverseClasses);
    }

    public Map<String, String> methods() {
        return Collections.unmodifiableMap(methods);
    }

    public Map<String, String> fields() {
        return Collections.unmodifiableMap(fields);
    }

    public Map<String, String> globalMethods() {
        return Collections.unmodifiableMap(globalMethods);
    }

    public Map<String, String> globalFields() {
        return Collections.unmodifiableMap(globalFields);
    }

    public String mappedClass(String internalName) {
        String mapped = classes.get(internalName);
        return mapped == null ? internalName : mapped;
    }

    public String mappedMethod(String name, String desc) {
        String mapped = globalMethods.get(name + desc);
        return mapped == null ? name : mapped;
    }

    public String mappedField(String name, String desc) {
        String mapped = globalFields.get(name + ":" + desc);
        return mapped == null ? name : mapped;
    }
}
