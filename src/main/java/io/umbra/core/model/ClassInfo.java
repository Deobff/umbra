package io.umbra.core.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Lightweight hierarchy node used by the renamer and the frame-computing writer. */
public final class ClassInfo {

    public enum Source {
        INPUT, LIBRARY, JDK, UNKNOWN
    }

    private final String name;
    private final String superName;
    private final String[] interfaces;
    private final int access;
    private final Source source;
    private final int version;
    private final Set<String> methods = new LinkedHashSet<String>();
    private final Set<String> fields = new LinkedHashSet<String>();
    private final Map<String, Integer> methodAccess = new LinkedHashMap<String, Integer>();
    private final Map<String, Integer> fieldAccess = new LinkedHashMap<String, Integer>();

    public ClassInfo(String name, String superName, String[] interfaces, int access, Source source, int version) {
        this.name = name;
        this.superName = superName;
        this.interfaces = interfaces == null ? new String[0] : interfaces;
        this.access = access;
        this.source = source;
        this.version = version;
    }

    public String name() { return name; }
    public String superName() { return superName; }
    public String[] interfaces() { return interfaces; }
    public int access() { return access; }
    public Source source() { return source; }
    public int version() { return version; }
    public Set<String> methods() { return Collections.unmodifiableSet(methods); }
    public Set<String> fields() { return Collections.unmodifiableSet(fields); }

    public void addMethod(String name, String desc) {
        methods.add(name + desc);
    }

    public void addMethod(String name, String desc, int access) {
        methods.add(name + desc);
        methodAccess.put(name + desc, Integer.valueOf(access));
    }

    public void addField(String name, String desc) {
        fields.add(name + ":" + desc);
    }

    public void addField(String name, String desc, int access) {
        fields.add(name + ":" + desc);
        fieldAccess.put(name + ":" + desc, Integer.valueOf(access));
    }

    /** Method access flags, or {@code null} when unknown. */
    public Integer methodAccess(String name, String desc) {
        return methodAccess.get(name + desc);
    }

    /** Field access flags, or {@code null} when unknown. */
    public Integer fieldAccess(String name, String desc) {
        return fieldAccess.get(name + ":" + desc);
    }

    public boolean hasMethod(String name, String desc) {
        return methods.contains(name + desc);
    }

    public boolean hasField(String name, String desc) {
        return fields.contains(name + ":" + desc);
    }

    public boolean isInput() { return source == Source.INPUT; }
    public boolean isInterface() { return (access & 0x0200) != 0; }
}
