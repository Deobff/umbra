package io.umbra.core.minecraft.mixin;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses the {@code method} element of Mixin injection annotations.
 *
 * <p>Supported forms, all of which are legal in Mixin annotations:</p>
 * <ul>
 *   <li>{@code name} - any descriptor of that member on the mixin targets;</li>
 *   <li>{@code name(desc)} - an exact member on the mixin targets;</li>
 *   <li>{@code Lowner;name(desc)} - an explicit owner in internal form;</li>
 *   <li>{@code owner.name(desc)} - an explicit owner as a binary or internal
 *       name (the final dot separates the owner from the member).</li>
 * </ul>
 *
 * <p>The element may be a single string, an array of strings or a nested
 * array/list; every element is parsed independently. Constructors and static
 * initializers are skipped because Umbra never renames them, and malformed
 * entries only produce a note.</p>
 */
public final class InjectionTargets {

    private InjectionTargets() {
    }

    /** Parses an annotation element value; never throws. */
    public static List<MixinMemberRef> parse(Object raw, MixinCollector collector, String where) {
        List<MixinMemberRef> out = new ArrayList<MixinMemberRef>();
        collect(raw, out, collector, where);
        return out;
    }

    private static void collect(Object raw, List<MixinMemberRef> out,
                                MixinCollector collector, String where) {
        if (raw == null) {
            return;
        }
        if (raw instanceof String) {
            MixinMemberRef ref = parseSpec(((String) raw).trim(), collector, where);
            if (ref != null) {
                out.add(ref);
            }
            return;
        }
        if (raw instanceof List) {
            for (Object item : (List<?>) raw) {
                collect(item, out, collector, where);
            }
            return;
        }
        if (raw instanceof Object[]) {
            for (Object item : (Object[]) raw) {
                collect(item, out, collector, where);
            }
            return;
        }
        note(collector, "ignored method target of unsupported type "
                + raw.getClass().getSimpleName() + " in " + where);
    }

    /**
     * Parses one method specification. Returns {@code null} for empty entries
     * and constructor/initializer targets.
     */
    public static MixinMemberRef parseSpec(String spec, MixinCollector collector, String where) {
        if (spec == null || spec.isEmpty()) {
            return null;
        }

        String head = spec;
        String desc = null;
        int paren = spec.indexOf('(');
        if (paren >= 0) {
            head = spec.substring(0, paren).trim();
            String rawDesc = spec.substring(paren).trim();
            if (looksLikeDescriptor(rawDesc)) {
                desc = rawDesc;
            } else {
                note(collector, "ignored malformed descriptor '" + rawDesc + "' in " + where);
            }
        }

        String owner = null;
        String name;
        int semicolon = head.indexOf(';');
        if (head.startsWith("L") && semicolon > 0) {
            owner = head.substring(1, semicolon);
            name = head.substring(semicolon + 1);
        } else {
            int dot = head.lastIndexOf('.');
            if (dot > 0) {
                owner = head.substring(0, dot);
                name = head.substring(dot + 1);
            } else {
                name = head;
            }
        }
        name = name.trim();
        if (name.isEmpty()) {
            note(collector, "ignored empty member name in '" + spec + "' in " + where);
            return null;
        }
        if ("<init>".equals(name) || "<clinit>".equals(name)) {
            note(collector, "skipped constructor/initializer target '" + spec + "' in " + where);
            return null;
        }
        if (!looksLikeMemberName(name)) {
            note(collector, "ignored malformed member name '" + name + "' in '" + spec + "' in " + where);
            return null;
        }
        if (owner != null) {
            owner = normalizeOwner(owner);
            if (owner == null) {
                note(collector, "ignored malformed owner in '" + spec + "' in " + where);
                return null;
            }
        }
        return new MixinMemberRef(owner, name, desc);
    }

    /** A method descriptor starts with {@code (} and closes the arguments. */
    private static boolean looksLikeDescriptor(String desc) {
        return desc.length() >= 3 && desc.charAt(0) == '(' && desc.indexOf(')') > 0;
    }

    private static String normalizeOwner(String raw) {
        String owner = raw.trim();
        int start = 0;
        while (start < owner.length() && owner.charAt(start) == '[') {
            start++;
        }
        owner = owner.substring(start);
        if (owner.length() > 2 && owner.charAt(0) == 'L' && owner.charAt(owner.length() - 1) == ';') {
            owner = owner.substring(1, owner.length() - 1);
        }
        owner = owner.replace('.', '/');
        if (owner.isEmpty() || owner.indexOf(';') >= 0 || owner.indexOf(' ') >= 0) {
            return null;
        }
        return owner;
    }

    private static boolean looksLikeMemberName(String name) {
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (Character.isJavaIdentifierPart(c) || c == '<' || c == '>') {
                continue;
            }
            return false;
        }
        return true;
    }

    private static void note(MixinCollector collector, String note) {
        if (collector != null) {
            collector.note(note);
        }
    }
}
