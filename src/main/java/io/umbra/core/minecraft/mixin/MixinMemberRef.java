package io.umbra.core.minecraft.mixin;

/**
 * A member reference parsed from a Mixin injection annotation.
 *
 * <p>{@code owner} is {@code null} when the annotation only names the member
 * and the owner has to be derived from the {@code @Mixin} target list.
 * {@code desc} is {@code null} when the reference names the member without a
 * descriptor, which means "keep every descriptor of that name".</p>
 */
public final class MixinMemberRef {

    private final String owner;
    private final String name;
    private final String desc;

    public MixinMemberRef(String owner, String name, String desc) {
        this.owner = owner;
        this.name = name;
        this.desc = desc;
    }

    /** Explicit target owner (internal name) or {@code null}. */
    public String owner() {
        return owner;
    }

    public String name() {
        return name;
    }

    /** Explicit descriptor or {@code null}. */
    public String desc() {
        return desc;
    }

    public boolean hasOwner() {
        return owner != null && !owner.isEmpty();
    }

    @Override
    public String toString() {
        return (owner == null ? "" : owner + ";") + name + (desc == null ? "" : desc);
    }
}
