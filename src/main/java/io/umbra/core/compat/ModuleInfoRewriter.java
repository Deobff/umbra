package io.umbra.core.compat;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;

import java.util.ArrayList;
import java.util.List;

/**
 * Remaps {@code module-info.class} descriptors through the naming mapping.
 *
 * <p>ASM's {@link ClassRemapper} rewrites {@code exports}/{@code opens}
 * packages via the package map and {@code uses}/{@code provides} classes via the
 * class map. Before rewriting, the descriptor is checked for package moves that
 * cannot be represented consistently; in {@code auto} mode such a descriptor is
 * dropped with a reason instead of being emitted stale, because an invalid
 * descriptor breaks JPMS resolution for the whole archive.</p>
 */
public final class ModuleInfoRewriter {

    /** What happened to one module descriptor. */
    public enum Action {
        /** Written unchanged. */
        KEPT,
        /** Written after remapping. */
        REWRITTEN,
        /** Not written. */
        DROPPED
    }

    /** Result of rewriting one descriptor. */
    public static final class Result {
        private final Action action;
        private final byte[] bytes;
        private final String detail;

        Result(Action action, byte[] bytes, String detail) {
            this.action = action;
            this.bytes = bytes;
            this.detail = detail;
        }

        public Action action() {
            return action;
        }

        public byte[] bytes() {
            return bytes;
        }

        /** Human readable reason for the action, used in warnings and stats. */
        public String detail() {
            return detail;
        }
    }

    private ModuleInfoRewriter() {
    }

    /** Rewrites one module descriptor according to {@code mode}. */
    public static Result rewrite(byte[] moduleInfo, ClassRenameMap rename,
                                 LayoutOptions.ModuleInfoMode mode, String entryName) {
        if (mode == null) {
            mode = LayoutOptions.ModuleInfoMode.AUTO;
        }
        if (moduleInfo == null) {
            return new Result(Action.DROPPED, null, "module descriptor bytes are missing");
        }
        if (mode == LayoutOptions.ModuleInfoMode.DROP) {
            return new Result(Action.DROPPED, null, "layout.moduleInfo=drop");
        }
        boolean noRenames = rename == null || rename.isEmpty() || !rename.hasClassMapping();
        Details details;
        try {
            details = inspect(moduleInfo);
        } catch (RuntimeException malformed) {
            if (mode == LayoutOptions.ModuleInfoMode.AUTO) {
                return new Result(Action.DROPPED, null,
                        "unparseable module descriptor (" + malformed.getMessage() + ')');
            }
            return new Result(Action.KEPT, moduleInfo, "unparseable; kept original");
        }
        if (details == null) {
            if (mode == LayoutOptions.ModuleInfoMode.AUTO) {
                return new Result(Action.DROPPED, null, "not a module descriptor");
            }
            return new Result(Action.KEPT, moduleInfo, "not a module descriptor; kept original");
        }
        if (noRenames) {
            // AUTO still validates: a structurally broken descriptor must not be
            // emitted even when no class was renamed.
            return new Result(Action.KEPT, moduleInfo, "no renames");
        }

        String problem = checkPackageMappings(details, rename);
        if (problem != null) {
            if (mode == LayoutOptions.ModuleInfoMode.AUTO) {
                return new Result(Action.DROPPED, null, problem);
            }
            return new Result(Action.KEPT, moduleInfo, problem + "; kept original");
        }
        byte[] rewritten;
        try {
            ClassReader reader = new ClassReader(moduleInfo);
            ClassWriter writer = new ClassWriter(0);
            reader.accept(new ClassRemapper(writer, rename.remapper()), 0);
            rewritten = writer.toByteArray();
        } catch (RuntimeException failure) {
            if (mode == LayoutOptions.ModuleInfoMode.AUTO) {
                return new Result(Action.DROPPED, null,
                        "module remap failed (" + failure.getMessage() + ')');
            }
            return new Result(Action.KEPT, moduleInfo, "module remap failed; kept original");
        }
        Details after;
        try {
            after = inspect(rewritten);
        } catch (RuntimeException malformed) {
            after = null;
        }
        if (after == null || !details.moduleName.equals(after.moduleName)) {
            if (mode == LayoutOptions.ModuleInfoMode.AUTO) {
                return new Result(Action.DROPPED, null, "module remap produced an invalid descriptor");
            }
            return new Result(Action.KEPT, moduleInfo, "module remap produced an invalid descriptor; "
                    + "kept original");
        }
        if (java.util.Arrays.equals(moduleInfo, rewritten)) {
            return new Result(Action.KEPT, moduleInfo, "descriptor does not reference renamed names");
        }
        return new Result(Action.REWRITTEN, rewritten, "descriptor remapped for " + entryName);
    }

    private static String checkPackageMappings(Details details, ClassRenameMap rename) {
        for (String packageName : details.exportedPackages) {
            String internal = packageName.replace('.', '/');
            if (rename.packageConflicts().contains(internal)) {
                return "exported package " + packageName + " has an inconsistent class mapping";
            }
            if (!rename.hasPackageMapping(internal) && rename.hasClassMovedOut(internal)) {
                return "exported package " + packageName + " lost classes to another package";
            }
        }
        for (String packageName : details.openedPackages) {
            String internal = packageName.replace('.', '/');
            if (rename.packageConflicts().contains(internal)) {
                return "opened package " + packageName + " has an inconsistent class mapping";
            }
            if (!rename.hasPackageMapping(internal) && rename.hasClassMovedOut(internal)) {
                return "opened package " + packageName + " lost classes to another package";
            }
        }
        return null;
    }

    private static Details inspect(byte[] moduleInfo) {
        final Details details = new Details();
        final boolean[] sawModule = new boolean[1];
        ClassReader reader = new ClassReader(moduleInfo);
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public ModuleVisitor visitModule(String name, int access, String version) {
                sawModule[0] = true;
                details.moduleName = name;
                return new ModuleVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitExport(String packaze, int access, String... modules) {
                        if (packaze != null) {
                            details.exportedPackages.add(packaze);
                        }
                    }

                    @Override
                    public void visitOpen(String packaze, int access, String... modules) {
                        if (packaze != null) {
                            details.openedPackages.add(packaze);
                        }
                    }

                    @Override
                    public void visitUse(String service) {
                        if (service != null) {
                            details.usedServices.add(service);
                        }
                    }

                    @Override
                    public void visitProvide(String service, String... providers) {
                        if (service != null) {
                            details.providedServices.add(service);
                        }
                    }
                };
            }
        }, 0);
        return sawModule[0] ? details : null;
    }

    private static final class Details {
        String moduleName;
        final List<String> exportedPackages = new ArrayList<String>();
        final List<String> openedPackages = new ArrayList<String>();
        final List<String> usedServices = new ArrayList<String>();
        final List<String> providedServices = new ArrayList<String>();
    }
}
