package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import org.objectweb.asm.tree.ClassNode;

import java.util.Collections;
import java.util.Random;

/** Randomizes the declaration order of fields and methods. */
public final class MemberShufflePass implements Pass {

    @Override
    public String name() {
        return "member-shuffle";
    }

    @Override
    public int order() {
        return 40;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().shuffle().enabled();
    }

    @Override
    public void run(PassContext context) {
        long seed = context.config().seed();
        int classes = 0;
        for (ClassNode node : context.classes().classes().values()) {
            if (!context.rules().transformClass(node) || context.classes().isFrozen(node.name)) {
                continue;
            }
            Random random = new Random(seed ^ node.name.hashCode());
            Collections.shuffle(node.fields, random);
            Collections.shuffle(node.methods, random);
            classes++;
        }
        context.stats().add("classes.shuffled", classes);
        context.log().info("member-shuffle: shuffled %d classes", classes);
    }
}
