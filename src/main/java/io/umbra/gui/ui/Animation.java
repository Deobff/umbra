package io.umbra.gui.ui;

import io.umbra.gui.theme.Tokens;

import javax.swing.JComponent;
import javax.swing.RepaintManager;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * One shared, tiny animation scheduler for the whole GUI.
 *
 * <p>A single 60 fps Swing timer drives every running transition. Each frame is
 * frame-time based (not tick based), uses {@link Tokens#easeOut(double)}, caps
 * at {@value #MAX_DURATION} ms, and repaints only the owning component through
 * {@link RepaintManager#addDirtyRegion}. When the last animation finishes the
 * shared timer stops, so the interface is completely idle when nothing moves.</p>
 *
 * <p>{@link #setEnabled(boolean)} (or {@code -Dumbra.gui.animations=false}) turns
 * all motion off for deterministic screenshots and the headless self test; an
 * animation then jumps straight to its final frame.</p>
 */
public final class Animation {

    /** Longest transition allowed for interactive motion (ms). */
    public static final int MAX_DURATION = 200;

    private static final int TICK_MS = 16;
    private static final List<Animator> ACTIVE = new ArrayList<Animator>();
    private static Timer timer;
    private static boolean enabled = !"false".equalsIgnoreCase(
            System.getProperty("umbra.gui.animations", "true"));

    private Animation() {
    }

    /** Receives eased progress values in {@code 0..1}; final frame is exactly 1. */
    public interface Frame {
        void frame(float eased);
    }

    /** Handle for a running (or instantly finished) animation. */
    public static final class Handle {
        private final Animator animator;

        Handle(Animator animator) {
            this.animator = animator;
        }

        /** Stops the animation without delivering another frame. */
        public void stop() {
            if (animator != null) {
                animator.stop();
            }
        }

        public boolean isRunning() {
            return animator != null && animator.running;
        }

        public float progress() {
            return animator == null ? 1f : animator.progress;
        }
    }

    /** Global switch; also used by {@code -Dumbra.gui.animations=false}. */
    public static boolean enabled() {
        return enabled;
    }

    public static void setEnabled(boolean value) {
        enabled = value;
        if (!enabled) {
            stopAll();
        }
    }

    /**
     * Starts an animation for one component.
     *
     * @param owner      component whose bounds are repainted
     * @param durationMs requested duration, clamped to 1..{@value #MAX_DURATION}
     * @param frame      eased frame callback (EDT)
     * @return handle, already finished when animations are disabled
     */
    public static Handle animate(JComponent owner, int durationMs, Frame frame) {
        return animate(owner, durationMs, frame, null);
    }

    /**
     * Starts an animation with a completion callback.
     *
     * @param owner      component whose bounds are repainted
     * @param durationMs requested duration, clamped to 1..{@value #MAX_DURATION}
     * @param frame      eased frame callback (EDT)
     * @param onDone     optional EDT callback after the final frame
     * @return handle
     */
    public static Handle animate(JComponent owner, int durationMs, Frame frame,
                                 Runnable onDone) {
        int duration = Math.max(1, Math.min(MAX_DURATION, durationMs));
        Animator animator = new Animator(owner, duration, frame, onDone);
        if (!enabled || owner == null) {
            animator.finishImmediately();
            return new Handle(animator);
        }
        synchronized (ACTIVE) {
            ACTIVE.add(animator);
        }
        ensureTimer();
        return new Handle(animator);
    }

    /** Stops every running animation (used by deterministic screenshot modes). */
    public static void stopAll() {
        List<Animator> copy;
        synchronized (ACTIVE) {
            copy = new ArrayList<Animator>(ACTIVE);
            ACTIVE.clear();
        }
        for (Animator animator : copy) {
            animator.running = false;
        }
        if (timer != null) {
            timer.stop();
            timer = null;
        }
    }

    private static void ensureTimer() {
        if (timer != null) {
            if (!timer.isRunning()) {
                timer.start();
            }
            return;
        }
        timer = new Timer(TICK_MS, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                tick();
            }
        });
        timer.setCoalesce(true);
        timer.start();
    }

    private static void tick() {
        long now = System.currentTimeMillis();
        List<Animator> finished = null;
        List<Animator> snapshot;
        synchronized (ACTIVE) {
            snapshot = new ArrayList<Animator>(ACTIVE);
        }
        for (Animator animator : snapshot) {
            if (!animator.step(now)) {
                if (finished == null) {
                    finished = new ArrayList<Animator>();
                }
                finished.add(animator);
            }
        }
        if (finished != null) {
            synchronized (ACTIVE) {
                ACTIVE.removeAll(finished);
            }
            for (Animator animator : finished) {
                animator.complete();
            }
        }
        synchronized (ACTIVE) {
            if (ACTIVE.isEmpty() && timer != null) {
                timer.stop();
                timer = null;
            }
        }
    }

    /** One running transition; mutations stay on the event dispatch thread. */
    private static final class Animator {
        private final JComponent owner;
        private final int duration;
        private final Frame frame;
        private final Runnable onDone;
        private final long started;
        private boolean running = true;
        private float progress;

        Animator(JComponent owner, int duration, Frame frame, Runnable onDone) {
            this.owner = owner;
            this.duration = duration;
            this.frame = frame;
            this.onDone = onDone;
            this.started = System.currentTimeMillis();
        }

        boolean step(long now) {
            float raw = Math.min(1f, (now - started) / (float) duration);
            progress = Tokens.easeOut(raw);
            paint();
            return raw < 1f;
        }

        void paint() {
            frame.frame(progress);
            repaintOwner(owner);
        }

        void finishImmediately() {
            running = false;
            progress = 1f;
            frame.frame(1f);
            repaintOwner(owner);
            if (onDone != null) {
                onDone.run();
            }
        }

        void complete() {
            running = false;
            progress = 1f;
            frame.frame(1f);
            repaintOwner(owner);
            if (onDone != null) {
                onDone.run();
            }
        }

        void stop() {
            running = false;
        }
    }

    private static void repaintOwner(JComponent owner) {
        if (owner == null || owner.getWidth() <= 0 || owner.getHeight() <= 0) {
            return;
        }
        try {
            RepaintManager.currentManager(owner).addDirtyRegion(owner, 0, 0,
                    owner.getWidth(), owner.getHeight());
        } catch (RuntimeException ignored) {
            // Painting is best effort during teardown.
            if (SwingUtilities.isEventDispatchThread()) {
                owner.repaint();
            }
        }
    }
}
