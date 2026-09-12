package com.jrobertgardzinski.security.system.throttle;

import com.jrobertgardzinski.security.domain.vo.IpAddress;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-source rate limit for the expensive anonymous endpoints: at most {@code maxPerWindow}
 * attempts from one {@link IpAddress} in a rolling {@code window}. Registration hashes a password
 * with Argon2 and creates accounts; the reset-password and verify-email requests mint tokens and
 * send mails — unthrottled, each is a CPU-exhaustion, mass-signup or mail-bomb vector. One
 * instance guards one endpoint (each gets its own window and cap), so a burst against one cannot
 * starve another. A fixed window in memory; the source is the spoof-resistant IP the resolver
 * already trusts. Deliberately separate from the authentication guard: that one defends accounts
 * against password guessing, this one defends the service against volume.
 */
public class SourceThrottle {

    /** Whether the attempt is allowed, and if not, how long until the window frees up. */
    public record Decision(boolean allowed, long retryAfterSeconds) {}

    private record Window(Instant start, int count) {}

    private final int maxPerWindow;
    private final Duration window;
    private final Clock clock;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public SourceThrottle(int maxPerWindow, Duration window, Clock clock) {
        this.maxPerWindow = maxPerWindow;
        this.window = window;
        this.clock = clock;
    }

    /** Above this many tracked sources, a check first evicts windows that have already rolled over. */
    private static final int SWEEP_THRESHOLD = 10_000;

    /**
     * The most sources this will remember at once, however busy the window is.
     *
     * <p>The sweep above only frees windows that have ALREADY rolled over, so inside one window a
     * caller rotating addresses could hold the map above the threshold with entries none of which
     * are expired — and then every single request paid for a full O(n) walk that freed nothing. Two
     * things fix that: a sweep only runs once per growth step (below), and past this ceiling the
     * oldest windows are dropped outright. Dropping a window forgives whoever owned it, which is
     * the lesser evil: the alternative is the service spending its request path on bookkeeping for
     * an attacker who is not being limited by it anyway.
     */
    private static final int HARD_CAP = 100_000;

    /** The size the map had when it was last swept; a sweep that frees nothing is not repeated. */
    private final java.util.concurrent.atomic.AtomicInteger sweptAt =
            new java.util.concurrent.atomic.AtomicInteger(SWEEP_THRESHOLD);

    /** Record one attempt from this source and decide whether it may proceed. */
    public Decision check(IpAddress source) {
        if (maxPerWindow <= 0) {
            return new Decision(true, 0);   // disabled
        }
        Instant now = clock.instant();
        // this map is fed by anonymous endpoints, so a source rotating IPs could grow it without
        // bound; drop windows that have already elapsed once the map gets large (poz. 17) — but
        // only once per growth step, because inside a single window there is nothing to free and
        // walking the whole map on every request is its own denial of service
        if (windows.size() > sweptAt.get()) {
            windows.values().removeIf(w -> Duration.between(w.start(), now).compareTo(window) >= 0);
            evictOldestAbove(HARD_CAP);
            sweptAt.set(Math.max(SWEEP_THRESHOLD, windows.size() * 2));
        }
        Window updated = windows.compute(source.value(), (ip, current) ->
                current == null || Duration.between(current.start(), now).compareTo(window) >= 0
                        ? new Window(now, 1)
                        : new Window(current.start(), current.count() + 1));
        if (updated.count() <= maxPerWindow) {
            return new Decision(true, 0);
        }
        long retryAfter = Math.max(1,
                window.minus(Duration.between(updated.start(), now)).toSeconds());
        return new Decision(false, retryAfter);
    }

    /** Oldest windows first, because they are the ones closest to rolling over by themselves. */
    private void evictOldestAbove(int cap) {
        int excess = windows.size() - cap;
        if (excess <= 0) {
            return;
        }
        windows.entrySet().stream()
                .sorted(java.util.Comparator.comparing(entry -> entry.getValue().start()))
                .limit(excess)
                .map(Map.Entry::getKey)
                .forEach(windows::remove);
    }
}
