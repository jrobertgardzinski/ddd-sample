package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.system.mfa.SpentTotpSteps;
import io.micronaut.scheduling.annotation.Scheduled;
import jakarta.inject.Singleton;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The highest TOTP step each enrolment has already spent, in memory. One entry per user who uses
 * TOTP, holding a single number; it is swept of anything older than an hour, because a step that
 * far in the past cannot be replayed anyway (the factor only ever looks one step either side of
 * now).
 *
 * <p>In memory like the rest of the short-lived MFA state: a restart re-opens a replay window of at
 * most 90 seconds, which is what this closes the other 99.9% of the time. A shared store takes over
 * if this service scales out — the same trade-off the pending-authentication store makes.
 */
@Singleton
final class InMemorySpentTotpSteps implements SpentTotpSteps {

    private static final long STEP_SECONDS = 30;
    private static final long KEEP_STEPS = 3600 / STEP_SECONDS;   // an hour's worth

    private final Map<String, Long> highestSpent = new ConcurrentHashMap<>();
    private final Clock clock;

    InMemorySpentTotpSteps(Clock clock) {
        this.clock = clock;
    }

    @Override
    public boolean claim(EnrolledFactor enrolment, long step) {
        String key = enrolment.userEmail().value() + "|" + enrolment.type().value();
        // compute, not get-then-put: two relays of the same code arriving together must not both win
        Long accepted = highestSpent.compute(key,
                (ignored, previous) -> previous == null || step > previous ? step : previous);
        return accepted != null && accepted == step && isFresh(step);
    }

    /** A step from the future or the distant past is nobody's live code; the factor bounds it anyway. */
    private boolean isFresh(long step) {
        long now = clock.instant().getEpochSecond() / STEP_SECONDS;
        return Math.abs(now - step) <= 1;
    }

    @Scheduled(fixedDelay = "30m")
    void evictOldSteps() {
        long oldest = clock.instant().getEpochSecond() / STEP_SECONDS - KEEP_STEPS;
        highestSpent.values().removeIf(step -> step < oldest);
    }
}
