package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;
import com.jrobertgardzinski.security.system.mfa.SessionElevation;
import io.micronaut.context.annotation.Value;
import io.micronaut.scheduling.annotation.Scheduled;
import jakarta.inject.Singleton;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link SessionElevation}: an access token is "recently re-proven" until a short TTL,
 * and the mark is cleared the first time it is consumed (one-shot). Not durable on purpose — a
 * restart just means stepping up again.
 */
@Singleton
final class InMemorySessionElevation implements SessionElevation {

    private final Map<String, Instant> elevatedUntil = new ConcurrentHashMap<>();
    private final Clock clock;
    private final Duration ttl;

    InMemorySessionElevation(Clock clock,
                             @Value("${security.step-up.ttl-minutes:5}") int ttlMinutes) {
        this.clock = clock;
        this.ttl = Duration.ofMinutes(ttlMinutes);
    }

    @Override
    public void elevate(String accessToken, StepUpAction action) {
        elevatedUntil.put(key(accessToken, action), clock.instant().plus(ttl));
    }

    @Override
    public boolean consume(String accessToken, StepUpAction action) {
        Instant until = elevatedUntil.remove(key(accessToken, action));
        return until != null && clock.instant().isBefore(until);
    }

    /** Token and action together — an elevation for one action never satisfies another (poz. 1). */
    private static String key(String accessToken, StepUpAction action) {
        // NUL separates the two parts: a base64url access token never contains it, so
        // (token, action) pairs cannot collide across a shared token.
        return accessToken + "\u0000" + action.wire();
    }

    /** Drops elevations whose TTL has passed so an unclaimed mark cannot pile up unbounded (poz. 17). */
    @Scheduled(fixedDelay = "1m")
    void evictExpired() {
        Instant now = clock.instant();
        elevatedUntil.values().removeIf(until -> !now.isBefore(until));
    }
}
