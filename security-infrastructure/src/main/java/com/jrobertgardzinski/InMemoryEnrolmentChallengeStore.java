package com.jrobertgardzinski;

import java.time.Clock;
import java.time.LocalDateTime;
import io.micronaut.context.annotation.Value;
import io.micronaut.scheduling.annotation.Scheduled;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.vo.FactorType;
import com.jrobertgardzinski.security.system.mfa.EnrolmentChallengeStore;
import jakarta.inject.Singleton;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Half-finished enrolments (a factor was started, the proof has not returned) held in memory, keyed
 * by user + factor type. Short-lived; a lost entry only means the user restarts the enrolment.
 *
 * <p>Every entry carries its OWN deadline, because not every pending enrolment has a challenge to
 * borrow one from. A TOTP enrolment stores the generated secret and no challenge at all (the code
 * is computed from the clock, nothing is sent), so the sweeper — which read
 * {@code enrolment.challenge().isExpired(clock)} — threw an NPE on the first such entry and
 * abandoned the rest of the sweep, for everybody: abandoned TOTP secrets then lived for ever and
 * stayed confirmable, and so did every entry the sweep never reached.
 */
@Singleton
final class InMemoryEnrolmentChallengeStore implements EnrolmentChallengeStore {

    /** What the store holds: the enrolment, and when it stops being worth holding. */
    private record Held(PendingEnrolment enrolment, LocalDateTime deadline) {}

    private final Map<String, Held> byKey = new ConcurrentHashMap<>();
    private final Clock clock;
    private final int ttlMinutes;

    InMemoryEnrolmentChallengeStore(Clock clock,
                                    @Value("${security.mfa.enrolment.ttl-minutes:15}") int ttlMinutes) {
        this.clock = clock;
        this.ttlMinutes = ttlMinutes;
    }

    @Override
    public void put(Email user, FactorType type, PendingEnrolment enrolment) {
        byKey.put(key(user, type), new Held(enrolment, deadlineFor(enrolment)));
    }

    @Override
    public Optional<PendingEnrolment> get(Email user, FactorType type) {
        return Optional.ofNullable(byKey.get(key(user, type))).map(Held::enrolment);
    }

    @Override
    public void remove(Email user, FactorType type) {
        byKey.remove(key(user, type));
    }

    /**
     * Drop enrolments nobody came back to finish.
     *
     * <p>An entry is written when someone STARTS adding a factor and removed when they confirm —
     * so every abandoned attempt stays until this runs, and starting one costs a request. The same
     * shape as the OAuth flow store that P18 poz. 17 found growing without a bound; the law that
     * watches for the missing sweeper is StoresWithADeadlineEvictThemTest, and the behaviour of
     * THIS one is pinned by EnrolmentSweeperTest — the law only greps for a sweeper's existence,
     * which is why an NPE inside it went unnoticed.
     */
    @Scheduled(fixedDelay = "5m")
    void evictAbandoned() {
        LocalDateTime now = LocalDateTime.now(clock);
        byKey.values().removeIf(held -> held.deadline().isBefore(now));
    }

    /**
     * A challenge factor's entry dies with its challenge; a possession factor's entry (TOTP: a
     * secret and no challenge) gets the store's own window, because otherwise it has no deadline at
     * all — and an enrolment secret that never expires is confirmable for ever.
     */
    private LocalDateTime deadlineFor(PendingEnrolment enrolment) {
        return enrolment.challenge() != null
                ? enrolment.challenge().expiresAt()
                : LocalDateTime.now(clock).plusMinutes(ttlMinutes);
    }

    private static String key(Email user, FactorType type) {
        return user.value() + "|" + type.value();
    }
}
