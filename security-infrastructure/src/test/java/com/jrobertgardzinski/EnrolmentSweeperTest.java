package com.jrobertgardzinski;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.vo.FactorType;
import com.jrobertgardzinski.security.system.mfa.Challenge;
import com.jrobertgardzinski.security.system.mfa.EnrolmentChallengeStore.PendingEnrolment;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The enrolment sweeper, exercised rather than grepped for.
 *
 * <p>{@code StoresWithADeadlineEvictThemTest} asserts that a store with a deadline HAS a sweeper,
 * by reading the source for {@code @Scheduled} and {@code removeIf}. That law was satisfied while
 * the sweeper threw: a TOTP enrolment has no challenge (nothing is sent — the code comes from the
 * clock), so {@code enrolment.challenge().isExpired(clock)} was an NPE on the first such entry and
 * the sweep died there for every user at once. Abandoned TOTP secrets then lived for ever and
 * stayed confirmable, and so did everything the sweep never reached.
 */
@Epic("Use case")
@Feature("MFA — enrolment")
class EnrolmentSweeperTest {

    private static final Email ALICE = Email.of("alice@example.com");
    private static final Email BOB = Email.of("bob@example.com");

    /** A clock the test moves, because a deadline is only interesting once time has passed. */
    private static final class MovableClock extends Clock {
        private Instant now = Instant.parse("2026-09-12T12:00:00Z");

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }

        void advance(Duration by) { now = now.plus(by); }
    }

    @Test
    @DisplayName("a pending TOTP enrolment neither breaks the sweep nor outlives its window")
    void the_sweep_survives_a_factor_with_no_challenge() {
        MovableClock clock = new MovableClock();
        InMemoryEnrolmentChallengeStore store = new InMemoryEnrolmentChallengeStore(clock, 15);

        // TOTP: a secret and NO challenge — the entry the sweeper used to trip over
        store.put(ALICE, FactorType.TOTP, new PendingEnrolment("JBSWY3DPEHPK3PXP", null));
        // a code factor beside it, so "the sweep reached the rest" is observable
        store.put(BOB, FactorType.EMAIL_CODE, new PendingEnrolment("bob@example.com",
                Challenge.secret("hash", LocalDateTime.now(clock).plusMinutes(5))));

        store.evictAbandoned();   // nothing is due yet — and nothing throws
        assertTrue(store.get(ALICE, FactorType.TOTP).isPresent(), "the TOTP enrolment is still fresh");
        assertTrue(store.get(BOB, FactorType.EMAIL_CODE).isPresent());

        clock.advance(Duration.ofHours(1));
        store.evictAbandoned();

        assertFalse(store.get(ALICE, FactorType.TOTP).isPresent(),
                "an abandoned TOTP secret must not stay confirmable for ever");
        assertFalse(store.get(BOB, FactorType.EMAIL_CODE).isPresent(),
                "and the entries behind it must be reached, which an NPE on the first one prevented");
    }

    @Test
    @DisplayName("an enrolment still inside its window survives the sweep")
    void a_live_enrolment_is_not_swept() {
        MovableClock clock = new MovableClock();
        InMemoryEnrolmentChallengeStore store = new InMemoryEnrolmentChallengeStore(clock, 15);
        store.put(ALICE, FactorType.TOTP, new PendingEnrolment("JBSWY3DPEHPK3PXP", null));

        clock.advance(Duration.ofMinutes(14));
        store.evictAbandoned();

        assertTrue(store.get(ALICE, FactorType.TOTP).isPresent(),
                "the window is 15 minutes; a sweeper that takes one minute too much is its own defect");
    }
}
