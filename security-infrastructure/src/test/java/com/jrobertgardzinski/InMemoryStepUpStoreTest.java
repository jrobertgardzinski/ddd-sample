package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.system.mfa.PendingAuthentication;
import com.jrobertgardzinski.security.system.mfa.StepUpStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A step-up ticket must not outlive its chain's TTL: without eviction an abandoned step-up lingered
 * until the process restarted (poz. 17), and its expiry backs the InvalidTicket check in StepUp (poz. 23).
 */
class InMemoryStepUpStoreTest {

    private final Clock clock = Clock.fixed(Instant.parse("2026-07-30T12:00:00Z"), ZoneOffset.UTC);

    private StepUpStore.StepUpPending pending(LocalDateTime expiresAt) {
        return new StepUpStore.StepUpPending(Email.of("user@example.com"), "access-token", StepUpAction.DELETE_ACCOUNT,
                new PendingAuthentication(Email.of("user@example.com"), List.of(), null, 3, expiresAt));
    }

    @Test
    @DisplayName("evictExpired drops aged tickets and keeps live ones")
    void evictsExpiredTickets() {
        InMemoryStepUpStore store = new InMemoryStepUpStore(clock);
        String expired = store.open(pending(LocalDateTime.now(clock).minusMinutes(1)));
        String live = store.open(pending(LocalDateTime.now(clock).plusMinutes(10)));

        store.evictExpired();

        assertTrue(store.find(expired).isEmpty(), "an expired ticket is evicted");
        assertFalse(store.find(live).isEmpty(), "a live ticket survives");
    }
}
