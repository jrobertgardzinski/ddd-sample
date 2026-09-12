package com.jrobertgardzinski.persistence;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** The database-less store answers the same questions as Postgres — see the contract's javadoc. */
class InMemoryAccountDeletionSagaStoreTest {

    @Test
    @DisplayName("the database-less store admits one running deletion per address, like Postgres")
    void one_running_saga_per_address() {
        AccountDeletionSagaStoreContract.oneRunningSagaPerAddress(
                new InMemoryAccountDeletionSagaStore(java.time.Clock.systemUTC()), "leaver@example.com", "other@example.com");
    }

    @Test
    @DisplayName("eviction measures age on the verdict, not on the request — as the table does")
    void eviction_measures_the_settlement_time() {
        java.time.Instant now = java.time.Instant.parse("2026-09-12T12:00:00Z");
        InMemoryAccountDeletionSagaStore store =
                new InMemoryAccountDeletionSagaStore(java.time.Clock.fixed(now, java.time.ZoneOffset.UTC));

        // a deletion that ran for a month and reached its verdict a minute ago
        String slow = "slow@example.com";
        store.start(java.util.UUID.randomUUID(), slow, now.minus(java.time.Duration.ofDays(30)));
        store.compensate(slow, now.minusSeconds(60));

        // and one that was settled three weeks ago: history, and nothing more
        String old = "old@example.com";
        store.start(java.util.UUID.randomUUID(), old, now.minus(java.time.Duration.ofDays(30)));
        store.compensate(old, now.minus(java.time.Duration.ofDays(21)));

        store.evictSettled();

        org.junit.jupiter.api.Assertions.assertTrue(store.lastSagaWasCompensated(slow),
                "the verdict is a minute old — Postgres sweeps on updated_at and still has this row;"
                        + " forgetting it here means the double answers 'no compensation' where the"
                        + " real store answers 'compensated'");
        org.junit.jupiter.api.Assertions.assertFalse(store.lastSagaWasCompensated(old),
                "a verdict from three weeks ago is past the window and goes, address and all");
    }
}
