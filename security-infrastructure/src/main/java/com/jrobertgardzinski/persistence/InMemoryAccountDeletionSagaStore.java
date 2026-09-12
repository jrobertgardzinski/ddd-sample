package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import io.micronaut.scheduling.annotation.Scheduled;
import jakarta.inject.Singleton;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link AccountDeletionSagaStore} for the database-less test environment. */
@Singleton
@Requires(missingBeans = DataSource.class)
class InMemoryAccountDeletionSagaStore implements AccountDeletionSagaStore {

    /**
     * {@code updatedAt} is the settlement time, the twin of the table's {@code updated_at}. The
     * record used to carry {@code createdAt} alone, and eviction measured age on it — so a deletion
     * that ran for weeks and finished a minute ago was forgotten here while Postgres (which measures
     * on the column the verdict wrote) still had it.
     */
    private record Saga(UUID id, String email, String state, Instant createdAt, Instant updatedAt) {}

    private final Map<UUID, Saga> sagas = new ConcurrentHashMap<>();
    private final java.time.Clock clock;

    InMemoryAccountDeletionSagaStore(java.time.Clock clock) {
        this.clock = clock;
    }

    /** One running saga per address, the same invariant V22 gives Postgres — see the port's javadoc. */
    @Override
    public synchronized boolean start(UUID sagaId, String email, Instant at) {
        if (running(email)) {
            return false;
        }
        sagas.put(sagaId, new Saga(sagaId, email, "STARTED", at, at));
        return true;
    }

    private boolean running(String email) {
        return sagas.values().stream()
                .anyMatch(saga -> saga.email().equals(email) && saga.state().equals("STARTED"));
    }

    @Override
    public synchronized boolean complete(String email, Instant at) {
        return transition(email, "COMPLETED", at);
    }

    @Override
    public synchronized boolean compensate(String email, Instant at) {
        return transition(email, "COMPENSATED", at);
    }

    @Override
    public synchronized boolean lastSagaWasCompensated(String email) {
        return sagas.values().stream()
                .filter(saga -> saga.email().equals(email))
                .max(java.util.Comparator.comparing(Saga::createdAt))
                .map(saga -> "COMPENSATED".equals(saga.state()))
                .orElse(false);
    }

    /**
     * Forget sagas that have SETTLED — completed or compensated — and settled long ago.
     *
     * <p>{@code SettledDeletionSagaReaper} does this for the table; the map had nothing, so every
     * account deletion ever run stayed remembered. A STARTED saga is never touched here, however
     * old: that one is still owed an outcome, and {@code compensateOverdue} is what decides it.
     *
     * <p>Age is measured on the SETTLEMENT time, as {@code deleteSettledBefore} measures it on
     * {@code updated_at}. Measuring it on {@code createdAt} forgot a long-running deletion the
     * moment it finished, which is the opposite of what retention is for.
     */
    @Scheduled(fixedDelay = "1h", initialDelay = "5m")
    synchronized void evictSettled() {
        Instant cutoff = Instant.now(clock).minus(java.time.Duration.ofDays(7));
        sagas.values().removeIf(saga -> !"STARTED".equals(saga.state()) && saga.updatedAt().isBefore(cutoff));
    }

    @Override
    public synchronized List<String> compensateOverdue(Instant cutoff, Instant at) {
        List<String> emails = new ArrayList<>();
        for (Saga saga : sagas.values()) {
            if (saga.state().equals("STARTED") && saga.createdAt().isBefore(cutoff)) {
                sagas.put(saga.id(), new Saga(saga.id(), saga.email(), "COMPENSATED", saga.createdAt(), at));
                emails.add(saga.email());
            }
        }
        return emails;
    }

    private boolean transition(String email, String to, Instant at) {
        for (Saga saga : sagas.values()) {
            if (saga.email().equals(email) && saga.state().equals("STARTED")) {
                sagas.put(saga.id(), new Saga(saga.id(), saga.email(), to, saga.createdAt(), at));
                return true;
            }
        }
        return false;
    }
}
