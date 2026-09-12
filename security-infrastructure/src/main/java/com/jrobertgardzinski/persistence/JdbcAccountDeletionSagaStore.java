package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** Postgres-backed {@link AccountDeletionSagaStore} (see V6/V17). */
@Singleton
@Requires(beans = DataSource.class)
class JdbcAccountDeletionSagaStore implements AccountDeletionSagaStore {

    private final AccountDeletionSagaJdbcRepository repository;

    JdbcAccountDeletionSagaStore(AccountDeletionSagaJdbcRepository repository) {
        this.repository = repository;
    }

    /**
     * One statement, and the partial unique index of V22 is the one that decides — so the race the
     * read cannot close ends in an honest "someone got here first" instead of a unique violation.
     * Losing used to abort the request's whole transaction: the second click on "delete my account"
     * answered 500, while the truth was that the deletion was already under way.
     */
    @Override
    public boolean start(UUID sagaId, String email, Instant at) {
        return repository.claimStart(sagaId, email, at) > 0;
    }

    @Override
    public boolean complete(String email, Instant at) {
        return repository.completeStarted(email, at) > 0;
    }

    @Override
    public boolean compensate(String email, Instant at) {
        return repository.compensateStarted(email, at) > 0;
    }

    @Override
    public boolean lastSagaWasCompensated(String email) {
        return repository.findLatestByEmail(email)
                .map(saga -> "COMPENSATED".equals(saga.state()))
                .orElse(false);
    }

    @Override
    public List<String> compensateOverdue(Instant cutoff, Instant at) {
        List<String> emails = new ArrayList<>();
        for (AccountDeletionSagaEntity saga : repository.findByStateAndCreatedAtBefore("STARTED", cutoff)) {
            if (repository.compensate(saga.id(), at) > 0) {
                emails.add(saga.email());
            }
        }
        return emails;
    }
}
