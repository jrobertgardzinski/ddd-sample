package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

import javax.sql.DataSource;

@JdbcRepository(dialect = Dialect.POSTGRES)
@Requires(beans = DataSource.class)
interface AuthenticationBlockJdbcRepository extends CrudRepository<AuthenticationBlockEntity, String> {

    /**
     * Take the source's lock for the rest of THIS transaction, before answering whether the source
     * is blocked — which is the brute-force guard's FIRST question, and therefore the real start of
     * its check-then-act. Locking only the counting half was not enough: every parallel attempt
     * still read "no block" together, and the one that finally tripped CLEARS the failure rows, so
     * the attempts queued behind it counted zero and were admitted after the block existed.
     *
     * <p>The same lock as {@code RejectedAuthenticationJdbcRepository#lockSource} — advisory locks
     * are re-entrant within a transaction, so taking it in both places costs nothing and means
     * neither entry point can be reached without it.
     */
    @Query("SELECT CAST(pg_advisory_xact_lock(hashtext(:ipAddress)) AS text)")
    String lockSource(String ipAddress);

    /**
     * One statement for "this source is blocked until then", whether or not it already was.
     *
     * <p>It used to be a delete followed by a save, on a primary key: two requests crossing the
     * threshold at the same moment both deleted, then both inserted, and the loser got a 23505 —
     * a 500 whose transaction took the rejection record down with it, so the attempt that tripped
     * the limit was not even counted. The idiom is the one
     * {@code ProcessedOutcomeJdbcRepository#claim} already uses.
     */
    @Query("INSERT INTO authentication_blocks (ip_address, expiry_date) VALUES (:ipAddress, :expiryDate)"
            + " ON CONFLICT (ip_address) DO UPDATE SET expiry_date = EXCLUDED.expiry_date")
    int upsert(String ipAddress, java.time.LocalDateTime expiryDate);

    /** Retention: a block whose expiry has passed decides nothing and names an address for ever. */
    int deleteByExpiryDateBefore(java.time.LocalDateTime cutoff);
}
