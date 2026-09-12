package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

import javax.sql.DataSource;
import java.time.LocalDateTime;

@JdbcRepository(dialect = Dialect.POSTGRES)
@Requires(beans = DataSource.class)
interface RejectedAuthenticationJdbcRepository extends CrudRepository<RejectedAuthenticationEntity, Long> {

    /**
     * Take the source's lock for the rest of THIS transaction — the serialisation point of the
     * brute-force guard.
     *
     * <p>The guard is check-then-act: it counts the failures in the window and, if the count has
     * reached the limit, writes a block. Twenty attempts arriving together all counted before any
     * of them wrote, so all twenty were admitted against a limit of three, and the one that finally
     * tripped WIPED the overshoot rows — so the per-source ceiling never saw them either. Counting
     * behind this lock makes the attempts from one address take their turn, which is the only thing
     * the limit can mean.
     *
     * <p>{@code hashtext} maps the address onto the bigint the advisory-lock API speaks; a
     * collision between two addresses costs a little serialisation and nothing else.
     */
    @Query("SELECT CAST(pg_advisory_xact_lock(hashtext(:ipAddress)) AS text)")
    String lockSource(String ipAddress);

    /** The ceiling: this address against anything at all — the shape of spraying. */
    long countByIpAddressAndOccurredAtAfter(String ipAddress, LocalDateTime since);

    /** The tight count: this address against ONE account — the shape of guessing a password. */
    long countByIpAddressAndAccountFingerprintAndOccurredAtAfter(
            String ipAddress, String accountFingerprint, LocalDateTime since);

    /** Forget one pair's failures; the rest of the address's record is other people's business. */
    void deleteByIpAddressAndAccountFingerprint(String ipAddress, String accountFingerprint);

    /**
     * Retention: a failure older than the cutoff is deleted.
     *
     * <p>The only deletion before this was {@code deleteByIpAddress}, run when a source SUCCEEDS or
     * gets blocked. A source that only ever fails — which is every scanner on the internet — was
     * therefore never cleaned at all: its rows, each an IP address plus a user-agent string, stayed
     * for ever. {@code Source}'s own javadoc promises the opposite ("the observed context is personal
     * data; it lives only as long as the failure records it annotates"), and there was nothing to
     * make that true.
     */
    @Query("DELETE FROM rejected_authentications WHERE occurred_at < :cutoff")
    int deleteOlderThan(LocalDateTime cutoff);
}
