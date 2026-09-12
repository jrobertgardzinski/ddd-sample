package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@JdbcRepository(dialect = Dialect.POSTGRES)
@Requires(beans = DataSource.class)
interface OutboxEventJdbcRepository extends CrudRepository<OutboxEventEntity, UUID> {

    /**
     * One tick's worth of backlog, oldest first.
     *
     * <p>The drain used to load EVERY unpublished row each second. On an ordinary day that is a
     * handful; on the day the broker has been away for an hour it is the whole hour, in memory, on
     * a scheduled thread — and again a second later, because the send that would clear it is what
     * is failing. A batch keeps the order (it is the same query with a limit) and bounds what one
     * tick can cost; the next tick continues where this one stopped.
     */
    @Query("SELECT * FROM outbox_events WHERE published_at IS NULL AND failed_at IS NULL"
            + " ORDER BY created_at LIMIT :batchSize")
    List<OutboxEventEntity> findUnpublishedBatch(int batchSize);

    @Query("UPDATE outbox_events SET published_at = :publishedAt WHERE id = :id")
    void markPublished(UUID id, Instant publishedAt);

    @Query("UPDATE outbox_events SET failed_at = :failedAt WHERE id = :id")
    void markFailed(UUID id, Instant failedAt);

    /**
     * Retention: a SETTLED row is deleted once it is older than the cutoff.
     *
     * <p>Nothing ever deleted from this table — a drained row was stamped and kept. Every row
     * carries the subject's address twice, as {@code event_key} AND inside the payload, so the
     * table was in effect a permanent register of every address ever registered: the
     * verification mail, the reset mail, the deletion fact with its purge choices. A user who
     * exercised their right to be forgotten had their address deleted from {@code users} and left
     * here for good, which is the same prize in a database dump that
     * {@link ExpiredSessionReaper} was written to stop handing over.
     *
     * <p>Both terminal states go: {@code published_at} (handed to the broker) and {@code failed_at}
     * (given up on permanently, V19). A row still awaiting the drain has NULL in both, and
     * {@code NULL < :cutoff} is unknown rather than true — so an undrained event is never swept, no
     * matter how old it is. That is the property that matters here: retention must not become a
     * silent second way to lose an event.
     */
    @Query("DELETE FROM outbox_events WHERE published_at < :cutoff OR failed_at < :cutoff")
    int deleteSettledBefore(Instant cutoff);
}
