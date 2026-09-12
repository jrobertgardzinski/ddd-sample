package com.jrobertgardzinski.persistence;

import io.micronaut.configuration.kafka.annotation.KafkaClient;
import io.micronaut.configuration.kafka.annotation.KafkaKey;
import io.micronaut.configuration.kafka.annotation.Topic;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.messaging.annotation.MessageHeader;
import io.micronaut.scheduling.annotation.Scheduled;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.TraceFlags;
import io.opentelemetry.api.trace.TraceState;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.Instant;

/**
 * Drains the transactional outbox to Kafka: unpublished events go out in creation order and are
 * then marked published. A crash between send and mark redelivers the event — at-least-once by
 * design; consumers deduplicate by the event id inside the payload. Off in the {@code test}
 * environment (no broker there).
 */
@Singleton
@Requires(notEnv = "test")
@Requires(beans = DataSource.class)
class OutboxPublisher {

    private static final Logger LOG = LoggerFactory.getLogger(OutboxPublisher.class);

    @KafkaClient
    @Requires(notEnv = "test")
    interface EventsProducer {
        void send(@Topic String topic, @KafkaKey String key,
                  @MessageHeader("X-Correlation-Id") @Nullable String cid, String payload);
    }

    private final OutboxEventJdbcRepository outbox;
    private final EventsProducer producer;
    private final Clock clock;
    private final int batchSize;

    OutboxPublisher(OutboxEventJdbcRepository outbox, EventsProducer producer, Clock clock,
                    @io.micronaut.context.annotation.Value("${security.outbox.drain-batch:500}") int batchSize) {
        this.outbox = outbox;
        this.producer = producer;
        this.clock = clock;
        this.batchSize = batchSize;
    }

    @Scheduled(fixedDelay = "1s", initialDelay = "5s")
    void drain() {
        for (OutboxEventEntity event : outbox.findUnpublishedBatch(batchSize)) {
            try {
                if (event.cid() != null) {
                    MDC.put("cid", event.cid());   // the drain log carries the originating request's cid
                }
                // re-establish the originating request's span as the parent, so the agent injects a
                // traceparent that continues that trace instead of starting a disconnected one
                try (Scope ignored = parentScope(event.traceparent())) {
                    producer.send(event.topic(), event.eventKey(), event.cid(), event.payload());
                }
                outbox.markPublished(event.id(), Instant.now(clock));
            } catch (RuntimeException failure) {
                if (isPermanent(failure)) {
                    // this row will NEVER publish (too large, unserializable). Stopping here would
                    // block every later event forever, so mark it failed and move on — the loop keeps
                    // ordering for the transient case, not for a poison row.
                    LOG.error("outbox event {} is permanently unpublishable, skipping it: {}",
                            event.id(), failure.toString());
                    outbox.markFailed(event.id(), Instant.now(clock));
                    MDC.remove("cid");
                    continue;
                }
                LOG.warn("outbox drain interrupted (will retry): {}", failure.getMessage());
                MDC.remove("cid");
                return; // keep ordering: stop at the first transient failure, retry next tick
            } finally {
                MDC.remove("cid");
            }
        }
    }

    /**
     * Whether a send failure is about THIS event rather than the broker's availability — a record
     * past {@code max.request.size} or a serialization fault. Such a failure repeats on every tick,
     * so the row must be set aside instead of blocking the queue. A timeout / connection error is
     * transient and is NOT permanent (the loop stops and retries).
     */
    static boolean isPermanent(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t instanceof org.apache.kafka.common.errors.RecordTooLargeException
                    || t instanceof org.apache.kafka.common.errors.SerializationException) {
                return true;
            }
        }
        return false;
    }

    /** The stored traceparent as a current OTel scope (its span becomes the parent), or a no-op. */
    private static Scope parentScope(String traceparent) {
        if (traceparent == null) {
            return Scope.noop();
        }
        String[] parts = traceparent.split("-");
        if (parts.length != 4) {
            return Scope.noop();
        }
        SpanContext parent = SpanContext.createFromRemoteParent(
                parts[1], parts[2], TraceFlags.fromHex(parts[3], 0), TraceState.getDefault());
        return parent.isValid() ? Context.root().with(Span.wrap(parent)).makeCurrent() : Scope.noop();
    }
}
