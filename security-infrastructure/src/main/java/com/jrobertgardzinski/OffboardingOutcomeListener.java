package com.jrobertgardzinski;

import com.jrobertgardzinski.closure.ClosureMessages;
import io.micronaut.configuration.kafka.annotation.ErrorStrategy;
import io.micronaut.configuration.kafka.annotation.ErrorStrategyValue;
import io.micronaut.configuration.kafka.annotation.KafkaListener;
import io.micronaut.configuration.kafka.annotation.OffsetReset;
import io.micronaut.configuration.kafka.annotation.OffsetStrategy;
import io.micronaut.configuration.kafka.annotation.Topic;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.json.JsonMapper;
import io.micronaut.messaging.annotation.MessageHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.Map;

import static com.jrobertgardzinski.MaskedEmail.masked;

/**
 * The saga's ear, after the extraction: identity no longer hears three content participants —
 * the portal's orchestrator (microservice-offboarding) collects those and announces ONE outcome
 * on {@code offboarding-events}. PORTAL_CONTENT_PURGED finishes the deletion for good;
 * PORTAL_PURGE_FAILED rolls the lock back and apologises. Everything else on the topic is not
 * ours. Idempotent by way of the claim on the outcome id.
 *
 * <h2>Why the delivery settings are spelled out</h2>
 * Idempotence protects against processing an outcome TWICE. It says nothing about processing it
 * ZERO times, and the defaults gave exactly that. Without an {@code errorStrategy}, an exception
 * out of {@code handle()} — the transaction rolling back on a momentary database hiccup is the
 * realistic one — was logged, the poll loop moved on, and {@code enable.auto.commit} committed the
 * offset anyway. The record never came back. Nothing else retries it either: the orchestrator's
 * sweeper stops re-announcing once ITS own outbox mark lands, which does not depend on this
 * service having heard anything.
 *
 * <p>The consequence was the worst-ordered one available. The portal has already erased every
 * meme, comment and collection by the time it announces PORTAL_CONTENT_PURGED. Lose that
 * announcement and the saga sits STARTED until {@code compensateOverdue} unlocks the account and
 * sends an apology — so the user keeps an account with nothing in it, {@code ACCOUNT_DELETED}
 * never goes out, and the {@code LOG.error} written for precisely this case
 * ("CONTENT ERASED AFTER COMPENSATION") never fires, because from this side nothing went wrong.
 *
 * <p>So: retry with a growing delay, and commit the offset ONLY after the record is through
 * ({@link OffsetStrategy#SYNC} — micronaut's retry strategies are inert while offsets
 * auto-commit). Redelivery is safe by construction: the claim on the outcome id is taken inside
 * the same transaction as the work, so a rollback releases it and a replay is a first attempt
 * again.
 *
 * <p><b>What {@code stopOnExhaustedRetry} actually does, corrected.</b> This javadoc said "the
 * container STOPS rather than skips" for half a day, and that is not what happens. In
 * micronaut-kafka 6.1.0 the setting does three things and no more: {@code seek} back to the failed
 * offset, one {@code handleException}, and {@code pause} on that ONE partition. The container keeps
 * running and the poll loop keeps turning; the partition is simply never resumed, because
 * {@code resumeTopicPartitions} skips everything in {@code pauseRequests}.
 *
 * <p>The guarantee that matters survives the correction — the offset is never committed, so a
 * restart replays the record rather than losing it — but the mechanism is a paused partition, not
 * a stopped service, and the difference is what a reader needs to act on. It also means the state
 * is INVISIBLE to anything watching liveness or poll activity, which is why
 * {@link OffboardingListenerHealth} asks {@code isPaused} instead of only reading the poll counter:
 * that lamp reported this service as healthy through exactly this failure until it was corrected.
 */
@KafkaListener(
        groupId = "security",
        offsetReset = OffsetReset.EARLIEST,
        offsetStrategy = OffsetStrategy.SYNC,
        errorStrategy = @ErrorStrategy(
                value = ErrorStrategyValue.RETRY_EXPONENTIALLY_ON_ERROR,
                retryDelay = "1s",
                retryCount = 10,
                stopOnExhaustedRetry = true))
@Requires(notEnv = "test")
class OffboardingOutcomeListener {

    private static final Logger LOG = LoggerFactory.getLogger(OffboardingOutcomeListener.class);

    private final AccountDeletionOrchestrator orchestrator;
    private final TransactionBoundary transactionBoundary;
    private final JsonMapper json;
    private final com.jrobertgardzinski.persistence.ProcessedOutcomes processedOutcomes;
    private final java.time.Clock clock;

    OffboardingOutcomeListener(AccountDeletionOrchestrator orchestrator, TransactionBoundary transactionBoundary,
                               JsonMapper json,
                               com.jrobertgardzinski.persistence.ProcessedOutcomes processedOutcomes,
                               java.time.Clock clock) {
        this.orchestrator = orchestrator;
        this.transactionBoundary = transactionBoundary;
        this.json = json;
        this.processedOutcomes = processedOutcomes;
        this.clock = clock;
    }

    @Topic("offboarding-events")
    void fromOffboarding(String payload, @MessageHeader("X-Correlation-Id") @Nullable String cid) {
        if (cid != null) {
            MDC.put("cid", cid);   // continue the trace the originating request started
        }
        try {
            handle(payload);
        } finally {
            MDC.remove("cid");
        }
    }

    /** Package-visible and broker-free, so the contract test drives the real consuming code. */
    void handle(String payload) {
        Map<?, ?> event;
        try {
            event = json.readValue(payload, Map.class);
        } catch (Exception malformed) {
            LOG.warn("dropping malformed offboarding event: {}", payload);
            return;
        }
        String type = String.valueOf(event.get("type"));
        if (!ClosureMessages.PORTAL_CONTENT_PURGED.equals(type)
                && !ClosureMessages.PORTAL_PURGE_FAILED.equals(type)) {
            return;
        }
        String email = String.valueOf(event.get("email"));
        String outcomeId = String.valueOf(event.get("id"));
        transactionBoundary.execute(() -> {
            // The id, not the e-mail, decides whether this outcome has already been acted on.
            // offboarding derives it from (saga, type) precisely so a re-announcement is
            // byte-identical — "consumers deduplicate on the id", says its own comment — and this
            // service, its only consumer, used to match on the e-mail instead. An e-mail is a
            // person; a person can have two deletion sagas. A re-announced outcome from the first
            // one then closed the second, unblocking an account while the portal was still erasing
            // its content, and the real outcome of the second saga was ignored for having no
            // STARTED saga left to close.
            if ("null".equals(outcomeId) || outcomeId.isBlank()) {
                // pre-ADR-0004 events and anything hand-published: fall through rather than drop,
                // but say so — an outcome without an id cannot be deduplicated by anyone
                LOG.warn("offboarding outcome {} for {} carries no id; acting on it without"
                        + " duplicate protection", type, masked(email));
            } else if (!processedOutcomes.claim(outcomeId, type, clock.instant())) {
                LOG.info("offboarding outcome {} ({}) was already acted on — ignoring the"
                        + " re-announcement", outcomeId, type);
                return null;
            }
            if (ClosureMessages.PORTAL_CONTENT_PURGED.equals(type)) {
                orchestrator.completePurge(email);
            } else {
                // the partial-purge disclosure the portal has always sent and nobody read
                Object confirmed = event.get("confirmed");
                orchestrator.compensate(email, confirmed instanceof java.util.List<?> participants
                        ? participants.stream().map(String::valueOf).toList()
                        : java.util.List.of());
            }
            return null;
        });
    }
}
