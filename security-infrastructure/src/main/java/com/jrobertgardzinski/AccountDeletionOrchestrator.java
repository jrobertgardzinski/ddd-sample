package com.jrobertgardzinski;

import com.jrobertgardzinski.closure.ClosureMessages;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.persistence.AccountDeletionSagaStore;
import com.jrobertgardzinski.persistence.OutboxAppender;
import com.jrobertgardzinski.security.domain.port.ContentPurge;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.AccountClosure;
import com.jrobertgardzinski.security.system.account.DeleteAccount;
import io.micronaut.context.annotation.Value;
import io.micronaut.json.JsonMapper;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static com.jrobertgardzinski.MaskedEmail.masked;

/**
 * The DISTRIBUTED answer to {@link ContentPurge}: the content lives in other services, so getting
 * rid of it is a saga. Identity's side of it only — the orchestration itself lives in the portal
 * ({@code microservice-offboarding}), because the content being purged is the portal's domain.
 *
 * <p>Everything below exists because there is no shared transaction: the fact has to be announced
 * durably (the outbox), the answer arrives minutes later on a topic, and a safety net has to
 * assume the other side died. A one-process deployment would implement the same port with a
 * transaction and need none of it.
 * {@link #begin} locks the account (saga STARTED) and announces the FACT that deletion was
 * requested — through the outbox, so the fact commits with the lock; the fact ferries the
 * leaver's purge choices without knowing their vocabulary. The portal answers with ONE outcome:
 * {@link #completePurge} (the user is deleted for good, a goodbye mail goes out) or
 * {@link #compensate} (the account unlocks, an apology goes out). {@link #compensateOverdue} is
 * the safety net for a dead orchestrator: no outcome at all in time unlocks the account too.
 * All transitions are idempotent — at-least-once delivery makes duplicates a fact of life.
 *
 * <p>An identity-only deployment (no portal, e.g. security + the F1 game) sets
 * {@code account-deletion.await-portal-purge=false}: there is no content to purge anywhere, so
 * the account deletes immediately.
 */
@Singleton
public class AccountDeletionOrchestrator implements ContentPurge {

    static final String FACTS_TOPIC = "security-events";
    static final String MAIL_TOPIC = "mail-requests";

    private static final Logger LOG = LoggerFactory.getLogger(AccountDeletionOrchestrator.class);

    private final AccountDeletionSagaStore sagas;
    private final OutboxAppender outbox;
    private final DeleteAccount deleteAccount;
    private final UserRepository userRepository;
    private final JsonMapper json;
    private final Clock clock;
    private final Duration purgeTimeout;
    private final boolean awaitPortalPurge;

    AccountDeletionOrchestrator(AccountDeletionSagaStore sagas, OutboxAppender outbox,
                                DeleteAccount deleteAccount, UserRepository userRepository,
                                JsonMapper json, Clock clock,
                                // The safety net must fire well AFTER the portal's own worst case,
                                // so the portal's verdict wins the race and this net is left for
                                // what it is FOR: a coordinator that died, not a slow participant.
                                //
                                // 12m, and the number is derived rather than felt. The portal's
                                // sweeper measures its purge timeout from the last command the
                                // participant actually RECEIVED (P18), so a silent participant
                                // costs 120s per delivered command and the whole case takes
                                // purgeTimeout x (retries + 1) = 120s x 4 = 8 minutes, plus a 15s
                                // sweep and the mail road. The old default of 5m predates that
                                // change and had quietly become the FIRST of the two to fire:
                                // measured on the live stack 2026-08-08, the account came back at
                                // ~5 min and its content only at ~8. Nobody decided that; it was
                                // the sum of two timeouts nobody re-read together.
                                //
                                // Raising this is the cheaper half of the fix. The expensive half
                                // would be teaching the two services about each other's clocks,
                                // and they are deliberately independent — so the rule is written
                                // down instead: this value stays above the portal's
                                // OFFBOARDING_PURGE_TIMEOUT_SEC x (OFFBOARDING_MAX_PURGE_RETRIES+1).
                                @Value("${account-deletion.purge-timeout:12m}") Duration purgeTimeout,
                                @Value("${account-deletion.await-portal-purge:true}") boolean awaitPortalPurge) {
        this.sagas = sagas;
        this.outbox = outbox;
        this.deleteAccount = deleteAccount;
        this.userRepository = userRepository;
        this.json = json;
        this.clock = clock;
        this.purgeTimeout = purgeTimeout;
        this.awaitPortalPurge = awaitPortalPurge;
    }

    @Override
    public void begin(AccountClosure closure) {
        Email email = closure.target();
        if (!awaitPortalPurge) {
            // identity-only deployment: no portal, no content, nothing to wait for
            deleteAccount.execute(email);
            appendMail("ACCOUNT_DELETED", email.value());
            LOG.info("account deleted immediately (no portal configured) for {}", masked(email.value()));
            return;
        }
        UUID sagaId = UUID.randomUUID();
        if (!sagas.start(sagaId, email.value(), Instant.now(clock))) {
            // a deletion for this address is already running: the account is locked, the fact is out
            // and the portal is working on it. Announcing it again would fork a second saga whose
            // outcome settles the first one's row — so this request joins the one under way instead.
            LOG.info("account deletion already under way for {}; joining it instead of announcing"
                    + " a second one", masked(email.value()));
            return;
        }
        Map<String, Object> fact = new LinkedHashMap<>(Map.of(
                "id", UUID.randomUUID().toString(),
                "sagaId", sagaId.toString(),
                "type", ClosureMessages.ACCOUNT_DELETION_REQUESTED,
                "email", email.value(),
                // the legal basis of the closure, and the only thing that tells the content
                // services whether the policy beside it may be honoured at all. Additive within
                // envelope version 1 (workspace ADR 0004); an older consumer that ignores it
                // simply behaves as every consumer did before, which is why the field is stated
                // ALWAYS rather than only for the interesting value
                "initiatedBy", closure.requestedBy().wire(),
                "version", 1));
        if (!closure.choices().rules().isEmpty()) {
            fact.put("policy", closure.choices().rules());
        }
        outbox.append(FACTS_TOPIC, email.value(), write(fact));
    }

    /**
     * The portal announced its content purged (PORTAL_CONTENT_PURGED): the user is deleted for
     * good and a goodbye mail goes out. Duplicates and strays are no-ops — the store's
     * STARTED→COMPLETED latch admits exactly one caller.
     */
    public void completePurge(String email) {
        if (!sagas.complete(email, Instant.now(clock))) {
            // Two very different reasons to be here, and they used to share one INFO line.
            //
            // A duplicate of an outcome already applied is routine. A genuine purge confirmation
            // arriving after we COMPENSATED is not: it means the portal erased the content anyway,
            // after this service had given up, unlocked the account and sent an apology. The user
            // keeps their account and loses every meme, comment and collection they had, and
            // nothing anywhere said so — the whole event was an INFO line nobody greps for.
            if (sagas.lastSagaWasCompensated(email)) {
                LOG.error("CONTENT ERASED AFTER COMPENSATION for {}: the portal confirmed the purge"
                                + " after this service had already given up, unlocked the account and"
                                + " apologised. The account exists; its content does not. This needs"
                                + " a human — the deletion timeout here and the portal's retry budget"
                                + " are independent dials in separate repositories.",
                        masked(email));
                return;
            }
            LOG.info("portal-purged outcome for {} matched no running deletion; ignoring",
                    masked(email));
            return;
        }
        deleteAccount.execute(Email.of(email));
        appendMail("ACCOUNT_DELETED", email);
        LOG.info("account deletion completed for {}", masked(email));
    }

    /** The portal announced the purge FAILED: the account unlocks and the user is apologised to. */
    public void compensate(String email) {
        compensate(email, java.util.List.of());
    }

    /**
     * The same, told which participants DID purge before the failure.
     *
     * <p>The portal has always disclosed that list on {@code PORTAL_PURGE_FAILED} — it is the
     * difference between "nothing happened, try again" and "your memes are gone, your comments are
     * not" — and nobody on this side read it. The apology mail says the deletion failed, full stop,
     * while some of the user's content really was erased. Naming the participants in the log is the
     * cheap half of the fix and closes the operator's blind spot; putting it in front of the USER
     * means a new field on the mail request and a wider pact, which belongs with that decision.
     */
    public void compensate(String email, java.util.List<String> alreadyPurged) {
        if (!sagas.compensate(email, Instant.now(clock))) {
            LOG.info("purge-failed outcome for {} matched no running deletion; ignoring",
                    masked(email));
            return;
        }
        userRepository.clearPendingDeletion(Email.of(email));
        appendMail("ACCOUNT_DELETION_FAILED", email);
        if (alreadyPurged.isEmpty()) {
            LOG.warn("account deletion compensated (portal reported a failed purge) for {}",
                    masked(email));
        } else {
            // The list is who CONFIRMED, and since ADR 0007 that means "reserved", not "destroyed":
            // a portal participant marks the leaver's content, hides it from every read and keeps
            // it, and the same capitulation that produced this outcome commands the restore. So
            // this line no longer cries about content that will not come back — it says who had it
            // hidden, which is still worth an operator's eye if the restore itself goes missing.
            // (The old wording — "already erased this user's content and will not put it back" —
            // was true when the participants deleted on the first command, and became a lie the
            // day they stopped. It fired on every compensated saga, so it would have sent someone
            // hunting a data loss that had not happened.)
            LOG.warn("account deletion compensated for {}; the portal had already RESERVED the"
                            + " content at {} and is restoring it — if it does not come back,"
                            + " that is a portal-side problem, not a lost purge",
                    masked(email), alreadyPurged);
        }
    }

    /** The safety net: no outcome AT ALL in time (a dead orchestrator) unlocks the account too. */
    public void compensateOverdue() {
        Instant now = Instant.now(clock);
        for (String email : sagas.compensateOverdue(now.minus(purgeTimeout), now)) {
            userRepository.clearPendingDeletion(Email.of(email));
            appendMail("ACCOUNT_DELETION_FAILED", email);
            LOG.warn("account deletion compensated (no portal outcome in {}) for {}",
                    purgeTimeout, masked(email));
        }
    }

    private void appendMail(String type, String to) {
        outbox.append(MAIL_TOPIC, to, write(Map.<String, Object>of(
                "id", UUID.randomUUID().toString(), "type", type, "to", to, "version", 1)));
    }

    private String write(Map<String, ?> payload) {
        try {
            return json.writeValueAsString(payload);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
