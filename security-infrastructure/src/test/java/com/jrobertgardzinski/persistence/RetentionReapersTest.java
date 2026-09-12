package com.jrobertgardzinski.persistence;

import io.micronaut.context.ApplicationContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Retention for the five tables that had none (poz. 10, 24), against a real PostgreSQL — the
 * predicates carry the whole weight here, so a fake store would prove nothing about them.
 *
 * <p>Each case pins the same two things: the row that is history goes, and the row that still has a
 * job stays. The second half is the important one. Retention that swept an undrained outbox event
 * would be a silent second way to lose a verification mail; retention that swept a STARTED saga
 * would leave an account locked for ever, because {@code compensateOverdue} finds accounts to unlock
 * by scanning exactly those rows.
 */
@Testcontainers(disabledWithoutDocker = true)
class RetentionReapersTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18-alpine");

    static ApplicationContext context;

    /** Well past every reaper's window (a week), so "old" is not a matter of timing. */
    private static final Duration ANCIENT = Duration.ofDays(30);

    @BeforeAll
    static void startContext() {
        context = ApplicationContext.run(Map.of(
                "datasources.default.url", POSTGRES.getJdbcUrl(),
                "datasources.default.username", POSTGRES.getUsername(),
                "datasources.default.password", POSTGRES.getPassword(),
                "datasources.default.driver-class-name", "org.postgresql.Driver",
                "datasources.default.dialect", "POSTGRES",
                "flyway.datasources.default.enabled", true));
    }

    @AfterAll
    static void stopContext() {
        if (context != null) {
            context.close();
        }
    }

    @Test
    @DisplayName("settled outbox rows are dropped; an undrained event survives at any age")
    void outboxRetention() {
        OutboxEventJdbcRepository events = context.getBean(OutboxEventJdbcRepository.class);
        Instant now = Instant.now();
        Instant ancient = now.minus(ANCIENT);

        UUID published = outboxRow(events, ancient, ancient, null);
        UUID failed = outboxRow(events, ancient, null, ancient);
        UUID undrained = outboxRow(events, ancient, null, null);
        UUID publishedToday = outboxRow(events, now, now, null);

        context.getBean(SettledOutboxReaper.class).reap();

        assertThat(events.findById(published))
                .as("a published row past the window carries the address for no reason")
                .isEmpty();
        assertThat(events.findById(failed))
                .as("a permanently failed row past the window carries it too")
                .isEmpty();
        assertThat(events.findById(undrained))
                .as("an event still awaiting the drain must NEVER be swept — retention is not a way"
                        + " to lose a verification mail")
                .isPresent();
        assertThat(events.findById(publishedToday))
                .as("a row inside the window stays available for inspection")
                .isPresent();
    }

    @Test
    @DisplayName("settled deletion sagas are dropped; a STARTED one survives at any age")
    void deletionSagaRetention() {
        AccountDeletionSagaJdbcRepository sagas = context.getBean(AccountDeletionSagaJdbcRepository.class);
        Instant now = Instant.now();
        Instant ancient = now.minus(ANCIENT);

        UUID completed = sagaRow(sagas, "completed@example.com", "COMPLETED", ancient);
        UUID compensated = sagaRow(sagas, "compensated@example.com", "COMPENSATED", ancient);
        UUID started = sagaRow(sagas, "still-running@example.com", "STARTED", ancient);
        UUID completedToday = sagaRow(sagas, "fresh@example.com", "COMPLETED", now);

        context.getBean(SettledDeletionSagaReaper.class).reap();

        assertThat(sagas.findById(completed))
                .as("the address of a finished deletion must not outlive it")
                .isEmpty();
        assertThat(sagas.findById(compensated)).isEmpty();
        assertThat(sagas.findById(started))
                .as("a running saga is what compensateOverdue scans — sweeping it locks an account"
                        + " for ever")
                .isPresent();
        assertThat(sagas.findById(completedToday)).isPresent();
    }

    @Test
    @DisplayName("old rejected authentications are dropped; a recent one still counts towards a block")
    void rejectedAuthenticationRetention() {
        RejectedAuthenticationJdbcRepository rejections =
                context.getBean(RejectedAuthenticationJdbcRepository.class);
        String ip = "203.0.113.77";
        rejections.save(new RejectedAuthenticationEntity(
                null, ip, "scanner/1.0", "fingerprint-of-some-account", LocalDateTime.now().minus(ANCIENT)));
        rejections.save(new RejectedAuthenticationEntity(
                null, ip, "scanner/1.0", "fingerprint-of-some-account", LocalDateTime.now().minusMinutes(1)));

        context.getBean(RejectedAuthenticationReaper.class).reap();

        assertThat(rejections.countByIpAddressAndOccurredAtAfter(ip, LocalDateTime.now().minus(ANCIENT).minusDays(1)))
                .as("only the recent failure may survive — the old one is an IP address kept for"
                        + " nothing, against what Source's javadoc promises")
                .isEqualTo(1);
        assertThat(rejections.countByIpAddressAndOccurredAtAfter(ip, LocalDateTime.now().minusMinutes(15)))
                .as("the surviving failure must still be countable inside the guard's window")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("verification rows nobody followed are dropped; a verified row and a fresh one stay")
    void abandonedVerificationRetention() {
        EmailVerificationJdbcRepository verifications =
                context.getBean(EmailVerificationJdbcRepository.class);
        LocalDateTime now = LocalDateTime.now();
        // this reaper's window is itself 30 days, so ANCIENT would sit exactly ON the edge and the
        // answer would turn on the JVM's zone against the clock bean's; twice the window is past it
        // under any zone
        LocalDateTime ancient = now.minus(ANCIENT.multipliedBy(2));

        verifications.save(new EmailVerificationEntity(
                "abandoned@example.com", "hash-of-a-link-nobody-clicked", false, ancient));
        verifications.save(new EmailVerificationEntity(
                "long-verified@example.com", null, true, ancient));
        verifications.save(new EmailVerificationEntity(
                "just-registered@example.com", "hash-of-a-fresh-link", false, now));

        context.getBean(AbandonedVerificationReaper.class).reap();

        assertThat(verifications.findById("abandoned@example.com"))
                .as("an address typed once and never confirmed is an address kept for nothing")
                .isEmpty();
        assertThat(verifications.findById("long-verified@example.com"))
                .as("a verified row is the ACCOUNT's own state — sweeping it would quietly"
                        + " un-verify a working account")
                .isPresent();
        assertThat(verifications.findById("just-registered@example.com"))
                .as("somebody who registered a minute ago still has a link to click")
                .isPresent();
    }

    @Test
    @DisplayName("password resets nobody redeemed are dropped; a fresh one still works")
    void unclaimedPasswordResetRetention() {
        PasswordResetJdbcRepository resets = context.getBean(PasswordResetJdbcRepository.class);
        LocalDateTime now = LocalDateTime.now();

        resets.save(new PasswordResetEntity(
                "gave-up@example.com", "hash-of-a-link-never-redeemed", now.minus(ANCIENT)));
        resets.save(new PasswordResetEntity(
                "waiting-for-mail@example.com", "hash-of-a-fresh-link", now));

        context.getBean(UnclaimedPasswordResetReaper.class).reap();

        assertThat(resets.findById("gave-up@example.com"))
                .as("asking for a reset costs one unauthenticated request; the address must not be"
                        + " kept for ever because nobody clicked the link")
                .isEmpty();
        assertThat(resets.findById("waiting-for-mail@example.com"))
                .as("somebody who just asked still has a link in their inbox")
                .isPresent();
    }

    private static UUID outboxRow(OutboxEventJdbcRepository events, Instant createdAt,
                                  Instant publishedAt, Instant failedAt) {
        UUID id = UUID.randomUUID();
        events.save(new OutboxEventEntity(id, "mail-requests", "subject@example.com",
                "{\"type\":\"ACCOUNT_DELETED\",\"to\":\"subject@example.com\"}",
                createdAt, publishedAt, null, null, failedAt));
        return id;
    }

    private static UUID sagaRow(AccountDeletionSagaJdbcRepository sagas, String email, String state,
                                Instant at) {
        UUID id = UUID.randomUUID();
        sagas.save(new AccountDeletionSagaEntity(id, email, state, at, at));
        return id;
    }
}
