package com.jrobertgardzinski;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.jrobertgardzinski.persistence.AccountDeletionSagaStore;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.PurgeChoices;
import com.jrobertgardzinski.security.system.account.DeleteAccount;
import io.micronaut.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * The deletion path used to mask the address in its FAILURE branches and print it in full in its
 * SUCCESS branches (poz. 36) — which is the wrong way round twice over: success is the common case,
 * so almost every address ever deleted went to the log whole, and the log outlives the row.
 *
 * <p>Each case here drives one of the three lines that got it wrong.
 */
class AccountDeletionLoggingTest {

    private static final String EMAIL = "victim@example.com";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-07-30T12:00:00Z"), ZoneOffset.UTC);

    private final Logger logger = (Logger) LoggerFactory.getLogger(AccountDeletionOrchestrator.class);
    private final ListAppender<ILoggingEvent> captured = new ListAppender<>();

    @BeforeEach
    void attachAppender() {
        captured.start();
        logger.addAppender(captured);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(captured);
        captured.stop();
    }

    @Test
    @DisplayName("the completed-deletion line carries a masked address")
    void completingADeletionDoesNotLogTheAddress() {
        orchestrator(latchedStore(true)).completePurge(EMAIL);

        assertMasked();
    }

    @Test
    @DisplayName("the overdue-compensation line carries a masked address")
    void compensatingAnOverdueDeletionDoesNotLogTheAddress() {
        orchestrator(latchedStore(true)).compensateOverdue();

        assertMasked();
    }

    @Test
    @DisplayName("the identity-only immediate deletion line carries a masked address")
    void deletingImmediatelyDoesNotLogTheAddress() {
        new AccountDeletionOrchestrator(latchedStore(true), (topic, key, payload) -> { },
                mock(DeleteAccount.class), mock(UserRepository.class), JsonMapper.createDefault(),
                CLOCK, Duration.ofMinutes(5), false)
                .begin(com.jrobertgardzinski.security.domain.vo.AccountClosure.requestedByOwner(
                        com.jrobertgardzinski.email.domain.Email.of(EMAIL)));

        assertMasked();
    }

    private AccountDeletionOrchestrator orchestrator(AccountDeletionSagaStore sagas) {
        return new AccountDeletionOrchestrator(sagas, (topic, key, payload) -> { },
                mock(DeleteAccount.class), mock(UserRepository.class), JsonMapper.createDefault(),
                CLOCK, Duration.ofMinutes(5), true);
    }

    private void assertMasked() {
        String lines = captured.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .reduce((a, b) -> a + " | " + b)
                .orElseThrow(() -> new AssertionError("nothing was logged at all"));
        assertFalse(lines.contains(EMAIL), "the full address reached the log: " + lines);
        assertTrue(lines.contains("vi***@example.com"),
                "the line must still name the subject, masked: " + lines);
    }

    /** A store that says "yes, this caller latched it" and reports one overdue saga. */
    private static AccountDeletionSagaStore latchedStore(boolean latched) {
        return new AccountDeletionSagaStore() {
            @Override
            public boolean start(UUID sagaId, String email, Instant at) {
                return true;
            }

            @Override
            public boolean complete(String email, Instant at) {
                return latched;
            }

            @Override
            public boolean compensate(String email, Instant at) {
                return latched;
            }

            @Override
            public List<String> compensateOverdue(Instant cutoff, Instant at) {
                return List.of(EMAIL);
            }

            @Override
            public boolean lastSagaWasCompensated(String email) {
                return false;
            }
        };
    }
}
