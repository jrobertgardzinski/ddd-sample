package com.jrobertgardzinski.security.infrastructure.persistence;

import com.jrobertgardzinski.TransactionBoundary;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.vo.AccessTokenValidityInHours;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenValidityInHours;
import com.jrobertgardzinski.security.domain.vo.SessionFamily;
import com.jrobertgardzinski.security.domain.vo.SessionTokensConfig;
import io.micronaut.context.ApplicationContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Revoking a lineage must take the successor a concurrent refresh is in the middle of writing —
 * against a real PostgreSQL, because this is a claim about MVCC and nothing smaller can settle it.
 *
 * <p>The in-memory adapter's version of this race was closed on 2026-07-29 with a monitor, and the
 * javadoc of {@code rotateAndCreate} then asserted that the JDBC adapter needed nothing, "because
 * the whole use case already runs inside one transaction". True, and irrelevant — which this test
 * exists to prove. Under READ COMMITTED the revoking DELETE takes its snapshot when the STATEMENT
 * starts; it blocks on the row the rotation locked, and when that transaction commits it
 * re-evaluates only that row. The successor inserted in the meantime is invisible to it and
 * survives, ACTIVE, in a family the service has just told the user is gone — a thief refreshing
 * beside the victim keeps a working session, and no device list or revoke will ever show it.
 *
 * <p>The fix is two statements instead of one: lock the lineage's rows, then delete them, so the
 * delete is a new statement with a new snapshot. Removing {@code lockFamily} from
 * {@code JdbcAuthorizationDataRepository#revokeFamily} turns this test red.
 */
@Testcontainers(disabledWithoutDocker = true)
class SessionLineageRaceTest {

    private static final Email USER = Email.of("race@example.com");
    private static final SessionTokensConfig CONFIG = new SessionTokensConfig(
            new RefreshTokenValidityInHours(24), new AccessTokenValidityInHours(1));

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18-alpine");

    static ApplicationContext context;

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
    @DisplayName("a revoke lands on the successor a concurrent rotation is still writing")
    void revoking_a_family_takes_the_successor_being_written() throws Exception {
        AuthorizationDataRepository sessions = context.getBean(AuthorizationDataRepository.class);
        TransactionBoundary transactions = context.getBean(TransactionBoundary.class);
        Clock clock = context.getBean(Clock.class);

        SessionFamily family = SessionFamily.start();
        SessionTokens original = SessionTokens.createFor(USER, CONFIG, clock);
        transactions.execute(() -> sessions.create(original, family));

        CountDownLatch rotationIsHalfDone = new CountDownLatch(1);
        CountDownLatch revokeHasBeenAsked = new CountDownLatch(1);
        AtomicReference<SessionTokens> successor = new AtomicReference<>();

        // The refreshing request: it has rotated the presented token and is about to write the
        // successor. It waits there, exactly where the window is.
        Thread refreshing = new Thread(() -> transactions.execute(() ->
                sessions.rotateAndCreate(original.refreshToken(), () -> {
                    SessionTokens next = SessionTokens.createFor(USER, CONFIG, clock);
                    successor.set(next);
                    rotationIsHalfDone.countDown();
                    try {
                        // give the revoke every chance to get in front of the insert
                        revokeHasBeenAsked.await(5, TimeUnit.SECONDS);
                        Thread.sleep(300);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                    return next;
                }, family)));
        refreshing.start();

        assertThat(rotationIsHalfDone.await(10, TimeUnit.SECONDS))
                .as("the rotation never reached the window this test is about")
                .isTrue();

        // The other request: reuse of this lineage was detected, so the whole family goes.
        Thread revoking = new Thread(() -> transactions.execute(() -> {
            revokeHasBeenAsked.countDown();
            sessions.revokeFamily(family);
            return null;
        }));
        revoking.start();

        refreshing.join(30_000);
        revoking.join(30_000);

        assertThat(sessions.findByRefreshToken(successor.get().refreshToken()))
                .as("the successor written during the revoke is a LIVE session in a family this"
                        + " service reports as destroyed — a stolen token that survives the very"
                        + " detection meant to kill it")
                .isEmpty();
        assertThat(sessions.listActiveSessions(USER))
                .as("and nothing of the lineage is left to list")
                .isEmpty();
    }

    @Test
    @DisplayName("sign out everywhere takes the successor a concurrent rotation is still writing")
    void revoking_every_session_takes_the_successor_being_written() throws Exception {
        AuthorizationDataRepository sessions = context.getBean(AuthorizationDataRepository.class);
        TransactionBoundary transactions = context.getBean(TransactionBoundary.class);
        Clock clock = context.getBean(Clock.class);

        // its own address: this test asserts that NOTHING of this user's is left, and the case above
        // leaves rows for USER whichever order the two run in
        Email user = Email.of("race-everywhere@example.com");
        SessionFamily family = SessionFamily.start();
        SessionTokens original = SessionTokens.createFor(user, CONFIG, clock);
        transactions.execute(() -> sessions.create(original, family));

        CountDownLatch rotationIsHalfDone = new CountDownLatch(1);
        CountDownLatch revokeHasBeenAsked = new CountDownLatch(1);
        AtomicReference<SessionTokens> successor = new AtomicReference<>();

        Thread refreshing = new Thread(() -> transactions.execute(() ->
                sessions.rotateAndCreate(original.refreshToken(), () -> {
                    SessionTokens next = SessionTokens.createFor(user, CONFIG, clock);
                    successor.set(next);
                    rotationIsHalfDone.countDown();
                    try {
                        revokeHasBeenAsked.await(5, TimeUnit.SECONDS);
                        Thread.sleep(300);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                    return next;
                }, family)));
        refreshing.start();

        assertThat(rotationIsHalfDone.await(10, TimeUnit.SECONDS))
                .as("the rotation never reached the window this test is about")
                .isTrue();

        // "Sign out everywhere" — asked by somebody who believes their password has leaked, or by
        // the service itself after the address changed hands. It is a different statement from
        // revokeFamily (by address, across every lineage) and so needs its own proof.
        Thread revoking = new Thread(() -> transactions.execute(() -> {
            revokeHasBeenAsked.countDown();
            sessions.revokeAllSessions(user);
            return null;
        }));
        revoking.start();

        refreshing.join(30_000);
        revoking.join(30_000);

        assertThat(sessions.findByRefreshToken(successor.get().refreshToken()))
                .as("a session written while 'sign out everywhere' ran is exactly the session the"
                        + " user asked to be rid of — and the answer they were given was yes")
                .isEmpty();
        assertThat(sessions.listActiveSessions(user))
                .as("everywhere means everywhere")
                .isEmpty();
    }
}
