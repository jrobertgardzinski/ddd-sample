package com.jrobertgardzinski.security.infrastructure.persistence;

import com.jrobertgardzinski.TransactionBoundary;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.password.domain.PlaintextPassword;
import com.jrobertgardzinski.security.domain.vo.AuthenticationRequest;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import com.jrobertgardzinski.security.domain.vo.Source;
import com.jrobertgardzinski.security.system.authentication.Authentication;
import com.jrobertgardzinski.security.system.authentication.AuthenticationResult;
import io.micronaut.context.ApplicationContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The brute-force limit is a limit, not an average — against a real PostgreSQL, because the defect
 * is about two transactions reading the same rows.
 *
 * <p>The guard is check-then-act: count the failures in the window, and if the count has reached
 * the limit, write a block. Attempts arriving together all counted BEFORE any of them wrote, so
 * with a limit of three, twenty parallel guesses were all admitted and not one block was written —
 * and the attempt that eventually tripped wiped the overshoot rows, so the per-source ceiling never
 * saw them either. Ten seconds of a real database says more here than any amount of reasoning: the
 * fix is a per-source advisory lock taken inside the request transaction
 * ({@code JdbcRejectedAuthenticationRepository#countFailuresOnAccount}), and removing it turns this
 * test red.
 */
@Testcontainers(disabledWithoutDocker = true)
class BruteForceRaceTest {

    private static final Email VICTIM = Email.of("victim@example.com");
    private static final String WRONG_PASSWORD = "NotTheirPassword1!";
    private static final int PARALLEL_ATTEMPTS = 20;
    private static final int MAX_FAILURES = 3;

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
                "flyway.datasources.default.enabled", true,
                // the tight limit, so the overshoot is unmistakable
                "security.brute.force.max.failures", MAX_FAILURES));
    }

    @AfterAll
    static void stopContext() {
        if (context != null) {
            context.close();
        }
    }

    @Test
    @DisplayName("twenty parallel guesses from one source do not all get in under a limit of three")
    void parallel_attempts_cannot_walk_past_the_limit() throws Exception {
        Authentication authentication = context.getBean(Authentication.class);
        TransactionBoundary transactions = context.getBean(TransactionBoundary.class);
        Source source = new Source(new IpAddress("198.51.100.7"), "race/1.0");

        CountDownLatch go = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(PARALLEL_ATTEMPTS);
        AtomicInteger admitted = new AtomicInteger();
        AtomicInteger blocked = new AtomicInteger();

        for (int attempt = 0; attempt < PARALLEL_ATTEMPTS; attempt++) {
            new Thread(() -> {
                try {
                    go.await(10, TimeUnit.SECONDS);
                    AuthenticationResult result = transactions.execute(() -> authentication.execute(
                            new AuthenticationRequest(source, VICTIM, PlaintextPassword.of(WRONG_PASSWORD))));
                    if (result instanceof AuthenticationResult.Blocked) {
                        blocked.incrementAndGet();
                    } else {
                        admitted.incrementAndGet();
                    }
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            }).start();
        }

        go.countDown();
        assertThat(done.await(60, TimeUnit.SECONDS)).as("the attempts never finished").isTrue();

        assertThat(blocked.get())
                .as("not one of %d parallel guesses was blocked: the limit of 3 never held",
                        PARALLEL_ATTEMPTS)
                .isGreaterThan(0);
        assertThat(admitted.get())
                .as("a limit of 3 means at most 3 guesses are answered before the block: %d got"
                        + " through, which is what 'check, then act' costs when the checks overlap",
                        admitted.get())
                .isLessThanOrEqualTo(MAX_FAILURES);
    }
}
