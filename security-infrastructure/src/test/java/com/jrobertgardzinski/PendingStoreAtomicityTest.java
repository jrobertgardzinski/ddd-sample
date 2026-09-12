package com.jrobertgardzinski;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.domain.vo.FactorType;
import com.jrobertgardzinski.security.system.mfa.PendingAuthentication;
import com.jrobertgardzinski.security.system.mfa.PendingAuthenticationStore;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An attempt at a second factor is spent once per proof, however many proofs arrive together.
 *
 * <p>The counter used to be read, decremented and written back across three calls to the store, so
 * proofs in flight at the same moment all read the same "five left" and all wrote "four left" —
 * twenty wrong guesses were verified against a ticket that allows five. That cap IS the protection
 * a factor adds to a password somebody already has: a six-digit code has a million values, and
 * unlimited guesses at it are no barrier at all.
 */
@Epic("Use case")
@Feature("Multi-factor sign-in")
class PendingStoreAtomicityTest {

    private static final int PROOFS_IN_FLIGHT = 20;
    private static final int ATTEMPTS_ALLOWED = 5;

    @Test
    @DisplayName("twenty proofs presented at once spend twenty attempts, not one")
    void the_attempt_counter_is_not_shared() throws Exception {
        PendingAuthenticationStore store = new InMemoryPendingAuthenticationStore(Clock.systemUTC());
        String ticket = store.open(pending());

        CountDownLatch go = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(PROOFS_IN_FLIGHT);
        for (int proof = 0; proof < PROOFS_IN_FLIGHT; proof++) {
            new Thread(() -> {
                try {
                    go.await(10, TimeUnit.SECONDS);
                    store.update(ticket, PendingAuthentication::afterWrongProof);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            }).start();
        }
        go.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS), "the proofs never finished");

        assertEquals(ATTEMPTS_ALLOWED - PROOFS_IN_FLIGHT, store.find(ticket).orElseThrow().attemptsLeft(),
                "every proof must cost an attempt of its own");
    }

    private static PendingAuthentication pending() {
        EnrolledFactor factor = new EnrolledFactor(Email.of("user@example.com"), FactorType.EMAIL_CODE,
                "e-mail code", 2, "user@example.com");
        return new PendingAuthentication(Email.of("user@example.com"), List.of(factor), null,
                ATTEMPTS_ALLOWED, LocalDateTime.now().plusMinutes(5));
    }
}
