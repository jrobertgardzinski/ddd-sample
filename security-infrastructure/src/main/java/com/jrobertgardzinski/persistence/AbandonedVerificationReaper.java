package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import io.micronaut.scheduling.annotation.Scheduled;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;

/**
 * Deletes verification rows nobody ever followed.
 *
 * <p>A row is written by every registration and by every re-request, and removed by nothing: an
 * address that was typed once, never confirmed and never seen again kept its row — an e-mail
 * address and a token hash — for as long as the database lived. That is personal data outliving
 * any purpose it had, in the one table whose whole subject is an address somebody has not even
 * confirmed is theirs.
 *
 * <p>Only the UNVERIFIED rows go. A verified row is the account's own state (sign-in asks it on
 * every attempt) and dies with the account, through the deletion saga's purge.
 *
 * <p>Retention is deliberately longer than the TTL {@code VerifyEmail} judges by, for the same
 * reason as the e-mail-change reaper: expiry is a decision and belongs in one place, while this
 * only sweeps what could not possibly matter any more.
 */
@Singleton
@Requires(beans = DataSource.class)
class AbandonedVerificationReaper {

    private static final Logger LOG = LoggerFactory.getLogger(AbandonedVerificationReaper.class);

    private static final Duration RETENTION = Duration.ofDays(30);

    private final EmailVerificationJdbcRepository verifications;
    private final Clock clock;

    AbandonedVerificationReaper(EmailVerificationJdbcRepository verifications, Clock clock) {
        this.verifications = verifications;
        this.clock = clock;
    }

    @Scheduled(fixedDelay = "1h", initialDelay = "7m")
    void reap() {
        try {
            LocalDateTime cutoff = LocalDateTime.now(clock).minus(RETENTION);
            int removed = verifications.deleteUnverifiedRequestedBefore(cutoff);
            if (removed > 0) {
                LOG.info("reaped {} verification row(s) nobody ever followed, older than {}", removed, cutoff);
            }
        } catch (RuntimeException failure) {
            // a sweep that cannot run is not a request that fails; it runs again in an hour
            LOG.warn("the verification reaper could not run: {}", failure.toString());
        }
    }
}
