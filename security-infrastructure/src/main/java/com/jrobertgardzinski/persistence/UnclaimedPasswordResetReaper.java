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
 * Deletes password-reset rows nobody ever redeemed.
 *
 * <p>The row is written by every "I forgot my password" and removed only when the link is USED, so
 * every request that was abandoned — or that was never the account owner's in the first place —
 * stayed for ever. Asking costs one unauthenticated request, so the table is not even bounded by
 * the number of real users: a scanner walking a list of addresses leaves a row per address, each
 * one an e-mail address plus the hash of a token that stopped working an hour later.
 *
 * <p>Retention is deliberately much longer than the TTL {@code ResetPassword} judges by, exactly as
 * for the e-mail change and the verification: expiry is a decision and lives in the use case, while
 * this sweeps up only what could not possibly matter any more.
 */
@Singleton
@Requires(beans = DataSource.class)
class UnclaimedPasswordResetReaper {

    private static final Logger LOG = LoggerFactory.getLogger(UnclaimedPasswordResetReaper.class);

    private static final Duration RETENTION = Duration.ofDays(7);

    private final PasswordResetJdbcRepository resets;
    private final Clock clock;

    UnclaimedPasswordResetReaper(PasswordResetJdbcRepository resets, Clock clock) {
        this.resets = resets;
        this.clock = clock;
    }

    @Scheduled(fixedDelay = "1h", initialDelay = "6m")
    void reap() {
        try {
            LocalDateTime cutoff = LocalDateTime.now(clock).minus(RETENTION);
            int deleted = resets.deleteByRequestedAtBefore(cutoff);
            if (deleted > 0) {
                LOG.info("dropped {} unredeemed password reset(s) requested before {}", deleted, cutoff);
            }
        } catch (RuntimeException reapFailed) {
            LOG.warn("password-reset retention sweep failed; will try again on the next tick", reapFailed);
        }
    }
}
