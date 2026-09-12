package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

import javax.sql.DataSource;
import java.util.Optional;

@JdbcRepository(dialect = Dialect.POSTGRES)
@Requires(beans = DataSource.class)
interface EmailVerificationJdbcRepository extends CrudRepository<EmailVerificationEntity, String> {

    Optional<EmailVerificationEntity> findByPendingTokenHash(String pendingTokenHash);

    /**
     * Consume the pending token and mark the address verified — conditional on the token still
     * being there, and reporting whether THIS caller was the one who consumed it, so two
     * presentations of one single-use link cannot both be answered "verified".
     *
     * @return 1 if this call consumed the token, 0 if it was already gone
     */
    @Query("UPDATE email_verifications SET verified = true, pending_token_hash = null "
            + "WHERE pending_token_hash = :hash")
    int markVerified(String hash);

    /**
     * Retention: an address that was typed once, never confirmed and never seen again keeps an
     * e-mail address and a token hash for as long as the database lives. A VERIFIED row is the
     * account's own state and is not touched here — it dies with the account.
     */
    @Query("DELETE FROM email_verifications WHERE verified = FALSE AND requested_at < :cutoff")
    int deleteUnverifiedRequestedBefore(java.time.LocalDateTime cutoff);
}
