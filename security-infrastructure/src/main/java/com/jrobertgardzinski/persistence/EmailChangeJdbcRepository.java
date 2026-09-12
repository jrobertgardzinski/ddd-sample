package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

import javax.sql.DataSource;

@JdbcRepository(dialect = Dialect.POSTGRES)
@Requires(beans = DataSource.class)
interface EmailChangeJdbcRepository extends CrudRepository<EmailChangeEntity, String> {

    /**
     * Spend the change token, and say whether THIS caller spent it — the same reason as
     * {@code PasswordResetJdbcRepository#consume}: find-then-delete let two presentations of one
     * single-use link both succeed, and this link MOVES the account.
     *
     * @return 1 if this call consumed the token, 0 if it was already gone
     */
    @Query("DELETE FROM email_changes WHERE token_hash = :tokenHash")
    int consume(String tokenHash);

    void deleteByCurrentEmail(String currentEmail);

    void deleteByNewEmail(String newEmail);

    /** Retention: a ticket nobody confirmed is rubbish the moment it stops being usable. */
    int deleteByStartedAtBefore(java.time.LocalDateTime cutoff);
}
