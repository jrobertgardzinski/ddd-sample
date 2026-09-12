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
interface PasswordResetJdbcRepository extends CrudRepository<PasswordResetEntity, String> {

    Optional<PasswordResetEntity> findByTokenHash(String tokenHash);

    /**
     * Spend the token, and say whether THIS caller was the one who spent it.
     *
     * <p>Consuming it was find-then-delete-by-e-mail: under READ COMMITTED two presentations of the
     * same link both found the row and both were told "yes, this link is good" — and a link that is
     * documented as single-use let two callers set the password. One conditional DELETE, and only
     * the caller whose statement removed a row may act on it.
     *
     * @return 1 if this call consumed the token, 0 if it was already gone
     */
    @Query("DELETE FROM password_resets WHERE token_hash = :tokenHash")
    int consume(String tokenHash);
}
