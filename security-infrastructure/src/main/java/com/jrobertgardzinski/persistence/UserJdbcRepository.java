package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

import javax.sql.DataSource;
import java.util.Optional;
import java.util.UUID;

@JdbcRepository(dialect = Dialect.POSTGRES)
@Requires(beans = DataSource.class)
interface UserJdbcRepository extends CrudRepository<UserEntity, UUID> {

    @Query("UPDATE users SET pending_deletion = :pending WHERE email = :email")
    void setPendingDeletion(String email, boolean pending);

    boolean existsByEmailAndPendingDeletionTrue(String email);


    Optional<UserEntity> findByEmail(String email);

    boolean existsByNormalizedEmail(String normalizedEmail);

    java.util.Optional<UserEntity> findByNormalizedEmail(String normalizedEmail);

    @Query("UPDATE users SET password_hash = :passwordHash WHERE email = :email")
    void updatePassword(String email, String passwordHash);

    @Query("UPDATE users SET roles = :roles WHERE email = :email")
    void setRoles(String email, String roles);

    @Query("UPDATE users SET email = :newEmail, normalized_email = :normalizedEmail WHERE email = :currentEmail")
    void updateEmail(String currentEmail, String newEmail, String normalizedEmail);

    void deleteByEmail(String email);
}
