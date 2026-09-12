package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

import javax.sql.DataSource;

@JdbcRepository(dialect = Dialect.POSTGRES)
@Requires(beans = DataSource.class)
interface SecuritySettingJdbcRepository extends CrudRepository<SecuritySettingEntity, String> {

    /**
     * One statement for an administrator's decision, whether or not the key has a row yet.
     *
     * <p>It was exists-then-save, with no transaction around the pair (the admin controller uses
     * none): two administrators writing the same key for the first time both saw "no row" and both
     * inserted, and the loser got a primary-key violation — a 500 for a legitimate write, on the
     * endpoint that exists to change how the service behaves at runtime.
     */
    @Query("INSERT INTO security_settings (name, value, updated_at) VALUES (:name, :value, :updatedAt)"
            + " ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at")
    int upsert(String name, String value, java.time.LocalDateTime updatedAt);
}
