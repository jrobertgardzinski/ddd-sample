package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * {@link SecuritySettingsTable} over the real table: one SELECT for the snapshot, one upsert for a
 * decision. Text in, text out - what a row holds is the ladder's business to parse and refuse,
 * so a hand-edited row never takes a read down.
 */
@Singleton
@Requires(beans = DataSource.class)
final class JdbcSecuritySettings implements SecuritySettingsTable {

    private final SecuritySettingJdbcRepository repository;
    private final Clock clock;

    JdbcSecuritySettings(SecuritySettingJdbcRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Override
    public Map<String, String> rows() {
        Map<String, String> rows = new HashMap<>();
        for (SecuritySettingEntity row : repository.findAll()) {
            rows.put(row.name(), row.value());
        }
        return rows;
    }

    @Override
    public void put(String name, String value) {
        // one statement: two admins first-writing the same key no longer collide on the key
        repository.upsert(name, value, LocalDateTime.now(clock));
    }
}
