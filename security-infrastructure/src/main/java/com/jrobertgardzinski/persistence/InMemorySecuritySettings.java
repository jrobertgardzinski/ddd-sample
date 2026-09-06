package com.jrobertgardzinski.persistence;

import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The table without a database: empty unless a test seeds it or an admin writes. Mirrors the
 * other InMemory* fallbacks - the service boots and behaves identically, the level is vacant and
 * the ladder falls through. {@link #put} is also the test's stand-in for a hand at the database
 * console: it bypasses the value object on purpose, and the snapshot notices it when it is next
 * taken - at a start or after an admin's write - like it would a real row.
 */
@Singleton
@Requires(missingBeans = DataSource.class)
public final class InMemorySecuritySettings implements SecuritySettingsTable {

    private final Map<String, String> rows = new ConcurrentHashMap<>();

    @Override
    public Map<String, String> rows() {
        return new HashMap<>(rows);
    }

    @Override
    public void put(String name, String value) {
        rows.put(name, value);
    }

    public void remove(String name) {
        rows.remove(name);
    }
}
