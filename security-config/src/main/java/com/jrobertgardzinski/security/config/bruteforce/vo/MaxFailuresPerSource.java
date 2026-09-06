package com.jrobertgardzinski.security.config.bruteforce.vo;

import com.jrobertgardzinski.config.ConfigValue;

/**
 * The ceiling on failures from ONE address against ANY account, inside the same window that
 * {@link MaxFailures} uses for a single account.
 *
 * <p>It exists because the tight per-account limit can be walked around: three guesses on each of a
 * thousand accounts is three thousand guesses from one address without ever reaching a per-account
 * limit — password spraying, and the shape an attacker moves to the moment the per-account count
 * starts working. This is the number that notices it.
 *
 * <p>Its default is deliberately far above {@link MaxFailures}: an address is not a person. Behind
 * one there may be an office, a CGNAT, or a CI runner creating accounts by the dozen, and a value
 * chosen for a single account's password would lock all of them out over somebody else's typos —
 * which is exactly what this project's own test suite proved by blocking itself halfway through a
 * run.
 */
public record MaxFailuresPerSource(Integer value) implements ConfigValue<Integer> {

    /** The name this limit goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.brute.force.max.failures.per.source";
    public static final int MIN = 5;
    public static final int MAX = 500;
    public static final MaxFailuresPerSource DEFAULT = new MaxFailuresPerSource(30);

    public MaxFailuresPerSource {
        if (value < MIN || value > MAX) {
            throw new IllegalArgumentException("Accepts values only from range " + MIN + "-" + MAX);
        }
    }

    @Override
    public String key() {
        return KEY;
    }

    @Override
    public Integer defaultValue() {
        return DEFAULT.value();
    }

    @Override
    public MaxFailuresPerSource holding(Integer value) {
        return new MaxFailuresPerSource(value);
    }
}
