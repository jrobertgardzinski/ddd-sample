package com.jrobertgardzinski.security.config.bruteforce.vo;

import com.jrobertgardzinski.config.ConfigValue;

public record FailureWindowMinutes(Integer value) implements ConfigValue<Integer> {

    /** The name this limit goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.brute.force.failure.window.minutes";
    public static final int MIN = 3;
    public static final int MAX = 120;
    public static final FailureWindowMinutes DEFAULT = new FailureWindowMinutes(15);

    public FailureWindowMinutes {
        if (value < MIN || value > MAX) throw new IllegalArgumentException("Accepts values only from range " + MIN + "-" + MAX);
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
    public FailureWindowMinutes holding(Integer value) {
        return new FailureWindowMinutes(value);
    }
}
