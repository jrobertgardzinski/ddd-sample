package com.jrobertgardzinski.security.config.bruteforce.vo;

import com.jrobertgardzinski.config.ConfigValue;

public record MaxFailures(Integer value) implements ConfigValue<Integer> {

    /** The name this limit goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.brute.force.max.failures";
    public static final int MIN = 1;
    public static final int MAX = 20;
    public static final MaxFailures DEFAULT = new MaxFailures(3);

    public MaxFailures {
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
    public MaxFailures holding(Integer value) {
        return new MaxFailures(value);
    }
}
