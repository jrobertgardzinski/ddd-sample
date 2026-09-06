package com.jrobertgardzinski.security.config.bruteforce.vo;

import com.jrobertgardzinski.config.ConfigValue;

public record MaxBlockMinutes(Integer value) implements ConfigValue<Integer> {

    /** The name this limit goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.brute.force.max.block.minutes";
    public static final int MIN = 1;
    public static final int MAX = 1440;
    public static final MaxBlockMinutes DEFAULT = new MaxBlockMinutes(10);

    public MaxBlockMinutes {
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
    public MaxBlockMinutes holding(Integer value) {
        return new MaxBlockMinutes(value);
    }
}
