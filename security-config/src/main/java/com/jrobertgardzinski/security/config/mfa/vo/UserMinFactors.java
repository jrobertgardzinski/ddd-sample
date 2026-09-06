package com.jrobertgardzinski.security.config.mfa.vo;

import com.jrobertgardzinski.config.ConfigValue;

/** The fewest factors a USER must present; also the floor for a role nobody configured. */
public record UserMinFactors(Integer value) implements ConfigValue<Integer> {

    /** The name this rule goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.mfa.min.factors.user";
    public static final UserMinFactors DEFAULT = new UserMinFactors(1);

    public UserMinFactors {
        if (value < 1) throw new IllegalArgumentException("minFactors must be at least 1");
    }

    @Override
    public String key() {
        return KEY;
    }

    @Override
    public Integer defaultValue() {
        return DEFAULT.value();
    }
}
