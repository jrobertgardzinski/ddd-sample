package com.jrobertgardzinski.security.config.mfa.vo;

import com.jrobertgardzinski.config.ConfigValue;

/** The fewest factors an ADMIN must present. */
public record AdminMinFactors(Integer value) implements ConfigValue<Integer> {

    /** The name this rule goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.mfa.min.factors.admin";
    public static final AdminMinFactors DEFAULT = new AdminMinFactors(3);

    public AdminMinFactors {
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

    @Override
    public AdminMinFactors holding(Integer value) {
        return new AdminMinFactors(value);
    }
}
