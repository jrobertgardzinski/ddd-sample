package com.jrobertgardzinski.security.config.mfa.vo;

import com.jrobertgardzinski.config.ConfigValue;

/** The fewest factors a MODERATOR must present. */
public record ModeratorMinFactors(Integer value) implements ConfigValue<Integer> {

    /** The name this rule goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.mfa.min.factors.moderator";
    public static final ModeratorMinFactors DEFAULT = new ModeratorMinFactors(2);

    public ModeratorMinFactors {
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
