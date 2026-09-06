package com.jrobertgardzinski.security.config.mfa.vo;

import com.jrobertgardzinski.config.ConfigValue;

/** How many recovery codes one generation mints. */
public record RecoveryCodeCount(Integer value) implements ConfigValue<Integer> {

    /** The name this rule goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.mfa.recovery.count";
    public static final RecoveryCodeCount DEFAULT = new RecoveryCodeCount(10);

    public RecoveryCodeCount {
        if (value < 1 || value > 50) throw new IllegalArgumentException("count must be between 1 and 50");
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
