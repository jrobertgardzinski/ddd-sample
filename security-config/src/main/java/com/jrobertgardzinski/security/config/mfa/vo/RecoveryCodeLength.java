package com.jrobertgardzinski.security.config.mfa.vo;

import com.jrobertgardzinski.config.ConfigValue;

/** How many characters a recovery code has. */
public record RecoveryCodeLength(Integer value) implements ConfigValue<Integer> {

    /** The name this rule goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.mfa.recovery.length";
    public static final RecoveryCodeLength DEFAULT = new RecoveryCodeLength(10);

    public RecoveryCodeLength {
        if (value < 8 || value > 40) throw new IllegalArgumentException("length must be between 8 and 40");
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
