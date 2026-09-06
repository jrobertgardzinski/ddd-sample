package com.jrobertgardzinski.security.config.mfa.vo;

import com.jrobertgardzinski.config.ConfigValue;

/** How many wrong codes a pending sign-in may take before it is discarded. */
public record CodeMaxAttempts(Integer value) implements ConfigValue<Integer> {

    /** The name this rule goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.mfa.code.max.attempts";
    public static final CodeMaxAttempts DEFAULT = new CodeMaxAttempts(5);

    public CodeMaxAttempts {
        if (value <= 0) throw new IllegalArgumentException("maxAttempts must be positive");
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
