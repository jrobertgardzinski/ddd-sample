package com.jrobertgardzinski.security.config.mfa.vo;

import com.jrobertgardzinski.config.ConfigValue;

/** How many wrong codes a pending sign-in may take before it is discarded. */
public record CodeMaxAttempts(Integer value) implements ConfigValue<Integer> {

    /** The name this rule goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.mfa.code.max.attempts";
    public static final int MIN = 1;
    public static final int MAX = 20;
    public static final CodeMaxAttempts DEFAULT = new CodeMaxAttempts(5);

    public CodeMaxAttempts {
        // The ceiling is what makes this a second FACTOR: a six-digit code has a million values,
        // so a hundred tries per ticket is a different security property than five, and the number
        // is a deployment's to choose only inside a range where the arithmetic still holds.
        if (value < MIN || value > MAX) {
            throw new IllegalArgumentException("maxAttempts must be between " + MIN + " and " + MAX
                    + " (enough tries and a six-digit code stops being a factor)");
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
    public CodeMaxAttempts holding(Integer value) {
        return new CodeMaxAttempts(value);
    }
}
