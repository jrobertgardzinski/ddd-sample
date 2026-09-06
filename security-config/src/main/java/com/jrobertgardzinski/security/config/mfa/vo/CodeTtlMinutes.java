package com.jrobertgardzinski.security.config.mfa.vo;

import com.jrobertgardzinski.config.ConfigValue;

/** How long a mailed or texted challenge code stays valid, in minutes. */
public record CodeTtlMinutes(Integer value) implements ConfigValue<Integer> {

    /** The name this rule goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.mfa.code.ttl.minutes";
    public static final CodeTtlMinutes DEFAULT = new CodeTtlMinutes(5);

    public CodeTtlMinutes {
        if (value <= 0) throw new IllegalArgumentException("codeTtlMinutes must be positive");
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
