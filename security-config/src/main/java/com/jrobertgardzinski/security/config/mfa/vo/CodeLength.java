package com.jrobertgardzinski.security.config.mfa.vo;

import com.jrobertgardzinski.config.ConfigValue;

/** How many digits a challenge code has. */
public record CodeLength(Integer value) implements ConfigValue<Integer> {

    /** The name this rule goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.mfa.code.length";
    public static final CodeLength DEFAULT = new CodeLength(6);

    public CodeLength {
        if (value < 4 || value > 10) throw new IllegalArgumentException("codeLength must be between 4 and 10");
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
    public CodeLength holding(Integer value) {
        return new CodeLength(value);
    }
}
