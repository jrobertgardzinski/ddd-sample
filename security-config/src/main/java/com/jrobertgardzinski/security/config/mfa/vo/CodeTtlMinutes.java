package com.jrobertgardzinski.security.config.mfa.vo;

import com.jrobertgardzinski.config.ConfigValue;

/** How long a mailed or texted challenge code stays valid, in minutes. */
public record CodeTtlMinutes(Integer value) implements ConfigValue<Integer> {

    /** The name this rule goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.mfa.code.ttl.minutes";
    public static final int MIN = 1;
    public static final int MAX = 60;
    public static final CodeTtlMinutes DEFAULT = new CodeTtlMinutes(5);

    public CodeTtlMinutes {
        // A ceiling as well as a floor, and the ceiling is the interesting one: a challenge code
        // is a six-digit secret sitting in somebody's mailbox, and "valid for a week" is a week in
        // which anybody who reads that mailbox can finish a sign-in. An hour is already generous
        // for "check your mail"; the floor keeps it usable for a person who has to switch devices.
        if (value < MIN || value > MAX) {
            throw new IllegalArgumentException("codeTtlMinutes must be between " + MIN + " and " + MAX
                    + " (a code that lives longer is a password sitting in a mailbox)");
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
    public CodeTtlMinutes holding(Integer value) {
        return new CodeTtlMinutes(value);
    }
}
