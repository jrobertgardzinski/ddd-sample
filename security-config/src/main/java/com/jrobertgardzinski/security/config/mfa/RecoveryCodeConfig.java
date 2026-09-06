package com.jrobertgardzinski.security.config.mfa;

import com.jrobertgardzinski.security.config.mfa.vo.RecoveryCodeCount;
import com.jrobertgardzinski.security.config.mfa.vo.RecoveryCodeLength;

/** How many recovery codes one generation mints and how long each is; two rules, one value. */
public record RecoveryCodeConfig(RecoveryCodeCount count, RecoveryCodeLength length) {

    public RecoveryCodeConfig(int count, int length) {
        this(new RecoveryCodeCount(count), new RecoveryCodeLength(length));
    }

    public static RecoveryCodeConfig withDefaults() {
        return new RecoveryCodeConfig(RecoveryCodeCount.DEFAULT, RecoveryCodeLength.DEFAULT);
    }
}
