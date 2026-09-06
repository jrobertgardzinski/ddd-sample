package com.jrobertgardzinski.security.config.mfa;

import com.jrobertgardzinski.security.config.mfa.vo.CodeLength;
import com.jrobertgardzinski.security.config.mfa.vo.CodeMaxAttempts;
import com.jrobertgardzinski.security.config.mfa.vo.CodeTtlMinutes;

/**
 * The shape of a mailed or texted challenge code: three rules, each a value object with its own
 * key and default, held together as one value.
 */
public record ChallengeCodeConfig(CodeTtlMinutes codeTtlMinutes, CodeMaxAttempts maxAttempts, CodeLength codeLength) {

    public ChallengeCodeConfig(int codeTtlMinutes, int maxAttempts, int codeLength) {
        this(new CodeTtlMinutes(codeTtlMinutes), new CodeMaxAttempts(maxAttempts), new CodeLength(codeLength));
    }

    public static ChallengeCodeConfig withDefaults() {
        return new ChallengeCodeConfig(CodeTtlMinutes.DEFAULT, CodeMaxAttempts.DEFAULT, CodeLength.DEFAULT);
    }
}
