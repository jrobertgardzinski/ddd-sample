package com.jrobertgardzinski.security.system.mfa;

import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;

/**
 * Remembers which TOTP time-step an enrolment has already been signed in with, so that one code
 * works ONCE.
 *
 * <p>A TOTP code is valid for its 30-second step and, for skew, one step either side — and nothing
 * recorded that a code had been used, so the same six digits kept working for up to a minute and a
 * half. That is the difference between a possession factor and a shouted password: anyone who sees
 * the code (over a shoulder, in a phishing relay, in a screenshot) has the rest of the window to
 * use it, beside the owner rather than instead of them.
 *
 * <p>Not durable on purpose, like the other short-lived MFA state: losing it means a code could be
 * replayed across a restart, which is a much smaller window than the one it closes.
 */
public interface SpentTotpSteps {

    /**
     * Claim a step for this enrolment: {@code true} the first time, {@code false} for that step and
     * every earlier one afterwards.
     */
    boolean claim(EnrolledFactor enrolment, long step);
}
