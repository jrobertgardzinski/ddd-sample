package com.jrobertgardzinski.security.system.account;

import com.jrobertgardzinski.email.config.CanRegisterConfig;

import java.util.List;

/**
 * Outcome of {@link RequestEmailChange}: a verification link was sent to the new address, that
 * address is already taken, or the address is one this deployment does not admit at all.
 */
public sealed interface RequestEmailChangeResult {

    record Requested() implements RequestEmailChangeResult {}

    record EmailTaken() implements RequestEmailChangeResult {}

    /**
     * The address broke the e-mail policy. Carries the policy in force alongside the broken rules,
     * exactly as registration does, so one client renders both refusals with one piece of code —
     * and so a closed shop can say which domains an employee may move to.
     */
    record Rejected(List<String> emailErrors, CanRegisterConfig emailPolicy) implements RequestEmailChangeResult {}
}
