package com.jrobertgardzinski.security.system.account;

import com.jrobertgardzinski.email.config.CanRegisterConfig;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.email.policy.CanRegister;
import com.jrobertgardzinski.util.constraint.Outcome;

import java.util.List;
import java.util.Optional;

/**
 * Whether an address may hold an account here at all — the same question {@code Register} asks of a
 * new one, asked again of the address an existing account wants to move to. A step of this use case
 * and nothing else (ADR 0002), so it stays package-private.
 *
 * <p>It exists because the policy was registration-only by accident rather than by decision: a
 * closed shop that admits only company addresses admitted anyone who had once been let in, since
 * they could then move the account to any address at all — roles, factors and federated links
 * following them out of the shop.
 */
record _NewEmailVerdict(Outcome<Email> outcome, CanRegisterConfig policy) {

    static _NewEmailVerdict judge(CanRegisterConfig policy, Email candidate) {
        CanRegister canRegister = CanRegister.builder()
                .blockingDomains(policy.blockedDomains())
                .blockingDisposable(policy.disposableDomains())
                .requiringCompanyEmployee(policy.companyDomains())
                .build();
        return new _NewEmailVerdict(canRegister.evaluate(() -> candidate), policy);
    }

    boolean accepted() {
        return outcome.findValue().isPresent();
    }

    List<String> errorCodes() {
        return outcome.errorCodes();
    }
}
