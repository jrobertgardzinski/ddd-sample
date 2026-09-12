package com.jrobertgardzinski.security.system.verification;

import com.jrobertgardzinski.security.domain.repository.EmailVerificationRepository;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;

import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;

/**
 * Completes e-mail verification: a matching, unused token that is still fresh marks the address
 * verified; an unknown, already-used or EXPIRED token is rejected.
 *
 * <p>An expired link is answered exactly like an unknown one, and is spent either way — the same
 * rule the password reset and the e-mail change follow, for the same reason: telling the difference
 * would tell a stranger that a verification for this address was once started. Re-requesting is one
 * click away and costs the requester a fresh mail, which is the intended way back.
 */
public class VerifyEmail {

    private final EmailVerificationRepository repository;
    private final Duration tokenTtl;
    private final Clock clock;

    public VerifyEmail(EmailVerificationRepository repository, Duration tokenTtl, Clock clock) {
        this.repository = repository;
        this.tokenTtl = tokenTtl;
        this.clock = clock;
    }

    public VerifyEmailResult execute(VerificationToken token) {
        return repository.completeVerification(token)
                .filter(pending -> !pending.requestedAt().plus(tokenTtl).isBefore(LocalDateTime.now(clock)))
                .<VerifyEmailResult>map(pending -> new VerifyEmailResult.Verified(pending.email()))
                .orElseGet(VerifyEmailResult.Rejected::new);
    }
}
