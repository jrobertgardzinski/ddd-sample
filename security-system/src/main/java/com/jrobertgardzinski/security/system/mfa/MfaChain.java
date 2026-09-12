package com.jrobertgardzinski.security.system.mfa;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.config.mfa.ChallengeCodeConfig;
import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.domain.repository.RecoveryCodeRepository;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;

/**
 * The factor chain, shared by every entry point that can trigger MFA: it opens a pending
 * authentication over the factors that remain after link #1 (a password OR a provider login),
 * issues each factor's challenge as it becomes current, and verifies a proof against the current
 * factor. It reaches into the {@link FactorRegistry} — which adapter serves a type — so the use
 * cases above it (password sign-in, federated sign-in, the continuation) never need to know.
 *
 * <p>A proof the current factor rejects gets one more chance: if it is an unused RECOVERY CODE it
 * is consumed (single-use) and stands in for that link — the break-glass path for a lost phone or
 * inbox. Recovery codes are an alternative to a link, never a link of their own, so every entry
 * point that walks the chain (sign-in continuation, step-up) accepts them without knowing.
 */
public class MfaChain {

    private final FactorRegistry registry;
    private final ChallengeCodeConfig config;
    private final RecoveryCodeRepository recoveryCodes;
    private final RecoveryCodeHasher recoveryCodeHasher;
    private final Clock clock;
    private final int ticketTtlMinutes;

    public MfaChain(FactorRegistry registry, ChallengeCodeConfig config,
                    RecoveryCodeRepository recoveryCodes, RecoveryCodeHasher recoveryCodeHasher,
                    Clock clock, int ticketTtlMinutes) {
        this.registry = registry;
        this.config = config;
        this.recoveryCodes = recoveryCodes;
        this.recoveryCodeHasher = recoveryCodeHasher;
        this.clock = clock;
        this.ticketTtlMinutes = ticketTtlMinutes;
    }

    /** Begin the tail: issue the first factor's challenge and build the pending authentication. */
    public PendingAuthentication begin(Email email, List<EnrolledFactor> factors) {
        return new PendingAuthentication(email, List.copyOf(factors), issue(factors.get(0)),
                config.maxAttempts().value(), LocalDateTime.now(clock).plusMinutes(ticketTtlMinutes));
    }

    /** Advance to the next factor, keeping the ticket's overall expiry, resetting the attempt count. */
    public PendingAuthentication advanceTo(PendingAuthentication pending, List<EnrolledFactor> tail) {
        return new PendingAuthentication(pending.email(), tail, issue(tail.get(0)),
                config.maxAttempts().value(), pending.expiresAt());
    }

    public Challenge issue(EnrolledFactor factor) {
        return registry.forType(factor.type())
                .flatMap(f -> f.issueChallenge(factor))
                .orElse(null);   // possession factors carry no challenge
    }

    public boolean verify(PendingAuthentication pending, String proof) {
        EnrolledFactor current = pending.currentFactor();
        boolean passed = registry.forType(current.type())
                .map(f -> f.verify(current, pending.challenge(), proof))
                .orElse(false);
        if (passed) {
            return true;
        }
        // not the factor's proof — maybe a recovery code standing in for this link (spent if so)
        return proof != null && !proof.isBlank() && recoveryCodes.consume(pending.email(),
                recoveryCodeHasher.hash(GenerateRecoveryCodes.normalise(proof)));
    }
}
