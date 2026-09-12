package com.jrobertgardzinski.security.system.authentication;

import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.system.mfa.PendingAuthentication;
import com.jrobertgardzinski.security.system.mfa.PendingAuthenticationStore;

import java.time.Clock;
import java.util.List;
import java.util.Optional;

/**
 * Drives a sign-in that is past link #1 through its remaining factors, one proof at a time. Lives
 * in the authentication package so it can mint the session through the same {@link _GenerateSession}
 * the password path uses — the session is identical however the chain was walked. A wrong proof
 * costs an attempt (and folds into brute-force accounting at the boundary, like a wrong password);
 * running out, or an unknown/expired ticket, ends the attempt.
 */
public class ContinueAuthentication {

    private final PendingAuthenticationStore store;
    private final com.jrobertgardzinski.security.system.mfa.MfaChain chain;
    private final _GenerateSession generateSession;
    private final Clock clock;

    ContinueAuthentication(PendingAuthenticationStore store, com.jrobertgardzinski.security.system.mfa.MfaChain chain,
                           _GenerateSession generateSession, Clock clock) {
        this.store = store;
        this.chain = chain;
        this.generateSession = generateSession;
        this.clock = clock;
    }

    public ContinueAuthenticationResult execute(String ticket, String proof) {
        Optional<PendingAuthentication> found = store.find(ticket);
        if (found.isEmpty() || found.get().isExpired(clock)) {
            store.close(ticket);
            return new ContinueAuthenticationResult.InvalidTicket();
        }
        PendingAuthentication pending = found.get();

        if (!chain.verify(pending, proof)) {
            // spend the attempt as one step and decide on what is NOW stored: reading the count,
            // subtracting one and writing it back as three calls let concurrent proofs share the
            // same attempt, so a ticket worth five guesses answered as many as were sent at once
            Optional<PendingAuthentication> afterWrong = store.update(ticket, PendingAuthentication::afterWrongProof);
            if (afterWrong.isEmpty() || afterWrong.get().attemptsLeft() <= 0) {
                store.close(ticket);
                return new ContinueAuthenticationResult.TooManyAttempts();
            }
            return new ContinueAuthenticationResult.WrongProof(afterWrong.get().attemptsLeft());
        }

        List<EnrolledFactor> tail = pending.tail();
        if (tail.isEmpty()) {
            store.close(ticket);
            return new ContinueAuthenticationResult.Completed(generateSession.create(pending.email()));
        }
        PendingAuthentication advanced = chain.advanceTo(pending, tail);
        store.replace(ticket, advanced);
        return new ContinueAuthenticationResult.NextFactor(tail.get(0).type(), advanced.challengeData());
    }
}
