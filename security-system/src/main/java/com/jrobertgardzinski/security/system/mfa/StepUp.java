package com.jrobertgardzinski.security.system.mfa;

import com.jrobertgardzinski.security.domain.vo.StepUpRequirement;
import com.jrobertgardzinski.security.domain.vo.StepUpAction;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.password.domain.HashAlgorithmPort;
import com.jrobertgardzinski.password.domain.PlaintextPassword;
import com.jrobertgardzinski.security.config.mfa.StepUpPolicy;
import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.domain.repository.EnrolledFactorRepository;
import com.jrobertgardzinski.security.domain.repository.PasswordlessAccountRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.FactorType;

import java.time.Clock;
import java.util.List;
import java.util.Optional;

/**
 * Re-proves a caller for a sensitive action. The requirement per action comes from the
 * {@link StepUpPolicy}: {@code NONE} elevates at once; {@code FULL_CHAIN} first re-verifies the
 * password (skipped for a passwordless federated account); then both walk the enrolled factors
 * through the shared {@link MfaChain}. Passing the last factor mints a one-shot
 * {@link SessionElevation} on the caller's access token — the sensitive endpoint consumes it.
 * A caller with no factors and no password step is elevated directly (there is nothing extra to
 * prove beyond the live session).
 */
public class StepUp {

    public sealed interface Result {
        record Elevated() implements Result {}
        record FactorRequired(String ticket, FactorType nextFactor, String challengeData) implements Result {}
        record WrongPassword() implements Result {}
        record WrongProof(int attemptsLeft) implements Result {}
        record TooManyAttempts() implements Result {}
        record InvalidTicket() implements Result {}
    }

    private final StepUpPolicy policy;
    private final UserRepository users;
    private final HashAlgorithmPort hashAlgorithm;
    private final PasswordlessAccountRepository passwordless;
    private final EnrolledFactorRepository factors;
    private final MfaChain chain;
    private final StepUpStore store;
    private final SessionElevation elevation;
    private final Clock clock;

    public StepUp(StepUpPolicy policy, UserRepository users, HashAlgorithmPort hashAlgorithm,
                  PasswordlessAccountRepository passwordless, EnrolledFactorRepository factors,
                  MfaChain chain, StepUpStore store, SessionElevation elevation, Clock clock) {
        this.policy = policy;
        this.users = users;
        this.hashAlgorithm = hashAlgorithm;
        this.passwordless = passwordless;
        this.factors = factors;
        this.chain = chain;
        this.store = store;
        this.elevation = elevation;
        this.clock = clock;
    }

    public Result start(Email email, StepUpAction action, String accessToken, String passwordAttempt) {
        StepUpRequirement requirement = policy.requirementFor(action);
        if (requirement == StepUpRequirement.NONE) {
            elevation.elevate(accessToken, action);
            return new Result.Elevated();
        }
        List<EnrolledFactor> enrolled = factors.findByUser(email);
        // The password is proven for FULL_CHAIN, and ALSO when there are no enrolled factors to
        // walk: a requirement other than NONE with an empty factor list used to elevate silently on
        // the live session alone, which turned any non-NONE action into "a stolen token is enough".
        // A passwordless (federated) account has nothing to prove here — its live session is all it
        // ever has — so it keeps the direct elevation.
        boolean mustProvePassword = requirement == StepUpRequirement.FULL_CHAIN || enrolled.isEmpty();
        if (mustProvePassword && !passwordless.isPasswordless(email)
                && !passwordMatches(email, passwordAttempt)) {
            return new Result.WrongPassword();
        }
        if (enrolled.isEmpty()) {
            elevation.elevate(accessToken, action);   // nothing further to prove
            return new Result.Elevated();
        }
        PendingAuthentication pending = chain.begin(email, enrolled);
        String ticket = store.open(new StepUpStore.StepUpPending(email, accessToken, action, pending));
        return new Result.FactorRequired(ticket, enrolled.get(0).type(), pending.challengeData());
    }

    public Result submitFactor(String ticket, String proof) {
        Optional<StepUpStore.StepUpPending> found = store.find(ticket);
        // an unknown ticket, or one whose chain has aged past its TTL, ends the step-up — the twin
        // ContinueAuthentication makes the same check, but StepUp used to trust the ticket forever
        if (found.isEmpty() || found.get().chain().isExpired(clock)) {
            store.close(ticket);
            return new Result.InvalidTicket();
        }
        StepUpStore.StepUpPending pending = found.get();
        if (!chain.verify(pending.chain(), proof)) {
            // one step, and the verdict comes from what is now stored — see StepUpStore#update
            Optional<StepUpStore.StepUpPending> afterWrong = store.update(ticket, current ->
                    new StepUpStore.StepUpPending(current.email(), current.accessToken(), current.action(),
                            current.chain().afterWrongProof()));
            if (afterWrong.isEmpty() || afterWrong.get().chain().attemptsLeft() <= 0) {
                store.close(ticket);
                return new Result.TooManyAttempts();
            }
            return new Result.WrongProof(afterWrong.get().chain().attemptsLeft());
        }
        List<EnrolledFactor> tail = pending.chain().tail();
        if (tail.isEmpty()) {
            store.close(ticket);
            elevation.elevate(pending.accessToken(), pending.action());
            return new Result.Elevated();
        }
        PendingAuthentication advanced = chain.advanceTo(pending.chain(), tail);
        store.replace(ticket, new StepUpStore.StepUpPending(pending.email(), pending.accessToken(), pending.action(), advanced));
        return new Result.FactorRequired(ticket, tail.get(0).type(), advanced.challengeData());
    }

    private boolean passwordMatches(Email email, String passwordAttempt) {
        return passwordAttempt != null && users.findBy(email)
                .map(user -> hashAlgorithm.verify(user.passwordHash(), PlaintextPassword.of(passwordAttempt)))
                .orElse(false);
    }
}
