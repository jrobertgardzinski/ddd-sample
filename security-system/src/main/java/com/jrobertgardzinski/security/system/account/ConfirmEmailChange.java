package com.jrobertgardzinski.security.system.account;

import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.repository.EmailChangeRepository;
import com.jrobertgardzinski.security.domain.repository.EmailVerificationRepository;
import com.jrobertgardzinski.security.domain.repository.EnrolledFactorRepository;
import com.jrobertgardzinski.security.domain.repository.FederatedIdentityRepository;
import com.jrobertgardzinski.security.domain.repository.PasswordResetRepository;
import com.jrobertgardzinski.security.domain.repository.PasswordlessAccountRepository;
import com.jrobertgardzinski.security.domain.repository.RecoveryCodeRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;

/**
 * Completes an email change: a matching, unused token applies the pending change (moving the user
 * to the new address); an unknown or already-used token is rejected. The new address is marked
 * verified — the change token was delivered there, which is the same ownership proof the regular
 * verification flow provides (and sign-in requires a verified address). Federated links FOLLOW the
 * account: they are keyed by the provider's durable subject (the same person, the same Google
 * account), so they are re-pointed at the new address — severing them would orphan the identity,
 * because the provider keeps reporting its own old address and the auto-link at the next sign-in
 * would never find the moved account.
 *
 * <p>A ticket is only good for as long as the window the caller sets: this link MOVES the account,
 * so one sitting unnoticed in an old mailbox must stop working, exactly as a password-reset link
 * does. It did not, until now — nothing was reading the date it was issued, because nothing was
 * stored.
 *
 * <p>Everything else the account owns is keyed by that address too, and not one of those tables has
 * a foreign key to cascade — so this use case moves them by hand or the move loses them. Two kinds,
 * two answers. What belongs to the ACCOUNT follows it: the MFA factors, the recovery codes and the
 * passwordless mark. Left behind, a lookup under the new address finds nothing, so the second factor
 * disappears without a trace and a password alone signs in again; and a federated account reads as
 * "has a password" under its new address, which locks its owner out of ever deleting it. What was
 * E-MAILED TO THE OLD ADDRESS is dropped instead: a pending reset, a pending further change, the
 * verification row. The account no longer owns that mailbox, and a live token pointing at a freed
 * address sets the password of whoever registers it next.
 *
 * <p>SESSIONS are neither moved nor kept: they are revoked, the same price a password change and a
 * password reset already charge. They cannot be moved, because a session remembers only the address
 * it was minted for — so a surviving one keeps authorizing as the OLD address, "sign out everywhere"
 * under the new address never reaches it, and the moment somebody registers the freed address that
 * session starts resolving to THEIR account: their roles, their session list. The owner signs in
 * again after moving; nobody inherits a session by taking over an abandoned address.
 *
 * <p>A ticket is also refused while the account is being DELETED. The deletion saga locks the
 * account and then waits for other services; a change landing in that window moves the locked user
 * to the new address, where the saga's compensation and its completion can no longer find them —
 * an account locked forever under an address its owner never finished moving to.
 */
public class ConfirmEmailChange {

    private final EmailChangeRepository emailChangeRepository;
    private final UserRepository userRepository;
    private final EmailVerificationRepository emailVerificationRepository;
    private final FederatedIdentityRepository federatedIdentityRepository;
    private final EnrolledFactorRepository enrolledFactorRepository;
    private final RecoveryCodeRepository recoveryCodeRepository;
    private final PasswordlessAccountRepository passwordlessAccountRepository;
    private final PasswordResetRepository passwordResetRepository;
    private final AuthorizationDataRepository authorizationDataRepository;
    private final java.time.Duration tokenTtl;
    private final java.time.Clock clock;

    public ConfirmEmailChange(EmailChangeRepository emailChangeRepository, UserRepository userRepository,
                              EmailVerificationRepository emailVerificationRepository,
                              FederatedIdentityRepository federatedIdentityRepository,
                              EnrolledFactorRepository enrolledFactorRepository,
                              RecoveryCodeRepository recoveryCodeRepository,
                              PasswordlessAccountRepository passwordlessAccountRepository,
                              PasswordResetRepository passwordResetRepository,
                              AuthorizationDataRepository authorizationDataRepository,
                              java.time.Duration tokenTtl, java.time.Clock clock) {
        this.emailChangeRepository = emailChangeRepository;
        this.userRepository = userRepository;
        this.emailVerificationRepository = emailVerificationRepository;
        this.federatedIdentityRepository = federatedIdentityRepository;
        this.enrolledFactorRepository = enrolledFactorRepository;
        this.recoveryCodeRepository = recoveryCodeRepository;
        this.passwordlessAccountRepository = passwordlessAccountRepository;
        this.passwordResetRepository = passwordResetRepository;
        this.authorizationDataRepository = authorizationDataRepository;
        this.tokenTtl = tokenTtl;
        this.clock = clock;
    }

    public ConfirmEmailChangeResult execute(VerificationToken token) {
        return emailChangeRepository.confirmChange(token)
                .filter(this::stillFresh)
                .map(EmailChangeRepository.PendingEmailChange::change)
                .filter(change -> !userRepository.isPendingDeletion(change.currentEmail()))
                .<ConfirmEmailChangeResult>map(change -> {
                    federatedIdentityRepository.relinkAll(change.currentEmail(), change.newEmail());
                    enrolledFactorRepository.reassign(change.currentEmail(), change.newEmail());
                    recoveryCodeRepository.reassign(change.currentEmail(), change.newEmail());
                    passwordlessAccountRepository.reassign(change.currentEmail(), change.newEmail());
                    passwordResetRepository.purge(change.currentEmail());
                    emailChangeRepository.purge(change.currentEmail());
                    emailVerificationRepository.purge(change.currentEmail());
                    userRepository.updateEmail(change.currentEmail(), change.newEmail());
                    authorizationDataRepository.revokeAllSessions(change.currentEmail());
                    emailVerificationRepository.markVerified(change.newEmail());
                    return new ConfirmEmailChangeResult.EmailChanged(change.newEmail());
                })
                .orElseGet(ConfirmEmailChangeResult.InvalidToken::new);
    }

    /**
     * An expired ticket is treated exactly like an unknown one — and it is already consumed by the
     * time we look, so it is spent for good either way. Same answer as a stale password-reset link,
     * for the same reason: telling the difference would tell a stranger that a change to this
     * address was once started.
     */
    private boolean stillFresh(EmailChangeRepository.PendingEmailChange pending) {
        return !pending.startedAt().plus(tokenTtl).isBefore(java.time.LocalDateTime.now(clock));
    }
}
