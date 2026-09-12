package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;

import java.util.Optional;

/**
 * Tracks pending e-mail verifications and their outcome. A pending verification remembers the
 * (hashed) token last e-mailed to an address; completing it with the matching token marks the
 * address verified and consumes the token. Raw tokens are never stored.
 */
public interface EmailVerificationRepository {

    /** Remember (or reset) the pending token e-mailed to this address; the address is not yet verified. */
    void startVerification(Email email, VerificationToken token);

    /**
     * A verification that was started and is still pending: the address it was mailed to, and WHEN.
     *
     * <p>The date is here for the same reason the password reset's is: a link that arrives in a
     * mailbox has to stop working, and the use case is where "how long" is decided. The row used to
     * carry no date at all, so a link from a year ago verified an address as happily as one from a
     * minute ago — which matters most for exactly the addresses nobody is watching.
     */
    record PendingVerification(Email email, java.time.LocalDateTime requestedAt) {}

    /**
     * If the token matches a pending verification, mark that address verified and return what was
     * pending; else empty. The token is spent either way — a presented token is a spent token, and
     * whether it was still fresh is the caller's judgement to make.
     */
    Optional<PendingVerification> completeVerification(VerificationToken token);

    /**
     * Mark the address verified without a token — for flows that proved ownership by other means
     * (e.g. confirming an email change, whose own token was delivered to that address).
     */
    void markVerified(Email email);

    boolean isVerified(Email email);

    /**
     * Forgets everything known about this address: the pending token and the verified flag. Called
     * when the account is deleted and when it moves to another address — a "verified" row left under
     * a freed address would vouch for whoever registers it next, and the address itself is personal
     * data that must not outlive the account.
     */
    void purge(Email email);
}
