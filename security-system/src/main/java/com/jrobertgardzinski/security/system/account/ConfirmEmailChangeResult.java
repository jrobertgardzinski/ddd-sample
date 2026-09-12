package com.jrobertgardzinski.security.system.account;

import com.jrobertgardzinski.email.domain.Email;

/**
 * Outcome of {@link ConfirmEmailChange}: the address was changed, the token was rejected, or the
 * address stopped being free while the link was in the mailbox.
 */
public sealed interface ConfirmEmailChangeResult {

    record EmailChanged(Email newEmail) implements ConfirmEmailChangeResult {}

    record InvalidToken() implements ConfirmEmailChangeResult {}

    /**
     * Somebody else holds the address now.
     *
     * <p>A change is requested against a free address and confirmed up to a day later, and nothing
     * reserves it in between — so this is an ordinary outcome, not an error, and it is the only one
     * the person can act on ("pick another address"). It is said plainly rather than folded into
     * {@link InvalidToken}: the token was perfectly good, and telling its owner it was not sends
     * them to request a second one that will fail in exactly the same way.
     *
     * <p>It does tell the confirming user that the address is taken — which is something the quiet
     * request endpoint deliberately does not say. The trade is deliberate too: they are the person
     * who asked to move there, they will find out when they try again, and the alternative is an
     * account stuck in a loop with no way to learn why.
     */
    record EmailTaken() implements ConfirmEmailChangeResult {}
}
