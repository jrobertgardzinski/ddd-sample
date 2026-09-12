package com.jrobertgardzinski.security.system.verification;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.port.EmailVerificationNotifier;
import com.jrobertgardzinski.security.domain.repository.EmailVerificationRepository;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;

/**
 * Starts e-mail verification: mints a single-use token, remembers it against the address, and
 * e-mails the verification link. Re-requesting while the address is still unverified simply
 * issues a fresh token — a lost mail costs nothing.
 *
 * <p>An ALREADY VERIFIED address is left alone, and that is a security rule, not an optimisation:
 * starting a verification resets the address to unverified, and this use case is reached from a
 * public endpoint that takes any address a stranger types in. Without the guard, one request per
 * victim shuts them out of their own account (sign-in demands a verified address) until they
 * follow a link they never asked for.
 */
public class RequestEmailVerification {

    private final EmailVerificationRepository repository;
    private final EmailVerificationNotifier notifier;

    public RequestEmailVerification(EmailVerificationRepository repository, EmailVerificationNotifier notifier) {
        this.repository = repository;
        this.notifier = notifier;
    }

    public void execute(Email email) {
        if (repository.isVerified(email)) {
            return;   // nothing to prove, and nothing to take away
        }
        VerificationToken token = VerificationToken.random();
        repository.startVerification(email, token);
        notifier.sendVerificationLink(email, token);
    }
}
