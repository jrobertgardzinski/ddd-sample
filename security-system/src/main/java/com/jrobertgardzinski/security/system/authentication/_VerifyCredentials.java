package com.jrobertgardzinski.security.system.authentication;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.password.domain.HashAlgorithmPort;
import com.jrobertgardzinski.password.domain.HashedPassword;
import com.jrobertgardzinski.password.domain.PlaintextPassword;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.AuthenticationEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Credentials;

import java.util.Optional;
import java.util.UUID;

class _VerifyCredentials {
    private final UserRepository userRepository;
    private final HashAlgorithmPort hashAlgorithmPort;

    /**
     * The hash an address with no account is checked against.
     *
     * <p>Without it, a sign-in for an unknown address skipped the Argon2 verify entirely and came
     * back in about a millisecond, while a known address cost the full hash — so the answer "no
     * such account here" was readable from the clock, on an endpoint whose whole vocabulary was
     * built to avoid saying it. (The registration side already refuses quietly for the same
     * reason.) Hashing a value nobody will ever type gives the absent case the same work to do; it
     * is computed once, when this step is built, against whatever algorithm the deployment wired.
     */
    private final HashedPassword absentAccountHash;

    public _VerifyCredentials(UserRepository userRepository, HashAlgorithmPort hashAlgorithmPort) {
        this.userRepository = userRepository;
        this.hashAlgorithmPort = hashAlgorithmPort;
        this.absentAccountHash = hashAlgorithmPort.hash(PlaintextPassword.of(UUID.randomUUID().toString()));
    }

    public AuthenticationEvent execute(Credentials credentials) {
        Email email = credentials.email();
        Optional<User> found = userRepository.findBy(email);
        // always verify SOMETHING: the branch that decides is taken after the work, not instead of it
        boolean passwordMatches = hashAlgorithmPort.verify(
                found.map(User::passwordHash).orElse(absentAccountHash), credentials.plaintextPassword());
        // an account locked by a running deletion saga behaves like a wrong password
        return found.isPresent() && passwordMatches && !userRepository.isPendingDeletion(email)
                // the STORED spelling from here on, not the one that was typed: everything after
                // this — the verified-address check, the factor lookup, the session and every
                // lookup the token later drives — is keyed by an address, and an account that can
                // be reached by two spellings must not be half-reached by one of them
                ? new AuthenticationEvent.Valid(found.get().email())
                : new AuthenticationEvent.Invalid(email);
    }
}
