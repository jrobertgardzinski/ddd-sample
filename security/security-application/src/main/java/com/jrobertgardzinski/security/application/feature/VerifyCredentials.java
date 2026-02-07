package com.jrobertgardzinski.security.application.feature;

import com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Credentials;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;

import java.util.Optional;
import java.util.function.Function;

public class VerifyCredentials implements Function<Credentials, AuthenticationEvent> {
    private final UserRepository userRepository;
    private final HashAlgorithmPort hashAlgorithmPort;

    public VerifyCredentials(UserRepository userRepository, HashAlgorithmPort hashAlgorithmPort) {
        this.userRepository = userRepository;
        this.hashAlgorithmPort = hashAlgorithmPort;
    }

    @Override
    public AuthenticationEvent apply(Credentials credentials) {// authentication logic
        Email email = credentials.email();

        Optional<User> optionalUser = userRepository.findBy(email);
        if (optionalUser.isEmpty()) {
            return new AuthenticationFailedEvent(email);
        }

        PasswordHash passwordHash = optionalUser.get().passwordHash();
        PlaintextPassword enteredPassword = credentials.plaintextPassword();
        if (!hashAlgorithmPort.verify(passwordHash, enteredPassword)) {
            return new AuthenticationFailedEvent(email);
        }

        return new AuthenticationPassedEvent(email);
    }
}
