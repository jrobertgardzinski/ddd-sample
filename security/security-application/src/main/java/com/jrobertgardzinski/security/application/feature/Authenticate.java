package com.jrobertgardzinski.security.application.feature;

import com.jrobertgardzinski.security.domain.event.auth.AuthResult;
import com.jrobertgardzinski.security.domain.event.auth.Failed;
import com.jrobertgardzinski.security.domain.event.auth.Passed;
import com.jrobertgardzinski.security.domain.event.authentication.*;
import com.jrobertgardzinski.security.domain.vo.*;
import com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.UserRepository;

import java.util.Optional;
import java.util.function.Function;

public class Authenticate implements Function<Credentials, AuthenticationEvent> {
    private final UserRepository userRepository;
    private final HashAlgorithmPort hashAlgorithmPort;

    public Authenticate(UserRepository userRepository, HashAlgorithmPort hashAlgorithmPort) {
        this.userRepository = userRepository;
        this.hashAlgorithmPort = hashAlgorithmPort;
    }

    @Override
    public AuthenticationEvent apply(Credentials credentials) {// authentication logic
        Email email = credentials.email();

        Optional<User> optionalUser = userRepository.findBy(email);
        if (optionalUser.isEmpty()) {
            return new UserNotFoundEvent(email);
        }

        PasswordHash passwordHash = optionalUser.get().passwordHash();
        PlainTextPassword enteredPassword = credentials.plainTextPassword();
        if (!hashAlgorithmPort.verify(passwordHash, enteredPassword)) {
            return new WrongPasswordEvent(email);
        }

        return new AuthenticationPassedEvent(email);
    }
}
