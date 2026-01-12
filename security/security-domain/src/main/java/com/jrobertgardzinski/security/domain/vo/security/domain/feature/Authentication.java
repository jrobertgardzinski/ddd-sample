package com.jrobertgardzinski.security.domain.vo.security.domain.feature;

import com.jrobertgardzinski.security.domain.vo.AuthenticationRequest;
import com.jrobertgardzinski.security.domain.vo.Credentials;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication.AuthenticationEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication.WrongEmail;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication.WrongPassword;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.UserRepository;

import java.util.Optional;
import java.util.function.Function;

public class Authentication implements Function<Credentials, AuthenticationEvent> {
    private final UserRepository userRepository;
    private final HashAlgorithmPort hashAlgorithmPort;

    public Authentication(UserRepository userRepository, HashAlgorithmPort hashAlgorithmPort) {
        this.userRepository = userRepository;
        this.hashAlgorithmPort = hashAlgorithmPort;
    }

    @Override
    public AuthenticationEvent apply(Credentials credentials) {// authentication logic
        PlainTextPassword enteredPassword = credentials.plainTextPassword();
        Email email = credentials.email();

        Optional<User> optionalUser = userRepository.findBy(email);
        if (optionalUser.isEmpty()) {
            return new WrongEmail();
        }
        User user = optionalUser.get();
        if (!hashAlgorithmPort.verify(user.passwordHash(), enteredPassword)) {
            return new WrongPassword();
        }

        return new AuthenticationPassedEvent(email);
    }
}
