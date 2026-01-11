package com.jrobertgardzinski.security.domain.vo.security.domain.feature;

import com.jrobertgardzinski.security.domain.vo.AuthenticationRequest;
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

public class Authentication implements Function<AuthenticationRequest, AuthenticationEvent> {
    private final UserRepository userRepository;
    private final HashAlgorithmPort hashAlgorithmPort;

    public Authentication(UserRepository userRepository, FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository, HashAlgorithmPort hashAlgorithmPort) {
        this.userRepository = userRepository;
        this.hashAlgorithmPort = hashAlgorithmPort;
    }

    @Override
    public AuthenticationEvent apply(/*todo switch to Credentials*/AuthenticationRequest authenticationRequest) {// authentication logic
        PlainTextPassword enteredPassword = authenticationRequest.plainTextPassword();
        Email email = authenticationRequest.email();

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
