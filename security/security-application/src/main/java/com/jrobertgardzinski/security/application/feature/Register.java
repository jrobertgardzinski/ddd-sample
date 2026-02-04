package com.jrobertgardzinski.security.application.feature;

import com.jrobertgardzinski.security.domain.vo.*;
import com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.registration.PossibleRaceCondition;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;

import java.util.function.Function;

public class Register implements Function<UserRegistration, RegistrationEvent> {
    private final UserRepository userRepository;
    private final HashAlgorithmPort hashAlgorithmPort;

    public Register(UserRepository userRepository, HashAlgorithmPort hashAlgorithmPort) {
        this.userRepository = userRepository;
        this.hashAlgorithmPort = hashAlgorithmPort;
    }

    @Override
    public RegistrationEvent apply(UserRegistration userRegistration) {
        Email email = userRegistration.email();
        if (userRepository.existsBy(email)) {
            return new UserAlreadyExistsEvent();
        }
        try {
            PlaintextPassword plaintextPassword = userRegistration.plaintextPassword();
            Salt salt = Salt.generate();
            PasswordHash passwordHash = hashAlgorithmPort.hash(plaintextPassword, salt);
            User user = new User(
                    userRegistration.email(),
                    passwordHash
            );
            userRepository.save(user);
            return new RegistrationPassedEvent(email);
        } catch (Exception e) {
            return new PossibleRaceCondition();
        }
    }
}
