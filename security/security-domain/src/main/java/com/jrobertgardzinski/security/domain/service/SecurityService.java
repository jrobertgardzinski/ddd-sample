package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;

import java.util.Optional;

public class SecurityService {
    private final UserRepository userRepository;

    public SecurityService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public enum RegistrationEvent {PASSED, FAILED};
    public RegistrationEvent registerUser(User user) {
        Optional<User> result = userRepository.createUser(user);
        return result.isEmpty() ?
                RegistrationEvent.FAILED :
                RegistrationEvent.PASSED;
    }

    public enum AuthenticationEvent {PASSED, FAILED};
    public AuthenticationEvent authenticateWithPlainPassword(Email email, Password password) {
        Optional<User> user = userRepository.findUserByEmail(email);
        return user.isPresent() && user.get().password().equals(password) ?
                AuthenticationEvent.PASSED :
                AuthenticationEvent.FAILED;
    }
}
