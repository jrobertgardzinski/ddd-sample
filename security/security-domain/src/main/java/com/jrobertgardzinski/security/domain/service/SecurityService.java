package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.UserDetails;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.repository.exception.UserAlreadyExistsException;

public class SecurityService {
    private final UserRepository userRepository;

    public SecurityService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public RegistrationEvent registerUser(UserDetails userDetails) {
        try {
            var user = userRepository.createUser(userDetails);
            return new RegistrationPassedEvent(user);
        } catch (UserAlreadyExistsException e) {
            return new UserAlreadyExistsEvent();
        }
    }
}
