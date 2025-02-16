package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.UserDetails;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;

public class SecurityService {
    private final UserRepository userRepository;

    public SecurityService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public RegistrationEvent registerUser(UserDetails userDetails) {
        var user = userRepository.createUser(userDetails);
        return user.isPresent() ?
            new RegistrationPassedEvent(user.get()) :
            new UserAlreadyExistsEvent();
    }


}
