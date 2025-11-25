package com.jrobertgardzinski.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;

import java.util.function.Function;

public record UserAlreadyExistsEvent() implements RegistrationFailedEvent {
    @Override
    public Function<Email, RuntimeException> exceptionSupplier() {
        return user -> new IllegalArgumentException(
                String.format("User with the e-mail: %s already exists!", user)
        );
    }
}
