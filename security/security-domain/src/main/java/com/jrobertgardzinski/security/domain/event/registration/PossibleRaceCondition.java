package com.jrobertgardzinski.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;

import java.util.function.Function;

public record PossibleRaceCondition() implements RegistrationFailedEvent {
    @Override
    public Function<Email, RuntimeException> exceptionSupplier() {
        return user -> new IllegalStateException(
                String.format("Race condition met registering a user with the e-mail: ", user));
    }
}
