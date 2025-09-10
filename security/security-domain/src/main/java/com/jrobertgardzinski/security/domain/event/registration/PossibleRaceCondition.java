package com.jrobertgardzinski.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.entity.User;

import java.util.function.Function;

public record PossibleRaceCondition() implements RegistrationFailureEvent {
    @Override
    public Function<User, RuntimeException> exceptionSupplier() {
        return user -> new IllegalStateException(
                String.format("Race condition met registering a %s", user));
    }
}
