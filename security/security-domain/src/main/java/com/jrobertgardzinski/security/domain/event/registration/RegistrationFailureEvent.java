package com.jrobertgardzinski.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.entity.User;

import java.util.function.Function;
import java.util.function.Supplier;

public sealed interface RegistrationFailureEvent extends RegistrationEvent permits PossibleRaceCondition, UserAlreadyExistsEvent {
    Function<User, RuntimeException> exceptionSupplier();
}
