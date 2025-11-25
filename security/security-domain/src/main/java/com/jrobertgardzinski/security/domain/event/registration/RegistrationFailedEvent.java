package com.jrobertgardzinski.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.vo.Email;

import java.util.function.Function;

public sealed interface RegistrationFailedEvent extends RegistrationEvent permits PossibleRaceCondition, UserAlreadyExistsEvent {
    Function<Email, RuntimeException> exceptionSupplier();
}
