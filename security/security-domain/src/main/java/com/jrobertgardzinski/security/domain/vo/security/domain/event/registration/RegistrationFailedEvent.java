package com.jrobertgardzinski.security.domain.vo.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.vo.Email;

import java.util.function.Function;

public sealed interface RegistrationFailedEvent extends RegistrationEvent permits PossibleRaceCondition, UserAlreadyExistsEvent {
    // todo switch from exception supplier to simple string message
    Function<Email, RuntimeException> exceptionSupplier();
}
