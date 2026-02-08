package com.jrobertgardzinski.security.application.usecase;

import com.jrobertgardzinski.security.application.factory.UserRegistrationValidationException;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;

public sealed interface RegisterResult {

    record Valid(RegistrationEvent event) implements RegisterResult {}

    record Invalid(UserRegistrationValidationException exception) implements RegisterResult {}
}
