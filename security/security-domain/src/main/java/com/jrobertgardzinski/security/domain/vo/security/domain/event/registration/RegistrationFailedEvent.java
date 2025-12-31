package com.jrobertgardzinski.security.domain.vo.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.vo.Email;

public sealed interface RegistrationFailedEvent extends RegistrationEvent permits PossibleRaceCondition, UserAlreadyExistsEvent {
    String error(Email email);
}
