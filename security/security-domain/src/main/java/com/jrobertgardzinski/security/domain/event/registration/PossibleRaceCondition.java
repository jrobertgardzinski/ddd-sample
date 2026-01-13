package com.jrobertgardzinski.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.vo.Email;

public record PossibleRaceCondition() implements RegistrationFailedEvent {
    @Override
    public String error(Email email) {
        return String.format("Race condition met registering a user with the e-mail: %s", email.value());
    }
}
