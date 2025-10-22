package com.jrobertgardzinski.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.vo.UserRegistration;

public record RegistrationPassedEvent(UserRegistration userRegistration) implements RegistrationEvent {
}
