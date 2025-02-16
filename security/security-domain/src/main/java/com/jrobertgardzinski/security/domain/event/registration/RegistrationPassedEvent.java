package com.jrobertgardzinski.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.entity.User;

public record RegistrationPassedEvent(User user) implements RegistrationEvent {
}
