package com.jrobertgardzinski.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.entity.UserDetails;

public record RegistrationPassedEvent(UserDetails userDetails) implements RegistrationEvent {
}
