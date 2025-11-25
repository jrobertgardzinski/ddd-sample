package com.jrobertgardzinski.security.domain.event.registration;

import com.jrobertgardzinski.security.domain.vo.Email;

public record RegistrationPassedEvent(Email email) implements RegistrationEvent {
}
