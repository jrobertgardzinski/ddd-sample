package com.jrobertgardzinski.security.domain.event.registration;


import com.jrobertgardzinski.security.domain.entity.UserLombok;

public record RegistrationPassedEvent(UserLombok userLombok) implements RegistrationEvent {
}
