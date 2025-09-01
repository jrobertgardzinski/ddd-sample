package com.jrobertgardzinski.security.domain.event.registration;


import com.jrobertgardzinski.security.port.entity.UserEntity;

public record RegistrationPassedEvent(UserEntity userEntity) implements RegistrationEvent {
}
