package com.jrobertgardzinski.security.domain.event.registration;


import com.jrobertgardzinski.security.domain.entity.UserEntity;

public record RegistrationPassedEvent(UserEntity userEntity) implements RegistrationEvent {
}
