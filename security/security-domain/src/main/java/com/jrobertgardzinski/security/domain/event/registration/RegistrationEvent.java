package com.jrobertgardzinski.security.domain.event.registration;

public sealed interface RegistrationEvent permits RegistrationPassedEvent, UserAlreadyExistsEvent {}
