package com.jrobertgardzinski.security.domain.vo.security.domain.event.registration;

public sealed interface RegistrationEvent permits RegistrationFailedEvent, RegistrationPassedEvent {}
