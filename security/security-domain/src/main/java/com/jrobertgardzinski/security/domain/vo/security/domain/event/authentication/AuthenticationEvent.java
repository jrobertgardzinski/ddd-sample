package com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication;

public sealed interface AuthenticationEvent permits AuthenticationFailedEvent, AuthenticationFailedForTheNthTimeEvent, AuthenticationFailedOnActiveBlockadeEvent, AuthenticationPassedEvent, WrongEmail, WrongPassword {
}
