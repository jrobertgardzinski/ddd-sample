package com.jrobertgardzinski.security.domain.event.authentication;

import com.jrobertgardzinski.security.domain.vo.Email;

// todo bring it back whenever you are ready to introduce security notifications
public record AuthenticationFailedEvent(Email email) implements AuthenticationEvent /*permits UserNotFoundEvent, WrongPasswordEvent*/ {
}
