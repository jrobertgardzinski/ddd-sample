package com.jrobertgardzinski.security.domain.event.authentication;

import com.jrobertgardzinski.security.domain.vo.Email;

// todo this has to wait for some time. It has to be combined
public record UserNotFoundEvent(Email email) /*implements AuthenticationEvent*/ {
}
