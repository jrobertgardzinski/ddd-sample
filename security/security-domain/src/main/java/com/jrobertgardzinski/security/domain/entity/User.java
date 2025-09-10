package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;

// todo give up on suppliers and throw an exception in the compact constructor. Use factory method instead
public record User (
        Email email,
        Password password
) {
}
