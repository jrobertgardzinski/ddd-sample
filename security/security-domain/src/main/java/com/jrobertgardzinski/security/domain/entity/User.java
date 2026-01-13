package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PasswordHash;

public record User (
        Email email,
        PasswordHash passwordHash
) {
}
