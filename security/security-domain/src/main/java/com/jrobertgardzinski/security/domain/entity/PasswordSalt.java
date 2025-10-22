package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Salt;

public record PasswordSalt(
        Email email,
        Salt salt
) {
}
