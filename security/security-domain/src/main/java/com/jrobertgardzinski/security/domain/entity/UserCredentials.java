package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;

public record UserCredentials(
        Email email,
        Password password) {

    public boolean enteredRight(Password password) {
        return this.password.equals(password);
    }
}
