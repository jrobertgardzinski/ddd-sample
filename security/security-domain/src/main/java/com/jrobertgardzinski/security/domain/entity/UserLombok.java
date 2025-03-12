package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;
import lombok.Getter;
import lombok.RequiredArgsConstructor;


@RequiredArgsConstructor
public class UserLombok {
    @Getter
    private final Email email;

    // write-only
    private final Password password;

    public boolean enteredRight(Password password) {
        return this.password.equals(password);
    }
}
