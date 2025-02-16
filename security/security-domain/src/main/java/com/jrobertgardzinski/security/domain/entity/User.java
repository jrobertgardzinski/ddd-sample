package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Password;
import com.jrobertgardzinski.security.domain.vo.UserDetails;
import com.jrobertgardzinski.security.domain.vo.UserId;

public record User(
        UserId id,
        UserDetails details) {

    public boolean enteredRight(Password password) {
        return details.password().equals(password);
    }
}
