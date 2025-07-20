package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;
import lombok.Getter;
import lombok.RequiredArgsConstructor;


@RequiredArgsConstructor
public class User {
    @Getter
    private final Email email;

    @Getter
    private final Password password;
}
