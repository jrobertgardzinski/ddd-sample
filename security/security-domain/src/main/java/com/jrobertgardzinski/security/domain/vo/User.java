package com.jrobertgardzinski.security.domain.vo;

import com.jrobertgardzinski.security.domain.entity.UserEntity;

public record User (
        Email email,
        Password password
) {
    public User(Email email, Password password) {
        this.email = email;
        this.password = password;
    }

    public User(UserEntity userEntity) {
        this(
                new Email(userEntity.getEmail()),
                new Password(userEntity.getPassword())
        );
    }
}
