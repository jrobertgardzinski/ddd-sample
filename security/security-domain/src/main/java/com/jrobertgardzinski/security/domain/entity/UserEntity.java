package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.User;
import lombok.Getter;

import java.util.Objects;

public class UserEntity {
    @Getter
    private final String email;
    @Getter
    private final String password;

    public UserEntity(User user) {
        this.email = user.email().value();
        this.password = user.password().value();
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        UserEntity that = (UserEntity) o;
        return Objects.equals(email, that.email) && Objects.equals(password, that.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(email, password);
    }

    @Override
    public String toString() {
        return "UserEntity{" +
                "email='" + email + '\'' +
                ", password='" + password + '\'' +
                '}';
    }
}
