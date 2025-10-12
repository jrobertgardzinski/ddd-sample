package com.jrobertgardzinski.security.entity;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Serdeable
@Entity
public class UserEntity {
    @Id
    private String email;
    private String password;

    public UserEntity() {
    }

    public UserEntity(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public static UserEntity fromDomain(User user) {
        return new UserEntity(user.email().value(), user.password().value());
    }

    public User asDomain() {
        return new User(new Email(email), new Password(password));
    }

    public String getEmail() {
        return email;
    }
}
