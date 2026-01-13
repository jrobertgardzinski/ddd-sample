package com.jrobertgardzinski.security.domain.vo.security.entity;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Serdeable
@Entity
public class UserEntity {
    @Id
    private String email;
    private String passwordHash;

    public UserEntity() {
    }

    public UserEntity(String email, String passwordHash) {
        this.email = email;
        this.passwordHash = passwordHash;
    }

    public static UserEntity fromDomain(User user) {
        return new UserEntity(user.email().value(), user.passwordHash().value());
    }

    public User asDomain() {
        return new User(new Email(email), new PasswordHash(passwordHash));
    }

    public String getEmail() {
        return email;
    }
}
