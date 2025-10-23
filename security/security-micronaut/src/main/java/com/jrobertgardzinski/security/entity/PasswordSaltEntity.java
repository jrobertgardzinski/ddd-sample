package com.jrobertgardzinski.security.entity;

import com.jrobertgardzinski.security.domain.entity.PasswordSalt;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Salt;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Serdeable
@Entity
public class PasswordSaltEntity {
    @Id
    private String email;
    private byte[] salt;

    public PasswordSaltEntity() {
    }

    public PasswordSaltEntity(byte[] salt, String email) {
        this.salt = salt;
        this.email = email;
    }

    public static PasswordSaltEntity fromDomain(PasswordSalt passwordSalt) {
        return new PasswordSaltEntity(passwordSalt.salt().value(), passwordSalt.email().value());
    }

    public PasswordSalt asDomain() {
        return new PasswordSalt(new Email(email), new Salt(salt));
    }

    public String getEmail() {
        return email;
    }
}
