package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.PasswordSalt;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.PasswordHash;

public class PasswordHashAlgorithm {
    private final HashAlgorithmPort hashAlgorithmPort;

    public PasswordHashAlgorithm(HashAlgorithmPort hashAlgorithmPort) {
        this.hashAlgorithmPort = hashAlgorithmPort;
    }

    public PasswordHash hash(PlainTextPassword plainTextPassword, PasswordSalt passwordSalt) {
        return hashAlgorithmPort.hash(plainTextPassword, passwordSalt.salt());
    }

    public boolean verify(PlainTextPassword plainTextPassword, PasswordSalt passwordSalt, User user) {
        PasswordHash passwordHash = hash(plainTextPassword, passwordSalt);
        return user.passwordHash().equals(passwordHash);
    }
}
