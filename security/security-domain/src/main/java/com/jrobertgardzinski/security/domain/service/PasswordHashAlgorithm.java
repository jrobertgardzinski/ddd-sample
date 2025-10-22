package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.PasswordSalt;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.PasswordSaltRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.PasswordHash;

public class PasswordHashAlgorithm {
    private final PasswordSaltRepository passwordSaltRepository;
    private final HashAlgorithmPort hashAlgorithmPort;

    public PasswordHashAlgorithm(PasswordSaltRepository passwordSaltRepository, HashAlgorithmPort hashAlgorithmPort) {
        this.passwordSaltRepository = passwordSaltRepository;
        this.hashAlgorithmPort = hashAlgorithmPort;
    }

    public PasswordHash hash(Email email, PlainTextPassword plainTextPassword) {
        PasswordSalt passwordSalt = passwordSaltRepository.findByEmail(email);
        return hashAlgorithmPort.hash(plainTextPassword, passwordSalt.salt());
    }

    public boolean verify(User user, PlainTextPassword plainTextPassword) {
        PasswordHash passwordHash = hash(user.email(), plainTextPassword);
        return user.passwordHash().equals(passwordHash);
    }
}
