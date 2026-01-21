package com.jrobertgardzinski.security.application.stub;

import com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.Salt;

public class StubHashAlgorithm implements HashAlgorithmPort {
    @Override
    public PasswordHash hash(PlainTextPassword plainTextPassword, Salt salt) {
        return new PasswordHash(
                salt.value() + plainTextPassword.value()
        );
    }

    @Override
    public boolean verify(PasswordHash passwordHash, PlainTextPassword plainTextPassword) {
        return passwordHash.value().endsWith(plainTextPassword.value());
    }
}
