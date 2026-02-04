package com.jrobertgardzinski.security.application.feature.register.context.dependency;

import com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;
import com.jrobertgardzinski.security.domain.vo.Salt;

public class StubHashAlgorithm implements HashAlgorithmPort {
    @Override
    public PasswordHash hash(PlaintextPassword plaintextPassword, Salt salt) {
        return new PasswordHash(
                salt.value() + plaintextPassword.value()
        );
    }

    @Override
    public boolean verify(PasswordHash passwordHash, PlaintextPassword plaintextPassword) {
        return passwordHash.value().endsWith(plaintextPassword.value());
    }
}
