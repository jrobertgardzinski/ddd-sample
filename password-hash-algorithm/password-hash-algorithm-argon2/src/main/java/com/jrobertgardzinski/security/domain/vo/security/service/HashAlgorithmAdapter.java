package com.jrobertgardzinski.security.domain.vo.security.service;

import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.Salt;
import com.jrobertgardzinski.security.domain.vo.hash.algorithm.domain.HashAlgorithmPort;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

// todo adjust parameters according to https://github.com/phxql/argon2-jvm?tab=readme-ov-file#recommended-parameters
public class HashAlgorithmAdapter implements HashAlgorithmPort {
    private static final int ITERATIONS = 2;
    private static final int MEM_LIMIT = 66536;
    private static final int PARALLELISM = 1;
    private static final Argon2 argon2 = Argon2Factory.create();

    @Override
    public PasswordHash hash(PlainTextPassword plainTextPassword, Salt salt) {
        String hash = argon2.hash(ITERATIONS, MEM_LIMIT, PARALLELISM, plainTextPassword.value().getBytes());
        return new PasswordHash(hash);
    }

    @Override
    public boolean verify(PasswordHash passwordHash, PlainTextPassword plainTextPassword) {
        return argon2.verify(
                passwordHash.value(),
                plainTextPassword.value().getBytes()
        );
    }
}
