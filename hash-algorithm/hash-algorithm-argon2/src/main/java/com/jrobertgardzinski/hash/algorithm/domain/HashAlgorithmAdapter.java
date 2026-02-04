package com.jrobertgardzinski.hash.algorithm.domain;

import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;
import com.jrobertgardzinski.security.domain.vo.Salt;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

public class HashAlgorithmAdapter implements HashAlgorithmPort {
    static final int ITERATIONS = 20;
    static final int MEM_LIMIT = 66536;
    static final int PARALLELISM = 1;
    static final Argon2 argon2 = Argon2Factory.create();

    @Override
    public PasswordHash hash(PlaintextPassword plaintextPassword, Salt salt) {
        String hash = argon2.hash(ITERATIONS, MEM_LIMIT, PARALLELISM, plaintextPassword.value().getBytes());
        return new PasswordHash(hash);
    }

    @Override
    public boolean verify(PasswordHash passwordHash, PlaintextPassword plaintextPassword) {
        return argon2.verify(
                passwordHash.value(),
                plaintextPassword.value().getBytes()
        );
    }
}
