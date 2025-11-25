package com.jrobertgardzinski.security.service;

import com.jrobertgardzinski.security.domain.service.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.Salt;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;

public class HashAlgorithmAdapter implements HashAlgorithmPort {
    private static final int ITERATIONS = 2;
    private static final int MEM_LIMIT = 66536;
    private static final int HASH_LENGTH = 32;
    private static final int PARALLELISM = 1;
    @Override
    public PasswordHash hash(PlainTextPassword plainTextPassword, Salt salt) {

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEM_LIMIT)
                .withParallelism(PARALLELISM)
                .withSalt(salt.value());

        Argon2BytesGenerator generate = new Argon2BytesGenerator();
        generate.init(builder.build());
        byte[] result = new byte[HASH_LENGTH];
        String password = plainTextPassword.value();
        generate.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);

        return new PasswordHash(result);
    }
}
