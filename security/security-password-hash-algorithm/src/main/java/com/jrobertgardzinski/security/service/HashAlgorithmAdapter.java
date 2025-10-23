package com.jrobertgardzinski.security.service;

import com.jrobertgardzinski.security.domain.service.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.Salt;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;

public class HashAlgorithmAdapter implements HashAlgorithmPort {
    @Override
    public PasswordHash hash(PlainTextPassword plainTextPassword, Salt salt) {
        int iterations = 2;
        int memLimit = 66536;
        int hashLength = 32;
        int parallelism = 1;

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(iterations)
                .withMemoryAsKB(memLimit)
                .withParallelism(parallelism)
                .withSalt(salt.value());

        Argon2BytesGenerator generate = new Argon2BytesGenerator();
        generate.init(builder.build());
        byte[] result = new byte[hashLength];
        String password = plainTextPassword.value();
        int hash = generate.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);

        return new PasswordHash(hash);
    }
}
