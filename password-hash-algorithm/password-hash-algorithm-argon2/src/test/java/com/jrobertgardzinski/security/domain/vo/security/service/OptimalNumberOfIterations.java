package com.jrobertgardzinski.security.domain.vo.security.service;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Helper;
import org.junit.jupiter.api.Test;

import static com.jrobertgardzinski.security.domain.vo.security.service.HashAlgorithmAdapter.MEM_LIMIT;
import static com.jrobertgardzinski.security.domain.vo.security.service.HashAlgorithmAdapter.PARALLELISM;

public class OptimalNumberOfIterations {
    // https://github.com/phxql/argon2-jvm?tab=readme-ov-file#recommended-parameters
    @Test
    void run() {
        long REQUIRED_CALCULATION_TIME = 1000;

        Argon2 argon2 = Argon2Factory.create();
        int iterations = Argon2Helper.findIterations(argon2, REQUIRED_CALCULATION_TIME, MEM_LIMIT, PARALLELISM);

        System.out.println("Set ITERATIONS for HashAlgorithmAdapter equal to: " + iterations);
    }
}
