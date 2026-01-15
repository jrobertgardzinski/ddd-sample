package com.jrobertgardzinski.hash.algorithm.domain;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Helper;

import static com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmAdapter.MEM_LIMIT;
import static com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmAdapter.PARALLELISM;

public class OptimalNumberOfIterations {
    // https://github.com/phxql/argon2-jvm?tab=readme-ov-file#recommended-parameters
    public static void main(String[] args) {
        long REQUIRED_CALCULATION_TIME = 1000;

        Argon2 argon2 = Argon2Factory.create();
        int iterations = Argon2Helper.findIterations(argon2, REQUIRED_CALCULATION_TIME, MEM_LIMIT, PARALLELISM);

        System.out.println("Set ITERATIONS for HashAlgorithmAdapter equal to: " + iterations);
    }
}
