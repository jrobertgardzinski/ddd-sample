package com.jrobertgardzinski.security.application.feature.register;

import com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.application.feature.Register;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubHashAlgorithm;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubUserRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;

import java.util.HashSet;

public class RegisterTestContext {
    // input
    private String email;
    private String password;

    // dependencies
    private final UserRepository userRepository;
    private final HashAlgorithmPort hashAlgorithm;

    // use case
    private final Register register;

    public RegisterTestContext() {
        email = null;
        password = null;
        userRepository = new StubUserRepository();
        hashAlgorithm = new StubHashAlgorithm();
        register = new Register(userRepository, hashAlgorithm);
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public UserRepository getUserRepository() {
        return userRepository;
    }

    public HashAlgorithmPort getHashAlgorithm() {
        return hashAlgorithm;
    }

    public Register getRegister() {
        return register;
    }
}
