package com.jrobertgardzinski.security.application.feature.register;

import com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.application.feature.Register;
import com.jrobertgardzinski.security.application.stub.StubHashAlgorithm;
import com.jrobertgardzinski.security.application.stub.StubUserRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;

import java.util.HashSet;

public class RegisterTestContext {

    private String email;
    private String password;

    private final UserRepository userRepository;
    private final HashAlgorithmPort hashAlgorithm;

    private final Register register;

    public RegisterTestContext() {
        email = null;
        password = null;
        userRepository = new StubUserRepository(new HashSet<>());
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
