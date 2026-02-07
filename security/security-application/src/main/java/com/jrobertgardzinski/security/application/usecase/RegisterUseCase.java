package com.jrobertgardzinski.security.application.usecase;

import com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.password.policy.domain.StrongPasswordPolicyAdapter;
import com.jrobertgardzinski.security.application.factory.RegisterFactory;
import com.jrobertgardzinski.security.application.factory.UserRegistrationValidationException;
import com.jrobertgardzinski.security.application.feature.Register;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;

public class RegisterUseCase {
    private final Register register;
    private final RegisterFactory registerFactory;

    public RegisterUseCase(
            UserRepository userRepository,
            HashAlgorithmPort hashAlgorithm) {

        this.register = new Register(
                userRepository,
                hashAlgorithm
        );
        this.registerFactory = new RegisterFactory(new StrongPasswordPolicyAdapter());
    }

    public RegisterResult execute(String email, String password) {
        try {
            UserRegistration userRegistration = registerFactory.create(email, password);
            return new RegisterResult.Valid(register.apply(userRegistration));
        } catch (UserRegistrationValidationException e) {
            return new RegisterResult.Invalid(e);
        }
    }
}
