package com.jrobertgardzinski.security.application.feature.register.context;

import com.jrobertgardzinski.security.application.factory.SecurityFactory;
import com.jrobertgardzinski.security.application.factory.UserRegistrationValidationException;
import com.jrobertgardzinski.security.application.feature.Register;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubHashAlgorithm;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubUserRepository;
import com.jrobertgardzinski.password.policy.domain.StrongPasswordPolicyAdapter;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;

public class RegisterUseCase {
    private final Register register;
    private final SecurityFactory securityFactory;

    public RegisterUseCase(
            StubUserRepository stubUserRepository,
            StubHashAlgorithm stubHashAlgorithm) {

        this.register = new Register(
                stubUserRepository,
                stubHashAlgorithm
        );
        this.securityFactory = new SecurityFactory(new StrongPasswordPolicyAdapter());
    }

    public RegisterResult execute(String email, String password) {
        try {
            UserRegistration userRegistration = securityFactory.createUserRegistration(email, password);
            return new RegisterResult.Valid(register.apply(userRegistration));
        } catch (UserRegistrationValidationException e) {
            return new RegisterResult.Invalid(e);
        }
    }
}
