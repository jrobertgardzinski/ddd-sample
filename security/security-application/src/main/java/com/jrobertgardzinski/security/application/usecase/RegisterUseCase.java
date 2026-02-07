package com.jrobertgardzinski.security.application.usecase;

import com.jrobertgardzinski.security.application.factory.RegisterFactory;
import com.jrobertgardzinski.security.application.factory.UserRegistrationValidationException;
import com.jrobertgardzinski.security.system.feature.Register;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;

public class RegisterUseCase {
    private final Register register;
    private final RegisterFactory registerFactory;

    public RegisterUseCase(Register register, RegisterFactory registerFactory) {
        this.register = register;
        this.registerFactory = registerFactory;
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
