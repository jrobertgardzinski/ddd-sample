package com.jrobertgardzinski.security.application.service;

import com.jrobertgardzinski.security.application.usecase.register.RegisterResult;
import com.jrobertgardzinski.security.application.usecase.register.RegisterUseCase;

public class SecurityService {
    private final RegisterUseCase registerUseCase;

    public SecurityService(RegisterUseCase registerUseCase) {
        this.registerUseCase = registerUseCase;
    }

    public RegisterResult register(String email, String password) {
        return registerUseCase.execute(email, password);
    }
}
