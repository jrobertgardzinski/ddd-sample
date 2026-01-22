package com.jrobertgardzinski.security.application.feature.register.context;

import com.jrobertgardzinski.security.application.feature.Register;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubHashAlgorithm;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubUserRepository;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;

public class RegisterUseCase {
    private final Register register;

    public RegisterUseCase(
            StubUserRepository stubUserRepository,
            StubHashAlgorithm stubHashAlgorithm) {

        this.register = new Register(
                stubUserRepository,
                stubHashAlgorithm
        );
    }

    public RegistrationEvent apply(UserRegistration userRegistration) {
        return register.apply(userRegistration);
    }
}
