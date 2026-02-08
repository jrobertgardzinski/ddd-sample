package com.jrobertgardzinski.security.application.factory;

import com.jrobertgardzinski.password.policy.domain.PasswordPolicyPort;
import com.jrobertgardzinski.security.domain.vo.*;
import io.vavr.control.Try;

import java.util.List;

public class RegisterFactory {

    private final PasswordPolicyPort passwordPolicy;

    public RegisterFactory(PasswordPolicyPort passwordPolicy) {
        this.passwordPolicy = passwordPolicy;
    }

    public UserRegistration create(String email, String password) throws UserRegistrationValidationException {
        Try<Email> emailTry = Try.of(() -> new Email(email));
        Try<PlaintextPassword> passwordTry = Try.of(() -> new PlaintextPassword(password));

        List<String> emailErrors = emailTry.isFailure()
                ? List.of(emailTry.getCause().getMessage())
                : List.of();

        List<String> passwordErrors = passwordTry.isFailure()
                ? List.of(passwordTry.getCause().getMessage())
                : passwordPolicy.validate(passwordTry.get());

        if (!emailErrors.isEmpty() || !passwordErrors.isEmpty()) {
            throw new UserRegistrationValidationException(emailErrors, passwordErrors);
        }

        return new UserRegistration(emailTry.get(), passwordTry.get());
    }
}
