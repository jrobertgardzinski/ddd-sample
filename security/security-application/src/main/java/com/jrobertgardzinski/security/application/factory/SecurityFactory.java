package com.jrobertgardzinski.security.application.factory;

import com.jrobertgardzinski.password.policy.domain.PasswordPolicyPort;
import com.jrobertgardzinski.security.domain.vo.*;
import io.vavr.control.Try;

import java.util.ArrayList;
import java.util.List;

public class SecurityFactory {

    private final PasswordPolicyPort passwordPolicy;

    public SecurityFactory(PasswordPolicyPort passwordPolicy) {
        this.passwordPolicy = passwordPolicy;
    }

    public UserRegistration createUserRegistration(String email, String password) throws UserRegistrationValidationException {
        Try<Email> emailTry = Try.of(() -> new Email(email));
        Try<PlainTextPassword> passwordTry = Try.of(() -> new PlainTextPassword(password));

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

    public AuthenticationRequest createAuthenticationRequest(String ipAddress, String email, String password) {
        Try<IpAddress> ipTry = Try.of(() -> new IpAddress(ipAddress));
        Try<Email> emailTry = Try.of(() -> new Email(email));
        Try<PlainTextPassword> passwordTry = Try.of(() -> new PlainTextPassword(password));

        List<String> errors = new ArrayList<>();
        if (ipTry.isFailure()) errors.add("ipAddress: " + ipTry.getCause().getMessage());
        if (emailTry.isFailure()) errors.add("email: " + emailTry.getCause().getMessage());
        if (passwordTry.isFailure()) errors.add("password: " + passwordTry.getCause().getMessage());

        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(errors.toString());
        }

        return new AuthenticationRequest(ipTry.get(), emailTry.get(), passwordTry.get());
    }

    public SessionRefreshRequest createTokenRefreshRequest(String email, String refreshToken) {
        Try<Email> emailTry = Try.of(() -> new Email(email));
        Try<RefreshToken> tokenTry = Try.of(() -> new RefreshToken(new Token(refreshToken)));

        List<String> errors = new ArrayList<>();
        if (emailTry.isFailure()) errors.add("email: " + emailTry.getCause().getMessage());
        if (tokenTry.isFailure()) errors.add("refreshToken: " + tokenTry.getCause().getMessage());

        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(errors.toString());
        }

        return new SessionRefreshRequest(emailTry.get(), tokenTry.get());
    }
}
