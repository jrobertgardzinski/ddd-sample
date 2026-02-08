package com.jrobertgardzinski.security.application.factory;

import java.util.List;

public class UserRegistrationValidationException extends Exception {

    private final List<String> emailErrors;
    private final List<String> passwordErrors;

    public UserRegistrationValidationException(List<String> emailErrors, List<String> passwordErrors) {
        super(buildMessage(emailErrors, passwordErrors));
        this.emailErrors = List.copyOf(emailErrors);
        this.passwordErrors = List.copyOf(passwordErrors);
    }

    public List<String> emailErrors() {
        return emailErrors;
    }

    public List<String> passwordErrors() {
        return passwordErrors;
    }

    public boolean hasEmailErrors() {
        return !emailErrors.isEmpty();
    }

    public boolean hasPasswordErrors() {
        return !passwordErrors.isEmpty();
    }

    private static String buildMessage(List<String> emailErrors, List<String> passwordErrors) {
        StringBuilder sb = new StringBuilder("Validation failed:");
        if (!emailErrors.isEmpty()) {
            sb.append(" email=").append(emailErrors);
        }
        if (!passwordErrors.isEmpty()) {
            sb.append(" password=").append(passwordErrors);
        }
        return sb.toString();
    }
}
