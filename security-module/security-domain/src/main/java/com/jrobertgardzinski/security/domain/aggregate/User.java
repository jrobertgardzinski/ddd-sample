package com.jrobertgardzinski.security.domain.aggregate;

import com.jrobertgardzinski.security.domain.vo.Id;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;
import jakarta.validation.*;

import java.util.*;

public record User(
        Id id,
        Email email,
        Password password
) {
    public User {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            Map<String, String> validationErrorMessages = new HashMap<>();

            String idViolations = validator.validate(id).stream().map(ConstraintViolation::getMessage).toList().toString();
            if (!idViolations.equals("[]")) {
                validationErrorMessages.put(id.toString(), idViolations);
            }

            String emailViolations = validator.validate(id).stream().map(ConstraintViolation::getMessage).toList().toString();
            if (!emailViolations.equals("[]")) {
                validationErrorMessages.put(email.toString(), emailViolations);
            }

            String passwordViolations = validator.validate(id).stream().map(ConstraintViolation::getMessage).toList().toString();
            if (!passwordViolations.equals("[]")) {
                validationErrorMessages.put(password.toString(), passwordViolations);
            }

            if (!validationErrorMessages.isEmpty()) {
                throw new ValidationException(validationErrorMessages.toString());
            }
        }
    }
}