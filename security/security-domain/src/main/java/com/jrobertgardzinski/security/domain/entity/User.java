package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;
import com.jrobertgardzinski.security.port.entity.UserEntity;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;

// todo test for incorrect email and passwordSupplier
public record User (
        Supplier<Email> emailSupplier,
        Supplier<Password> passwordSupplier
) {
    public User {
        List<String> errors = new LinkedList<>();

        try {
            emailSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("email: " + e.getMessage());
        }
        try {
            passwordSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("passwordSupplier: " + e.getMessage());
        }

        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(errors.toString());
        }
    }
}
