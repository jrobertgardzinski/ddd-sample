package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;

// todo give up on suppliers and throw an exception in the compact constructor. Use factory method instead
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

    @Override
    public String toString() {
        return "User{" +
                "email=" + emailSupplier.get() +
                '}';
    }
}
