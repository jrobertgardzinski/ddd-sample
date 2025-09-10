package com.jrobertgardzinski.security.domain.factory;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;

public class SecurityFactory {
    public User createUser(
            String email,
            String password) {

        List<String> errors = new LinkedList<>();

        Supplier<Email> emailSupplier = () -> new Email(email);
        try {
            emailSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("email: " + e.getMessage());
        }

        Supplier<Password> passwordSupplier = () -> new Password(password);
        try {
            passwordSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("password: " + e.getMessage());
        }

        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(errors.toString());
        }
        else {
            return new User(emailSupplier.get(), passwordSupplier.get());
        }
    }
}
