package com.jrobertgardzinski.security.domain.factory;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.*;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;

public class SecurityFactory {

    public User createUser(
            String email,
            String passwordHash) {

        List<String> errors = new LinkedList<>();

        Supplier<Email> emailSupplier = () -> new Email(email);
        try {
            emailSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("email: " + e.getMessage());
        }

        Supplier<PasswordHash> passwordHashSupplier = () -> new PasswordHash(passwordHash);
        try {
            passwordHashSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("passwordHash: " + e.getMessage());
        }

        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(errors.toString());
        }
        else {
            return new User(emailSupplier.get(), passwordHashSupplier.get());
        }
    }

    public AuthenticationRequest createAuthenticationRequest(String ipAddress, String email, String password) {

        List<String> errors = new LinkedList<>();

        Supplier<IpAddress> ipAddressSupplier = () -> new IpAddress(ipAddress);
        try {
            ipAddressSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("ipAddress: " + e.getMessage());
        }

        Supplier<Email> emailSupplier = () -> new Email(email);
        try {
            emailSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("email: " + e.getMessage());
        }

        Supplier<PlainTextPassword> passwordSupplier = () -> new PlainTextPassword(password);
        try {
            passwordSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("passwordHash: " + e.getMessage());
        }

        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(errors.toString());
        }
        else {
            return new AuthenticationRequest(
                    ipAddressSupplier.get(),
                    emailSupplier.get(),
                    passwordSupplier.get()
            );
        }
    }

    public TokenRefreshRequest createTokenRefreshRequest(String email, String refreshToken) {

        List<String> errors = new LinkedList<>();

        Supplier<Email> emailSupplier = () -> new Email(email);
        try {
            emailSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("email: " + e.getMessage());
        }

        Supplier<RefreshToken> refreshTokenSupplier = () -> new RefreshToken(new Token(refreshToken));
        try {
            refreshTokenSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("refreshToken: " + e.getMessage());
        }

        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(errors.toString());
        }
        else {
            return new TokenRefreshRequest(
                    emailSupplier.get(),
                    refreshTokenSupplier.get()
            );
        }
    }
}
