package com.jrobertgardzinski.security.domain.factory;

import com.jrobertgardzinski.security.domain.vo.*;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;

public class SecurityFactory {

    public UserRegistration createUserRegistration(
            String email,
            String PlainTextPassword) {

        List<String> errors = new LinkedList<>();

        Supplier<Email> emailSupplier = () -> new Email(email);
        try {
            emailSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("email: " + e.getMessage());
        }

        Supplier<PlainTextPassword> PlainTextPasswordSupplier = () -> new PlainTextPassword(PlainTextPassword);
        try {
            PlainTextPasswordSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("PlainTextPassword: " + e.getMessage());
        }

        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(errors.toString());
        }
        else {
            return new UserRegistration(emailSupplier.get(), PlainTextPasswordSupplier.get());
        }
    }

    public AuthenticationRequest createAuthenticationRequest(String ipAddress, String email, String PlainTextPassword) {

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

        Supplier<PlainTextPassword> PlainTextPasswordSupplier = () -> new PlainTextPassword(PlainTextPassword);
        try {
            PlainTextPasswordSupplier.get();
        }
        catch (RuntimeException e) {
            errors.add("PlainTextPassword: " + e.getMessage());
        }

        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(errors.toString());
        }
        else {
            return new AuthenticationRequest(
                    ipAddressSupplier.get(),
                    emailSupplier.get(),
                    PlainTextPasswordSupplier.get()
            );
        }
    }

    public SessionRefreshRequest createTokenRefreshRequest(String email, String refreshToken) {

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
            return new SessionRefreshRequest(
                    emailSupplier.get(),
                    refreshTokenSupplier.get()
            );
        }
    }
}
