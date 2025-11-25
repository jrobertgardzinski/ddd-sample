package com.jrobertgardzinski.security;

import com.jrobertgardzinski.security.aggregate.AuthorizedUserAggregateRootEntity;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationFailedEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.vo.*;
import com.jrobertgardzinski.security.entity.AuthorizationDataEntity;
import com.jrobertgardzinski.security.entity.UserEntity;
import com.jrobertgardzinski.security.factory.SecurityFactoryAdapter;
import com.jrobertgardzinski.security.service.SecurityServiceAdapter;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.server.util.HttpClientAddressResolver;

@Controller
public class DefaultController {
    private final SecurityServiceAdapter service;
    private final HttpClientAddressResolver addressResolver;
    private final SecurityFactoryAdapter factory;

    public DefaultController(SecurityServiceAdapter service, HttpClientAddressResolver addressResolver, SecurityFactoryAdapter factory) {
        this.service = service;
        this.addressResolver = addressResolver;
        this.factory = factory;
    }

    @Post(uri="register")
    public Email register(String email, String password) {
        return switch (service.register(
                factory.createUserRegistration(
                        email,
                        password))) {
            case RegistrationPassedEvent e -> e.email();
            case RegistrationFailedEvent e -> throw e.exceptionSupplier().apply(new Email(email));
        };
    }

    @Post(uri="authenticate")
    public AuthorizedUserAggregateRootEntity authenticate(HttpRequest<?> httpRequest, String email, String password) {
        return service.authenticate(
                factory.createAuthenticationRequest(
                        addressResolver.resolve(httpRequest),
                        email,
                        password));
    }

    @Post(uri="refresh")
    public AuthorizationDataEntity refreshToken(String email, String refreshToken) {
        return service.refreshToken(
                factory.createTokenRefreshRequest(
                        email, refreshToken));
    }
}