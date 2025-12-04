package com.jrobertgardzinski.security;

import com.jrobertgardzinski.security.aggregate.AuthorizedUserAggregateRootEntity;
import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.event.registration.*;
import com.jrobertgardzinski.security.domain.vo.*;
import com.jrobertgardzinski.security.entity.AuthorizationDataEntity;
import com.jrobertgardzinski.security.factory.SecurityFactoryAdapter;
import com.jrobertgardzinski.security.service.SecurityService;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.server.util.HttpClientAddressResolver;
import io.vavr.control.Try;

@Controller
public class DefaultController {
    private final SecurityService service;
    private final HttpClientAddressResolver addressResolver;
    private final SecurityFactoryAdapter factory;

    public DefaultController(SecurityService service, HttpClientAddressResolver addressResolver, SecurityFactoryAdapter factory) {
        this.service = service;
        this.addressResolver = addressResolver;
        this.factory = factory;
    }

    @Post(uri="register")
    public HttpResponse<Void> register(String email, String password) {
        return switch (service.register(
                factory.createUserRegistration(
                        email,
                        password))) {
            case RegistrationPassedEvent e -> HttpResponse.ok();
            // case RegistrationFailedEvent e -> throw e.exceptionSupplier().apply(new Email(email));
            case UserAlreadyExistsEvent e -> HttpResponse.status(
                    HttpStatus.CONFLICT,
                    e.exceptionSupplier().apply(new Email(email)).getMessage());
            case PossibleRaceCondition e -> HttpResponse.status(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    e.exceptionSupplier().apply(new Email(email)).getMessage());
        };
    }

    @Post(uri="authenticate")
    public HttpResponse<AuthorizedUserAggregateRootEntity> authenticate(HttpRequest<?> httpRequest, String email, String password) {
        AuthenticationRequest arg = factory.createAuthenticationRequest(
                addressResolver.resolve(httpRequest),
                email,
                password);
        Try<AuthorizedUserAggregate> result = service.authenticate(arg);
        HttpResponse<AuthorizedUserAggregateRootEntity> p = result.fold(
                throwable -> HttpResponse.status(HttpStatus.INTERNAL_SERVER_ERROR, throwable.getMessage()),
                authorizedUserAggregate -> HttpResponse.ok(authorizedUserAggregate)
        );
        return (HttpResponse<AuthorizedUserAggregateRootEntity>) p;
    }

    @Post(uri="refresh")
    public AuthorizationDataEntity refreshToken(String email, String refreshToken) {
        return service.refreshToken(
                factory.createTokenRefreshRequest(
                        email, refreshToken));
    }
}