package com.jrobertgardzinski.security;

import com.jrobertgardzinski.security.aggregate.AuthorizedUserAggregateRootEntity;
import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailedForTheNthTimeEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailedOnActiveBlockadeEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.event.refresh.NoRefreshTokenFoundEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenExpiredEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.*;
import com.jrobertgardzinski.security.domain.vo.*;
import com.jrobertgardzinski.security.entity.AuthorizationDataEntity;
import com.jrobertgardzinski.security.factory.SecurityFactoryAdapter;
import com.jrobertgardzinski.security.service.SecurityService;
import io.micronaut.http.*;
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
    public HttpResponse<Void> register(
            String email,
            String password) {

        UserRegistration arg = factory.createUserRegistration(
                email,
                password);

        return switch (service.register(arg)) {
            case RegistrationPassedEvent e -> HttpResponse
                    .ok();
            case UserAlreadyExistsEvent e -> HttpResponse
                    .status(
                            HttpStatus.CONFLICT,
                            e.exceptionSupplier().apply(new Email(email)).getMessage());
            case PossibleRaceCondition e -> HttpResponse
                    .status(
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            e.exceptionSupplier().apply(new Email(email)).getMessage());
        };
    }

    @Post(uri="authenticate")
    public HttpResponse<AuthorizedUserAggregateRootEntity> authenticate(
            HttpRequest<?> httpRequest,
            String email,
            String password) {

        AuthenticationRequest arg = factory.createAuthenticationRequest(
                addressResolver.resolve(httpRequest),
                email,
                password);

        return switch (service.authenticate(arg)) {
            case AuthenticationPassedEvent e -> HttpResponse
                    .ok(
                            AuthorizedUserAggregateRootEntity.fromDomain(
                                    e.authorizedUserAggregate()));
            case AuthenticationFailedEvent e -> HttpResponse
                    .status(
                            HttpStatus.UNAUTHORIZED,
                            e.toString());
            case AuthenticationFailedForTheNthTimeEvent e -> HttpResponse
                    .status(
                            HttpStatus.TOO_MANY_REQUESTS,
                            e.toString());
            case AuthenticationFailedOnActiveBlockadeEvent e -> HttpResponse
                    .<AuthorizedUserAggregateRootEntity>status(HttpStatus.FORBIDDEN, e.toString())
                    .header(HttpHeaders.RETRY_AFTER, Integer.toString(e.retryAfterHeader()));
        };
    }

    @Post(uri="refresh")
    public HttpResponse<SessionTokens> refreshToken(String email, String refreshToken) {

        SessionRefreshRequest arg = factory.createTokenRefreshRequest(email, refreshToken);

        return switch (service.refreshToken(arg)) {
            case RefreshTokenPassedEvent e -> HttpResponse
                    .ok(e.sessionTokens());
            case NoRefreshTokenFoundEvent e -> HttpResponse
                    .status(HttpStatus.NOT_FOUND, e.toString());
            case RefreshTokenExpiredEvent e -> HttpResponse
                    .status(HttpStatus.INTERNAL_SERVER_ERROR, e.toString());
        };
    }
}