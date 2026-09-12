package com.jrobertgardzinski;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.server.exceptions.ExceptionHandler;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * What the edge answers when something below it refused or broke — in ONE shape, and without ever
 * quoting an internal message back to the caller.
 *
 * <p>The module had no exception handler at all, and the two consequences were the same defect
 * seen from either end. A value object's own rule ("must not be blank", "is not valid!") reached
 * the caller as a 500 carrying that sentence — a missing field, a non-IP header, an address with a
 * typo in an admin path, each answering Internal Server Error and describing the inside of the
 * service while doing it. And because they were 500s rather than refusals, a one-shot step-up
 * elevation consumed by the guard above was spent on a request the controller then failed to
 * parse: the caller had to walk the whole chain again to retry a typo.
 *
 * <p>So: a refusal the domain states is a 400 with a fixed body, an unauthenticated caller is a
 * 401, and anything genuinely unexpected is a 500 that says only that — with the real cause in the
 * service's own log, where it belongs.
 */
final class EdgeErrors {

    private static final Logger LOG = LoggerFactory.getLogger(EdgeErrors.class);

    private EdgeErrors() {
    }

    /** A value the domain refuses to construct is the caller's mistake, not the server's. */
    @Singleton
    @Requires(classes = {IllegalArgumentException.class, ExceptionHandler.class})
    @Produces
    static final class BadInput implements ExceptionHandler<IllegalArgumentException, HttpResponse<?>> {
        @Override
        public HttpResponse<?> handle(HttpRequest request, IllegalArgumentException refused) {
            LOG.debug("refused {} {}: {}", request.getMethod(), request.getPath(), refused.getMessage());
            return HttpResponse.badRequest(Map.of("status", "BAD_REQUEST"));
        }
    }

    /** A protected resource reached without an authenticated caller — see {@link Caller#of}. */
    @Singleton
    @Requires(classes = {NotAuthenticatedException.class, ExceptionHandler.class})
    @Produces
    static final class NotAuthenticated implements ExceptionHandler<NotAuthenticatedException, HttpResponse<?>> {
        @Override
        public HttpResponse<?> handle(HttpRequest request, NotAuthenticatedException unauthenticated) {
            LOG.warn("no authenticated caller on {} {} — is the path filtered?",
                    request.getMethod(), request.getPath());
            return HttpResponse.status(HttpStatus.UNAUTHORIZED);
        }
    }
}
