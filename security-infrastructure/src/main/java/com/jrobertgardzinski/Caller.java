package com.jrobertgardzinski;

import com.jrobertgardzinski.email.domain.Email;
import io.micronaut.http.HttpRequest;

/**
 * The authenticated caller of a protected request: the authorization filter publishes the address
 * under {@link #ATTRIBUTE} once the bearer token is accepted, and every resource reads it here.
 */
public final class Caller {

    public static final String ATTRIBUTE = "authenticatedEmail";

    private Caller() {
    }

    /**
     * Only meaningful behind the authorization filter; a request that never passed it has no
     * caller — and is answered 401, not 500. {@code GET /me/} (one trailing slash) used to miss the
     * filter's Ant pattern and land here, so a protected route executed unfiltered and answered
     * "No value present" with an Internal Server Error.
     */
    public static Email of(HttpRequest<?> request) {
        return Email.of(request.getAttribute(ATTRIBUTE, String.class)
                .orElseThrow(NotAuthenticatedException::new));
    }

    /** The bearer token as sent, or null when the header is missing or empty. */
    public static String bearerToken(HttpRequest<?> request) {
        return request.getHeaders().getAuthorization()
                .filter(header -> header.startsWith("Bearer "))
                .map(header -> header.substring("Bearer ".length()).trim())
                .filter(token -> !token.isEmpty())
                .orElse(null);
    }
}
