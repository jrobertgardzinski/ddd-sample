package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.SessionTokensConfig;
import io.micronaut.context.annotation.Value;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.SameSite;
import jakarta.inject.Singleton;

import java.time.Duration;
import java.util.Optional;

/**
 * Issues and reads the refresh-token cookie. The refresh token is delivered to the client only as
 * an {@code HttpOnly}, {@code SameSite=Strict} cookie — never in a response body — so it is out of
 * reach of page JavaScript (XSS) and not sent on cross-site requests (CSRF). {@code Secure} is on
 * by default (the cookie then rides only over TLS); it is turned off under the {@code test}
 * environment via {@code security.cookie.secure} so the cookie round-trips over plain HTTP in tests.
 */
@Singleton
public class RefreshCookies {

    static final String NAME = "refresh_token";

    private final boolean secure;
    private final long maxAgeSeconds;

    public RefreshCookies(@Value("${security.cookie.secure:true}") boolean secure,
                          SessionTokensConfig sessionTokensConfig) {
        this.secure = secure;
        this.maxAgeSeconds = Duration.ofHours(sessionTokensConfig.refreshTokenValidityInHours().value()).toSeconds();
    }

    public Cookie issue(String refreshToken) {
        return Cookie.of(NAME, refreshToken)
                .httpOnly(true)
                .secure(secure)
                .sameSite(SameSite.Strict)
                .path("/")
                .maxAge(maxAgeSeconds);
    }

    public Optional<String> read(HttpRequest<?> request) {
        // an EMPTY cookie is the shape logout itself leaves behind, and a token that cannot be
        // constructed is not a token: without this filter /refresh and /logout answered 500 to a
        // browser that had merely signed out
        return request.getCookies().findCookie(NAME).map(Cookie::getValue).filter(value -> !value.isBlank());
    }

    /** An immediately-expiring cookie that clears the refresh token from the browser (logout). */
    public Cookie clear() {
        return Cookie.of(NAME, "")
                .httpOnly(true)
                .secure(secure)
                .sameSite(SameSite.Strict)
                .path("/")
                .maxAge(0);
    }
}
