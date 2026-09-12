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
 *
 * <p><b>What SameSite does NOT cover.</b> It is a SITE rule, not an origin rule: a different PORT on
 * localhost and a sibling subdomain in production are the same site, so a page there can make the
 * browser send this cookie — and {@code POST /refresh} and {@code POST /logout} act on the cookie
 * alone, with no header a cross-site page could not set. In dev that is every other service on this
 * laptop; in production it is anything under the registrable domain. The cost is bounded by what
 * those two endpoints do (rotate a session, or end one — neither reads the response, which the
 * same-origin policy still hides), and the honest fix if that stops being acceptable is a
 * double-submit token on the refresh route rather than a stricter cookie flag, because there is no
 * stricter flag.
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
