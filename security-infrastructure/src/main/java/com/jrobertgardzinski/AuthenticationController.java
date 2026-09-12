package com.jrobertgardzinski;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.password.domain.PlaintextPassword;
import com.jrobertgardzinski.security.domain.vo.AuthenticationRequest;
import com.jrobertgardzinski.security.domain.vo.Source;
import com.jrobertgardzinski.security.system.authentication.Authentication;
import com.jrobertgardzinski.security.system.authentication.AuthenticationResult;
import com.jrobertgardzinski.security.system.throttle.SourceThrottle;
import jakarta.inject.Named;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.http.annotation.Post;

import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * HTTP entry point for authentication. Drives the same {@link Authentication} use case the
 * application-level Cucumber glue drives directly — "same behaviour, different entry point". The
 * source IP that brute-force protection keys on is resolved from the connection (see
 * {@link ClientIpResolver}), not from the request body, so a caller cannot pick its own source.
 * The User-Agent header rides along as observed context — forensics only, never part of the key.
 *
 * <p>The HTTP contract:
 * <ul>
 *   <li>{@code Authenticated}    &rarr; 200 OK, {@code {"accessToken": ...}} — plus the refresh
 *       token in a {@code Set-Cookie}, HttpOnly, and <b>never in the body</b>. This line used to
 *       promise {@code refreshToken} in the JSON, which the code has never sent: a client author
 *       implementing from the contract read null and built a refresh flow that could not work,
 *       while the mechanism that does work (a credentialed cookie, and therefore
 *       {@code credentials: 'include'} on the fetch and {@code allow-credentials} on the CORS
 *       configuration — the whole of the 2026-07-29 sign-in outage) went undocumented. Described
 *       the way {@code RefreshController} already describes its own rotated cookie.</li>
 *   <li>{@code Rejected}         &rarr; 401 Unauthorized</li>
 *   <li>{@code EmailNotVerified} &rarr; 403 Forbidden, {@code {"error": "EMAIL_NOT_VERIFIED"}}
 *       (correct credentials, but the address awaits verification)</li>
 *   <li>{@code Blocked}          &rarr; 429 Too Many Requests, with a {@code Retry-After} header
 *       (seconds until the block expires)</li>
 * </ul>
 */
// controllers do blocking work (JDBC, the mail service's HTTP client) — keep it off the event loop
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/authenticate")
public class AuthenticationController {

    private final Authentication authentication;
    private final ClientIpResolver ipResolver;
    private final RefreshCookies refreshCookies;
    private final TransactionBoundary transactionBoundary;
    private final SourceThrottle throttle;
    private final Clock clock;

    public AuthenticationController(Authentication authentication, ClientIpResolver ipResolver,
                                    RefreshCookies refreshCookies, TransactionBoundary transactionBoundary,
                                    @Named("authentication") SourceThrottle throttle, Clock clock) {
        this.authentication = authentication;
        this.ipResolver = ipResolver;
        this.refreshCookies = refreshCookies;
        this.transactionBoundary = transactionBoundary;
        this.throttle = throttle;
        this.clock = clock;
    }

    @Post(consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    public HttpResponse<Map<String, Object>> authenticate(@Body Map<String, String> body, HttpRequest<?> request) {
        Source source = new Source(ipResolver.resolve(request),
                request.getHeaders().findFirst("User-Agent").orElse(""));
        // the per-account guard counts FAILURES and a correct password clears them, so it does not
        // bound how many attempts one source may start — this does
        SourceThrottle.Decision decision = throttle.check(source.ipAddress());
        if (!decision.allowed()) {
            return HttpResponse.<Map<String, Object>>status(HttpStatus.TOO_MANY_REQUESTS)
                    .header("Retry-After", String.valueOf(decision.retryAfterSeconds()))
                    .body(Refusal.alsoAsError("TOO_MANY_ATTEMPTS"));
        }
        AuthenticationRequest authenticationRequest;
        try {
            authenticationRequest = new AuthenticationRequest(
                    source, Email.of(body.get("email")), PlaintextPassword.of(body.get("password")));
        } catch (IllegalArgumentException unreadable) {
            // A credential the domain cannot even construct used to escape as a 500 carrying the
            // domain's own sentence: an Internal Server Error for a typo, plus a stack trace in the
            // log for every one of them. To the caller it is not a different KIND of failure — an
            // address that cannot exist owns no account — so it answers exactly like a wrong
            // password, and learns nothing the 401 did not already say. It costs no lookup and
            // therefore no brute-force count: there is no account here to guess at.
            return HttpResponse.status(HttpStatus.UNAUTHORIZED);
        }
        AuthenticationResult result = transactionBoundary.execute(() -> authentication.execute(authenticationRequest));

        return switch (result) {
            case AuthenticationResult.Authenticated authenticated ->
                    HttpResponse.ok(Map.<String, Object>of("accessToken", authenticated.session().plainAccessToken()))
                            .cookie(refreshCookies.issue(authenticated.session().plainRefreshToken()));
            case AuthenticationResult.Rejected rejected ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.UNAUTHORIZED)
                            .body(Refusal.of("WRONG_CREDENTIALS"));
            case AuthenticationResult.EmailNotVerified notVerified ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.FORBIDDEN)
                            .body(Refusal.alsoAsError("EMAIL_NOT_VERIFIED"));
            case AuthenticationResult.Blocked blocked ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.TOO_MANY_REQUESTS)
                            .header("Retry-After", Long.toString(secondsUntil(blocked.authenticationBlock().expiryDate())))
                            .body(Refusal.alsoAsError("TOO_MANY_ATTEMPTS"));
            // password was right, but the user has factors — no session yet; the first challenge is out.
            // The refresh token is withheld until the chain completes (see AuthFactorController).
            case AuthenticationResult.MfaRequired mfa ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.ACCEPTED)
                            .body(MfaBody.of(mfa.ticket(), mfa.nextFactor().value(), mfa.challengeData()));
        };
    }

    private long secondsUntil(LocalDateTime expiry) {
        return Math.max(0, Duration.between(LocalDateTime.now(clock), expiry).toSeconds());
    }
}
