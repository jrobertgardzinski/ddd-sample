package com.jrobertgardzinski;

import com.jrobertgardzinski.security.system.authentication.ContinueAuthentication;
import com.jrobertgardzinski.security.system.authentication.ContinueAuthenticationResult;
import com.jrobertgardzinski.security.system.throttle.SourceThrottle;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import jakarta.inject.Named;

import java.util.Map;

/**
 * The second (and further) steps of a multi-factor sign-in: the client presents a proof against the
 * ticket it got from {@code /authenticate}. Completing the chain returns the same session shape as a
 * single-factor sign-in (access token in the body, refresh token in the HttpOnly cookie); a wrong
 * proof reports how many tries remain; running out or an unknown ticket ends the attempt.
 *
 * <p>Per ticket the attempts are capped, but tickets are not: somebody holding the password can
 * open one after another (a correct password clears the brute-force count rather than adding to it)
 * and buy five guesses at the second factor each time — and every ticket for a code factor mails
 * the victim another code. So this endpoint shares one per-source window with {@code /authenticate}
 * itself: the loop is bounded by the source, whichever half of it is being spun.
 */
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/authenticate/factor")
final class AuthFactorController {

    private final ContinueAuthentication continueAuthentication;
    private final RefreshCookies refreshCookies;
    private final TransactionBoundary transactionBoundary;
    private final SourceThrottle throttle;
    private final ClientIpResolver clientIpResolver;

    AuthFactorController(ContinueAuthentication continueAuthentication, RefreshCookies refreshCookies,
                         TransactionBoundary transactionBoundary,
                         @Named("authentication") SourceThrottle throttle, ClientIpResolver clientIpResolver) {
        this.continueAuthentication = continueAuthentication;
        this.refreshCookies = refreshCookies;
        this.transactionBoundary = transactionBoundary;
        this.throttle = throttle;
        this.clientIpResolver = clientIpResolver;
    }

    @Post(consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> submit(HttpRequest<?> request, @Body Map<String, String> body) {
        SourceThrottle.Decision decision = throttle.check(clientIpResolver.resolve(request));
        if (!decision.allowed()) {
            return HttpResponse.<Map<String, Object>>status(HttpStatus.TOO_MANY_REQUESTS)
                    .header("Retry-After", String.valueOf(decision.retryAfterSeconds()))
                    .body(Map.of("status", "TOO_MANY_ATTEMPTS"));
        }
        String ticket = body.get("mfaTicket");
        String proof = body.get("proof");
        ContinueAuthenticationResult result =
                transactionBoundary.execute(() -> continueAuthentication.execute(ticket, proof));
        return switch (result) {
            case ContinueAuthenticationResult.Completed completed ->
                    HttpResponse.ok(Map.<String, Object>of("accessToken", completed.session().plainAccessToken()))
                            .cookie(refreshCookies.issue(completed.session().plainRefreshToken()));
            case ContinueAuthenticationResult.NextFactor next ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.ACCEPTED)
                            .body(MfaBody.of(ticket, next.type().value(), next.challengeData()));
            case ContinueAuthenticationResult.WrongProof wrong ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "WRONG_CODE", "attemptsLeft", wrong.attemptsLeft()));
            case ContinueAuthenticationResult.TooManyAttempts tooMany ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "TOO_MANY_ATTEMPTS"));
            case ContinueAuthenticationResult.InvalidTicket invalid ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "INVALID_OR_EXPIRED_TICKET"));
        };
    }
}
