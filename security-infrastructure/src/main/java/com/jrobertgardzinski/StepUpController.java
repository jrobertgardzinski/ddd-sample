package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;


import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import com.jrobertgardzinski.security.system.mfa.StepUp;
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
 * Step-up authentication: re-prove yourself for a sensitive action. {@code POST /account/step-up}
 * begins it (the per-action policy decides whether a password and/or factors are needed);
 * {@code POST /account/step-up/factor} walks the factor chain. Passing it elevates the caller's
 * access token for a short window, which the sensitive endpoint then consumes. {@link
 * AuthorizationFilter} has already authorized the caller and published the email.
 */
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/account/step-up")
final class StepUpController {

    private final StepUp stepUp;
    private final SourceThrottle throttle;
    private final ClientIpResolver clientIpResolver;

    StepUpController(StepUp stepUp, @Named("step-up") SourceThrottle throttle,
                     ClientIpResolver clientIpResolver) {
        this.stepUp = stepUp;
        this.throttle = throttle;
        this.clientIpResolver = clientIpResolver;
    }

    @Post(consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> start(HttpRequest<?> request, @Body Map<String, String> body) {
        HttpResponse<Map<String, Object>> throttled = throttled(request);
        if (throttled != null) {
            return throttled;
        }
        Email email = Email.of(request.getAttribute(Caller.ATTRIBUTE, String.class).orElseThrow());
        String token = StepUpGuard.bearerToken(request);
        // the action must be one of the catalogue: an unknown name is a client error, not an
        // elevation minted for something nobody would ever consume
        java.util.Optional<StepUpAction> action = StepUpAction.fromWire(body.getOrDefault("action", ""));
        if (action.isEmpty()) {
            return HttpResponse.badRequest(Map.of("status", "UNKNOWN_ACTION"));
        }
        return respond(stepUp.start(email, action.get(), token, body.get("password")));
    }

    @Post(value = "/factor", consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> factor(HttpRequest<?> request, @Body Map<String, String> body) {
        HttpResponse<Map<String, Object>> throttled = throttled(request);
        if (throttled != null) {
            return throttled;
        }
        return respond(stepUp.submitFactor(body.get("stepUpTicket"), body.get("proof")));
    }

    /** A 429 (with Retry-After) when the source has spent its window, otherwise null (proceed). */
    private HttpResponse<Map<String, Object>> throttled(HttpRequest<?> request) {
        IpAddress source = clientIpResolver.resolve(request);
        SourceThrottle.Decision decision = throttle.check(source);
        if (decision.allowed()) {
            return null;
        }
        return HttpResponse.<Map<String, Object>>status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", String.valueOf(decision.retryAfterSeconds()))
                .body(Map.of("status", "TOO_MANY_STEP_UP_ATTEMPTS"));
    }

    private static HttpResponse<Map<String, Object>> respond(StepUp.Result result) {
        return switch (result) {
            case StepUp.Result.Elevated elevated ->
                    HttpResponse.ok(Map.of("status", "ELEVATED"));
            case StepUp.Result.FactorRequired next ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.ACCEPTED)
                            .body(MfaBody.stepUp(next.ticket(), next.nextFactor().value(), next.challengeData()));
            case StepUp.Result.WrongPassword wrong ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "WRONG_PASSWORD"));
            case StepUp.Result.WrongProof wrong ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "WRONG_CODE", "attemptsLeft", wrong.attemptsLeft()));
            case StepUp.Result.TooManyAttempts tooMany ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "TOO_MANY_ATTEMPTS"));
            case StepUp.Result.InvalidTicket invalid ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "INVALID_TICKET"));
        };
    }
}
