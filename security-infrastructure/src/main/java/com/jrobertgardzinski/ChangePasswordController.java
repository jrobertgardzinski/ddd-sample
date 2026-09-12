package com.jrobertgardzinski;


import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.password.domain.PlaintextPassword;
import com.jrobertgardzinski.security.system.account.ChangePassword;
import com.jrobertgardzinski.security.system.account.ChangePasswordResult;
import com.jrobertgardzinski.security.system.throttle.SourceThrottle;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.http.annotation.Post;
import jakarta.inject.Named;

import java.util.Map;

/**
 * HTTP entry point for changing a password. A protected endpoint: {@link AuthorizationFilter} has
 * already authorized the access token and published the caller's email, so we change that user's
 * password once their current password checks out, driving the {@link ChangePassword} use case.
 *
 * <p>Authorized is not the same as unlimited. Checking the current password runs a full Argon2 and
 * answers whether the guess was right, so with a stolen access token this endpoint is a password
 * oracle — and a hit is a takeover, because changing the password revokes every session, the
 * owner's included. Hence a per-source window of its own, the same shape the anonymous endpoints
 * and the step-up already use.
 */
// controllers do blocking work (JDBC, the mail service's HTTP client) — keep it off the event loop
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/account/password")
final class ChangePasswordController {

    private final ChangePassword changePassword;
    private final TransactionBoundary transactionBoundary;
    private final SourceThrottle throttle;
    private final ClientIpResolver clientIpResolver;

    ChangePasswordController(ChangePassword changePassword, TransactionBoundary transactionBoundary,
                             @Named("change-password") SourceThrottle throttle, ClientIpResolver clientIpResolver) {
        this.changePassword = changePassword;
        this.transactionBoundary = transactionBoundary;
        this.throttle = throttle;
        this.clientIpResolver = clientIpResolver;
    }

    @Post(consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    HttpResponse<?> change(HttpRequest<?> request, @Body Map<String, Object> body) {
        SourceThrottle.Decision decision = throttle.check(clientIpResolver.resolve(request));
        if (!decision.allowed()) {
            return HttpResponse.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header("Retry-After", String.valueOf(decision.retryAfterSeconds()))
                    .body(Map.of("status", "TOO_MANY_ATTEMPTS"));
        }
        Email email = Email.of(request.getAttribute(Caller.ATTRIBUTE, String.class).orElseThrow());
        String current = JsonBody.text(body, "currentPassword");
        String next = JsonBody.text(body, "newPassword");
        ChangePasswordResult result = transactionBoundary.execute(() -> changePassword.execute(
                email, () -> PlaintextPassword.of(current), () -> PlaintextPassword.of(next)));
        return switch (result) {
            case ChangePasswordResult.Changed ignored ->
                    HttpResponse.ok(Map.of("status", "PASSWORD_CHANGED"));
            case ChangePasswordResult.WrongCurrentPassword ignored ->
                    HttpResponse.badRequest().body(Map.of("status", "WRONG_CURRENT_PASSWORD"));
            case ChangePasswordResult.WeakPassword ignored ->
                    HttpResponse.badRequest().body(Map.of("status", "WEAK_PASSWORD"));
        };
    }
}
