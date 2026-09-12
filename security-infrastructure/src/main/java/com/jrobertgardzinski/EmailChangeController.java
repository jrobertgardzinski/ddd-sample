package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;


import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.system.account.RequestEmailChange;
import com.jrobertgardzinski.security.system.account.RequestEmailChangeResult;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.http.annotation.Post;

import java.util.Map;

/**
 * HTTP entry point to start an email change. Protected: {@link AuthorizationFilter} has authorized
 * the access token and published the caller's current email; here we request a change to the new
 * address, which e-mails a verification link there (confirmed separately, pre-login).
 *
 * <p>Same anti-enumeration stance as {@code /register}: a taken address answers exactly like a
 * fresh request, and the OWNER of that address learns by mail that someone tried to use it. A
 * signed-in caller probing addresses gets nothing the anonymous one would not.
 */
// controllers do blocking work (JDBC, the mail service's HTTP client) — keep it off the event loop
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/account/email")
final class EmailChangeController {

    private final RequestEmailChange requestEmailChange;
    private final TransactionBoundary transactionBoundary;
    private final com.jrobertgardzinski.security.domain.port.RegistrationNoticeNotifier noticeNotifier;
    private final StepUpGuard stepUpGuard;

    EmailChangeController(RequestEmailChange requestEmailChange, TransactionBoundary transactionBoundary,
                          com.jrobertgardzinski.security.domain.port.RegistrationNoticeNotifier noticeNotifier,
                          StepUpGuard stepUpGuard) {
        this.requestEmailChange = requestEmailChange;
        this.transactionBoundary = transactionBoundary;
        this.noticeNotifier = noticeNotifier;
        this.stepUpGuard = stepUpGuard;
    }

    @Post(value = "/request", consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    HttpResponse<?> request(HttpRequest<?> request, @Body Map<String, Object> body) {
        // moving the address moves the account, and the confirmation lands in the NEW mailbox — so
        // a thief with a live session could walk off with the whole account and the owner would
        // learn about it from a notice. Guarded where the change STARTS; the confirmation itself
        // still needs the token mailed to that new address.
        java.util.Optional<HttpResponse<Map<String, Object>>> stepUp =
                stepUpGuard.requireElevation(request, StepUpAction.CHANGE_EMAIL);
        if (stepUp.isPresent()) {
            return stepUp.get();
        }
        Email currentEmail = Caller.of(request);
        Email newEmail;
        try {
            newEmail = Email.of(JsonBody.text(body, "newEmail"));
        } catch (IllegalArgumentException invalid) {
            return HttpResponse.badRequest().body(Map.of("status", "INVALID_EMAIL"));
        }
        RequestEmailChangeResult result = transactionBoundary.execute(
                () -> requestEmailChange.execute(currentEmail, newEmail));
        return switch (result) {
            case RequestEmailChangeResult.Requested ignored ->
                    HttpResponse.accepted().body(Map.of("status", "EMAIL_CHANGE_LINK_SENT"));
            // the policy's refusal is NOT quiet: it is about the address the caller typed, not
            // about who else holds it, so it says which rule was broken — exactly as /register does
            case RequestEmailChangeResult.Rejected rejected ->
                    HttpResponse.unprocessableEntity().body(Map.of(
                            "emailErrors",
                            SecurityController.emailErrors(rejected.emailErrors(), rejected.emailPolicy())));
            case RequestEmailChangeResult.EmailTaken ignored -> {
                // quiet refusal: the wire looks like a fresh request; the address owner is told by mail
                transactionBoundary.execute(() -> {
                    noticeNotifier.sendAlreadyRegistered(newEmail);
                    return null;
                });
                yield HttpResponse.accepted().body(Map.of("status", "EMAIL_CHANGE_LINK_SENT"));
            }
        };
    }
}
