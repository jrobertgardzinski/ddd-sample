package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;


import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.vo.PurgeChoices;
import com.jrobertgardzinski.security.system.account.StartAccountDeletion;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Post;
import io.micronaut.core.annotation.Nullable;

import java.util.Optional;
import java.util.Map;

/**
 * HTTP entry point for closing an account. Protected: {@link AuthorizationFilter} has authorized the
 * access token and published the caller's email. Closing is a saga: {@link StartAccountDeletion}
 * locks the account at once (sessions revoked, sign-in refused) and asks microservice-memes to
 * purge the user's content; the confirmation — not this request — deletes the user for good.
 */
// controllers do blocking work (JDBC, the mail service's HTTP client) — keep it off the event loop
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/account/delete")
final class DeleteAccountController {

    private final StartAccountDeletion startAccountDeletion;
    private final TransactionBoundary transactionBoundary;
    private final StepUpGuard stepUpGuard;

    DeleteAccountController(StartAccountDeletion startAccountDeletion, TransactionBoundary transactionBoundary,
                           StepUpGuard stepUpGuard) {
        this.startAccountDeletion = startAccountDeletion;
        this.transactionBoundary = transactionBoundary;
        this.stepUpGuard = stepUpGuard;
    }

    @Post(consumes = MediaType.ALL, produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> delete(HttpRequest<?> request, @Body @Nullable Map<String, Map<String, String>> body) {
        // deleting an account is irreversible: a live session is not enough, the caller must have
        // just stepped up (the thief of a live session would have to pass the chain too)
        Optional<HttpResponse<Map<String, Object>>> stepUp = stepUpGuard.requireElevation(request, StepUpAction.DELETE_ACCOUNT);
        if (stepUp.isPresent()) {
            return stepUp.get();
        }
        Email email = Email.of(request.getAttribute(Caller.ATTRIBUTE, String.class).orElseThrow());
        PurgeChoices choices;
        try {
            choices = purgeChoices(body);
        } catch (IllegalArgumentException oversized) {
            // an over-large or over-wide purge map is a bad request, not a server fault — reject it
            // here so it never becomes an unpublishable outbox row (see PurgeChoices bounds)
            return HttpResponse.<Map<String, Object>>status(io.micronaut.http.HttpStatus.UNPROCESSABLE_ENTITY)
                    .body(Map.of("status", "INVALID_PURGE_CHOICES"));
        }
        transactionBoundary.execute(() -> {
            startAccountDeletion.execute(email, choices);
            return null;
        });
        return HttpResponse.accepted().body(Map.of("status", "ACCOUNT_DELETION_STARTED"));
    }

    /**
     * The wizard's choice: {@code {"purge": {"memes": "...", "comments": "..."}}} — any axes, or
     * none. Both the axis names and the rule strings stay opaque here: their vocabulary belongs
     * to the content services, and identity only ferries the map into the deletion fact.
     */
    private static PurgeChoices purgeChoices(Map<String, Map<String, String>> body) {
        Map<String, String> purge = body == null ? null : body.get("purge");
        if (purge == null || purge.isEmpty()) {
            return PurgeChoices.serviceDefaults();
        }
        return new PurgeChoices(purge);
    }
}
