package com.jrobertgardzinski;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.email.domain.InvalidEmailException;
import com.jrobertgardzinski.email.domain.NormalizedEmail;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.AccountClosure;
import com.jrobertgardzinski.security.domain.vo.PurgeChoices;
import com.jrobertgardzinski.security.domain.vo.Role;
import com.jrobertgardzinski.security.domain.vo.StepUpAction;
import com.jrobertgardzinski.security.system.account.StartAccountDeletion;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;

import static com.jrobertgardzinski.MaskedEmail.masked;

/**
 * The ONE door out of an account, for the person whose account it is and for an administrator
 * closing somebody else's. Which of the two it is comes from the request itself — the address in
 * the path against the address in the token — and everything else follows from that comparison:
 * what must be proven, and whether the caller may say what happens to the content.
 *
 * <ul>
 *   <li><strong>Your own account.</strong> A fresh step-up ({@link StepUpAction#DELETE_ACCOUNT}),
 *       and then everything you ever posted goes. This request IS the right to erasure, and the
 *       grounds on which content may survive such a request are enumerated by law — "the community
 *       up-voted it" is not one of them — so any conditions in the body are dropped, by
 *       {@link AccountClosure} itself rather than by this controller remembering to.</li>
 *   <li><strong>Somebody else's.</strong> The ADMIN role on top of the step-up
 *       ({@link StepUpAction#ADMIN_DELETE_ACCOUNT}), because this destroys another person's
 *       account and their content on one press. Nobody is exercising a right here — it is a ban,
 *       or house rules — so the caller MAY state a rule per content axis, and it rides the saga.</li>
 * </ul>
 *
 * <p>The two used to be two routes. One is closer to the truth: "am I closing my own account or
 * someone else's" is a property of the request, not of the URL, and the authorisation is what
 * follows from it rather than what picks it.
 *
 * <p>Protected: {@link AuthorizationFilter} has authorized the access token and published the
 * caller's email. Closing is a saga: {@link StartAccountDeletion} locks the account at once
 * (sessions revoked, sign-in refused) and asks the content services to purge; their confirmation —
 * not this request — deletes the account for good.
 */
// controllers do blocking work (JDBC, the mail service's HTTP client) — keep it off the event loop
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/account")
final class DeleteAccountController {

    private static final Logger LOG = LoggerFactory.getLogger(DeleteAccountController.class);

    private final StartAccountDeletion startAccountDeletion;
    private final UserRepository userRepository;
    private final TransactionBoundary transactionBoundary;
    private final RoleGuard roleGuard;
    private final StepUpGuard stepUpGuard;

    DeleteAccountController(StartAccountDeletion startAccountDeletion, UserRepository userRepository,
                            TransactionBoundary transactionBoundary, RoleGuard roleGuard,
                            StepUpGuard stepUpGuard) {
        this.startAccountDeletion = startAccountDeletion;
        this.userRepository = userRepository;
        this.transactionBoundary = transactionBoundary;
        this.roleGuard = roleGuard;
        this.stepUpGuard = stepUpGuard;
    }

    @Delete(value = "/{email}", consumes = MediaType.ALL, produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> delete(HttpRequest<?> request, @PathVariable String email,
                                             @Body @Nullable Map<String, Map<String, String>> body) {
        Email target;
        try {
            target = Email.of(email);
        } catch (InvalidEmailException notAnAddress) {
            return HttpResponse.<Map<String, Object>>status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("status", "INVALID_EMAIL"));
        }
        Email caller = Caller.of(request);
        // the same account, by the same rule registration uses to decide two addresses are one
        // person: a caller whose token spells their address differently from the path is still
        // closing their OWN account, and must not be sent down the administrator's road
        boolean ownAccount = NormalizedEmail.of(target).equals(NormalizedEmail.of(caller));
        // on the own-account road the CALLER's address is what travels, never the path's: the
        // comparison above accepts a different spelling of the same account, and everything
        // downstream — the lock, the saga row, the fact's key — addresses the user by the exact
        // string the account is stored under, which is the one the token carries
        return ownAccount
                ? closeOwnAccount(request, caller)
                : closeSomebodyElses(request, caller, target, body);
    }

    /**
     * The body is not read here, and that is the point rather than an omission: a request to be
     * forgotten states no conditions, so there are none to parse, validate or reject. An older
     * client that still sends {@code {"purge": …}} is answered with the deletion it asked for —
     * refusing it would leave that person unable to close their account over a field that could
     * not have changed the outcome anyway.
     */
    private HttpResponse<Map<String, Object>> closeOwnAccount(HttpRequest<?> request, Email target) {
        // closing an account is irreversible: a live session is not enough, the caller must have
        // just stepped up (the thief of a live session would have to pass the chain too)
        Optional<HttpResponse<Map<String, Object>>> stepUp =
                stepUpGuard.requireElevation(request, StepUpAction.DELETE_ACCOUNT);
        if (stepUp.isPresent()) {
            return stepUp.get();
        }
        return start(AccountClosure.requestedByOwner(target));
    }

    private HttpResponse<Map<String, Object>> closeSomebodyElses(HttpRequest<?> request, Email caller,
                                                                 Email target,
                                                                 Map<String, Map<String, String>> body) {
        Optional<HttpResponse<Map<String, Object>>> notAnAdmin = roleGuard.require(request, Role.ADMIN);
        if (notAnAdmin.isPresent()) {
            return notAnAdmin.get();
        }
        // AFTER the role check, so somebody who may not do this at all learns only that. A stolen
        // admin session must prove itself again before destroying a stranger's account, exactly as
        // it must before granting a role next door.
        Optional<HttpResponse<Map<String, Object>>> stepUp =
                stepUpGuard.requireElevation(request, StepUpAction.ADMIN_DELETE_ACCOUNT);
        if (stepUp.isPresent()) {
            return stepUp.get();
        }
        PurgeChoices choices;
        try {
            choices = purgeChoices(body);
        } catch (IllegalArgumentException oversized) {
            // an over-large or over-wide purge map is a bad request, not a server fault — reject it
            // here so it never becomes an unpublishable outbox row (see PurgeChoices bounds)
            return HttpResponse.<Map<String, Object>>status(HttpStatus.UNPROCESSABLE_ENTITY)
                    .body(Map.of("status", "INVALID_PURGE_CHOICES"));
        }
        // asked before the lock, and only on this road: starting a saga for an address nobody holds
        // would announce a deletion fact the portal then purges content for, and answer 202 to an
        // administrator who mistyped. (On the other road the caller's own account exists by
        // definition — their token was issued for it.)
        if (userRepository.findBy(target).isEmpty()) {
            return HttpResponse.<Map<String, Object>>status(HttpStatus.NOT_FOUND)
                    .body(Map.of("status", "NO_SUCH_USER"));
        }
        // the audit line, and the only place the two addresses ever meet: the fact on the wire says
        // ADMIN and not WHICH admin, because three content services would then hold an extra
        // person's address for no use of their own
        LOG.warn("account deletion started for {} by administrator {}", masked(target.value()),
                masked(caller.value()));
        return start(AccountClosure.requestedByAdministrator(target, choices));
    }

    private HttpResponse<Map<String, Object>> start(AccountClosure closure) {
        transactionBoundary.execute(() -> {
            startAccountDeletion.execute(closure);
            return null;
        });
        return HttpResponse.accepted().body(Map.of("status", "ACCOUNT_DELETION_STARTED"));
    }

    /**
     * An administrator's decision: {@code {"purge": {"memes": "KEEP_POPULAR_ANONYMIZED:100"}}} —
     * any axes, or none. Both the axis names and the rule strings stay opaque here: their
     * vocabulary belongs to the content services, and identity only ferries the map.
     */
    private static PurgeChoices purgeChoices(Map<String, Map<String, String>> body) {
        Map<String, String> purge = body == null ? null : body.get("purge");
        if (purge == null || purge.isEmpty()) {
            return PurgeChoices.serviceDefaults();
        }
        return new PurgeChoices(purge);
    }
}
