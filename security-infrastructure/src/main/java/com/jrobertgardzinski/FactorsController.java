package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;


import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.repository.EnrolledFactorRepository;
import com.jrobertgardzinski.security.domain.vo.FactorType;
import com.jrobertgardzinski.security.system.mfa.EnrolFactor;
import com.jrobertgardzinski.security.system.mfa.FactorRegistry;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Post;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

import java.util.List;
import java.util.Map;

/**
 * Manage a signed-in user's MFA factors — the per-user half of the configuration. Enrolling proves
 * control of the new factor in two steps ({@code enroll/start} sends a challenge, {@code
 * enroll/confirm} accepts one proof). {@link AuthorizationFilter} has already authorized the caller
 * and published their e-mail; every action is against their own factors.
 */
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/account/factors")
final class FactorsController {

    private final EnrolFactor enrolFactor;
    private final EnrolledFactorRepository enrolledFactors;
    private final FactorRegistry registry;
    private final TransactionBoundary transactionBoundary;
    private final com.jrobertgardzinski.security.domain.repository.UserRepository users;
    private final com.jrobertgardzinski.security.system.mfa.MfaCompliance compliance;
    private final StepUpGuard stepUpGuard;

    FactorsController(EnrolFactor enrolFactor, EnrolledFactorRepository enrolledFactors,
                      FactorRegistry registry, TransactionBoundary transactionBoundary,
                      com.jrobertgardzinski.security.domain.repository.UserRepository users,
                      com.jrobertgardzinski.security.system.mfa.MfaCompliance compliance,
                      StepUpGuard stepUpGuard) {
        this.enrolFactor = enrolFactor;
        this.enrolledFactors = enrolledFactors;
        this.registry = registry;
        this.transactionBoundary = transactionBoundary;
        this.users = users;
        this.compliance = compliance;
        this.stepUpGuard = stepUpGuard;
    }

    @Get(produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> list(HttpRequest<?> request) {
        Email caller = caller(request);
        List<Map<String, String>> have = enrolledFactors.findByUser(caller).stream()
                .map(f -> Map.of("type", f.type().value(), "label", f.label()))
                .toList();
        List<String> offered = registry.offered().stream().map(FactorType::value).sorted().toList();
        return HttpResponse.ok(Map.of("have", have, "offered", offered));
    }

    @Post(value = "/{type}/enroll/start", consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> start(HttpRequest<?> request, @PathVariable String type,
                                            @Nullable @Body Map<String, String> body) {
        // the path is read BEFORE the guard, because the guard SPENDS a one-shot elevation: a typo
        // in the factor type used to cost the whole step-up chain and answer 400 afterwards
        Email caller = caller(request);
        FactorType factorType = FactorType.of(type);
        // enrolling a factor rewrites the sign-in chain, so a merely-live (possibly stolen) session
        // must step up first — otherwise a thief adds an attacker-held factor and locks the owner out.
        // Guarding start alone is enough: confirm needs a pending enrolment only a guarded start mints.
        java.util.Optional<HttpResponse<Map<String, Object>>> stepUp =
                stepUpGuard.requireElevation(request, StepUpAction.ENROL_FACTOR);
        if (stepUp.isPresent()) {
            return stepUp.get();
        }
        // the e-mail factor's code always goes to the caller's OWN already-verified address — never a
        // target from the body, or a thief would point the codes at their own inbox
        String target = "EMAIL_CODE".equals(factorType.value()) || body == null || body.get("target") == null
                ? caller.value() : body.get("target");
        return respond(transactionBoundary.execute(
                () -> enrolFactor.start(caller, factorType, target)));
    }

    @Post(value = "/{type}/enroll/confirm", consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> confirm(HttpRequest<?> request, @PathVariable String type,
                                              @Body Map<String, String> body) {
        Email caller = caller(request);
        return respond(transactionBoundary.execute(
                () -> enrolFactor.confirm(caller, FactorType.of(type), body.get("code"))));
    }

    @Delete(value = "/{type}", produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> remove(HttpRequest<?> request, @PathVariable String type) {
        // read the path first: the guard below spends a one-shot elevation, and a factor type that
        // does not exist must not cost it (HTTP-10)
        Email caller = caller(request);
        FactorType factorType = FactorType.of(type);
        java.util.Set<com.jrobertgardzinski.security.domain.vo.Role> roles = users.findBy(caller)
                .map(u -> u.roles()).orElse(java.util.Set.of(com.jrobertgardzinski.security.domain.vo.Role.USER));
        // the floor is answered BEFORE the step-up as well as inside it: "you cannot do this at
        // all" is a better answer than "prove yourself again, and then you still cannot" — and it
        // costs no elevation to say
        if (compliance.removalWouldBreakFloor(caller, roles)) {
            return HttpResponse.<Map<String, Object>>status(io.micronaut.http.HttpStatus.CONFLICT)
                    .body(Map.of("status", "WOULD_BREAK_MFA_FLOOR"));
        }
        // dropping a factor weakens the account, so a stolen live session must step up to do it
        java.util.Optional<HttpResponse<Map<String, Object>>> stepUp =
                stepUpGuard.requireElevation(request, StepUpAction.REMOVE_FACTOR);
        if (stepUp.isPresent()) {
            return stepUp.get();
        }
        // and again INSIDE the transaction that removes. The check used to happen only outside it,
        // so two removals racing each other both read "one left over the floor" and both removed;
        // here the second sees what the first wrote. (Two transactions that START together can
        // still both read the old count under READ COMMITTED — closing that needs the account's own
        // lock, as the brute-force guard takes one: the same shape of race, far less reachable.)
        return transactionBoundary.execute(() -> {
            if (compliance.removalWouldBreakFloor(caller, roles)) {
                return HttpResponse.<Map<String, Object>>status(io.micronaut.http.HttpStatus.CONFLICT)
                        .body(Map.of("status", "WOULD_BREAK_MFA_FLOOR"));
            }
            enrolledFactors.remove(caller, factorType);
            return HttpResponse.ok(Map.of("status", "REMOVED"));
        });
    }

    private static HttpResponse<Map<String, Object>> respond(EnrolFactor.Result result) {
        return switch (result) {
            case EnrolFactor.Result.Started started -> {
                // a code factor sent a code (no display); a possession factor returns what to show (TOTP URI)
                Map<String, Object> body = started.display() == null
                        ? Map.of("status", "ENROLL_CODE_SENT")
                        : Map.of("status", "ENROLL_SETUP", "display", started.display());
                yield HttpResponse.accepted().body(body);
            }
            case EnrolFactor.Result.Enrolled enrolled ->
                    HttpResponse.ok(Map.of("status", "ENROLLED", "type", enrolled.type().value()));
            case EnrolFactor.Result.WrongProof wrong ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "WRONG_CODE"));
            case EnrolFactor.Result.NoPendingEnrolment none ->
                    HttpResponse.<Map<String, Object>>badRequest(Map.of("status", "NO_PENDING_ENROLMENT"));
            case EnrolFactor.Result.UnsupportedFactor unsupported ->
                    HttpResponse.<Map<String, Object>>badRequest(Map.of("status", "UNSUPPORTED_FACTOR"));
        };
    }

    private static Email caller(HttpRequest<?> request) {
        return Caller.of(request);
    }
}
