package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;


import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.repository.EnrolledFactorRepository;
import com.jrobertgardzinski.security.domain.vo.Role;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Put;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

import java.util.Map;
import java.util.Optional;

/**
 * Admin-only: reset another user's MFA factors — the recovery path when someone is locked out of
 * every factor (lost phone, etc.). The caller must be an ADMIN ({@link RoleGuard}: a persisted role
 * or the deployment's bootstrap list) and must have just STEPPED UP, since wiping a user's factors drops them below their
 * role floor and forces re-enrolment. Same double gate as granting roles, plus step-up.
 */
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/admin/users")
final class AdminFactorsController {

    private final EnrolledFactorRepository factors;
    private final RoleGuard roleGuard;
    private final StepUpGuard stepUpGuard;
    private final TransactionBoundary transactionBoundary;

    AdminFactorsController(EnrolledFactorRepository factors, RoleGuard roleGuard, StepUpGuard stepUpGuard,
                           TransactionBoundary transactionBoundary) {
        this.factors = factors;
        this.roleGuard = roleGuard;
        this.stepUpGuard = stepUpGuard;
        this.transactionBoundary = transactionBoundary;
    }

    @Put(value = "/{email}/factors/reset", produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> reset(HttpRequest<?> request, @PathVariable String email) {
        Optional<HttpResponse<Map<String, Object>>> notAnAdmin = roleGuard.require(request, Role.ADMIN);
        if (notAnAdmin.isPresent()) {
            return notAnAdmin.get();
        }
        Optional<HttpResponse<Map<String, Object>>> stepUp = stepUpGuard.requireElevation(request, StepUpAction.ADMIN_RESET);
        if (stepUp.isPresent()) {
            return stepUp.get();
        }
        transactionBoundary.execute(() -> {
            factors.removeAll(Email.of(email));
            return null;
        });
        return HttpResponse.ok(Map.of("status", "FACTORS_RESET", "user", email));
    }
}
