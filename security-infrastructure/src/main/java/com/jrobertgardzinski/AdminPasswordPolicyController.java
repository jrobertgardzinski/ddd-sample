package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;
import com.jrobertgardzinski.config.ladder.Resolution;
import com.jrobertgardzinski.security.domain.vo.Role;
import com.jrobertgardzinski.security.system.passwordpolicy.SetMinPasswordLength;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

import java.util.Map;
import java.util.Optional;

/**
 * Admin-only: the minimum password length as a live decision. POST sets it through the use case,
 * so the value object is the only gate and a refused length changes nothing. GET reports the value
 * IN FORCE with its provenance: which level answered and what was refused on the way, in the
 * gate's own words — how an admin learns that a row written at the database console is not the
 * value the system uses. The caller must be an ADMIN, and setting the policy takes a fresh
 * step-up, since it binds every future password.
 */
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/admin/settings/password")
final class AdminPasswordPolicyController {

    static final StepUpAction STEP_UP_ACTION = StepUpAction.ADMIN_SETTINGS;

    private final SetMinPasswordLength setMinPasswordLength;
    private final LadderedPasswordPolicy policy;
    private final RoleGuard roleGuard;
    private final StepUpGuard stepUpGuard;

    AdminPasswordPolicyController(SetMinPasswordLength setMinPasswordLength,
                                  LadderedPasswordPolicy policy,
                                  RoleGuard roleGuard, StepUpGuard stepUpGuard) {
        this.setMinPasswordLength = setMinPasswordLength;
        this.policy = policy;
        this.roleGuard = roleGuard;
        this.stepUpGuard = stepUpGuard;
    }

    @Get(value = "/min-length", produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> report(HttpRequest<?> request) {
        Optional<HttpResponse<Map<String, Object>>> notAnAdmin = roleGuard.require(request, Role.ADMIN);
        if (notAnAdmin.isPresent()) {
            return notAnAdmin.get();
        }
        return HttpResponse.ok(report(policy.minLengthResolution()));
    }

    @Post(value = "/min-length", consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> set(HttpRequest<?> request, @Body Map<String, Object> body) {
        Optional<HttpResponse<Map<String, Object>>> notAnAdmin = roleGuard.require(request, Role.ADMIN);
        if (notAnAdmin.isPresent()) {
            return notAnAdmin.get();
        }
        Optional<HttpResponse<Map<String, Object>>> stepUp = stepUpGuard.requireElevation(request, STEP_UP_ACTION);
        if (stepUp.isPresent()) {
            return stepUp.get();
        }
        int requested;
        try {
            requested = Integer.parseInt(String.valueOf(body.get("value")).trim());
        } catch (NumberFormatException notANumber) {
            return HttpResponse.badRequest(Map.of("status", "NOT_A_NUMBER"));
        }
        SetMinPasswordLength.Result result = setMinPasswordLength.execute(requested);
        if (result.status() == SetMinPasswordLength.Status.REFUSED) {
            return HttpResponse.badRequest(Map.of("status", "REFUSED", "reason", result.reason()));
        }
        return HttpResponse.ok(Map.of("status", "ACCEPTED", "value", result.minLength().value()));
    }

    private static Map<String, Object> report(Resolution<Integer> resolution) {
        return Map.of(
                "value", resolution.value(),
                "source", resolution.source(),
                "rejected", resolution.rejected().stream()
                        .map(r -> Map.<String, Object>of("source", r.source(), "value", r.value(), "reason", r.reason()))
                        .toList());
    }
}
