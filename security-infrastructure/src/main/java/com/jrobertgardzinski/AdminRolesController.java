package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;


import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.vo.Role;
import com.jrobertgardzinski.security.system.roles.SetUserRoles;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Put;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Admin-only: grant or revoke another user's roles. {@link AuthorizationFilter} has already
 * authorized the caller; {@link RoleGuard} adds the second gate — the caller must themselves be an
 * ADMIN, from a persisted grant or the deployment's bootstrap list, which breaks the
 * chicken-and-egg: a bootstrap admin is ADMIN before any grant and can hand out roles to everyone else.
 */
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/admin/users")
final class AdminRolesController {

    private final SetUserRoles setUserRoles;
    private final RoleGuard roleGuard;
    private final StepUpGuard stepUpGuard;

    AdminRolesController(SetUserRoles setUserRoles, RoleGuard roleGuard, StepUpGuard stepUpGuard) {
        this.setUserRoles = setUserRoles;
        this.roleGuard = roleGuard;
        this.stepUpGuard = stepUpGuard;
    }

    @Put(value = "/{email}/roles", consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    HttpResponse<?> setRoles(HttpRequest<?> request, @PathVariable String email, @Body Map<String, Object> body) {
        java.util.Optional<HttpResponse<Map<String, Object>>> notAnAdmin = roleGuard.require(request, Role.ADMIN);
        if (notAnAdmin.isPresent()) {
            return notAnAdmin.get();
        }
        // BEFORE the step-up guard, which CONSUMES a one-shot elevation: an address with a typo in
        // it used to be parsed after, so the request died on the address (a 500, at that) with the
        // elevation already spent — and the retry needed the whole chain walked again.
        Email target;
        try {
            target = Email.of(email);
        } catch (IllegalArgumentException notAnAddress) {
            return HttpResponse.badRequest(Map.of("status", "INVALID_EMAIL"));
        }
        Set<Role> roles;
        try {
            roles = parseRoles(body.get("roles"));
        } catch (IllegalArgumentException unknownRole) {
            // the roles that exist, not the exception's sentence — which named the enum's class
            return HttpResponse.badRequest(Map.of("status", "UNKNOWN_ROLE",
                    "roles", java.util.Arrays.stream(Role.values()).map(Role::name).sorted().toList()));
        }
        // AFTER the role check, so a non-admin still learns only that they are not an admin. A
        // granted role is a permanent widening of what a session may do, so a stolen admin session
        // must prove itself again before handing that out — the same rule the factor reset next
        // door already follows.
        java.util.Optional<HttpResponse<Map<String, Object>>> stepUp =
                stepUpGuard.requireElevation(request, StepUpAction.ADMIN_ROLES);
        if (stepUp.isPresent()) {
            return stepUp.get();
        }
        SetUserRoles.Result result = setUserRoles.execute(target, roles);
        if (result.status() == SetUserRoles.Status.NO_SUCH_USER) {
            return HttpResponse.notFound(Map.of("status", "NO_SUCH_USER"));
        }
        return HttpResponse.ok(Map.of("email", email,
                "roles", result.roles().stream().map(Role::name).sorted().toList()));
    }

    @SuppressWarnings("unchecked")
    private static Set<Role> parseRoles(Object raw) {
        if (!(raw instanceof List<?> list)) {
            throw new IllegalArgumentException("roles must be a list");
        }
        return ((List<Object>) list).stream()
                .map(o -> Role.valueOf(String.valueOf(o).trim().toUpperCase(Locale.ROOT)))
                .collect(Collectors.toUnmodifiableSet());
    }
}
