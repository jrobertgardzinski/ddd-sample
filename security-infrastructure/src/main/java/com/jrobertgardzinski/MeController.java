package com.jrobertgardzinski;


import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Role;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.http.annotation.Get;

import java.util.List;
import java.util.Map;

/**
 * A protected resource: returns who the caller is AND what roles they hold — the source of truth
 * other services read to gate moderator/admin actions. Reaching this controller means
 * {@link AuthorizationFilter} already authorized the access token and published the email; here we
 * read it back and look up the user's roles.
 */
// controllers do blocking work (JDBC, the mail service's HTTP client) — keep it off the event loop
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/me")
final class MeController {

    private final com.jrobertgardzinski.security.system.roles.RequireRole roles;
    private final com.jrobertgardzinski.security.system.mfa.MfaCompliance compliance;

    MeController(com.jrobertgardzinski.security.system.roles.RequireRole roles,
                 com.jrobertgardzinski.security.system.mfa.MfaCompliance compliance) {
        this.roles = roles;
        this.compliance = compliance;
    }

    @Get(produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> me(HttpRequest<?> request) {
        Email email = Caller.of(request);
        // rolesInForce, not the persisted grants: a BOOTSTRAP ADMIN holds ADMIN by configuration and
        // has no row saying so. Reading the row alone told such an administrator they were a plain
        // USER — here and in the JWT — while /admin/** let them in, so every consumer that gates on
        // this answer disagreed with the service that issued it.
        java.util.Set<Role> roleSet = this.roles.rolesInForce(email);
        List<String> roles = roleSet.stream().map(Role::name).sorted().toList();
        // the MFA role floor, so consumers and the UI can nudge an under-protected privileged account
        return HttpResponse.ok(Map.of(
                "email", email.value(),
                "roles", roles,
                "mfaCompliant", compliance.isCompliant(email, roleSet),
                "requiredFactors", compliance.requiredFactors(roleSet),
                "haveFactors", compliance.effectiveFactorCount(email)));
    }
}
