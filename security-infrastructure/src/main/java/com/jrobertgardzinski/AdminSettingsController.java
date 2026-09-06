package com.jrobertgardzinski;

import com.jrobertgardzinski.config.ConfigValue;
import com.jrobertgardzinski.config.Configuration;
import com.jrobertgardzinski.config.LiveKey;
import com.jrobertgardzinski.config.ladder.Resolution;
import com.jrobertgardzinski.security.domain.vo.Role;
import com.jrobertgardzinski.security.domain.vo.StepUpAction;
import com.jrobertgardzinski.security.system.settings.SetSetting;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Put;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Admin-only: every rule declared live, by its key. GET lists the catalogue with what is in force
 * under each key and its provenance - the level that answered and what was refused on the way.
 * PUT tells one rule a value by its key: the catalogue supplies the rule's own parser and gate,
 * so there is no code per rule and no rule an ADMIN can reach that the system does not read.
 * The value arrives as text, the way a property or a row holds it; a number or a flag in the
 * JSON is read as its text. A key nobody declared is 404, a value the rule refuses is 400 with
 * the gate's reason, and in both cases nothing is written. The caller must be an ADMIN, and
 * every write takes a fresh step-up, since a rule binds every future decision under it.
 */
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/admin/settings")
final class AdminSettingsController {

    static final StepUpAction STEP_UP_ACTION = StepUpAction.ADMIN_SETTINGS;

    private final SetSetting setSetting;
    private final Configuration configuration;
    private final RoleGuard roleGuard;
    private final StepUpGuard stepUpGuard;

    AdminSettingsController(SetSetting setSetting, Configuration configuration,
                            RoleGuard roleGuard, StepUpGuard stepUpGuard) {
        this.setSetting = setSetting;
        this.configuration = configuration;
        this.roleGuard = roleGuard;
        this.stepUpGuard = stepUpGuard;
    }

    @Get(produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> catalogue(HttpRequest<?> request) {
        Optional<HttpResponse<Map<String, Object>>> notAnAdmin = roleGuard.require(request, Role.ADMIN);
        if (notAnAdmin.isPresent()) {
            return notAnAdmin.get();
        }
        Map<String, Object> report = new LinkedHashMap<>();
        configuration.liveKeys().forEach((key, live) -> report.put(key, report(live)));
        return HttpResponse.ok(report);
    }

    @Put(value = "/{key}", consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> set(HttpRequest<?> request, @PathVariable String key, @Body Map<String, Object> body) {
        Optional<HttpResponse<Map<String, Object>>> notAnAdmin = roleGuard.require(request, Role.ADMIN);
        if (notAnAdmin.isPresent()) {
            return notAnAdmin.get();
        }
        Optional<HttpResponse<Map<String, Object>>> stepUp = stepUpGuard.requireElevation(request, STEP_UP_ACTION);
        if (stepUp.isPresent()) {
            return stepUp.get();
        }
        Object told = body.get("value");
        if (told == null) {
            return HttpResponse.badRequest(Map.of("status", "NO_VALUE"));
        }
        SetSetting.Result result = setSetting.execute(key, String.valueOf(told));
        return switch (result.status()) {
            case ACCEPTED -> HttpResponse.ok(Map.of("status", "ACCEPTED", "key", key, "value", result.value()));
            case REFUSED -> HttpResponse.badRequest(Map.of("status", "REFUSED", "key", key, "reason", result.reason()));
            case UNKNOWN_KEY -> HttpResponse.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("status", "UNKNOWN_KEY", "key", key, "reason", result.reason()));
        };
    }

    private static Map<String, Object> report(LiveKey live) {
        Resolution<? extends ConfigValue<?>> resolution = live.resolution();
        return Map.of(
                "value", resolution.value().value(),
                "source", resolution.source(),
                "rejected", resolution.rejected().stream()
                        .map(r -> Map.<String, Object>of("source", r.source(), "value", r.value(), "reason", r.reason()))
                        .toList());
    }
}
