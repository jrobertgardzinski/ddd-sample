package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;


import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.repository.RecoveryCodeRepository;
import com.jrobertgardzinski.security.system.mfa.GenerateRecoveryCodes;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

import java.util.List;
import java.util.Map;

/**
 * A signed-in user's recovery codes: {@code POST} mints a fresh batch — the plain codes appear in
 * this one response and never again (only hashes are stored); any previous batch dies with it.
 * {@code GET} says how many remain unspent. {@link AuthorizationFilter} has already authorized
 * the caller; the codes are always their own.
 */
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/account/recovery-codes")
final class RecoveryCodesController {

    private final GenerateRecoveryCodes generateRecoveryCodes;
    private final RecoveryCodeRepository recoveryCodes;
    private final TransactionBoundary transactionBoundary;
    private final StepUpGuard stepUpGuard;

    RecoveryCodesController(GenerateRecoveryCodes generateRecoveryCodes,
                            RecoveryCodeRepository recoveryCodes,
                            TransactionBoundary transactionBoundary,
                            StepUpGuard stepUpGuard) {
        this.generateRecoveryCodes = generateRecoveryCodes;
        this.recoveryCodes = recoveryCodes;
        this.transactionBoundary = transactionBoundary;
        this.stepUpGuard = stepUpGuard;
    }

    @Post(produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> generate(HttpRequest<?> request) {
        // recovery codes are spare keys: shown once, and each one signs in when a factor is out of
        // reach. A merely-live session must not be able to mint itself a set and keep them.
        java.util.Optional<HttpResponse<Map<String, Object>>> stepUp =
                stepUpGuard.requireElevation(request, StepUpAction.GENERATE_RECOVERY_CODES);
        if (stepUp.isPresent()) {
            return stepUp.get();
        }
        Email caller = caller(request);
        List<String> plainCodes = transactionBoundary.execute(() -> generateRecoveryCodes.execute(caller));
        return HttpResponse.ok(Map.of("status", "GENERATED", "codes", plainCodes));
    }

    @Get(produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> remaining(HttpRequest<?> request) {
        return HttpResponse.ok(Map.of("unused", recoveryCodes.unusedCount(caller(request))));
    }

    private static Email caller(HttpRequest<?> request) {
        return Caller.of(request);
    }
}
