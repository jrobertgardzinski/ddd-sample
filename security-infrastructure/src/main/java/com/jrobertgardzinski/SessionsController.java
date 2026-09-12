package com.jrobertgardzinski;


import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.vo.ActiveSession;
import com.jrobertgardzinski.security.system.session.ListActiveSessions;
import com.jrobertgardzinski.security.system.session.RevokeAllSessions;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;

import java.util.List;
import java.util.Map;

/**
 * HTTP entry point for the caller's own sessions. A protected resource: {@link AuthorizationFilter}
 * has already authorized the access token and published the caller's email. {@code GET /sessions}
 * lists the active sessions; {@code POST /sessions/revoke-all} logs out everywhere (the presented
 * access token is itself one of the sessions revoked, so it stops working right after).
 */
// controllers do blocking work (JDBC, the mail service's HTTP client) — keep it off the event loop
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/sessions")
final class SessionsController {

    private final ListActiveSessions listActiveSessions;
    private final RevokeAllSessions revokeAllSessions;
    private final TransactionBoundary transactionBoundary;

    SessionsController(ListActiveSessions listActiveSessions, RevokeAllSessions revokeAllSessions,
                       TransactionBoundary transactionBoundary) {
        this.listActiveSessions = listActiveSessions;
        this.revokeAllSessions = revokeAllSessions;
        this.transactionBoundary = transactionBoundary;
    }

    @Get(produces = MediaType.APPLICATION_JSON)
    public HttpResponse<Map<String, Object>> list(HttpRequest<?> request) {
        Email email = Caller.of(request);
        List<Map<String, Object>> sessions = listActiveSessions.execute(email).stream()
                .map(SessionsController::toJson)
                .toList();
        return HttpResponse.ok(Map.of("sessions", sessions));
    }

    @Post(value = "/revoke-all", consumes = MediaType.ALL, produces = MediaType.APPLICATION_JSON)
    public HttpResponse<Map<String, Object>> revokeAll(HttpRequest<?> request) {
        String email = Caller.of(request).value();
        transactionBoundary.execute(() -> {
            revokeAllSessions.execute(Email.of(email));
            return null;
        });
        return HttpResponse.ok(Map.of("status", "ALL_SESSIONS_REVOKED"));
    }

    private static Map<String, Object> toJson(ActiveSession session) {
        return Map.of(
                "family", session.family().value().toString(),
                "expiresAt", session.refreshTokenExpiration().value().toString());
    }
}
