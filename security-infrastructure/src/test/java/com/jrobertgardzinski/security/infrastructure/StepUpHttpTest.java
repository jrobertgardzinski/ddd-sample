package com.jrobertgardzinski.security.infrastructure;

import com.jrobertgardzinski.CapturingEmailCodeChannel;
import com.jrobertgardzinski.CapturingEmailVerificationNotifier;
import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Step-up authentication guards a sensitive action. Deleting an account (FULL_CHAIN) is refused on
 * a merely-live session — the caller must re-prove themselves first: the password, and then any
 * enrolled factors. A wrong password does not elevate; passing the chain elevates the token once,
 * which the delete then consumes.
 */
@Epic("Authentication")
@Feature("Step-up")
class StepUpHttpTest {

    private static final String PASSWORD = "StrongPassword1!";

    private EmbeddedServer server;
    private BlockingHttpClient client;

    @BeforeEach
    void start() {
        server = ApplicationContext.run(EmbeddedServer.class, "test");
        client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();
    }

    @AfterEach
    void stop() {
        if (server != null) {
            server.close();
        }
    }

    @Test
    @DisplayName("a live session cannot delete without stepping up; a wrong password does not elevate")
    void delete_needs_step_up() {
        String email = "stepper@example.com";
        String token = onboard(email);

        // straight to delete → refused, told to step up
        HttpResponse<Map> refused = delete(token);
        assertEquals(HttpStatus.FORBIDDEN, refused.getStatus());
        assertEquals("STEP_UP_REQUIRED", refused.getBody(Map.class).orElseThrow().get("status"));

        // wrong password does not elevate; delete still refused
        HttpResponse<Map> wrong = exchange(HttpRequest.POST("/account/step-up",
                Map.of("action", "delete-account", "password", "WrongButStrong1!"))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.UNAUTHORIZED, wrong.getStatus());
        assertEquals(HttpStatus.FORBIDDEN, delete(token).getStatus());

        // the right password (no factors here) elevates at once; delete goes through
        HttpResponse<Map> elevated = exchange(HttpRequest.POST("/account/step-up",
                Map.of("action", "delete-account", "password", PASSWORD))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.OK, elevated.getStatus());
        assertEquals("ELEVATED", elevated.getBody(Map.class).orElseThrow().get("status"));
        assertEquals(HttpStatus.ACCEPTED, delete(token).getStatus());
    }

    @Test
    @DisplayName("with a factor enrolled, step-up walks the chain before it elevates")
    void step_up_walks_the_factor_chain() {
        String email = "stepper-2fa@example.com";
        String token = onboard(email);
        enrolEmailFactor(email, token);

        // FULL_CHAIN: password first → a factor is now due, not an elevation yet
        HttpResponse<Map> started = exchange(HttpRequest.POST("/account/step-up",
                Map.of("action", "delete-account", "password", PASSWORD))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.ACCEPTED, started.getStatus());
        Map<?, ?> body = started.getBody(Map.class).orElseThrow();
        assertEquals("FACTOR_REQUIRED", body.get("status"));
        assertEquals("EMAIL_CODE", body.get("nextFactor"));

        // the mailed code completes the step-up and elevates; delete then works
        String code = server.getApplicationContext().getBean(CapturingEmailCodeChannel.class).lastCodeFor(email);
        HttpResponse<Map> done = exchange(HttpRequest.POST("/account/step-up/factor",
                Map.of("stepUpTicket", body.get("stepUpTicket"), "proof", code))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.OK, done.getStatus());
        assertEquals("ELEVATED", done.getBody(Map.class).orElseThrow().get("status"));
        assertEquals(HttpStatus.ACCEPTED, delete(token).getStatus());
    }

    @Test
    @DisplayName("an unknown action is refused outright; an elevation earned for another action does not unlock delete (poz. 1)")
    void a_stolen_token_cannot_delete_via_a_cheap_or_unknown_action() {
        String email = "poz1@example.com";
        String token = onboard(email);   // has a password, no factors

        // an action outside the catalogue is a client error - no elevation is ever minted for it,
        // so there is nothing to fall open or closed on
        HttpResponse<Map> unknown = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "some-unknown-action", "password", PASSWORD))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.BAD_REQUEST, unknown.getStatus());
        assertEquals("UNKNOWN_ACTION", unknown.getBody(Map.class).orElseThrow().get("status"));

        // a catalogue action at FULL_CHAIN never elevates without the password
        HttpResponse<Map> noPassword = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "admin-reset"))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.UNAUTHORIZED, noPassword.getStatus());

        // even WITH the password, the elevation is minted for that action alone
        HttpResponse<Map> elevated = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "admin-reset", "password", PASSWORD))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.OK, elevated.getStatus());

        // and it must NOT open delete-account - the delete still demands its own step-up
        assertEquals(HttpStatus.FORBIDDEN, delete(token).getStatus());
    }

    @Test
    @DisplayName("a step-up ticket left to age past its TTL is refused (poz. 23)")
    void an_expired_step_up_ticket_is_refused() {
        String email = "poz23@example.com";
        String token = onboard(email);
        enrolEmailFactor(email, token);

        // FULL_CHAIN: the password is right → a factor is due, a ticket is issued
        HttpResponse<Map> started = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "delete-account", "password", PASSWORD))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.ACCEPTED, started.getStatus());
        Map<?, ?> body = started.getBody(Map.class).orElseThrow();

        // let the ticket age past its 10-minute TTL (the access token lives an hour, so it stays valid)
        exchange(HttpRequest.POST("/test/clock/advance", Map.of("duration", "PT11M")));

        String code = server.getApplicationContext().getBean(CapturingEmailCodeChannel.class).lastCodeFor(email);
        HttpResponse<Map> late = exchange(HttpRequest.POST("/account/step-up/factor",
                        Map.of("stepUpTicket", body.get("stepUpTicket"), "proof", code))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.UNAUTHORIZED, late.getStatus());
        assertEquals("INVALID_TICKET", late.getBody(Map.class).orElseThrow().get("status"));
    }

    // --- Helpers --------------------------------------------------------------

    private HttpResponse<Map> delete(String token) {
        return exchange(HttpRequest.POST("/account/delete", null).header("Authorization", "Bearer " + token));
    }

    private String onboard(String email) {
        exchange(HttpRequest.POST("/register", Map.of("email", email, "password", PASSWORD)));
        String verificationToken = server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(email);
        exchange(HttpRequest.POST("/verify-email", Map.of("token", verificationToken)));
        return (String) exchange(HttpRequest.POST("/authenticate", Map.of("email", email, "password", PASSWORD)))
                .getBody(Map.class).orElseThrow().get("accessToken");
    }

    private void enrolEmailFactor(String email, String token) {
        // enrolment sits behind a step-up now (a stolen session must not silently add a factor); a
        // factor-less account elevates on the password alone
        HttpResponse<Map> elevated = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "enrol-factor", "password", PASSWORD))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.OK, elevated.getStatus());
        exchange(HttpRequest.POST("/account/factors/EMAIL_CODE/enroll/start", Map.of())
                .header("Authorization", "Bearer " + token));
        String code = server.getApplicationContext().getBean(CapturingEmailCodeChannel.class).lastCodeFor(email);
        exchange(HttpRequest.POST("/account/factors/EMAIL_CODE/enroll/confirm", Map.of("code", code))
                .header("Authorization", "Bearer " + token));
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<Map> exchange(HttpRequest<?> request) {
        try {
            return client.exchange(request, Map.class);
        } catch (HttpClientResponseException e) {
            return (HttpResponse<Map>) e.getResponse();
        }
    }
}
