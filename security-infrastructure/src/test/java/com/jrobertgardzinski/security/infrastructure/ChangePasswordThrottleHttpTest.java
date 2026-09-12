package com.jrobertgardzinski.security.infrastructure;

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
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Changing a password is authorized, not unlimited. The endpoint verifies the CURRENT password with
 * a full Argon2 and says whether the guess was right, so with a stolen access token it answers the
 * one question a thief still has — and a right answer is a takeover, because the change revokes
 * every session, the owner's included. Past the window it answers 429 + Retry-After instead.
 *
 * <p>Pinned here rather than in {@code change-password.feature} for the reason every other throttle
 * is pinned in a test of its own: the limit is a deployment-level number, and the scenario would
 * have to boot its own server to set it.
 */
@Epic("Throttling")
@Feature("Per-source throttle")
class ChangePasswordThrottleHttpTest {

    private static final String PASSWORD = "StrongPassword1!";
    private static final String EMAIL = "oracle@example.com";

    private EmbeddedServer server;
    private BlockingHttpClient client;
    private String accessToken;

    @BeforeEach
    void start() {
        server = ApplicationContext.run(EmbeddedServer.class,
                Map.of("security.change-password.max-per-window", 2), "test");
        client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

        assertEquals(HttpStatus.CREATED,
                exchange(HttpRequest.POST("/register", Map.of("email", EMAIL, "password", PASSWORD))).getStatus());
        String token = server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(EMAIL);
        assertEquals(HttpStatus.OK, exchange(HttpRequest.POST("/verify-email", Map.of("token", token))).getStatus());
        accessToken = (String) exchange(HttpRequest.POST("/authenticate", Map.of("email", EMAIL, "password", PASSWORD)))
                .getBody(Map.class).orElseThrow().get("accessToken");
    }

    @AfterEach
    void stop() {
        if (server != null) {
            server.close();
        }
    }

    @Test
    @DisplayName("guessing the current password runs out of window: 429 + Retry-After, not another Argon2")
    void the_password_oracle_is_capped() {
        assertEquals(HttpStatus.BAD_REQUEST, change("WrongPassword1!").getStatus());
        assertEquals(HttpStatus.BAD_REQUEST, change("WrongPassword2!").getStatus());

        HttpResponse<Map> refused = change("WrongPassword3!");
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, refused.getStatus(),
                "an authorized caller may still not guess the password at full speed");
        assertEquals("TOO_MANY_ATTEMPTS", refused.getBody(Map.class).orElseThrow().get("status"));
        assertNotNull(refused.getHeaders().get("Retry-After"));
    }

    @Test
    @DisplayName("the window counts attempts, not outcomes: a successful change spends one too")
    void a_correct_change_spends_the_window() {
        String newPassword = "BrandNewPassword1!";
        assertEquals(HttpStatus.OK, change(PASSWORD).getStatus(), "the owner's own change goes through");

        // the change revoked every session, this token included, so the owner signs in again —
        // /authenticate has a window of its own and does not refund this one
        accessToken = (String) exchange(HttpRequest.POST("/authenticate",
                        Map.of("email", EMAIL, "password", newPassword))
                ).getBody(Map.class).orElseThrow().get("accessToken");

        assertEquals(HttpStatus.BAD_REQUEST, change("WrongPassword1!").getStatus(),
                "one attempt is left: the successful change spent the other");
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, change("WrongPassword2!").getStatus(),
                "and the window is spent, however the attempts in it ended");
    }

    private HttpResponse<Map> change(String currentPassword) {
        return exchange(HttpRequest.POST("/account/password",
                        Map.of("currentPassword", currentPassword, "newPassword", "BrandNewPassword1!"))
                .header("Authorization", "Bearer " + accessToken));
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
