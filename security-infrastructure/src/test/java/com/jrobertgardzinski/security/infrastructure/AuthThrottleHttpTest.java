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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * The window that bounds sign-in ITSELF, not just its failures. The per-account brute-force guard
 * counts wrong passwords and a correct one clears the count — so somebody who already holds the
 * password was free to open MFA tickets forever, each worth five guesses at the second factor and,
 * for a code factor, one more code mailed to the victim. One per-source window covers both halves
 * of the chain.
 */
@Epic("Throttling")
@Feature("Per-source throttle")
class AuthThrottleHttpTest {

    private static final String PASSWORD = "StrongPassword1!";

    private EmbeddedServer server;
    private BlockingHttpClient client;

    private void start(Map<String, Object> properties) {
        server = ApplicationContext.run(EmbeddedServer.class, properties, "test");
        client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();
    }

    @AfterEach
    void stop() {
        if (server != null) {
            server.close();
        }
    }

    @Test
    @DisplayName("past the window sign-in answers 429 + Retry-After, even with the correct password")
    void sign_in_is_capped_per_source() {
        start(Map.of("security.authentication.max-per-window", 2));
        String email = registerAndVerify("throttled@example.com");

        assertEquals(HttpStatus.OK, authenticate(email).getStatus());
        assertEquals(HttpStatus.OK, authenticate(email).getStatus());

        HttpResponse<Map> refused = authenticate(email);
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, refused.getStatus());
        assertNotNull(refused.getHeaders().get("Retry-After"), "a throttled caller is told when to come back");
    }

    @Test
    @DisplayName("opening tickets to guess the second factor runs out of window: /authenticate/factor shares it")
    void factor_submissions_spend_the_same_window() {
        start(Map.of("security.authentication.max-per-window", 4));
        String email = registerAndVerify("mfa-throttled@example.com");
        enrolEmailFactor(email);   // signs in once to reach the account page: call 1 of the window

        // the ticket is call 2 and the guesses are calls 3 and 4; the ticket still has three of its
        // five attempts left, and the window has none
        Map<?, ?> first = authenticate(email).getBody(Map.class).orElseThrow();
        assertEquals("EMAIL_CODE", first.get("nextFactor"));
        assertEquals(HttpStatus.UNAUTHORIZED, submitProof(first.get("mfaTicket"), "000000").getStatus());
        assertEquals(HttpStatus.UNAUTHORIZED, submitProof(first.get("mfaTicket"), "000001").getStatus());

        HttpResponse<Map> refused = submitProof(first.get("mfaTicket"), "000002");
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, refused.getStatus(),
                "guesses at the second factor must spend the same per-source window as sign-in");
        assertEquals("TOO_MANY_ATTEMPTS", refused.getBody(Map.class).orElseThrow().get("status"));
    }

    private String registerAndVerify(String email) {
        assertEquals(HttpStatus.CREATED,
                exchange(HttpRequest.POST("/register", Map.of("email", email, "password", PASSWORD))).getStatus());
        String token = server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(email);
        assertEquals(HttpStatus.OK, exchange(HttpRequest.POST("/verify-email", Map.of("token", token))).getStatus());
        return email;
    }

    /** Enrol the e-mail factor so the chain has a second link; enrolment does not touch this window. */
    private void enrolEmailFactor(String email) {
        String accessToken = (String) authenticate(email).getBody(Map.class).orElseThrow().get("accessToken");
        assertEquals(HttpStatus.OK, exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "enrol-factor", "password", PASSWORD))
                .header("Authorization", "Bearer " + accessToken)).getStatus());
        assertEquals(HttpStatus.ACCEPTED, exchange(HttpRequest.POST("/account/factors/EMAIL_CODE/enroll/start", Map.of())
                .header("Authorization", "Bearer " + accessToken)).getStatus());
        String code = server.getApplicationContext().getBean(CapturingEmailCodeChannel.class).lastCodeFor(email);
        assertEquals(HttpStatus.OK, exchange(HttpRequest.POST("/account/factors/EMAIL_CODE/enroll/confirm",
                Map.of("code", code)).header("Authorization", "Bearer " + accessToken)).getStatus());
    }

    private HttpResponse<Map> authenticate(String email) {
        return exchange(HttpRequest.POST("/authenticate", Map.of("email", email, "password", PASSWORD)));
    }

    private HttpResponse<Map> submitProof(Object ticket, String proof) {
        return exchange(HttpRequest.POST("/authenticate/factor", Map.of("mfaTicket", ticket, "proof", proof)));
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
