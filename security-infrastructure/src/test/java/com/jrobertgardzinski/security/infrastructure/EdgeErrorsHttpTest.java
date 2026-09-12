package com.jrobertgardzinski.security.infrastructure;

import com.jrobertgardzinski.CapturingEmailVerificationNotifier;
import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.cookie.Cookie;
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

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Nothing a client can type is an Internal Server Error, and no refusal quotes the service back at
 * the caller. The module had no exception handler at all, so a missing field, a blank one, an empty
 * cookie or an address with a typo each answered 500 carrying a value object's own sentence.
 *
 * <p>The endpoints below are the ones the review walked: the two ticket adapters, the password
 * adapter, the refresh cookie, and /me with the trailing slash the filter's pattern did not match.
 */
@Epic("HTTP edge")
@Feature("One error shape, no 500 for a client's mistake")
class EdgeErrorsHttpTest {

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
    @DisplayName("a factor proof without a ticket is a 400, not a 500 from ConcurrentHashMap.get(null)")
    void the_ticket_adapters_refuse_instead_of_breaking() {
        assertEquals(HttpStatus.BAD_REQUEST, post("/authenticate/factor", Map.of()).getStatus());
        assertEquals(HttpStatus.BAD_REQUEST, post("/authenticate/factor", blank("mfaTicket", "proof")).getStatus());

        String token = registerVerifyAuthenticate("edge-ticket@example.com");
        assertEquals(HttpStatus.BAD_REQUEST, authed("/account/step-up/factor", Map.of(), token).getStatus());
        assertEquals(HttpStatus.BAD_REQUEST,
                authed("/account/step-up/factor", blank("stepUpTicket", "proof"), token).getStatus());
    }

    @Test
    @DisplayName("a blank password is answered the way an absent one always was, not with 500")
    void the_password_adapters_refuse_instead_of_breaking() {
        String token = registerVerifyAuthenticate("edge-password@example.com");

        assertEquals(HttpStatus.BAD_REQUEST,
                authed("/account/password", blank("currentPassword", "newPassword"), token).getStatus());
        assertEquals(HttpStatus.BAD_REQUEST, authed("/account/password", Map.of(), token).getStatus());

        // step-up answers 401 for a password it did not get — absent or blank, one situation
        Map<String, Object> blankPassword = new HashMap<>(Map.of("action", "enrol-factor"));
        blankPassword.put("password", "");
        assertEquals(HttpStatus.UNAUTHORIZED, authed("/account/step-up", blankPassword, token).getStatus());
    }

    @Test
    @DisplayName("GET /me/ is filtered like /me: 401 without a token, never an unfiltered 500")
    void the_trailing_slash_does_not_slip_past_the_filter() {
        HttpResponse<Map> answered = exchange(HttpRequest.GET("/me/"));
        assertEquals(HttpStatus.UNAUTHORIZED, answered.getStatus());
    }

    @Test
    @DisplayName("an empty refresh cookie — the shape logout leaves behind — is 401 and 200, not 500")
    void an_empty_cookie_is_no_cookie() {
        HttpResponse<Map> refreshed = exchange(
                HttpRequest.POST("/refresh", null).cookie(Cookie.of("refresh_token", "")));
        assertEquals(HttpStatus.UNAUTHORIZED, refreshed.getStatus());

        HttpResponse<Map> loggedOut = exchange(
                HttpRequest.POST("/logout", null).cookie(Cookie.of("refresh_token", "")));
        assertEquals(HttpStatus.OK, loggedOut.getStatus());
    }

    @Test
    @DisplayName("no refusal quotes the service back at the caller")
    void refusals_carry_no_internal_message() {
        String body = String.valueOf(post("/authenticate/factor", Map.of()).getBody(Map.class).orElseThrow());
        assertTrue(body.contains("BAD_REQUEST"), "the shape is one fixed code: " + body);
        assertFalse(body.toLowerCase().contains("null"), "an internal sentence must not travel: " + body);
    }

    private static Map<String, Object> blank(String... fields) {
        Map<String, Object> body = new HashMap<>();
        for (String field : fields) {
            body.put(field, "  ");
        }
        return body;
    }

    private String registerVerifyAuthenticate(String email) {
        assertEquals(HttpStatus.CREATED, post("/register", Map.of("email", email, "password", PASSWORD)).getStatus());
        String token = server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(email);
        assertEquals(HttpStatus.OK, post("/verify-email", Map.of("token", token)).getStatus());
        return (String) post("/authenticate", Map.of("email", email, "password", PASSWORD))
                .getBody(Map.class).orElseThrow().get("accessToken");
    }

    private HttpResponse<Map> post(String path, Map<String, ?> body) {
        return exchange(HttpRequest.POST(path, body));
    }

    private HttpResponse<Map> authed(String path, Map<String, ?> body, String token) {
        return exchange(HttpRequest.POST(path, body).header("Authorization", "Bearer " + token));
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
