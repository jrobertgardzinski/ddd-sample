package com.jrobertgardzinski.security.infrastructure;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An address the domain cannot even read is a typo, not a fault of the server.
 *
 * Every endpoint that builds an {@code Email} straight from the request body used to let the value
 * object's exception escape: {@code "xyz"} came back as 500 with the domain's own sentence in the
 * body, and each attempt left a stack trace in the log. The answer belongs to the endpoint's own
 * vocabulary instead — the sign-in door answers like any other failed sign-in, and the two quiet
 * request doors stay quiet, because an answer reserved for malformed input is still a different
 * answer for SOME inputs.
 *
 * The addresses below are refused by different rules on purpose (no '@', a domain without a dot, a
 * dot at the edge, two dots in a row), so the test pins the BEHAVIOUR at the boundary rather than
 * one rule's spelling.
 */
@Epic("Registration")
@Feature("Malformed input at the HTTP boundary")
class MalformedEmailHttpTest {

    /** A body whose field carries the wrong JSON type, or no field at all. */
    private static final String NUMBER_INSTEAD_OF_TEXT = "{\"email\": 123, \"token\": 456, \"password\": 789}";
    private static final String NOTHING_AT_ALL = "{}";

    private EmbeddedServer server;
    private BlockingHttpClient client;

    @BeforeEach
    void start() {
        server = ApplicationContext.run(EmbeddedServer.class, "test");
        client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();
    }

    @AfterEach
    void stop() {
        client.close();
        server.close();
    }

    @ParameterizedTest(name = "signing in with \"{0}\"")
    @ValueSource(strings = {"xyz", "user@wp", ".lead@wp.pl", "a..b@wp.pl", ""})
    @DisplayName("a sign-in with an unreadable address is refused like any other, not with a 500")
    void signInAnswersLikeAWrongPassword(String email) {
        HttpResponse<?> response = exchange(HttpRequest.POST("/authenticate",
                Map.of("email", email, "password", "StrongPassword1!")));

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatus(),
                "a malformed address must answer exactly like an unknown account");
    }

    @ParameterizedTest(name = "asking for a verification link for \"{0}\"")
    @ValueSource(strings = {"xyz", "user@wp", "a..b@wp.pl"})
    @DisplayName("a verification request stays quiet, malformed address or not")
    void verificationRequestStaysQuiet(String email) {
        assertSameAsForAValidAddress("/verify-email/request", email, "VERIFICATION_LINK_SENT");
    }

    @ParameterizedTest(name = "asking for a reset link for \"{0}\"")
    @ValueSource(strings = {"xyz", "user@wp", "a..b@wp.pl"})
    @DisplayName("a reset request stays quiet, malformed address or not")
    void resetRequestStaysQuiet(String email) {
        assertSameAsForAValidAddress("/reset-password/request", email, "RESET_LINK_SENT");
    }

    /** The doors that answer in their own vocabulary: a malformed request is REFUSED, 4xx. */
    private static final List<String> REFUSING = List.of("/authenticate", "/verify-email", "/reset-password");

    /**
     * The two doors that answer the same thing to everybody — on purpose. An answer reserved for
     * malformed input is still a different answer for SOME inputs, and these two exist precisely so
     * that nobody can learn anything by asking: they accept, and the truth goes by mail or not at
     * all. So what is pinned here is that the quiet answer stays quiet, not that it becomes a 400.
     */
    private static final List<String> QUIET = List.of("/verify-email/request", "/reset-password/request");

    @ParameterizedTest(name = "POST {0} with a number where text belongs")
    @MethodSource("refusingDoors")
    @DisplayName("a field sent with the wrong JSON type is refused in the endpoint's own words")
    void wrongJsonTypeIsRefused(String path) {
        assertRefused(path, NUMBER_INSTEAD_OF_TEXT);
    }

    @ParameterizedTest(name = "POST {0} with an empty body")
    @MethodSource("refusingDoors")
    @DisplayName("a missing field is refused in the endpoint's own words")
    void missingFieldIsRefused(String path) {
        assertRefused(path, NOTHING_AT_ALL);
    }

    @ParameterizedTest(name = "POST {0} with a malformed body")
    @MethodSource("quietDoors")
    @DisplayName("the quiet doors stay quiet: the same 202 as for a perfectly good address")
    void theQuietDoorsStayQuiet(String path) {
        for (String body : List.of(NUMBER_INSTEAD_OF_TEXT, NOTHING_AT_ALL)) {
            HttpResponse<?> response = exchange(
                    HttpRequest.POST(path, body).contentType(MediaType.APPLICATION_JSON));
            assertEquals(HttpStatus.ACCEPTED, response.getStatus(),
                    path + " must answer malformed input exactly as it answers a stranger's address");
            assertNoInternalSentence(path, response);
        }
    }

    static java.util.stream.Stream<String> refusingDoors() {
        return REFUSING.stream();
    }

    static java.util.stream.Stream<String> quietDoors() {
        return QUIET.stream();
    }

    /**
     * A malformed request is REFUSED — not redirected, not obeyed, and never answered with the
     * inside of the service. "Not a 500" was the whole assertion until 2026-09-12, and a 301 to a
     * login page or a 200 that quietly did the thing would both have passed it.
     */
    private void assertRefused(String path, String body) {
        HttpResponse<?> response = exchange(HttpRequest.POST(path, body).contentType(MediaType.APPLICATION_JSON));

        int status = response.getStatus().getCode();
        assertTrue(status >= 400 && status < 500,
                () -> path + " answered " + response.getStatus() + " for " + body
                        + " — a malformed request is refused, not redirected and not obeyed");
        assertNoInternalSentence(path, response);
    }

    private void assertNoInternalSentence(String path, HttpResponse<?> response) {
        String answered = String.valueOf(response.getBody(String.class).orElse(""));
        assertFalse(answered.contains("Exception") || answered.contains("com.jrobertgardzinski")
                        || answered.toLowerCase().contains("cannot invoke"),
                () -> path + " quoted the inside of the service back at the caller: " + answered);
    }


    /** The malformed attempt must be indistinguishable from one for a well-formed stranger. */
    private void assertSameAsForAValidAddress(String path, String malformed, String expectedStatus) {
        HttpResponse<Map> stranger = exchange(HttpRequest.POST(path, Map.of("email", "nobody@example.com")));
        HttpResponse<Map> broken = exchange(HttpRequest.POST(path, Map.of("email", malformed)));

        assertEquals(HttpStatus.ACCEPTED, broken.getStatus());
        assertEquals(stranger.getStatus(), broken.getStatus());
        assertEquals(Map.of("status", expectedStatus), broken.getBody(Map.class).orElseThrow());
        assertEquals(stranger.getBody(Map.class).orElseThrow(), broken.getBody(Map.class).orElseThrow(),
                "an answer reserved for malformed input would be a way to probe the door");
    }

    @SuppressWarnings("unchecked")
    private <T> HttpResponse<T> exchange(HttpRequest<?> request) {
        try {
            return (HttpResponse<T>) client.exchange(request, Map.class);
        } catch (HttpClientResponseException e) {
            return (HttpResponse<T>) e.getResponse();
        }
    }
}
