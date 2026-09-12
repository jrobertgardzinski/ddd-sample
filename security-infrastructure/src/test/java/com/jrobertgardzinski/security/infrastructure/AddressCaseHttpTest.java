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
 * One person, one account, however they hold the shift key.
 *
 * <p>The local part used to be lower-cased only for gmail, yahoo, outlook and icloud — so on every
 * other domain {@code Alice@corp.com} and {@code alice@corp.com} were two identities. The person who
 * capitalised their own name on the day they signed up was told "wrong e-mail or password" ever
 * after if they later typed it in lower case, and could not register again either, because the
 * quiet duplicate-refusal answered them as a fresh registration.
 */
@Epic("Registration")
@Feature("An address is the same address in any case")
class AddressCaseHttpTest {

    private static final String PASSWORD = "StrongPassword1!";
    private static final String AS_TYPED = "Alice.Brown@corp.example";
    private static final String IN_LOWER_CASE = "alice.brown@corp.example";

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
    @DisplayName("an account registered with capitals signs in in lower case, and cannot be registered twice")
    void the_case_is_not_part_of_the_identity() {
        assertEquals(HttpStatus.CREATED,
                exchange(HttpRequest.POST("/register", Map.of("email", AS_TYPED, "password", PASSWORD))).getStatus());
        String token = server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(AS_TYPED);
        assertNotNull(token, "the link goes to the address as its owner typed it");
        assertEquals(HttpStatus.OK, exchange(HttpRequest.POST("/verify-email", Map.of("token", token))).getStatus());

        HttpResponse<Map> signedIn = exchange(HttpRequest.POST("/authenticate",
                Map.of("email", IN_LOWER_CASE, "password", PASSWORD)));
        assertEquals(HttpStatus.OK, signedIn.getStatus(),
                "the same person, the same password, one capital letter different");

        // and the session speaks of the account as it is STORED, so everything keyed by the address
        // afterwards reaches it
        String accessToken = (String) signedIn.getBody(Map.class).orElseThrow().get("accessToken");
        assertEquals(AS_TYPED, exchange(HttpRequest.GET("/me").header("Authorization", "Bearer " + accessToken))
                .getBody(Map.class).orElseThrow().get("email"));

        // a second registration in the other case is the quiet refusal, not a second account
        assertEquals(HttpStatus.CREATED,
                exchange(HttpRequest.POST("/register", Map.of("email", IN_LOWER_CASE, "password", PASSWORD))).getStatus());
        assertEquals(HttpStatus.OK, exchange(HttpRequest.POST("/authenticate",
                        Map.of("email", AS_TYPED, "password", PASSWORD))).getStatus(),
                "the original account must still work — a duplicate registration may not replace it");
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
