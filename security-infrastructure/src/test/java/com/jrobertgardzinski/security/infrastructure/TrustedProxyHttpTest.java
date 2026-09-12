package com.jrobertgardzinski.security.infrastructure;

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
 * Who the service believes the caller is when it sits behind a proxy it trusts. The header is a
 * list the caller can write the left half of, so the source — the key of every throttle and of the
 * brute-force lockout — is the RIGHTMOST element that is not one of our own proxies.
 *
 * <p>The throttle is the instrument: with one request per window, two requests that share a source
 * answer 201 then 429, and two that do not answer 201 twice. So "was this caller throttled?" reads
 * "did the service give these two requests the same source?".
 */
@Epic("Throttling")
@Feature("Trusted proxy")
class TrustedProxyHttpTest {

    private EmbeddedServer server;
    private BlockingHttpClient client;

    @BeforeEach
    void start() {
        server = ApplicationContext.run(EmbeddedServer.class,
                Map.of("security.trusted-proxies", java.util.List.of("127.0.0.1", "0:0:0:0:0:0:0:1", "::1"),
                        "security.registration.max-per-window", 1),
                "test");
        client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();
    }

    @AfterEach
    void stop() {
        if (server != null) {
            server.close();
        }
    }

    @Test
    @DisplayName("a rotating leftmost element does not buy a fresh window: the rightmost untrusted element is the source")
    void the_client_cannot_choose_its_own_source() {
        // the proxy appended the peer it saw (9.9.9.9); everything left of it is the caller's own text
        assertEquals(HttpStatus.CREATED, register("alice@example.com", "10.0.0.1, 9.9.9.9").getStatus());
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, register("bob@example.com", "10.0.0.2, 9.9.9.9").getStatus(),
                "rotating the leftmost element must not hand the caller a fresh window");
    }

    @Test
    @DisplayName("our own proxies are walked past: the source is the last hop before them")
    void trusted_hops_are_skipped() {
        // 127.0.0.1 is ours, so the client is 9.9.9.9 in both — one window between them
        assertEquals(HttpStatus.CREATED, register("carol@example.com", "9.9.9.9, 127.0.0.1").getStatus());
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, register("dave@example.com", "9.9.9.9, 127.0.0.1").getStatus());
    }

    @Test
    @DisplayName("a header element that is not an address falls back to the peer instead of answering 500")
    void garbage_in_the_header_is_not_a_500() {
        HttpResponse<Map> answered = register("erin@example.com", "unknown");
        assertEquals(HttpStatus.CREATED, answered.getStatus(),
                "a non-address element used to reach the IpAddress constructor and 500 the endpoint");
    }

    @Test
    @DisplayName("an address too long for the column it is keyed in cannot become the key")
    void an_overlong_address_falls_back_to_the_peer() {
        // the domain's validator accepts an IPv6 zone id of any length; the columns are VARCHAR(64),
        // so such a source could not be RECORDED — and a source that cannot be recorded cannot be
        // limited. It falls back to the peer, and the zone id is dropped from the ones that do fit.
        String overlong = "fe80::1%" + "e".repeat(200);
        assertEquals(HttpStatus.CREATED, register("heidi@example.com", overlong).getStatus());
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, register("ivan@example.com", overlong).getStatus(),
                "both fell back to the same peer, so they share its window");
    }

    @Test
    @DisplayName("two callers behind the same trusted proxy keep their own windows")
    void distinct_clients_are_distinct_sources() {
        assertEquals(HttpStatus.CREATED, register("frank@example.com", "9.9.9.9").getStatus());
        assertEquals(HttpStatus.CREATED, register("grace@example.com", "8.8.8.8").getStatus(),
                "a different client behind the same proxy is a different source");
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<Map> register(String email, String forwardedFor) {
        HttpRequest<?> request = HttpRequest.POST("/register", Map.of("email", email, "password", "StrongPassword1!"))
                .header("X-Forwarded-For", forwardedFor);
        try {
            return client.exchange(request, Map.class);
        } catch (HttpClientResponseException e) {
            return (HttpResponse<Map>) e.getResponse();
        }
    }
}
