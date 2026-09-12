package com.jrobertgardzinski.security.infrastructure;

import com.sun.net.httpserver.HttpServer;
import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.DefaultHttpClientConfiguration;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The whole social sign-in dance over the wire, against a fake provider: /oauth/{provider}/start
 * hands the browser a PKCE-armed authorize redirect; /oauth/callback exchanges the code at the
 * provider's token endpoint, validates the assertion and lands the browser back on the
 * allow-listed return URL with an access token in the fragment and the refresh cookie set.
 * States are single-use; a wrong nonce or an unvouched email never opens a session.
 *
 * <p>Both identity sources are danced: {@code fake} asserts through an OIDC id_token (HS256
 * against the client secret, issuer, audience, nonce); {@code hub} is GitHub-shaped plain OAuth2
 * (numeric id in userinfo, address hidden behind /emails) and {@code faces} Facebook-shaped
 * (no verified flag at all — accepted only where the deployment says so).
 */
@Epic("Authentication")
@Feature("Federated sign-in")
class OauthFlowHttpTest {

    private static final String CLIENT_SECRET = "test-secret";
    private static final String RETURN_URL = "http://app.example/gallery";

    private HttpServer fakeIdp;
    private final AtomicReference<String> nextIdToken = new AtomicReference<>();
    private final AtomicReference<String> nextUserinfo = new AtomicReference<>();
    private final AtomicReference<String> nextEmails = new AtomicReference<>();
    private EmbeddedServer server;
    private BlockingHttpClient client;

    @BeforeEach
    void start() throws Exception {
        fakeIdp = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        fakeIdp.createContext("/token", exchange -> respond(exchange,
                "{\"access_token\":\"at-1\",\"token_type\":\"Bearer\",\"id_token\":\""
                        + nextIdToken.get() + "\"}"));
        fakeIdp.createContext("/userinfo", exchange -> respond(exchange,
                "Bearer at-1".equals(exchange.getRequestHeaders().getFirst("Authorization"))
                        ? nextUserinfo.get() : null));
        fakeIdp.createContext("/emails", exchange -> respond(exchange,
                "Bearer at-1".equals(exchange.getRequestHeaders().getFirst("Authorization"))
                        ? nextEmails.get() : null));
        fakeIdp.start();
        String idp = "http://localhost:" + fakeIdp.getAddress().getPort();

        server = ApplicationContext.run(EmbeddedServer.class, Map.ofEntries(
                Map.entry("security.oauth.providers.fake.issuer", idp),
                Map.entry("security.oauth.providers.fake.authorize-url", idp + "/authorize"),
                Map.entry("security.oauth.providers.fake.token-url", idp + "/token"),
                Map.entry("security.oauth.providers.fake.client-id", "test-client"),
                Map.entry("security.oauth.providers.fake.client-secret", CLIENT_SECRET),
                Map.entry("security.oauth.providers.fake.redirect-uri", "http://security.example/oauth/callback"),
                // GitHub-shaped: identity read from userinfo, address behind /emails
                Map.entry("security.oauth.providers.hub.identity-source", "USERINFO"),
                Map.entry("security.oauth.providers.hub.authorize-url", idp + "/authorize"),
                Map.entry("security.oauth.providers.hub.token-url", idp + "/token"),
                Map.entry("security.oauth.providers.hub.userinfo-url", idp + "/userinfo"),
                Map.entry("security.oauth.providers.hub.emails-url", idp + "/emails"),
                Map.entry("security.oauth.providers.hub.scope", "read:user user:email"),
                Map.entry("security.oauth.providers.hub.subject-field", "id"),
                Map.entry("security.oauth.providers.hub.client-id", "test-client"),
                Map.entry("security.oauth.providers.hub.client-secret", CLIENT_SECRET),
                Map.entry("security.oauth.providers.hub.redirect-uri", "http://security.example/oauth/callback"),
                // Facebook-shaped: no verified flag ever; the deployment vouches deliberately
                Map.entry("security.oauth.providers.faces.identity-source", "USERINFO"),
                Map.entry("security.oauth.providers.faces.authorize-url", idp + "/authorize"),
                Map.entry("security.oauth.providers.faces.token-url", idp + "/token"),
                Map.entry("security.oauth.providers.faces.userinfo-url", idp + "/userinfo"),
                Map.entry("security.oauth.providers.faces.subject-field", "id"),
                Map.entry("security.oauth.providers.faces.assume-email-verified", "true"),
                Map.entry("security.oauth.providers.faces.client-id", "test-client"),
                Map.entry("security.oauth.providers.faces.client-secret", CLIENT_SECRET),
                Map.entry("security.oauth.providers.faces.redirect-uri", "http://security.example/oauth/callback"),
                // same Facebook shape WITHOUT the vouch — must never open a session
                Map.entry("security.oauth.providers.strict.identity-source", "USERINFO"),
                Map.entry("security.oauth.providers.strict.authorize-url", idp + "/authorize"),
                Map.entry("security.oauth.providers.strict.token-url", idp + "/token"),
                Map.entry("security.oauth.providers.strict.userinfo-url", idp + "/userinfo"),
                Map.entry("security.oauth.providers.strict.subject-field", "id"),
                Map.entry("security.oauth.providers.strict.client-id", "test-client"),
                Map.entry("security.oauth.providers.strict.client-secret", CLIENT_SECRET),
                Map.entry("security.oauth.providers.strict.redirect-uri", "http://security.example/oauth/callback"),
                // WITHOUT a trailing slash on purpose: that is what a deployment naturally writes,
                // and it is the shape in which a raw startsWith stops being a host check at all
                Map.entry("security.oauth.allowed-return-prefixes", "http://app.example")), "test");
        DefaultHttpClientConfiguration noRedirects = new DefaultHttpClientConfiguration();
        noRedirects.setFollowRedirects(false);
        client = server.getApplicationContext()
                .createBean(HttpClient.class, server.getURL(), noRedirects).toBlocking();
    }

    @AfterEach
    void stop() {
        if (server != null) {
            server.close();
        }
        if (fakeIdp != null) {
            fakeIdp.stop(0);
        }
    }

    @Test
    @DisplayName("start redirects to the provider PKCE-armed; the callback opens a session and returns to the app")
    void the_full_dance_signs_in() {
        Map<String, String> authorize = startFlow();
        assertEquals("S256", authorize.get("code_challenge_method"));
        assertNotNull(authorize.get("code_challenge"));
        assertNotNull(authorize.get("nonce"));

        nextIdToken.set(idToken(Map.of(
                "iss", issuer(), "aud", "test-client", "sub", "prov-sub-1",
                "email", "dancer@example.com", "email_verified", true,
                "exp", Instant.now().getEpochSecond() + 300, "nonce", authorize.get("nonce"))));
        HttpResponse<?> back = callback("/oauth/callback?state=" + authorize.get("state") + "&code=c-1");

        assertEquals(HttpStatus.FOUND, back.getStatus());
        String location = back.getHeaders().get("Location");
        assertTrue(location.startsWith(RETURN_URL + "#accessToken="),
                "the access token rides back in the fragment, got: " + location);
        assertTrue(back.getHeaders().getAll("Set-Cookie").stream().anyMatch(c -> c.startsWith("refresh_token=")),
                "the refresh token rides in its usual HttpOnly cookie");

        String accessToken = location.substring((RETURN_URL + "#accessToken=").length());
        HttpResponse<Map> me = exchange(HttpRequest.GET("/me").header("Authorization", "Bearer " + accessToken), Map.class);
        assertEquals(HttpStatus.OK, me.getStatus());
        assertEquals("dancer@example.com", me.getBody(Map.class).orElseThrow().get("email"));

        HttpResponse<?> replayed = callback("/oauth/callback?state=" + authorize.get("state") + "&code=c-1");
        assertEquals(HttpStatus.BAD_REQUEST, replayed.getStatus(), "a state is single-use");
    }

    @Test
    @DisplayName("a Keycloak-shaped id_token signs in: aud as an array, azp naming the client")
    void an_array_audience_with_azp_signs_in() {
        Map<String, String> authorize = startFlow();
        nextIdToken.set(idToken(Map.of(
                "iss", issuer(), "aud", List.of("test-client", "account"), "azp", "test-client",
                "sub", "kc-sub-1", "email", "keycloaker@example.com", "email_verified", true,
                "exp", Instant.now().getEpochSecond() + 300, "nonce", authorize.get("nonce"))));
        HttpResponse<?> back = callback("/oauth/callback?state=" + authorize.get("state") + "&code=c-kc");

        assertEquals(HttpStatus.FOUND, back.getStatus());
        assertTrue(back.getHeaders().get("Location").startsWith(RETURN_URL + "#accessToken="),
                "an array aud that contains the client (azp agreeing) is a valid audience");
    }

    @Test
    @DisplayName("an array audience whose azp names someone else is refused")
    void an_array_audience_with_foreign_azp_is_refused() {
        Map<String, String> authorize = startFlow();
        nextIdToken.set(idToken(Map.of(
                "iss", issuer(), "aud", List.of("test-client", "account"), "azp", "someone-else",
                "sub", "kc-sub-2", "email", "mitm@example.com", "email_verified", true,
                "exp", Instant.now().getEpochSecond() + 300, "nonce", authorize.get("nonce"))));
        HttpResponse<?> back = callback("/oauth/callback?state=" + authorize.get("state") + "&code=c-kx");

        assertEquals(HttpStatus.FOUND, back.getStatus());
        assertTrue(back.getHeaders().get("Location").endsWith("#oauthError=SIGN_IN_FAILED"));
    }

    @Test
    @DisplayName("a nonce mismatch or an unvouched email bounces back with an error, no session")
    void bad_assertions_do_not_sign_in() {
        Map<String, String> first = startFlow();
        nextIdToken.set(idToken(Map.of(
                "iss", issuer(), "aud", "test-client", "sub", "prov-sub-2",
                "email", "replayed@example.com", "email_verified", true,
                "exp", Instant.now().getEpochSecond() + 300, "nonce", "NOT-THE-NONCE")));
        HttpResponse<?> replayAttempt = callback("/oauth/callback?state=" + first.get("state") + "&code=c-2");
        assertEquals(HttpStatus.FOUND, replayAttempt.getStatus());
        assertTrue(replayAttempt.getHeaders().get("Location").endsWith("#oauthError=SIGN_IN_FAILED"));

        Map<String, String> second = startFlow();
        nextIdToken.set(idToken(Map.of(
                "iss", issuer(), "aud", "test-client", "sub", "prov-sub-3",
                "email", "shady@example.com", "email_verified", false,
                "exp", Instant.now().getEpochSecond() + 300, "nonce", second.get("nonce"))));
        HttpResponse<?> unvouched = callback("/oauth/callback?state=" + second.get("state") + "&code=c-3");
        assertEquals(HttpStatus.FOUND, unvouched.getStatus());
        assertTrue(unvouched.getHeaders().get("Location").endsWith("#oauthError=EMAIL_NOT_VOUCHED"));
    }

    @Test
    @DisplayName("a return URL that already carries a fragment gets ours appended, not a second '#'")
    void a_second_hash_would_hide_the_token() {
        // the app's own state rides through the provider on the return URL — it is allowed to, and
        // it comes back
        String withFragment = RETURN_URL + "#view=grid";
        HttpResponse<?> redirect = exchange("/oauth/fake/start?return="
                + java.net.URLEncoder.encode(withFragment, StandardCharsets.UTF_8));
        assertEquals(HttpStatus.FOUND, redirect.getStatus());
        stateCookie = redirect.getCookies().findCookie("oauth_state")
                .map(io.micronaut.http.cookie.Cookie::getValue).orElseThrow();
        Map<String, String> authorize = queryOf(redirect.getHeaders().get("Location"));
        nextIdToken.set(idToken(Map.of("iss", issuer(), "aud", "test-client", "sub", "frag-1",
                "email", "fragment@example.com", "email_verified", true, "nonce", authorize.get("nonce"),
                "exp", Instant.now().plusSeconds(300).getEpochSecond())));

        HttpResponse<?> back = callback("/oauth/callback?state=" + authorize.get("state") + "&code=c-frag");

        String location = back.getHeaders().get("Location");
        assertEquals(HttpStatus.FOUND, back.getStatus());
        assertEquals(1, location.chars().filter(c -> c == '#').count(),
                "two fragments mean the SPA reads neither: " + location);
        assertTrue(location.contains("view=grid") && location.contains("accessToken="),
                "both the app's state and the token must survive: " + location);
    }

    @Test
    @DisplayName("a callback handed to somebody else is refused: the dance belongs to the browser that started it")
    void a_callback_link_is_not_a_bearer_token() {
        Map<String, String> authorize = startFlow();   // the attacker starts a dance of their own
        String attackersLink = "/oauth/callback?state=" + authorize.get("state") + "&code=c-1";
        nextIdToken.set(idToken(Map.of("iss", issuer(), "aud", "test-client", "sub", "attacker-1",
                "email", "attacker@example.com", "email_verified", true, "nonce", authorize.get("nonce"),
                "exp", Instant.now().plusSeconds(300).getEpochSecond())));

        // the victim opens it in THEIR browser, which never started this dance and has no cookie
        stateCookie = null;
        HttpResponse<?> refused = callback(attackersLink);

        assertEquals(HttpStatus.BAD_REQUEST, refused.getStatus(),
                "otherwise the victim's browser receives a session for the ATTACKER's identity —"
                        + " session fixation: everything they do next, they do in that account");
        assertNull(refused.getCookies().findCookie("refresh_token").map(c -> c.getValue()).orElse(null),
                "and no session may be issued by a refused callback");
    }

    @Test
    @DisplayName("a return URL outside the allow-list is refused before anything starts")
    void foreign_return_urls_are_refused() {
        HttpResponse<?> refused = exchange("/oauth/fake/start?return=" + "http://evil.example/");
        assertEquals(HttpStatus.BAD_REQUEST, refused.getStatus());
    }

    @Test
    @DisplayName("a host that merely BEGINS with an allowed one is not allowed: the token would land there")
    void a_longer_host_cannot_wear_an_allowed_one_as_its_prefix() {
        // the allow-list here is "http://app.example/" — and the access token travels in the
        // fragment of whatever this redirects to, so a raw startsWith would hand it to either of
        // these. The second is the nastier one: everything before the @ is a userinfo field.
        assertEquals(HttpStatus.BAD_REQUEST,
                exchange("/oauth/fake/start?return=" + "http://app.example.evil.net/").getStatus());
        assertEquals(HttpStatus.BAD_REQUEST,
                exchange("/oauth/fake/start?return=" + "http://app.example@evil.net/").getStatus());
        // the allowed host itself still starts a dance, with and without a path
        assertEquals(HttpStatus.FOUND, exchange("/oauth/fake/start?return=" + RETURN_URL).getStatus());
        assertEquals(HttpStatus.FOUND, exchange("/oauth/fake/start?return=" + "http://app.example/").getStatus());
    }

    @Test
    @DisplayName("a USERINFO provider signs in through userinfo; a private address is found behind emails-url")
    void the_userinfo_dance_signs_in() {
        Map<String, String> authorize = startFlow("hub");
        assertEquals("read:user user:email", authorize.get("scope"),
                "the provider's own scope rides on the authorize redirect");

        // GitHub shape: numeric id, the address held back (private), no verified flag anywhere
        nextUserinfo.set("{\"id\":42,\"login\":\"octo\",\"email\":null}");
        nextEmails.set("[{\"email\":\"old@example.com\",\"primary\":false,\"verified\":true},"
                + "{\"email\":\"octo@example.com\",\"primary\":true,\"verified\":true},"
                + "{\"email\":\"spam@example.com\",\"primary\":false,\"verified\":false}]");
        HttpResponse<?> back = callback("/oauth/callback?state=" + authorize.get("state") + "&code=c-9");

        assertEquals(HttpStatus.FOUND, back.getStatus());
        String location = back.getHeaders().get("Location");
        assertTrue(location.startsWith(RETURN_URL + "#accessToken="),
                "the userinfo path signs in like the id_token one, got: " + location);

        String accessToken = location.substring((RETURN_URL + "#accessToken=").length());
        HttpResponse<Map> me = exchange(HttpRequest.GET("/me").header("Authorization", "Bearer " + accessToken), Map.class);
        assertEquals(HttpStatus.OK, me.getStatus());
        assertEquals("octo@example.com", me.getBody(Map.class).orElseThrow().get("email"),
                "the primary verified address from emails-url wins");
    }

    @Test
    @DisplayName("a provider without a verified flag needs the deployment's explicit vouch")
    void assume_email_verified_is_a_deliberate_decision() {
        // Facebook shape: subject + email, verification never stated
        Map<String, String> vouched = startFlow("faces");
        nextUserinfo.set("{\"id\":\"fb-7\",\"email\":\"faced@example.com\"}");
        HttpResponse<?> in = callback("/oauth/callback?state=" + vouched.get("state") + "&code=c-10");
        assertEquals(HttpStatus.FOUND, in.getStatus());
        assertTrue(in.getHeaders().get("Location").startsWith(RETURN_URL + "#accessToken="),
                "assume-email-verified lets the configured deployment accept it");

        // the same assertion through a provider nobody vouched for stays outside
        Map<String, String> unvouched = startFlow("strict");
        nextUserinfo.set("{\"id\":\"fb-8\",\"email\":\"stranger@example.com\"}");
        HttpResponse<?> out = callback("/oauth/callback?state=" + unvouched.get("state") + "&code=c-11");
        assertEquals(HttpStatus.FOUND, out.getStatus());
        assertTrue(out.getHeaders().get("Location").endsWith("#oauthError=EMAIL_NOT_VOUCHED"),
                "no verified flag and no vouch means no session, got: " + out.getHeaders().get("Location"));
    }

    @Test
    @DisplayName("the configured providers are listed for the UI to draw its buttons from")
    void providers_are_listed() {
        HttpResponse<Map> listed = exchange(HttpRequest.GET("/oauth/providers"), Map.class);
        assertEquals(HttpStatus.OK, listed.getStatus());
        java.util.List<Map<String, String>> providers =
                (java.util.List<Map<String, String>>) listed.getBody(Map.class).orElseThrow().get("providers");
        assertEquals(java.util.List.of("faces", "fake", "hub", "strict"),
                providers.stream().map(p -> p.get("name")).toList());
        assertEquals("Hub", providers.stream()
                        .filter(p -> "hub".equals(p.get("name"))).findFirst().orElseThrow().get("label"),
                "the label defaults to the capitalised name");
    }

    // --- Helpers --------------------------------------------------------------

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String json)
            throws java.io.IOException {
        int status = json == null ? 401 : 200;
        byte[] body = (json == null ? "{\"error\":\"invalid_token\"}" : json).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private Map<String, String> startFlow() {
        return startFlow("fake");
    }

    /** The cookie /start sets to bind the dance to THIS browser; the callback needs it back. */
    private String stateCookie;

    private Map<String, String> queryOf(String location) {
        return URI.create(location).getQuery().lines()
                .flatMap(q -> java.util.Arrays.stream(q.split("&")))
                .map(pair -> pair.split("=", 2))
                .collect(Collectors.toMap(kv -> kv[0], kv -> java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8)));
    }

    private Map<String, String> startFlow(String provider) {
        HttpResponse<?> redirect = exchange("/oauth/" + provider + "/start?return=" + RETURN_URL);
        assertEquals(HttpStatus.FOUND, redirect.getStatus());
        stateCookie = redirect.getCookies().findCookie("oauth_state")
                .map(io.micronaut.http.cookie.Cookie::getValue).orElse(null);
        assertNotNull(stateCookie, "/start must bind the flow to the browser that started it");
        String location = redirect.getHeaders().get("Location");
        assertTrue(location.startsWith(issuer() + "/authorize?"), "unexpected authorize URL: " + location);
        return URI.create(location).getQuery().lines()
                .flatMap(q -> java.util.Arrays.stream(q.split("&")))
                .map(pair -> pair.split("=", 2))
                .collect(Collectors.toMap(kv -> kv[0], kv -> java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8)));
    }

    /** A callback as the browser makes it: the query the provider sent, plus the binding cookie. */
    private HttpResponse<?> callback(String uri) {
        io.micronaut.http.MutableHttpRequest<?> request = HttpRequest.GET(uri);
        if (stateCookie != null) {
            request = request.cookie(io.micronaut.http.cookie.Cookie.of("oauth_state", stateCookie));
        }
        return exchange(request, String.class);
    }

    private String issuer() {
        return "http://localhost:" + fakeIdp.getAddress().getPort();
    }

    private String idToken(Map<String, Object> claims) {
        String header = b64(("{\"alg\":\"HS256\",\"typ\":\"JWT\"}").getBytes(StandardCharsets.UTF_8));
        String payload = b64(claims.entrySet().stream()
                .map(e -> "\"" + e.getKey() + "\":" + jsonValue(e.getValue()))
                .collect(Collectors.joining(",", "{", "}")).getBytes(StandardCharsets.UTF_8));
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(CLIENT_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return header + "." + payload + "."
                    + b64(mac.doFinal((header + "." + payload).getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String jsonValue(Object value) {
        if (value instanceof String s) {
            return "\"" + s + "\"";
        }
        if (value instanceof List<?> list) {   // an array claim, e.g. Keycloak's aud
            return list.stream().map(OauthFlowHttpTest::jsonValue)
                    .collect(Collectors.joining(",", "[", "]"));
        }
        return String.valueOf(value);
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private HttpResponse<?> exchange(String uri) {
        return exchange(HttpRequest.GET(uri), String.class);
    }

    @SuppressWarnings("unchecked")
    private <T> HttpResponse<T> exchange(HttpRequest<?> request, Class<T> type) {
        try {
            return client.exchange(request, type);
        } catch (HttpClientResponseException e) {
            return (HttpResponse<T>) e.getResponse();
        }
    }
}
