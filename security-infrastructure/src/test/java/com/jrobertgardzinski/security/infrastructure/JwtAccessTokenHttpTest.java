package com.jrobertgardzinski.security.infrastructure;

import com.jrobertgardzinski.CapturingEmailVerificationNotifier;
import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.json.JsonMapper;
import io.micronaut.runtime.server.EmbeddedServer;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The self-contained access token at the HTTP boundary: /authenticate hands out an EdDSA-signed
 * JWT whose signature verifies against the public key served at /.well-known/jwks.json and whose
 * claims carry the subject and roles — enough for another service to trust the caller offline.
 * And the flip side that makes it a complement rather than a replacement: logout still kills the
 * token instantly on the introspection path, even though the signature stays valid until expiry.
 */
@Epic("Authorization")
@Feature("Self-contained access token")
class JwtAccessTokenHttpTest {

    private static final String PASSWORD = "StrongPassword1!";

    private EmbeddedServer server;
    private BlockingHttpClient client;
    private final JsonMapper json = JsonMapper.createDefault();

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
    @DisplayName("the access token is a JWT: subject and roles inside, signature verifiable via JWKS")
    void access_token_verifies_offline_against_jwks() throws Exception {
        String email = "jwt-user@example.com";
        String token = registerVerifyAuthenticate(email).accessToken;

        String[] parts = token.split("\\.");
        assertEquals(3, parts.length, "a compact JWS has three dot-separated parts");
        Map<String, Object> header = decodeJson(parts[0]);
        Map<String, Object> claims = decodeJson(parts[1]);

        assertEquals("EdDSA", header.get("alg"));
        assertNotNull(header.get("kid"), "the header names the key so verifiers can pick it from the set");
        assertEquals("microservice-security", claims.get("iss"));
        assertEquals(email, claims.get("sub"));
        assertTrue(((List<?>) claims.get("roles")).contains("USER"), "roles ride inside the token");
        long exp = ((Number) claims.get("exp")).longValue();
        long iat = ((Number) claims.get("iat")).longValue();
        assertTrue(exp > iat, "the token expires after it was issued");

        Map<String, Object> jwks = client.retrieve(HttpRequest.GET("/.well-known/jwks.json"), Map.class);
        Map<String, Object> jwk = ((List<Map<String, Object>>) jwks.get("keys")).stream()
                .filter(key -> header.get("kid").equals(key.get("kid")))
                .findFirst().orElseThrow(() -> new AssertionError("the token's kid is not in the JWK set"));
        assertEquals("OKP", jwk.get("kty"));
        assertEquals("Ed25519", jwk.get("crv"));

        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKeyFrom((String) jwk.get("x")));
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(Base64.getUrlDecoder().decode(parts[2])),
                "the JWKS public key verifies the token's signature — no call-back needed");
    }

    @Test
    @DisplayName("a bootstrap ADMIN is an ADMIN in the token and in /me, not only at the admin gate")
    void the_bootstrap_admin_holds_its_role_everywhere() throws Exception {
        // admin@example.com is declared in application-test.yml's security.bootstrap-admins: it
        // holds ADMIN by configuration and has no row saying so
        String token = registerVerifyAuthenticate("admin@example.com").accessToken;

        assertTrue(((List<?>) decodeJson(token.split("\\.")[1]).get("roles")).contains("ADMIN"),
                "the claim other services gate on must say what /admin/** says");
        assertTrue(((List<?>) me(token).getBody(Map.class).orElseThrow().get("roles")).contains("ADMIN"),
                "and so must the answer the UI reads");
        // the gate itself has always let them in — that is what made the disagreement invisible
        assertEquals(HttpStatus.OK, exchange(HttpRequest.GET("/admin/settings")
                .header("Authorization", "Bearer " + token)).getStatus());
    }

    @Test
    @DisplayName("rotation overlap: a retired public key stays in the JWK set beside the new one")
    void rotation_keeps_the_retired_key_in_the_jwks() throws Exception {
        // the key pair retired by the rotation — only its PUBLIC half survives, in config
        String retiredPublicKey = Base64.getEncoder().encodeToString(
                java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
                        .getPublic().getEncoded());
        server.close();
        server = ApplicationContext.run(EmbeddedServer.class,
                Map.of("security.jwt.previous-public-keys", retiredPublicKey), "test");
        client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

        String token = registerVerifyAuthenticate("jwt-rotation@example.com").accessToken;
        Map<String, Object> header = decodeJson(token.split("\\.")[0]);

        Map<String, Object> jwks = client.retrieve(HttpRequest.GET("/.well-known/jwks.json"), Map.class);
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
        assertEquals(2, keys.size(), "the set carries the signing key AND the retired one");
        assertTrue(keys.stream().anyMatch(key -> header.get("kid").equals(key.get("kid"))),
                "fresh tokens point at the new key");
        String retiredKid = kidOf(retiredPublicKey);
        assertTrue(keys.stream().anyMatch(key -> retiredKid.equals(key.get("kid"))),
                "tokens signed before the rotation still find their key until they expire");
    }

    @Test
    @DisplayName("self-contained does not mean irrevocable: logout kills the still-valid JWT instantly")
    void logout_still_revokes_instantly() {
        Session session = registerVerifyAuthenticate("jwt-leaver@example.com");
        assertEquals(HttpStatus.OK, me(session.accessToken).getStatus(), "the fresh token authorizes");

        HttpResponse<Map> loggedOut = exchange(HttpRequest.POST("/logout", null)
                .cookie(Cookie.of("refresh_token", session.refreshCookie)));
        assertEquals(HttpStatus.OK, loggedOut.getStatus());

        assertEquals(HttpStatus.UNAUTHORIZED, me(session.accessToken).getStatus(),
                "introspection rejects the revoked session although the signature is still valid");
    }

    // --- Helpers --------------------------------------------------------------

    private record Session(String accessToken, String refreshCookie) {}

    private Session registerVerifyAuthenticate(String email) {
        assertEquals(HttpStatus.CREATED,
                exchange(HttpRequest.POST("/register", Map.of("email", email, "password", PASSWORD))).getStatus());
        String verificationToken = server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(email);
        assertEquals(HttpStatus.OK,
                exchange(HttpRequest.POST("/verify-email", Map.of("token", verificationToken))).getStatus());
        HttpResponse<Map> authenticated =
                exchange(HttpRequest.POST("/authenticate", Map.of("email", email, "password", PASSWORD)));
        assertEquals(HttpStatus.OK, authenticated.getStatus());
        String accessToken = (String) authenticated.getBody(Map.class).orElseThrow().get("accessToken");
        String refreshCookie = authenticated.getCookies().findCookie("refresh_token")
                .map(Cookie::getValue).orElse(null);
        return new Session(accessToken, refreshCookie);
    }

    private HttpResponse<Map> me(String accessToken) {
        return exchange(HttpRequest.GET("/me").header("Authorization", "Bearer " + accessToken));
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<Map> exchange(HttpRequest<?> request) {
        try {
            return client.exchange(request, Map.class);
        } catch (HttpClientResponseException e) {
            return (HttpResponse<Map>) e.getResponse();
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> decodeJson(String base64Url) throws Exception {
        return json.readValue(Base64.getUrlDecoder().decode(base64Url), Map.class);
    }

    /** The kid the mint derives for a base64 X.509 public key: first 8 bytes of its SHA-256, hex. */
    private static String kidOf(String publicKeyBase64) throws Exception {
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(Base64.getDecoder().decode(publicKeyBase64));
        return HexFormat.of().formatHex(digest, 0, 8);
    }

    /** Rebuild the Ed25519 public key from a JWK's raw {@code x}: fixed DER prefix + 32 raw bytes. */
    private static PublicKey publicKeyFrom(String x) throws Exception {
        byte[] raw = Base64.getUrlDecoder().decode(x);
        byte[] derPrefix = HexFormat.of().parseHex("302a300506032b6570032100");
        byte[] encoded = new byte[derPrefix.length + raw.length];
        System.arraycopy(derPrefix, 0, encoded, 0, derPrefix.length);
        System.arraycopy(raw, 0, encoded, derPrefix.length, raw.length);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
    }
}
