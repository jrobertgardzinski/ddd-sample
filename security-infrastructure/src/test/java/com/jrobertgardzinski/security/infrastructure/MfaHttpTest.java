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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The whole multi-factor sign-in over the wire: enrol the e-mail factor, then a correct password no
 * longer yields a session (202, a ticket) — the mailed code, submitted against the ticket,
 * completes the chain and returns the same session shape as a single-factor sign-in. A wrong code
 * is refused with tries remaining.
 */
@Epic("Authentication")
@Feature("Multi-factor sign-in")
class MfaHttpTest {

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
    @DisplayName("with the e-mail factor enrolled, sign-in needs the mailed code, and the right code completes it")
    void password_then_code_signs_in() {
        String email = "mfa-user@example.com";
        String token = registerVerifyAuthenticate(email);
        enrolEmailFactor(email, token);

        // password alone no longer signs in — 202 with a ticket, and a fresh code is out
        HttpResponse<Map> first = exchange(HttpRequest.POST("/authenticate", Map.of("email", email, "password", PASSWORD)));
        assertEquals(HttpStatus.ACCEPTED, first.getStatus());
        Map<?, ?> firstBody = first.getBody(Map.class).orElseThrow();
        assertEquals("MFA_REQUIRED", firstBody.get("status"));
        assertEquals("EMAIL_CODE", firstBody.get("nextFactor"));
        String ticket = (String) firstBody.get("mfaTicket");

        // a wrong code is refused, tries remaining
        HttpResponse<Map> wrong = exchange(HttpRequest.POST("/authenticate/factor",
                Map.of("mfaTicket", ticket, "proof", "000000")));
        assertEquals(HttpStatus.UNAUTHORIZED, wrong.getStatus());
        assertEquals("WRONG_CODE", wrong.getBody(Map.class).orElseThrow().get("status"));

        // the mailed code completes the chain — a real session comes back
        String code = codeChannel().lastCodeFor(email);
        HttpResponse<Map> done = exchange(HttpRequest.POST("/authenticate/factor",
                Map.of("mfaTicket", ticket, "proof", code)));
        assertEquals(HttpStatus.OK, done.getStatus());
        String accessToken = (String) done.getBody(Map.class).orElseThrow().get("accessToken");

        HttpResponse<Map> me = exchange(HttpRequest.GET("/me").header("Authorization", "Bearer " + accessToken));
        assertEquals(HttpStatus.OK, me.getStatus());
        assertEquals(email, me.getBody(Map.class).orElseThrow().get("email"));
    }

    @Test
    @DisplayName("TOTP (authenticator app) enrols with an otpauth secret and signs in with a computed code")
    void totp_enrols_and_signs_in() {
        String email = "totp-user@example.com";
        String token = registerVerifyAuthenticate(email);

        // enrol: start returns the secret to scan (no code sent), confirm seals it with a live code
        stepUpToEnrol(token);
        HttpResponse<Map> start = exchange(HttpRequest.POST("/account/factors/TOTP/enroll/start", Map.of())
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.ACCEPTED, start.getStatus());
        Map<?, ?> startBody = start.getBody(Map.class).orElseThrow();
        assertEquals("ENROLL_SETUP", startBody.get("status"));
        String secret = secretFromOtpauth((String) startBody.get("display"));

        HttpResponse<Map> confirmed = exchange(HttpRequest.POST("/account/factors/TOTP/enroll/confirm",
                Map.of("code", totp(secret))).header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.OK, confirmed.getStatus());

        // sign in: password → ticket → a fresh TOTP code → session
        Map<?, ?> first = exchange(HttpRequest.POST("/authenticate",
                Map.of("email", email, "password", PASSWORD))).getBody(Map.class).orElseThrow();
        assertEquals("TOTP", first.get("nextFactor"));
        HttpResponse<Map> done = exchange(HttpRequest.POST("/authenticate/factor",
                Map.of("mfaTicket", first.get("mfaTicket"), "proof", totp(secret))));
        assertEquals(HttpStatus.OK, done.getStatus());
        assertEquals(email, exchange(HttpRequest.GET("/me")
                .header("Authorization", "Bearer " + done.getBody(Map.class).orElseThrow().get("accessToken")))
                .getBody(Map.class).orElseThrow().get("email"));
    }

    @Test
    @DisplayName("WebAuthn (passkey) enrols a signature credential and signs in with an assertion over the drut")
    void webauthn_enrols_and_signs_in() throws Exception {
        String email = "passkey-user@example.com";
        String token = registerVerifyAuthenticate(email);
        java.security.KeyPair key = p256();

        // enrol: start returns creation options (challenge nonce), confirm seals it with a signed
        // attestation carrying the credential's public key — the browser's job, played here
        stepUpToEnrol(token);
        HttpResponse<Map> start = exchange(HttpRequest.POST("/account/factors/WEBAUTHN/enroll/start", Map.of())
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.ACCEPTED, start.getStatus());
        String enrolNonce = webauthnField((String) start.getBody(Map.class).orElseThrow().get("display"), "challenge");
        String publicKey = b64url(key.getPublic().getEncoded());
        String attestation = "{\"type\":\"webauthn.create\",\"credentialId\":\"passkey-1\",\"publicKey\":\""
                + publicKey + "\",\"clientDataJSON\":\"" + b64url(clientData("webauthn.create", enrolNonce)) + "\"}";
        assertEquals(HttpStatus.OK, exchange(HttpRequest.POST("/account/factors/WEBAUTHN/enroll/confirm",
                Map.of("code", attestation)).header("Authorization", "Bearer " + token)).getStatus());

        // sign in: password → 202 carries the challengeData (nonce) → a signed assertion → session
        Map<?, ?> first = exchange(HttpRequest.POST("/authenticate",
                Map.of("email", email, "password", PASSWORD))).getBody(Map.class).orElseThrow();
        assertEquals("WEBAUTHN", first.get("nextFactor"));
        String signInNonce = (String) first.get("challengeData");
        assertEquals(false, signInNonce == null, "the 202 must hand the client a challenge to sign");

        String assertion = webauthnAssertion(key, signInNonce);
        HttpResponse<Map> done = exchange(HttpRequest.POST("/authenticate/factor",
                Map.of("mfaTicket", first.get("mfaTicket"), "proof", assertion)));
        assertEquals(HttpStatus.OK, done.getStatus());
        assertEquals(email, exchange(HttpRequest.GET("/me")
                .header("Authorization", "Bearer " + done.getBody(Map.class).orElseThrow().get("accessToken")))
                .getBody(Map.class).orElseThrow().get("email"));

        // a tampered assertion (flip the last signature byte) is refused
        Map<?, ?> again = exchange(HttpRequest.POST("/authenticate",
                Map.of("email", email, "password", PASSWORD))).getBody(Map.class).orElseThrow();
        String forged = webauthnAssertion(key, (String) again.get("challengeData")).replaceFirst("(.)\"}$", "X\"}");
        assertEquals(HttpStatus.UNAUTHORIZED, exchange(HttpRequest.POST("/authenticate/factor",
                Map.of("mfaTicket", again.get("mfaTicket"), "proof", forged))).getStatus());
    }

    @Test
    @DisplayName("a recovery code stands in for the factor once — generated while signed in, spent at sign-in, dead after")
    void recovery_code_signs_in_once() {
        String email = "recovery-user@example.com";
        String token = registerVerifyAuthenticate(email);
        enrolEmailFactor(email, token);

        // generate a batch: plain codes appear exactly once in this response
        stepUpToMintCodes(email, token);
        HttpResponse<Map> minted = exchange(HttpRequest.POST("/account/recovery-codes", Map.of())
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.OK, minted.getStatus());
        java.util.List<String> codes = (java.util.List<String>) minted.getBody(Map.class).orElseThrow().get("codes");
        assertEquals(10, codes.size(), "the default batch is ten codes");
        assertEquals(10, unusedCount(token));

        // sign in: password → ticket → a RECOVERY code (typed with its print formatting) instead of the mailed one
        Map<?, ?> first = exchange(HttpRequest.POST("/authenticate",
                Map.of("email", email, "password", PASSWORD))).getBody(Map.class).orElseThrow();
        String recoveryCode = codes.get(0).toUpperCase();   // case and hyphens are forgiven
        HttpResponse<Map> done = exchange(HttpRequest.POST("/authenticate/factor",
                Map.of("mfaTicket", first.get("mfaTicket"), "proof", recoveryCode)));
        assertEquals(HttpStatus.OK, done.getStatus(), "an unused recovery code completes the chain");
        assertEquals(9, unusedCount(token), "the spent code is gone from the count");

        // the same code again buys nothing
        Map<?, ?> second = exchange(HttpRequest.POST("/authenticate",
                Map.of("email", email, "password", PASSWORD))).getBody(Map.class).orElseThrow();
        HttpResponse<Map> replayed = exchange(HttpRequest.POST("/authenticate/factor",
                Map.of("mfaTicket", second.get("mfaTicket"), "proof", recoveryCode)));
        assertEquals(HttpStatus.UNAUTHORIZED, replayed.getStatus(), "a recovery code is single-use");

        // a fresh batch kills the remaining nine
        stepUpToMintCodes(email, token);
        exchange(HttpRequest.POST("/account/recovery-codes", Map.of())
                .header("Authorization", "Bearer " + token));
        HttpResponse<Map> third = exchange(HttpRequest.POST("/authenticate",
                Map.of("email", email, "password", PASSWORD)));
        Map<?, ?> thirdBody = third.getBody(Map.class).orElseThrow();
        HttpResponse<Map> oldBatch = exchange(HttpRequest.POST("/authenticate/factor",
                Map.of("mfaTicket", thirdBody.get("mfaTicket"), "proof", codes.get(1))));
        assertEquals(HttpStatus.UNAUTHORIZED, oldBatch.getStatus(), "regeneration invalidates the old batch");
    }

    private int unusedCount(String token) {
        return (int) exchange(HttpRequest.GET("/account/recovery-codes")
                .header("Authorization", "Bearer " + token))
                .getBody(Map.class).orElseThrow().get("unused");
    }

    @Test
    @DisplayName("enrolling/removing a factor needs a step-up, and the e-mail target is the caller's own (poz. 2)")
    void factor_changes_are_guarded_and_target_is_the_caller() {
        String email = "poz2@example.com";
        String token = registerVerifyAuthenticate(email);

        // straight to enrol/start on a merely-live session → refused, told to step up
        HttpResponse<Map> refused = exchange(HttpRequest.POST("/account/factors/EMAIL_CODE/enroll/start", Map.of())
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.FORBIDDEN, refused.getStatus());
        assertEquals("STEP_UP_REQUIRED", refused.getBody(Map.class).orElseThrow().get("status"));

        // step up, then enrol — but aim the e-mail factor at an attacker address: the code must still
        // go to the account's OWN verified address, never the body-supplied target
        stepUpToEnrol(token);
        exchange(HttpRequest.POST("/account/factors/EMAIL_CODE/enroll/start", Map.of("target", "attacker@evil.com"))
                .header("Authorization", "Bearer " + token));
        org.junit.jupiter.api.Assertions.assertNotNull(codeChannel().lastCodeFor(email),
                "the enrolment code goes to the caller's own address");
        org.junit.jupiter.api.Assertions.assertNull(codeChannel().lastCodeFor("attacker@evil.com"),
                "never to a target supplied in the request body");
        String enrolCode = codeChannel().lastCodeFor(email);
        exchange(HttpRequest.POST("/account/factors/EMAIL_CODE/enroll/confirm", Map.of("code", enrolCode))
                .header("Authorization", "Bearer " + token));

        // now the account has password + EMAIL_CODE (floor is 1, so removal would not break it): a
        // removal on a merely-live session is still refused for a step-up, not silently allowed
        HttpResponse<Map> removeRefused = exchange(HttpRequest.DELETE("/account/factors/EMAIL_CODE")
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.FORBIDDEN, removeRefused.getStatus());
        assertEquals("STEP_UP_REQUIRED", removeRefused.getBody(Map.class).orElseThrow().get("status"));
    }

    @Test
    @DisplayName("an enrolment envelope is not a sign-in: the passkey cannot be answered with the password alone")
    void webauthn_enrolment_envelope_does_not_sign_in() throws Exception {
        String email = "passkey-bypass@example.com";
        String token = registerVerifyAuthenticate(email);
        java.security.KeyPair key = p256();
        enrolWebauthnFactor(token, key);

        // the attacker holds the password and nothing else: the 202 hands out the challenge nonce,
        // which is public by design, and they echo it back inside an ENROLMENT envelope
        Map<?, ?> first = exchange(HttpRequest.POST("/authenticate",
                Map.of("email", email, "password", PASSWORD))).getBody(Map.class).orElseThrow();
        assertEquals("WEBAUTHN", first.get("nextFactor"));
        String envelope = enrolmentEnvelope((String) first.get("challengeData"));

        HttpResponse<Map> refused = exchange(HttpRequest.POST("/authenticate/factor",
                Map.of("mfaTicket", first.get("mfaTicket"), "proof", envelope)));
        assertEquals(HttpStatus.UNAUTHORIZED, refused.getStatus(),
                "a create envelope proves possession of nothing — the passkey must be signed");
        assertEquals("WRONG_CODE", refused.getBody(Map.class).orElseThrow().get("status"));

        // the same envelope at the step-up gate, where the caller already holds a live session
        Map<?, ?> started = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "enrol-factor", "password", PASSWORD))
                .header("Authorization", "Bearer " + token)).getBody(Map.class).orElseThrow();
        assertEquals("WEBAUTHN", started.get("nextFactor"), "the enrolled passkey guards the step-up too");
        HttpResponse<Map> notElevated = exchange(HttpRequest.POST("/account/step-up/factor",
                        Map.of("stepUpTicket", started.get("stepUpTicket"),
                                "proof", enrolmentEnvelope((String) started.get("challengeData"))))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.UNAUTHORIZED, notElevated.getStatus());

        // and the honest assertion still signs in, so the refusal is about the envelope, not the flow
        Map<?, ?> again = exchange(HttpRequest.POST("/authenticate",
                Map.of("email", email, "password", PASSWORD))).getBody(Map.class).orElseThrow();
        assertEquals(HttpStatus.OK, exchange(HttpRequest.POST("/authenticate/factor",
                Map.of("mfaTicket", again.get("mfaTicket"),
                        "proof", webauthnAssertion(key, (String) again.get("challengeData"))))).getStatus());
    }

    // --- WebAuthn test helpers: this test plays the browser (build + sign), the server verifies ---

    private static final java.util.Base64.Encoder B64URL = java.util.Base64.getUrlEncoder().withoutPadding();
    private static final String WEBAUTHN_RP_ID = "localhost";
    private static final String WEBAUTHN_ORIGIN = "http://localhost:4200";

    private static java.security.KeyPair p256() throws Exception {
        java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("EC");
        g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    private static byte[] clientData(String type, String challengeNonce) {
        return ("{\"type\":\"" + type + "\",\"challenge\":\"" + challengeNonce + "\",\"origin\":\""
                + WEBAUTHN_ORIGIN + "\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String webauthnAssertion(java.security.KeyPair key, String challengeNonce) throws Exception {
        byte[] cd = clientData("webauthn.get", challengeNonce);
        byte[] authData = new byte[37];
        System.arraycopy(sha256(WEBAUTHN_RP_ID.getBytes(java.nio.charset.StandardCharsets.UTF_8)), 0, authData, 0, 32);
        authData[32] = 0x05;   // UP + UV
        byte[] message = new byte[authData.length + 32];
        System.arraycopy(authData, 0, message, 0, authData.length);
        System.arraycopy(sha256(cd), 0, message, authData.length, 32);
        java.security.Signature ecdsa = java.security.Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(key.getPrivate());
        ecdsa.update(message);
        return "{\"type\":\"webauthn.get\",\"credentialId\":\"passkey-1\",\"authenticatorData\":\""
                + b64url(authData) + "\",\"signature\":\"" + b64url(ecdsa.sign())
                + "\",\"clientDataJSON\":\"" + b64url(cd) + "\"}";
    }

    /** Enrol a passkey honestly: start, then confirm with an attestation carrying the public key. */
    private void enrolWebauthnFactor(String token, java.security.KeyPair key) {
        stepUpToEnrol(token);
        HttpResponse<Map> start = exchange(HttpRequest.POST("/account/factors/WEBAUTHN/enroll/start", Map.of())
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.ACCEPTED, start.getStatus());
        String nonce = webauthnField((String) start.getBody(Map.class).orElseThrow().get("display"), "challenge");
        String attestation = "{\"type\":\"webauthn.create\",\"credentialId\":\"passkey-1\",\"publicKey\":\""
                + b64url(key.getPublic().getEncoded()) + "\",\"clientDataJSON\":\""
                + b64url(clientData("webauthn.create", nonce)) + "\"}";
        assertEquals(HttpStatus.OK, exchange(HttpRequest.POST("/account/factors/WEBAUTHN/enroll/confirm",
                Map.of("code", attestation)).header("Authorization", "Bearer " + token)).getStatus());
    }

    /** What an attacker can build from the password alone: an enrolment envelope with no signature. */
    private static String enrolmentEnvelope(String challengeNonce) {
        return "{\"type\":\"webauthn.create\",\"credentialId\":\"forged\",\"publicKey\":\"forged\","
                + "\"clientDataJSON\":\"" + b64url(clientData("webauthn.create", challengeNonce)) + "\"}";
    }

    /** Read a flat string field from the enrol display JSON (challenge nonce). */
    private static String webauthnField(String json, String key) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        assertEquals(true, m.find(), "no " + key + " in " + json);
        return m.group(1);
    }

    private static byte[] sha256(byte[] input) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-256").digest(input);
    }

    private static String b64url(byte[] bytes) {
        return B64URL.encodeToString(bytes);
    }

    private static String secretFromOtpauth(String uri) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("secret=([A-Z2-7]+)").matcher(uri);
        assertEquals(true, m.find(), "no secret in otpauth URI: " + uri);
        return m.group(1);
    }

    /** A TOTP code for the current second — the server runs a frozen test clock, so "now" agrees. */
    private String totp(String base32) {
        try {
            long step = server.getApplicationContext().getBean(java.time.Clock.class).instant().getEpochSecond() / 30;
            byte[] key = base32Decode(base32);
            byte[] data = new byte[8];
            for (int i = 7; i >= 0; i--) { data[i] = (byte) (step & 0xff); step >>= 8; }
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA1"));
            byte[] h = mac.doFinal(data);
            int o = h[h.length - 1] & 0x0f;
            int bin = ((h[o] & 0x7f) << 24) | ((h[o + 1] & 0xff) << 16) | ((h[o + 2] & 0xff) << 8) | (h[o + 3] & 0xff);
            return String.format("%06d", bin % 1_000_000);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] base32Decode(String s) {
        String base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int buffer = 0, bits = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char ch : s.replace("=", "").toUpperCase().toCharArray()) {
            int v = base32.indexOf(ch);
            if (v < 0) continue;
            buffer = (buffer << 5) | v; bits += 5;
            if (bits >= 8) { out.write((buffer >> (bits - 8)) & 0xff); bits -= 8; }
        }
        return out.toByteArray();
    }

    // --- Helpers --------------------------------------------------------------

    private String registerVerifyAuthenticate(String email) {
        assertEquals(HttpStatus.CREATED,
                exchange(HttpRequest.POST("/register", Map.of("email", email, "password", PASSWORD))).getStatus());
        String verificationToken = server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(email);
        assertEquals(HttpStatus.OK,
                exchange(HttpRequest.POST("/verify-email", Map.of("token", verificationToken))).getStatus());
        HttpResponse<Map> authenticated =
                exchange(HttpRequest.POST("/authenticate", Map.of("email", email, "password", PASSWORD)));
        assertEquals(HttpStatus.OK, authenticated.getStatus(), "no factors yet, so the password signs in directly");
        return (String) authenticated.getBody(Map.class).orElseThrow().get("accessToken");
    }

    /**
     * Minting recovery codes is guarded by the SECOND_FACTORS policy: these are durable spare keys
     * that stand in for the factor, so proving the factor is exactly the proof that fits. The
     * password alone starts the step-up and answers with a ticket; the mailed code completes it.
     */
    private void stepUpToMintCodes(String email, String token) {
        HttpResponse<Map> started = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "generate-recovery-codes", "password", PASSWORD))
                .header("Authorization", "Bearer " + token));
        // 200 when the password was the whole chain, 202 when a factor challenge went out
        assertTrue(started.getStatus() == HttpStatus.OK || started.getStatus() == HttpStatus.ACCEPTED,
                "step-up refused outright: " + started.getStatus());
        Map<?, ?> body = started.getBody(Map.class).orElseThrow();
        if ("ELEVATED".equals(body.get("status"))) {
            return;   // no factor enrolled: the password was the whole chain
        }
        HttpResponse<Map> completed = exchange(HttpRequest.POST("/account/step-up/factor",
                        Map.of("stepUpTicket", body.get("stepUpTicket"), "proof", codeChannel().lastCodeFor(email)))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.OK, completed.getStatus(), "the factor proof must complete the step-up");
        assertEquals("ELEVATED", completed.getBody(Map.class).orElseThrow().get("status"));
    }

    /** Enrolling a factor now needs a fresh step-up; a factor-less account elevates on the password alone. */
    private void stepUpToEnrol(String token) {
        HttpResponse<Map> elevated = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "enrol-factor", "password", PASSWORD))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.OK, elevated.getStatus(), "step-up before enrolment must elevate");
    }

    private void enrolEmailFactor(String email, String token) {
        stepUpToEnrol(token);
        assertEquals(HttpStatus.ACCEPTED, exchange(HttpRequest.POST("/account/factors/EMAIL_CODE/enroll/start", Map.of())
                .header("Authorization", "Bearer " + token)).getStatus());
        String enrolCode = codeChannel().lastCodeFor(email);
        HttpResponse<Map> confirmed = exchange(HttpRequest.POST("/account/factors/EMAIL_CODE/enroll/confirm",
                        Map.of("code", enrolCode)).header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.OK, confirmed.getStatus());
        assertEquals("ENROLLED", confirmed.getBody(Map.class).orElseThrow().get("status"));
    }

    private CapturingEmailCodeChannel codeChannel() {
        return server.getApplicationContext().getBean(CapturingEmailCodeChannel.class);
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
