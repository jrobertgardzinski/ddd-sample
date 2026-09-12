package com.jrobertgardzinski.security.system.mfa;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.domain.vo.FactorType;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The WebAuthn factor verified against a keypair generated right here — no recorded fixture, no
 * library: the test plays the browser (build clientDataJSON + authenticatorData, sign with a P-256
 * key) and the factor plays the server. Proves enrolment stores the public key, a genuine assertion
 * passes, and a tampered one is refused.
 */
@Epic("Use case")
@Feature("MFA — WebAuthn factor")
class WebauthnFactorTest {

    private static final Base64.Decoder URL = Base64.getUrlDecoder();
    private static final Base64.Encoder URL_NOPAD = Base64.getUrlEncoder().withoutPadding();
    private static final String RP_ID = "localhost";
    private static final String ORIGIN = "http://localhost:4200";

    private final Clock clock = Clock.fixed(Instant.parse("2026-07-07T12:00:00Z"), ZoneOffset.UTC);
    private final WebauthnFactor factor =
            new WebauthnFactor(clock, RP_ID, "Security", List.of(ORIGIN), 5);
    private final KeyPair keyPair = p256();

    @Test
    @DisplayName("enrolment accepts a create attestation and stores the credential's public key")
    void enrols_and_stores_the_key() {
        EnrolmentSetup setup = factor.beginEnrolment("alice@example.com");
        String nonce = setup.challenge().publicData();

        String clientData = clientDataJson("webauthn.create", nonce);
        String publicKey = b64(keyPair.getPublic().getEncoded());   // SPKI, as the browser hands it
        String proof = "{\"type\":\"webauthn.create\",\"credentialId\":\"cred-1\","
                + "\"publicKey\":\"" + publicKey + "\",\"clientDataJSON\":\"" + b64(clientData.getBytes(StandardCharsets.UTF_8)) + "\"}";

        EnrolledFactor pending = new EnrolledFactor(Email.of("alice@example.com"),
                FactorType.WEBAUTHN, "passkey", 1, "");
        assertTrue(factor.verify(pending, Optional.of(setup.challenge()), proof));

        String stored = factor.enrolledMaterial("", proof);
        assertTrue(stored.contains(publicKey), "the stored material carries the public key");
        assertTrue(stored.contains("cred-1"));
    }

    @Test
    @DisplayName("a genuine assertion passes; a tampered signature is refused")
    void verifies_an_assertion() throws Exception {
        EnrolledFactor enrolment = new EnrolledFactor(Email.of("alice@example.com"),
                FactorType.WEBAUTHN, "passkey", 1,
                "{\"credentialId\":\"cred-1\",\"publicKey\":\"" + b64(keyPair.getPublic().getEncoded()) + "\"}");

        Challenge challenge = factor.issueChallenge(enrolment).orElseThrow();
        String nonce = challenge.publicData();
        String clientData = clientDataJson("webauthn.get", nonce);
        byte[] authenticatorData = authenticatorData();
        byte[] signed = concat(authenticatorData, sha256(clientData.getBytes(StandardCharsets.UTF_8)));

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(keyPair.getPrivate());
        ecdsa.update(signed);
        byte[] signature = ecdsa.sign();

        assertTrue(factor.verify(enrolment, Optional.of(challenge), assertionProof(authenticatorData, signature, clientData)));

        byte[] tampered = signature.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertFalse(factor.verify(enrolment, Optional.of(challenge), assertionProof(authenticatorData, tampered, clientData)));
    }

    @Test
    @DisplayName("an enrolment envelope does not sign in: a create proof against a stored passkey is refused")
    void refuses_a_create_envelope_against_an_enrolled_factor() {
        // the enrolled factor carries the credential — this is what sign-in and step-up verify against
        EnrolledFactor enrolment = new EnrolledFactor(Email.of("alice@example.com"),
                FactorType.WEBAUTHN, "passkey", 1,
                "{\"credentialId\":\"cred-1\",\"publicKey\":\"" + b64(keyPair.getPublic().getEncoded()) + "\"}");
        Challenge challenge = factor.issueChallenge(enrolment).orElseThrow();

        // the nonce is public by design (it is handed to the client in the 202), so echoing it back
        // inside an enrolment envelope proves nothing about possessing the passkey
        String clientData = clientDataJson("webauthn.create", challenge.publicData());
        String enrolmentEnvelope = "{\"type\":\"webauthn.create\",\"credentialId\":\"anything\","
                + "\"publicKey\":\"whatever\",\"clientDataJSON\":\""
                + b64(clientData.getBytes(StandardCharsets.UTF_8)) + "\"}";

        assertFalse(factor.verify(enrolment, Optional.of(challenge), enrolmentEnvelope),
                "only a pending enrolment may be proven by a create envelope");
    }

    @Test
    @DisplayName("a foreign origin is refused even with a valid signature")
    void refuses_a_foreign_origin() throws Exception {
        EnrolledFactor enrolment = new EnrolledFactor(Email.of("alice@example.com"),
                FactorType.WEBAUTHN, "passkey", 1,
                "{\"credentialId\":\"cred-1\",\"publicKey\":\"" + b64(keyPair.getPublic().getEncoded()) + "\"}");
        Challenge challenge = factor.issueChallenge(enrolment).orElseThrow();
        String clientData = clientDataJson("webauthn.get", challenge.publicData())
                .replace(ORIGIN, "http://evil.example.com");
        byte[] authenticatorData = authenticatorData();
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(keyPair.getPrivate());
        ecdsa.update(concat(authenticatorData, sha256(clientData.getBytes(StandardCharsets.UTF_8))));
        byte[] signature = ecdsa.sign();

        assertFalse(factor.verify(enrolment, Optional.of(challenge), assertionProof(authenticatorData, signature, clientData)));
    }

    @Test
    @DisplayName("an assertion without the User Present flag is refused, even correctly signed")
    void refuses_without_user_presence() throws Exception {
        EnrolledFactor enrolment = new EnrolledFactor(Email.of("alice@example.com"),
                FactorType.WEBAUTHN, "passkey", 1,
                "{\"credentialId\":\"cred-1\",\"publicKey\":\"" + b64(keyPair.getPublic().getEncoded()) + "\"}");
        Challenge challenge = factor.issueChallenge(enrolment).orElseThrow();
        String clientData = clientDataJson("webauthn.get", challenge.publicData());
        byte[] authenticatorData = authenticatorData();
        authenticatorData[32] = 0x00;   // no User Present bit — a signature with no gesture
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(keyPair.getPrivate());
        ecdsa.update(concat(authenticatorData, sha256(clientData.getBytes(StandardCharsets.UTF_8))));

        assertFalse(factor.verify(enrolment, Optional.of(challenge),
                assertionProof(authenticatorData, ecdsa.sign(), clientData)));
    }

    private static String clientDataJson(String type, String challengeNonce) {
        return "{\"type\":\"" + type + "\",\"challenge\":\"" + challengeNonce + "\",\"origin\":\"" + ORIGIN + "\"}";
    }

    private static String assertionProof(byte[] authenticatorData, byte[] signature, String clientData) {
        return "{\"type\":\"webauthn.get\",\"credentialId\":\"cred-1\","
                + "\"authenticatorData\":\"" + b64(authenticatorData) + "\","
                + "\"signature\":\"" + b64(signature) + "\","
                + "\"clientDataJSON\":\"" + b64(clientData.getBytes(StandardCharsets.UTF_8)) + "\"}";
    }

    private static byte[] authenticatorData() {
        byte[] data = new byte[37];                       // rpIdHash(32) + flags(1) + counter(4)
        System.arraycopy(sha256(RP_ID.getBytes(StandardCharsets.UTF_8)), 0, data, 0, 32);
        data[32] = 0x05;                                  // UP + UV set
        return data;
    }

    private static KeyPair p256() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String b64(byte[] bytes) {
        return URL_NOPAD.encodeToString(bytes);
    }
}
