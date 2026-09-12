package com.jrobertgardzinski.security.system.mfa;

import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.domain.vo.FactorType;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * A WebAuthn / passkey factor — a POSSESSION factor proven by a signature, no code sent. Pure JDK,
 * no library: the browser hands us the credential's public key directly (SPKI from
 * {@code AuthenticatorAttestationResponse.getPublicKey()}), so there is no CBOR/COSE to parse, and
 * an assertion is an ordinary {@code SHA256withECDSA} signature over
 * {@code authenticatorData || SHA256(clientDataJSON)}. This is the proof that the factor port is
 * genuinely plug-and-play: it plugs in beside the code and TOTP factors, the chain never changes.
 *
 * <p>Enrolment ({@code webauthn.create}) stores {credentialId, publicKey} distilled from the proof
 * via {@link #enrolledMaterial}; sign-in ({@code webauthn.get}) verifies the assertion signature
 * against that stored key. Both check the challenge (against the issued {@link Challenge}), the
 * relying-party id and an allow-listed origin.
 *
 * <p>The two envelopes are not interchangeable, and the enrolment state decides which one is even
 * looked at: a {@code create} envelope is only ever accepted against a PENDING enrolment (blank
 * secret material). An enrolled factor is proven by a signature and nothing else — otherwise the
 * password alone would sign in, since the challenge nonce is public by design.
 *
 * <p>Proof envelopes (the UI sends flat JSON, all binary base64url):
 * <ul>
 *   <li>enrolment: {@code {"type":"webauthn.create","credentialId":..,"publicKey":..(SPKI),
 *       "clientDataJSON":..}}</li>
 *   <li>sign-in: {@code {"type":"webauthn.get","credentialId":..,"authenticatorData":..,
 *       "signature":..,"clientDataJSON":..}}</li>
 * </ul>
 */
public class WebauthnFactor implements AuthenticationFactor {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Decoder URL = Base64.getUrlDecoder();
    private static final Base64.Encoder URL_NOPAD = Base64.getUrlEncoder().withoutPadding();

    private final Clock clock;
    private final String rpId;         // the relying-party id (an eTLD+1, e.g. "localhost")
    private final String rpName;       // shown by the authenticator
    private final List<String> allowedOrigins;
    private final int challengeTtlMinutes;

    public WebauthnFactor(Clock clock, String rpId, String rpName, List<String> allowedOrigins,
                          int challengeTtlMinutes) {
        this.clock = clock;
        this.rpId = rpId;
        this.rpName = rpName;
        this.allowedOrigins = List.copyOf(allowedOrigins);
        this.challengeTtlMinutes = challengeTtlMinutes;
    }

    @Override
    public FactorType type() {
        return FactorType.WEBAUTHN;
    }

    @Override
    public boolean needsChallenge() {
        return true;
    }

    @Override
    public EnrolmentSetup beginEnrolment(String accountName) {
        byte[] nonce = randomNonce();
        // display carries the creation options the browser needs for navigator.credentials.create;
        // the stored pending material is empty — the real secret (the public key) arrives at confirm
        String creationOptions = "{"
                + "\"challenge\":\"" + b64(nonce) + "\","
                + "\"rpId\":\"" + rpId + "\","
                + "\"rpName\":\"" + rpName + "\","
                + "\"userName\":\"" + accountName + "\"}";
        return new EnrolmentSetup("", creationOptions, challengeOf(nonce));
    }

    @Override
    public Optional<Challenge> issueChallenge(EnrolledFactor enrolment) {
        return Optional.of(challengeOf(randomNonce()));
    }

    @Override
    public boolean verify(EnrolledFactor enrolment, Optional<Challenge> challenge, String proof) {
        if (proof == null || challenge.isEmpty()) {
            return false;
        }
        try {
            String clientDataB64 = field(proof, "clientDataJSON");
            byte[] clientData = URL.decode(clientDataB64);
            String clientJson = new String(clientData, StandardCharsets.UTF_8);

            String type = field(clientJson, "type");
            String challengeEcho = field(clientJson, "challenge");
            String origin = field(clientJson, "origin");
            if (type == null || challengeEcho == null || !allowedOrigins.contains(origin)) {
                return false;
            }
            // the browser echoes the challenge we issued; its SHA-256 must match what we stored
            if (!Arrays.equals(sha256(URL.decode(challengeEcho)), URL.decode(challenge.get().codeHash()))) {
                return false;
            }
            if ("webauthn.create".equals(type)) {
                // enrolment only, and only while the enrolment is still pending: the public key is
                // distilled by enrolledMaterial after this passes. A stored factor always carries
                // {credentialId,publicKey}, so at sign-in and step-up this branch is refused and
                // the proof has to be a signed webauthn.get assertion against the enrolled key.
                return isPending(enrolment)
                        && field(proof, "publicKey") != null && field(proof, "credentialId") != null;
            }
            if ("webauthn.get".equals(type)) {
                return verifyAssertion(enrolment, proof, clientData);
            }
            return false;
        } catch (RuntimeException malformed) {
            return false;
        }
    }

    @Override
    public String enrolledMaterial(String pendingMaterial, String proof) {
        // store exactly what a sign-in assertion needs to be checked against
        return "{\"credentialId\":\"" + field(proof, "credentialId") + "\","
                + "\"publicKey\":\"" + field(proof, "publicKey") + "\"}";
    }

    /**
     * Whether this is the candidate {@link EnrolFactor#confirm} builds from the pending material —
     * blank, the sentinel {@link #beginEnrolment} stores, because the real secret (the public key)
     * only arrives with the confirming attestation. Anything read back from the factor repository
     * carries that key, so it is not pending.
     */
    private static boolean isPending(EnrolledFactor enrolment) {
        return enrolment.secretMaterial() == null || enrolment.secretMaterial().isBlank();
    }

    private boolean verifyAssertion(EnrolledFactor enrolment, String proof, byte[] clientData) {
        try {
            byte[] authenticatorData = URL.decode(field(proof, "authenticatorData"));
            byte[] signature = URL.decode(field(proof, "signature"));
            // authenticatorData is rpIdHash(32) + flags(1) + signCount(4) + ...
            if (authenticatorData.length < 37) {
                return false;
            }
            // it begins with the SHA-256 of the relying-party id
            if (!Arrays.equals(Arrays.copyOfRange(authenticatorData, 0, 32), sha256(rpId.getBytes(StandardCharsets.UTF_8)))) {
                return false;
            }
            // the User Present bit MUST be set — a signature alone is not a sign-in gesture (WebAuthn §7.2)
            if ((authenticatorData[32] & 0x01) == 0) {
                return false;
            }
            PublicKey key = publicKeyFrom(field(enrolment.secretMaterial(), "publicKey"));
            byte[] signedMessage = concat(authenticatorData, sha256(clientData));
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initVerify(key);
            ecdsa.update(signedMessage);
            return ecdsa.verify(signature);
        } catch (Exception invalid) {
            return false;
        }
    }

    private Challenge challengeOf(byte[] nonce) {
        // codeHash holds SHA-256(nonce) base64url; publicData is the raw nonce base64url for the client
        return Challenge.withPublicData(b64(sha256(nonce)),
                LocalDateTime.now(clock).plusMinutes(challengeTtlMinutes), b64(nonce));
    }

    private static PublicKey publicKeyFrom(String spkiBase64Url) throws Exception {
        return KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(URL.decode(spkiBase64Url)));
    }

    private static byte[] randomNonce() {
        byte[] nonce = new byte[32];
        RANDOM.nextBytes(nonce);
        return nonce;
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required but unavailable", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String b64(byte[] bytes) {
        return URL_NOPAD.encodeToString(bytes);
    }

    /**
     * Reads one flat string field {@code "key":"value"} out of a small, trusted JSON object. The
     * inputs are the browser's clientDataJSON (type/challenge/origin) and our own proof envelope —
     * both flat, both with ASCII string values — so a full JSON parser (and its dependency) is not
     * warranted. Returns null when the key is absent.
     */
    static String field(String json, String key) {
        String needle = "\"" + key + "\"";
        int at = json.indexOf(needle);
        if (at < 0) {
            return null;
        }
        int colon = json.indexOf(':', at + needle.length());
        if (colon < 0) {
            return null;
        }
        int quote = json.indexOf('"', colon + 1);
        if (quote < 0) {
            return null;
        }
        StringBuilder value = new StringBuilder();
        for (int i = quote + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                value.append(json.charAt(++i));   // keep the escaped char verbatim (URLs, etc.)
            } else if (c == '"') {
                return value.toString();
            } else {
                value.append(c);
            }
        }
        return null;
    }
}
