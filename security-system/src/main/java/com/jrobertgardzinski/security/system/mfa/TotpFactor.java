package com.jrobertgardzinski.security.system.mfa;

import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.domain.vo.FactorType;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Optional;

/**
 * A time-based one-time-password factor (RFC 6238 over HMAC-SHA1), i.e. Google Authenticator. A
 * POSSESSION factor: it sends nothing — enrolment generates a shared secret and hands back an
 * {@code otpauth://} URI for the user's app to scan; verification recomputes the current code from
 * the secret. Self-contained, no channel, no I/O — the proof that the registry is genuinely
 * plug-and-play (this factor plugs in beside the code factors with no change to the chain).
 *
 * <p>Codes are checked for the current 30-second step and one step either side, to tolerate clock
 * skew between the server and the authenticator app — and each step is spendable ONCE
 * ({@link SpentTotpSteps}), because a code that keeps working for the rest of its window is a code
 * anyone who saw it can still use.
 */
public class TotpFactor implements AuthenticationFactor {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int STEP_SECONDS = 30;
    private static final int DIGITS = 6;
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private final Clock clock;
    private final String issuerLabel;
    private final SpentTotpSteps spentSteps;

    public TotpFactor(Clock clock, String issuerLabel, SpentTotpSteps spentSteps) {
        this.clock = clock;
        this.issuerLabel = issuerLabel;
        this.spentSteps = spentSteps;
    }

    @Override
    public FactorType type() {
        return FactorType.TOTP;
    }

    @Override
    public boolean needsChallenge() {
        return false;
    }

    @Override
    public EnrolmentSetup beginEnrolment(String accountName) {
        String secret = randomBase32Secret();
        String label = enc(issuerLabel) + ":" + enc(accountName);
        String otpauth = "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + enc(issuerLabel)
                + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + STEP_SECONDS;
        return new EnrolmentSetup(secret, otpauth, null);   // nothing sent; the URI is shown for a QR
    }

    @Override
    public Optional<Challenge> issueChallenge(EnrolledFactor enrolment) {
        return Optional.empty();   // possession factor — nothing to send
    }

    @Override
    public boolean verify(EnrolledFactor enrolment, Optional<Challenge> challenge, String proof) {
        String normalised = proof == null ? "" : proof.strip();
        if (!normalised.matches("\\d{" + DIGITS + "}")) {
            return false;
        }
        byte[] key = base32Decode(enrolment.secretMaterial());
        long step = clock.instant().getEpochSecond() / STEP_SECONDS;
        for (long window = -1; window <= 1; window++) {   // tolerate ±1 step of skew
            if (constantTimeEquals(code(key, step + window), normalised)) {
                // the digits are right; they are only a PROOF the first time they are presented
                return spentSteps.claim(enrolment, step + window);
            }
        }
        return false;
    }

    /**
     * Compares the two codes without letting the clock answer first.
     *
     * <p>Unexploitable here — five attempts per ticket, and the window bounds the guessing anyway —
     * so this is hygiene rather than a fix: a comparison of a secret that returns early is a habit
     * worth not having, and the next thing compared this way may not be attempt-limited.
     */
    private static boolean constantTimeEquals(String expected, String presented) {
        return java.security.MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), presented.getBytes(StandardCharsets.UTF_8));
    }

    private static String code(byte[] key, long counter) {
        byte[] data = new byte[8];
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) (counter & 0xff);
            counter >>= 8;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
            return String.format("%0" + DIGITS + "d", binary % (int) Math.pow(10, DIGITS));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA1 is required but unavailable", e);
        }
    }

    private static String randomBase32Secret() {
        byte[] bytes = new byte[20];   // 160-bit secret, RFC 4226's recommendation
        RANDOM.nextBytes(bytes);
        StringBuilder out = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : bytes) {
            buffer = (buffer << 8) | (b & 0xff);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                out.append(BASE32.charAt((buffer >> (bitsLeft - 5)) & 0x1f));
                bitsLeft -= 5;
            }
        }
        return out.toString();
    }

    private static byte[] base32Decode(String secret) {
        String clean = secret.trim().replace("=", "").toUpperCase();
        int buffer = 0;
        int bitsLeft = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char c : clean.toCharArray()) {
            int value = BASE32.indexOf(c);
            if (value < 0) {
                continue;
            }
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.write((buffer >> (bitsLeft - 8)) & 0xff);
                bitsLeft -= 8;
            }
        }
        return out.toByteArray();
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
