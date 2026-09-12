package com.jrobertgardzinski.security.system.mfa;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.domain.vo.FactorType;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Epic("Use case")
@Feature("MFA — TOTP factor")
class TotpFactorTest {

    // RFC 6238 SHA1 test seed "12345678901234567890" in Base32, and its known code at T=59s
    private static final String RFC_SECRET_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final String CODE_AT_59S = "287082";

    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.ofEpochSecond(59));
    private final Clock clock = new Clock() {
        public Instant instant() { return now.get(); }
        public ZoneOffset getZone() { return ZoneOffset.UTC; }
        public Clock withZone(java.time.ZoneId zone) { return this; }
    };
    /**
     * The steps already spent, as the production adapter remembers them: the highest one wins and
     * anything at or below it is refused. A test double rather than a mock, because the rule this
     * pins IS the arithmetic.
     */
    private final java.util.Map<String, Long> spent = new java.util.HashMap<>();
    private final SpentTotpSteps spentSteps = (enrolment, step) -> {
        String key = enrolment.userEmail().value() + "|" + enrolment.type().value();
        Long previous = spent.get(key);
        if (previous != null && step <= previous) {
            return false;
        }
        spent.put(key, step);
        return true;
    };
    private final TotpFactor factor = new TotpFactor(clock, "security", spentSteps);

    private EnrolledFactor enrolmentWith(String secret) {
        return new EnrolledFactor(Email.of("u@example.com"), FactorType.TOTP, "authenticator app", 0, secret);
    }

    @Test
    @DisplayName("the RFC 6238 code verifies at its time step; a wrong code does not")
    void verifies_the_reference_code() {
        EnrolledFactor enrolment = enrolmentWith(RFC_SECRET_BASE32);
        assertTrue(factor.verify(enrolment, Optional.empty(), CODE_AT_59S), "the RFC test vector must verify");
        assertFalse(factor.verify(enrolment, Optional.empty(), "000000"));
        assertFalse(factor.verify(enrolment, Optional.empty(), "not-a-code"));
    }

    @Test
    @DisplayName("a code works ONCE: the same digits presented again are refused, window or no window")
    void a_spent_code_is_not_a_proof_any_more() {
        EnrolledFactor enrolment = enrolmentWith(RFC_SECRET_BASE32);
        assertTrue(factor.verify(enrolment, Optional.empty(), CODE_AT_59S));

        // same step, seconds later — this is the relay case: someone who saw the code has the rest
        // of the window to use it beside the owner
        assertFalse(factor.verify(enrolment, Optional.empty(), CODE_AT_59S),
                "a possession factor that accepts the same proof twice proves possession once");

        // and still refused a step later, where the ±1 skew window would otherwise re-admit it
        now.set(Instant.ofEpochSecond(59 + 30));
        assertFalse(factor.verify(enrolment, Optional.empty(), CODE_AT_59S),
                "the skew window must not resurrect a code that has already been spent");
    }

    @Test
    @DisplayName("a code from the adjacent time step still verifies (clock-skew tolerance)")
    void tolerates_one_step_of_skew() {
        EnrolledFactor enrolment = enrolmentWith(RFC_SECRET_BASE32);
        now.set(Instant.ofEpochSecond(59 + 30));   // one 30s step later
        assertTrue(factor.verify(enrolment, Optional.empty(), CODE_AT_59S), "the previous step's code is still accepted");
        now.set(Instant.ofEpochSecond(59 + 90));    // three steps later — out of the ±1 window
        assertFalse(factor.verify(enrolment, Optional.empty(), CODE_AT_59S));
    }

    @Test
    @DisplayName("enrolment mints a secret and an otpauth URI to scan, and sends nothing")
    void enrolment_produces_a_scannable_secret() {
        EnrolmentSetup setup = factor.beginEnrolment("u@example.com");
        assertNotNull(setup.secretMaterial());
        assertTrue(setup.display().startsWith("otpauth://totp/"), "a QR-scannable URI, got: " + setup.display());
        assertTrue(setup.display().contains("secret=" + setup.secretMaterial()));
        org.junit.jupiter.api.Assertions.assertNull(setup.challenge(), "a possession factor sends no challenge");
        assertFalse(factor.needsChallenge());

        // a code computed from the freshly minted secret verifies
        EnrolledFactor enrolment = enrolmentWith(setup.secretMaterial());
        String live = new TotpProbe(setup.secretMaterial(), now.get().getEpochSecond()).code();
        assertTrue(factor.verify(enrolment, Optional.empty(), live), "a code from the new secret verifies");
    }

    /** An independent TOTP computation, to prove the factor against a second implementation. */
    private static final class TotpProbe {
        private final byte[] key;
        private final long step;

        TotpProbe(String base32, long epoch) {
            this.key = base32Decode(base32);
            this.step = epoch / 30;
        }

        String code() {
            try {
                byte[] data = new byte[8];
                long c = step;
                for (int i = 7; i >= 0; i--) { data[i] = (byte) (c & 0xff); c >>= 8; }
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
            String clean = s.replace("=", "").toUpperCase();
            int buffer = 0, bits = 0;
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            for (char ch : clean.toCharArray()) {
                int v = base32.indexOf(ch);
                if (v < 0) continue;
                buffer = (buffer << 5) | v; bits += 5;
                if (bits >= 8) { out.write((buffer >> (bits - 8)) & 0xff); bits -= 8; }
            }
            return out.toByteArray();
        }
    }
}
