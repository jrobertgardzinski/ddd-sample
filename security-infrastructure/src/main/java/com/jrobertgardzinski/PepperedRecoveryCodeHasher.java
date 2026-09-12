package com.jrobertgardzinski;

import com.jrobertgardzinski.security.system.mfa.RecoveryCodeHasher;
import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Value;
import io.micronaut.context.env.Environment;
import jakarta.inject.Singleton;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

/**
 * HMAC-SHA256 under a server-held PEPPER — what the database holds for a recovery code.
 *
 * <p>Keyed rather than salted, and that is the design constraint rather than a preference: a code
 * is spent by looking its hash up, so every code must hash to the same value every time. A pepper
 * keeps that while making a stolen table worthless on its own — the attacker needs the key as well,
 * and the key is not in the database.
 *
 * <p>The pepper is deployment configuration ({@code security.mfa.recovery.pepper}). Under a
 * declared {@code prod} profile it MUST be set, for the same reason the datasource password must
 * (see {@link CredentialsFuse}): a default that ships in the repository is not a secret. In dev and
 * test a fixed value is used, so the stack starts with nothing to configure.
 *
 * <p><b>Changing the pepper invalidates every recovery code already issued</b> — they hash to
 * something else afterwards. So does arriving here from the old unkeyed digest: codes minted before
 * this class existed no longer match, and their owners must generate a fresh batch.
 */
@Context
@Singleton
final class PepperedRecoveryCodeHasher implements RecoveryCodeHasher {

    /** Dev and test only, and it says so out loud. */
    private static final String DEV_PEPPER = "dev-pepper-not-a-secret";

    private final SecretKeySpec key;

    PepperedRecoveryCodeHasher(@Value("${security.mfa.recovery.pepper:}") String pepper,
                               Environment environment) {
        String inForce = pepper == null || pepper.isBlank() ? null : pepper.strip();
        if (inForce == null && environment.getActiveNames().contains("prod")) {
            throw new IllegalStateException("outside dev/test the recovery codes need their own"
                    + " pepper - set security.mfa.recovery.pepper (or SECURITY_MFA_RECOVERY_PEPPER)"
                    + " in the deployment; a value shipped in the repository is not a secret, and"
                    + " without one a stolen table hands over every user's break-glass codes");
        }
        this.key = new SecretKeySpec((inForce == null ? DEV_PEPPER : inForce)
                .getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    @Override
    public String hash(String rawCode) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return HexFormat.of().formatHex(mac.doFinal(rawCode.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException impossible) {
            throw new IllegalStateException("HMAC-SHA256 is required but unavailable", impossible);
        }
    }
}
