package com.jrobertgardzinski.security.system.mfa;

import com.jrobertgardzinski.security.config.mfa.ChallengeCodeConfig;
import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.domain.port.CodeChannel;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Optional;

/**
 * A one-time-code factor over a {@link CodeChannel} — the same factor for every channel that
 * delivers a short code (e-mail, SMS, …). It mints a random numeric code, sends it through the
 * channel, and remembers only its hash and expiry; verification checks the presented code against
 * that hash, refusing an expired one. The channel decides the medium and which {@code FactorType}
 * this instance is; everything else is shared. Two channels, two factors, one class — the
 * plug-and-play win: a new code channel is a new bean, not a new factor class.
 */
public class CodeFactor implements AuthenticationFactor {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final CodeChannel channel;
    private final CodeHasher hasher;
    private final ChallengeCodeConfig config;
    private final Clock clock;

    public CodeFactor(CodeChannel channel, CodeHasher hasher, ChallengeCodeConfig config, Clock clock) {
        this.channel = channel;
        this.hasher = hasher;
        this.config = config;
        this.clock = clock;
    }

    @Override
    public com.jrobertgardzinski.security.domain.vo.FactorType type() {
        return channel.servesFactor();
    }

    @Override
    public boolean needsChallenge() {
        return true;
    }

    @Override
    public EnrolmentSetup beginEnrolment(String requestedTarget) {
        // the secret IS the target (where to send the code); a code goes out now to prove control
        return new EnrolmentSetup(requestedTarget, null, sendCodeTo(requestedTarget));
    }

    @Override
    public Optional<Challenge> issueChallenge(EnrolledFactor enrolment) {
        return Optional.of(sendCodeTo(enrolment.secretMaterial()));
    }

    @Override
    public boolean verify(EnrolledFactor enrolment, Optional<Challenge> challenge, String proof) {
        return challenge
                .filter(c -> !c.isExpired(clock))
                .map(c -> c.codeHash().equals(hasher.hash(proof)))
                .orElse(false);
    }

    private Challenge sendCodeTo(String target) {
        String code = randomCode();
        channel.sendCode(target, code);
        return Challenge.secret(hasher.hash(code), LocalDateTime.now(clock).plusMinutes(config.codeTtlMinutes().value()));
    }

    private String randomCode() {
        StringBuilder code = new StringBuilder(config.codeLength().value());
        for (int i = 0; i < config.codeLength().value(); i++) {
            code.append(RANDOM.nextInt(10));
        }
        return code.toString();
    }
}
