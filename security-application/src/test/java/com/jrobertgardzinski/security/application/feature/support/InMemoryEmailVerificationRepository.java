package com.jrobertgardzinski.security.application.feature.support;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.repository.EmailVerificationRepository;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Test double for {@link EmailVerificationRepository}: plain maps, raw token values as keys (test
 * scope, so no hashing).
 */
public class InMemoryEmailVerificationRepository implements EmailVerificationRepository {

    private final Map<String, String> pendingTokenByEmail = new HashMap<>();
    private final Map<String, LocalDateTime> requestedAtByEmail = new HashMap<>();
    private final Map<String, Boolean> verifiedByEmail = new HashMap<>();
    private final Clock clock;

    public InMemoryEmailVerificationRepository(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void startVerification(Email email, VerificationToken token) {
        pendingTokenByEmail.put(email.value(), token.value());
        requestedAtByEmail.put(email.value(), LocalDateTime.now(clock));
        verifiedByEmail.put(email.value(), false);
    }

    @Override
    public Optional<PendingVerification> completeVerification(VerificationToken token) {
        return pendingTokenByEmail.entrySet().stream()
                .filter(e -> e.getValue().equals(token.value()))
                .findFirst()
                .map(e -> {
                    verifiedByEmail.put(e.getKey(), true);
                    pendingTokenByEmail.remove(e.getKey());
                    return new PendingVerification(
                            Email.of(e.getKey()), requestedAtByEmail.remove(e.getKey()));
                });
    }

    @Override
    public void markVerified(Email email) {
        pendingTokenByEmail.remove(email.value());
        requestedAtByEmail.remove(email.value());
        verifiedByEmail.put(email.value(), true);
    }

    @Override
    public boolean isVerified(Email email) {
        return verifiedByEmail.getOrDefault(email.value(), false);
    }

    @Override
    public void purge(Email email) {
        pendingTokenByEmail.remove(email.value());
        requestedAtByEmail.remove(email.value());
        verifiedByEmail.remove(email.value());
    }
}
