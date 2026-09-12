package com.jrobertgardzinski;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.repository.EmailVerificationRepository;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;
import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link EmailVerificationRepository} used when no database is configured (tests). Keyed
 * by e-mail, each row holds the SHA-256 hash of the pending token (never the raw token) and whether
 * the address is verified.
 */
@Singleton
@Requires(missingBeans = DataSource.class)
final class InMemoryEmailVerificationRepository implements EmailVerificationRepository {

    private record Row(String pendingTokenHash, boolean verified, LocalDateTime requestedAt) {}

    private final Map<String, Row> byEmail = new ConcurrentHashMap<>();
    private final Clock clock;

    InMemoryEmailVerificationRepository(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void startVerification(Email email, VerificationToken token) {
        byEmail.put(email.value(), new Row(TokenHashing.hash(token), false, LocalDateTime.now(clock)));
    }

    @Override
    public Optional<PendingVerification> completeVerification(VerificationToken token) {
        String hash = TokenHashing.hash(token);
        return byEmail.entrySet().stream()
                .filter(e -> hash.equals(e.getValue().pendingTokenHash()))
                .findFirst()
                .map(e -> {
                    LocalDateTime requestedAt = e.getValue().requestedAt();
                    byEmail.put(e.getKey(), new Row(null, true, requestedAt));
                    return new PendingVerification(Email.of(e.getKey()), requestedAt);
                });
    }

    @Override
    public void markVerified(Email email) {
        byEmail.put(email.value(), new Row(null, true, LocalDateTime.now(clock)));
    }

    @Override
    public boolean isVerified(Email email) {
        Row row = byEmail.get(email.value());
        return row != null && row.verified();
    }

    @Override
    public void purge(Email email) {
        byEmail.remove(email.value());
    }
}
