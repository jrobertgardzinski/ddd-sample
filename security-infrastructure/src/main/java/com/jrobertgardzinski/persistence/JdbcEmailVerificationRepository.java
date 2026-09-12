package com.jrobertgardzinski.persistence;

import com.jrobertgardzinski.TokenHashing;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.repository.EmailVerificationRepository;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;
import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Optional;

/**
 * PostgreSQL-backed {@link EmailVerificationRepository}. Stores the pending token as a SHA-256 hash
 * (see {@link TokenHashing}); completing verification matches on that hash, marks the row verified
 * and clears the token. Raw tokens are never stored.
 */
@Singleton
@Requires(beans = DataSource.class)
final class JdbcEmailVerificationRepository implements EmailVerificationRepository {

    private final EmailVerificationJdbcRepository repository;
    private final Clock clock;

    JdbcEmailVerificationRepository(EmailVerificationJdbcRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Override
    public void startVerification(Email email, VerificationToken token) {
        repository.deleteById(email.value());   // re-requesting reissues a fresh token
        repository.save(new EmailVerificationEntity(email.value(), TokenHashing.hash(token), false,
                LocalDateTime.now(clock)));
    }

    @Override
    public Optional<PendingVerification> completeVerification(VerificationToken token) {
        String hash = TokenHashing.hash(token);
        return repository.findByPendingTokenHash(hash)
                .filter(entity -> repository.markVerified(hash) > 0)   // the UPDATE decides
                .map(entity -> new PendingVerification(Email.of(entity.email()), entity.requestedAt()));
    }

    @Override
    public void markVerified(Email email) {
        repository.deleteById(email.value());
        repository.save(new EmailVerificationEntity(email.value(), null, true, LocalDateTime.now(clock)));
    }

    @Override
    public boolean isVerified(Email email) {
        return repository.findById(email.value()).map(EmailVerificationEntity::verified).orElse(false);
    }

    @Override
    public void purge(Email email) {
        repository.deleteById(email.value());
    }
}
