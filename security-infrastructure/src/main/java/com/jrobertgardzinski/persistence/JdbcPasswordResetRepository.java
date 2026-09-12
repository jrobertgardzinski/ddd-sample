package com.jrobertgardzinski.persistence;

import com.jrobertgardzinski.TokenHashing;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.repository.PasswordResetRepository;
import com.jrobertgardzinski.security.domain.vo.token.PasswordResetToken;
import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Optional;

/**
 * PostgreSQL-backed {@link PasswordResetRepository}. Stores the pending token as a SHA-256 hash (see
 * {@link TokenHashing}); consuming it matches on that hash, deletes the row (single-use) and returns
 * the address. Raw tokens are never stored.
 */
@Singleton
@Requires(beans = DataSource.class)
final class JdbcPasswordResetRepository implements PasswordResetRepository {

    private final PasswordResetJdbcRepository repository;
    private final Clock clock;

    JdbcPasswordResetRepository(PasswordResetJdbcRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Override
    public void startReset(Email email, PasswordResetToken token) {
        repository.deleteById(email.value());   // re-requesting reissues a fresh token
        repository.save(new PasswordResetEntity(email.value(), TokenHashing.hash(token),
                LocalDateTime.now(clock)));
    }

    @Override
    public Optional<PendingReset> consumeReset(PasswordResetToken token) {
        String hash = TokenHashing.hash(token);
        // the DELETE decides, not the read: whoever removes the row consumed the link, and a second
        // presentation of it removes nothing and is told nothing
        return repository.findByTokenHash(hash)
                .filter(entity -> repository.consume(hash) > 0)
                .map(entity -> new PendingReset(Email.of(entity.email()), entity.requestedAt()));
    }

    @Override
    public void purge(Email email) {
        repository.deleteById(email.value());
    }
}
