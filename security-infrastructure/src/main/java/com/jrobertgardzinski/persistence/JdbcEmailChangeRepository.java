package com.jrobertgardzinski.persistence;

import com.jrobertgardzinski.TokenHashing;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.repository.EmailChangeRepository;
import com.jrobertgardzinski.security.domain.vo.EmailChange;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;
import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;

import javax.sql.DataSource;
import java.util.Optional;

/**
 * PostgreSQL-backed {@link EmailChangeRepository}. Keyed by the SHA-256 hash of the pending token
 * (see {@link TokenHashing}); confirming matches on that hash, deletes the row (single-use) and
 * returns the change. Raw tokens are never stored.
 */
@Singleton
@Requires(beans = DataSource.class)
final class JdbcEmailChangeRepository implements EmailChangeRepository {

    private final EmailChangeJdbcRepository repository;
    private final java.time.Clock clock;

    JdbcEmailChangeRepository(EmailChangeJdbcRepository repository, java.time.Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Override
    public void startChange(EmailChange change, VerificationToken token) {
        repository.save(new EmailChangeEntity(
                TokenHashing.hash(token), change.currentEmail().value(), change.newEmail().value(),
                java.time.LocalDateTime.now(clock)));
    }

    @Override
    public Optional<PendingEmailChange> confirmChange(VerificationToken token) {
        String hash = TokenHashing.hash(token);
        return repository.findById(hash)
                .filter(entity -> repository.consume(hash) > 0)   // the DELETE decides, not the read
                .map(entity -> new PendingEmailChange(
                        new EmailChange(Email.of(entity.currentEmail()), Email.of(entity.newEmail())),
                        entity.startedAt()));
    }

    /** Both ends of a move: the address can appear as the source of one change and the target of another. */
    @Override
    public void purge(Email email) {
        repository.deleteByCurrentEmail(email.value());
        repository.deleteByNewEmail(email.value());
    }
}
