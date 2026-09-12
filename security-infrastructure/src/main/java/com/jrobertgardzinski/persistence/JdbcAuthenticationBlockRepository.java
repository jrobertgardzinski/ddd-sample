package com.jrobertgardzinski.persistence;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import com.jrobertgardzinski.security.domain.vo.Source;
import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;

import javax.sql.DataSource;
import java.util.Optional;

/**
 * PostgreSQL-backed {@link AuthenticationBlockRepository}. At most one block per source, so
 * {@code create} replaces any prior (e.g. expired) block for the same IP.
 */
@Singleton
@Requires(beans = DataSource.class)
final class JdbcAuthenticationBlockRepository implements AuthenticationBlockRepository {

    private final AuthenticationBlockJdbcRepository repository;

    JdbcAuthenticationBlockRepository(AuthenticationBlockJdbcRepository repository) {
        this.repository = repository;
    }

    @Override
    public AuthenticationBlock create(AuthenticationBlock authenticationBlock) {
        // one statement, so two requests tripping the limit together cannot collide on the key
        repository.upsert(authenticationBlock.source().ipAddress().value(), authenticationBlock.expiryDate());
        return authenticationBlock;
    }

    @Override
    public void removeAllFor(Source source) {
        repository.deleteById(source.ipAddress().value());
    }

    @Override
    public Optional<AuthenticationBlock> findBy(Source source) {
        // the guard asks this first, so this is where one source's attempts start taking their turn
        repository.lockSource(source.ipAddress().value());
        // only the identity is stored for blocks; the reloaded Source carries no observed context
        return repository.findById(source.ipAddress().value())
                .map(entity -> new AuthenticationBlock(
                        Source.of(new IpAddress(entity.ipAddress())), entity.expiryDate()));
    }
}
