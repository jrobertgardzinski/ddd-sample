package com.jrobertgardzinski.security.repository;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import com.jrobertgardzinski.security.entity.AuthenticationBlockEntity;

import java.util.Optional;

public class AuthenticationBlockRepositoryAdapter implements AuthenticationBlockRepository {
    private final AuthenticationBlockJpaRepository repository;

    public AuthenticationBlockRepositoryAdapter(AuthenticationBlockJpaRepository repository) {
        this.repository = repository;
    }

    @Override
    public AuthenticationBlock create(AuthenticationBlock authenticationBlock) {
        return repository.save(AuthenticationBlockEntity.fromDomain(authenticationBlock)).asDomain();
    }

    @Override
    public void removeAllFor(IpAddress ipAddress) {
        repository.deleteById(ipAddress.value());
    }

    @Override
    public Optional<AuthenticationBlock> findBy(IpAddress ipAddress) {
        return Optional.empty();
    }
}
