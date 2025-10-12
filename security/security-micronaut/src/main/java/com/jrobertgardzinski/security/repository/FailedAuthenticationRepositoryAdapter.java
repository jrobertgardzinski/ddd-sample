package com.jrobertgardzinski.security.repository;

import com.jrobertgardzinski.security.domain.entity.FailedAuthentication;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.FailuresCount;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import com.jrobertgardzinski.security.entity.FailedAuthenticationEntity;

import java.time.LocalDateTime;

public class FailedAuthenticationRepositoryAdapter implements FailedAuthenticationRepository {
    private final FailedAuthenticationJpaRepository repository;

    public FailedAuthenticationRepositoryAdapter(FailedAuthenticationJpaRepository repository) {
        this.repository = repository;
    }

    @Override
    public FailedAuthentication create(FailedAuthenticationDetails failedAuthenticationDetails) {
        return repository.save(
                new FailedAuthenticationEntity(
                        failedAuthenticationDetails.ipAddress().value(),
                        failedAuthenticationDetails.time()))
                .asDomain();
    }

    @Override
    public FailuresCount countFailuresBy(IpAddress ipAddress) {
        return new FailuresCount(repository.countByIpAddress(ipAddress.value()));
    }

    @Override
    public void removeAllFor(IpAddress ipAddress) {
        repository.deleteByIpAddress(ipAddress.value());
    }
}
