package com.jrobertgardzinski.security.repository;

import com.jrobertgardzinski.security.entity.FailedAuthenticationEntity;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jpa.repository.JpaRepository;

@Repository
public interface FailedAuthenticationJpaRepository extends JpaRepository<FailedAuthenticationEntity, Long> {
    void deleteByIpAddress(String ipAddress);
    int countByIpAddress(String ipAddress);
}
