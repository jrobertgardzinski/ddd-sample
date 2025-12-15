package com.jrobertgardzinski.security.domain.vo.security.repository;


import com.jrobertgardzinski.security.domain.vo.security.entity.AuthorizationDataEntity;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jpa.repository.JpaRepository;

@Repository
public interface AuthorizationDataJpaRepository extends JpaRepository<AuthorizationDataEntity, String> {
    void deleteByEmail(String value);
    AuthorizationDataEntity findByEmailAndRefreshToken(String email, String refreshToken);
}
