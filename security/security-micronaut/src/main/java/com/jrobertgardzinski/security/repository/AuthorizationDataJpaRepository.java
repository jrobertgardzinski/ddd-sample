package com.jrobertgardzinski.security.repository;


import com.jrobertgardzinski.security.entity.AuthorizationDataEntity;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jpa.repository.JpaRepository;

import java.util.Calendar;

@Repository
public interface AuthorizationDataJpaRepository extends JpaRepository<AuthorizationDataEntity, String> {
    void deleteByEmail(String value);
    AuthorizationDataEntity findByEmailAndRefreshToken(String email, String refreshToken);
}
