package com.jrobertgardzinski.security.domain.vo.security.repository;

import com.jrobertgardzinski.security.domain.vo.security.entity.AuthenticationBlockEntity;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jpa.repository.JpaRepository;

@Repository
public interface AuthenticationBlockJpaRepository extends JpaRepository<AuthenticationBlockEntity, String> {
}
