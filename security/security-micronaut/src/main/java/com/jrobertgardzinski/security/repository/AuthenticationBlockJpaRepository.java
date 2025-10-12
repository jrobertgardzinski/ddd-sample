package com.jrobertgardzinski.security.repository;

import com.jrobertgardzinski.security.entity.AuthenticationBlockEntity;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jpa.repository.JpaRepository;

@Repository
public interface AuthenticationBlockJpaRepository extends JpaRepository<AuthenticationBlockEntity, String> {
}
