package com.jrobertgardzinski.security.repository;

import com.jrobertgardzinski.security.entity.PasswordSaltEntity;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jpa.repository.JpaRepository;

@Repository
public interface PasswordSaltRepositoryJpa extends JpaRepository<PasswordSaltEntity, String> {
    PasswordSaltEntity findByEmail(String email);
}
