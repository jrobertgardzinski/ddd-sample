package com.jrobertgardzinski.security.repository;

import com.jrobertgardzinski.security.entity.UserEntity;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jpa.repository.JpaRepository;

@Repository
public interface UserJpaRepository extends JpaRepository<UserEntity, String> {
    boolean existsByEmail(String email);
    UserEntity findByEmail(String email);
    //UserEntity save(Use);
}
