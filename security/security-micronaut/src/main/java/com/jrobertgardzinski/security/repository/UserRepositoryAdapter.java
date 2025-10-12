package com.jrobertgardzinski.security.repository;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.entity.UserEntity;

import java.util.Optional;

public class UserRepositoryAdapter implements UserRepository {
    private final UserJpaRepository userJpaRepository;

    public UserRepositoryAdapter(UserJpaRepository userJpaRepository) {
        this.userJpaRepository = userJpaRepository;
    }

    @Override
    public boolean existsBy(Email email) {
        return userJpaRepository.existsByEmail(email.value());
    }

    @Override
    public Optional<User> findBy(Email email) {
        return Optional.ofNullable(userJpaRepository.findByEmail(email.value()).asDomain());
    }

    @Override
    public User save(User user) {
        return userJpaRepository.save(UserEntity.fromDomain(user)).asDomain();
    }
}
