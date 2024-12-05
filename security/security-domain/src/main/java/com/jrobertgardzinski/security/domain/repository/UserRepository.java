package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;

import java.util.Optional;

public interface UserRepository {
    Optional<User> createUser(User user);
    Optional<User> findUserByEmail(Email email);
}
