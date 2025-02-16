package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.UserDetails;

import java.util.Optional;

public interface UserRepository {
    Optional<User> createUser(UserDetails userDetails);
    Optional<User> findUserByEmail(Email email);
}
