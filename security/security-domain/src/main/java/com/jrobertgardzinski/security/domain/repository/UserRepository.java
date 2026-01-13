package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;

import java.util.Optional;

public interface UserRepository {

    boolean existsBy(Email email);

    Optional<User> findBy(Email email);

    User save(User user) throws Exception;
}
