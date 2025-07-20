package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;

public interface UserRepository {
    boolean existsByEmail(Email email);
    User findByEmail(Email email);
    User save(User user);
}
