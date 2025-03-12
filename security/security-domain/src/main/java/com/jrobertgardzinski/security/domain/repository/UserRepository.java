package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;

public interface UserRepository {
    boolean doesExist(Email email);
    User create(User user);
    User findBy(Email email);
}
