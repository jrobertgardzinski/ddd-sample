package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.port.entity.UserEntity;

public interface UserRepository {

    boolean existsBy(Email email);

    User findBy(Email email);

    User save(User user);
}
