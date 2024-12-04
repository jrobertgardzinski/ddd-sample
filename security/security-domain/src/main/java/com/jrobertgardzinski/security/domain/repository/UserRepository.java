package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.exception.UserAlreadyExistsException;
import com.jrobertgardzinski.security.domain.vo.Email;

import java.util.Optional;

public interface UserRepository {
    User createUser(User user) throws UserAlreadyExistsException;
    User findUserByEmail(Email email);
}
