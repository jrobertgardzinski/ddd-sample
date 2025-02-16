package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.entity.UserDetails;
import com.jrobertgardzinski.security.domain.repository.exception.UserAlreadyExistsException;

public interface UserRepository {
    User createUser(UserDetails userDetails) throws UserAlreadyExistsException;
}
