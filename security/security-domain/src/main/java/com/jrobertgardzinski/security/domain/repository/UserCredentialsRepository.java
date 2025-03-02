package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.UserCredentials;
import com.jrobertgardzinski.security.domain.vo.Email;

public interface UserCredentialsRepository {
    UserCredentials create(UserCredentials userCredentials);
    UserCredentials findBy(Email email);
}
