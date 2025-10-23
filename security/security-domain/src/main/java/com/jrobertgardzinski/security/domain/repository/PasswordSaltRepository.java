package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.PasswordSalt;
import com.jrobertgardzinski.security.domain.vo.Email;

public interface PasswordSaltRepository {
    PasswordSalt findByEmail(Email email);
    PasswordSalt save(PasswordSalt passwordSalt);
}
