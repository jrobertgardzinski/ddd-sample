package com.jrobertgardzinski.security.repository;

import com.jrobertgardzinski.security.domain.entity.PasswordSalt;
import com.jrobertgardzinski.security.domain.repository.PasswordSaltRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.entity.PasswordSaltEntity;

public class PasswordSaltRepositoryAdapter implements PasswordSaltRepository {
    private final PasswordSaltRepositoryJpa jpa;

    public PasswordSaltRepositoryAdapter(PasswordSaltRepositoryJpa jpa) {
        this.jpa = jpa;
    }

    @Override
    public PasswordSalt findByEmail(Email email) {
        return jpa.findByEmail(email.value()).asDomain();
    }

    @Override
    public PasswordSalt save(PasswordSalt passwordSalt) {
        return jpa.save(PasswordSaltEntity.fromDomain(passwordSalt)).asDomain();
    }
}
