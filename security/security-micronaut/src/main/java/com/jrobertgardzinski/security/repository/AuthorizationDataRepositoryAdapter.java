package com.jrobertgardzinski.security.repository;

import com.jrobertgardzinski.security.domain.entity.AuthorizationData;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.RefreshToken;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenExpiration;
import com.jrobertgardzinski.security.domain.vo.TokenExpiration;
import com.jrobertgardzinski.security.entity.AuthorizationDataEntity;

import java.util.Optional;

public class AuthorizationDataRepositoryAdapter implements AuthorizationDataRepository {
    private final AuthorizationDataJpaRepository repository;

    public AuthorizationDataRepositoryAdapter(AuthorizationDataJpaRepository repository) {
        this.repository = repository;
    }

    @Override
    public AuthorizationData create(AuthorizationData authorizationData) {
        return repository.save(AuthorizationDataEntity.fromDomain(authorizationData)).asDomain();
    }

    @Override
    public void deleteBy(Email email) {
        repository.deleteByEmail(email.value());
    }

    @Override
    public RefreshTokenExpiration findRefreshTokenExpirationBy(Email email, RefreshToken refreshToken) {
        AuthorizationDataEntity blah = repository.findByEmailAndRefreshToken(email.value(), refreshToken.value().value());
        return new RefreshTokenExpiration(
                new TokenExpiration(
                        blah.getRefreshTokenExpiration()));
    }

    @Override
    public Optional<AuthorizationData> findBy(Email email) {
        return repository.findById(email.value()).map(AuthorizationDataEntity::asDomain);
    }
}

/*

Ogólnie jest problem z mapowaniem Calendar z jpa repo
//
//{
//        "_links": {
//        "self": [
//        {
//        "href": "/refresh",
//        "templated": false
//        }
//        ]
//        },
//        "_embedded": {
//        "errors": [
//        {
//        "message": "Internal Server Error: Error encoding object [com.jrobertgardzinski.security.entity.AuthorizationDataEntity@2174bb6e] to JSON: Error getting property [int setStateFields] of type [class java.util.Calendar]: Unable to make final int java.util.Calendar.getSetStateFields() accessible: module java.base does not \"opens java.util\" to unnamed module @71be98f5"
//        }
//        ]
//        },
//        "message": "Internal Server Error"
//        }*/