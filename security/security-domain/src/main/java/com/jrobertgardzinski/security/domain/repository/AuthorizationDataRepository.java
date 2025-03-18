package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.AuthorizationData;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.RefreshToken;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenExpiration;

public interface AuthorizationDataRepository {
    AuthorizationData create(AuthorizationData authorizationData);

    void deleteBy(Email email);

    RefreshTokenExpiration findRefreshTokenExpirationBy(Email email, RefreshToken refreshToken);

}
