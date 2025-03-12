package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.AuthorizationData;
import com.jrobertgardzinski.security.domain.vo.AuthorizationTokenExpiration;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenExpiration;

public interface AuthorizationDataRepository {
    AuthorizationData createFor(Email email, RefreshTokenExpiration refreshTokenExpiration, AuthorizationTokenExpiration authorizationTokenExpiration);
}
